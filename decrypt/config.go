package decrypt

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
	"github.com/oiweiwei/gokrb5.fork/v9/keytab"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// Config holds whichever --decrypt-* credential(s) the operator supplied
// (mutually exclusive within each mechanism family, enforced in
// ResolveConfig).
//
// NTHash/Password are the connecting client's own NTLM credential (the
// account being proxied) - used for NTLM/Sicily decryption, and for the
// NTLM-under-bare-GSSAPI/NTLM-under-SPNEGO fallback cases. NTHash is
// resolved once at startup, either directly from --decrypt-hash or by
// hashing --decrypt-password.
//
// SvcPassword/Salt are a different principal's credential: the target LDAP
// service's own Kerberos key (e.g. the DC's machine account), derived from a
// plaintext password via RFC 3962 string2key - needed to decrypt a GSSAPI/SPNEGO
// AP-REQ's Ticket.  The client's own credential can't decrypt this because the
// ticket's session key is a fresh KDC-generated value never derived from the
// client's password.  Keytab/RawSvcKey are other ways to supply this same
// service key and take priority when set - see resolveSessionKey.
//
// CCache is the exception: it needs no service credential at all. It's the
// connecting user's own ticket cache, which stores the service ticket's
// session key alongside the ticket, so the traffic can be decrypted straight
// from that stored key - see resolveSessionKey's CCACHE branch.
//
// RawSvcKey is the service's own long-term key, given directly as raw bytes
// rather than via a keytab file - used to decrypt the Ticket's EncPart the
// same way a keytab entry would. Its encryption type is not stored here: the
// observed ticket's own EncPart.EType (sent in the clear) is authoritative,
// which also disambiguates a 16-byte AES128 key from a 16-byte RC4-HMAC one -
// something the key's byte length alone cannot do.
type Config struct {
	NTHash   []byte
	Password string

	SvcPassword string
	Salt        string

	Keytab    *keytab.Keytab
	CCache    *credentials.CCache
	RawSvcKey []byte
}

// ResolveConfig validates the --decrypt-* flags (mutual exclusion within
// each mechanism family) and loads whichever credential source(s) were
// given. All arguments empty is valid - decryption simply never engages,
// since these flags are the opt-in signal themselves; there's no separate
// gate flag.
func ResolveConfig(ntHashHex, ntPassword, svcPassword, svcKeytabPath, ccachePath, svcKeySpec, salt string) (Config, error) {
	var cfg Config

	if ntHashHex != "" && ntPassword != "" {
		return cfg, errors.New("invalid decryption flags: --decrypt-hash and --decrypt-password are mutually exclusive")
	}
	switch {
	case ntHashHex != "":
		h, err := hex.DecodeString(ntHashHex)
		if err != nil {
			return cfg, fmt.Errorf("invalid --decrypt-hash: %w", err)
		}
		cfg.NTHash = h
	case ntPassword != "":
		cfg.NTHash = NTHashFromPassword(ntPassword)
		cfg.Password = ntPassword
	}

	cfg.SvcPassword = svcPassword
	cfg.Salt = salt

	krb5Sources := 0
	for _, s := range []string{svcKeytabPath, ccachePath, svcKeySpec} {
		if s != "" {
			krb5Sources++
		}
	}
	if krb5Sources > 1 {
		return cfg, errors.New("invalid decryption flags: --decrypt-svc-keytab, --decrypt-ccache, and --decrypt-svc-key are mutually exclusive")
	}

	switch {
	case svcKeytabPath != "":
		kt, err := keytab.Load(svcKeytabPath)
		if err != nil {
			return cfg, fmt.Errorf("load --decrypt-svc-keytab: %w", err)
		}
		cfg.Keytab = kt
	case ccachePath != "":
		cc, err := credentials.LoadCCache(ccachePath)
		if err != nil {
			return cfg, fmt.Errorf("load --decrypt-ccache: %w", err)
		}
		cfg.CCache = cc
	case svcKeySpec != "":
		key, err := parseRawKrb5Key(svcKeySpec)
		if err != nil {
			return cfg, fmt.Errorf("invalid --decrypt-svc-key: %w", err)
		}
		cfg.RawSvcKey = key
	}

	return cfg, nil
}

// resolveNTHash returns the configured NT hash and whether one was given at
// all - the "was any --decrypt-hash/--decrypt-password flag given" check
// bindinspect.go needs before even attempting NTLM key derivation. Falls
// back to hashing Password if NTHash wasn't already populated (normally
// ResolveConfig does this eagerly, but Config values built directly - e.g.
// in tests - may only set one of the two).
func (c Config) resolveNTHash() (hash []byte, ok bool) {
	if len(c.NTHash) > 0 {
		return c.NTHash, true
	}
	if c.Password != "" {
		return NTHashFromPassword(c.Password), true
	}
	return nil, false
}

// resolveSessionKey recovers the Kerberos session key for an observed
// AP-REQ's ticket, via whichever credential source is configured. Keytab,
// CCACHE, and RawSvcKey/password are materially different routes here,
// not just equivalent syntaxes for the same thing:
//
//   - Keytab holds the *service's* long-term key, which decrypts the
//     ticket generically for any client's exchange to that service - the
//     session key only exists after that decryption succeeds.
//   - CCACHE hands over the session key *directly* - there is nothing to
//     decrypt with it, and attempting to use it as a ticket-decryption key
//     would simply fail (it isn't the service's key). This is the path that
//     needs no service credential at all: a ccache stores each ticket's
//     session key alongside the ticket itself, so the *connecting user's own*
//     ticket cache (their KRB5CCNAME / exported cache), containing the
//     service ticket they used on the wire, is sufficient to decrypt the
//     traffic. The right entry is found by which cached key actually decrypts
//     the AP-REQ's Authenticator (see below), not by matching ticket bytes.
//   - --decrypt-svc-key and --decrypt-svc-password (+ --decrypt-salt for
//     AES) derive or supply a service key directly, without a keytab file -
//     they must be the credential for whichever account the ticket's SPN
//     resolves to (e.g. the target DC's machine account), not the
//     connecting client's own credential, which can't decrypt this exchange
//     at all: the ticket's session key is a fresh value the KDC generated
//     for it, never derived from any password. See
//     deriveServiceKeyFromPassword for the derivation itself and its salt
//     caveat.
func resolveSessionKey(cfg Config, apReq *messages.APReq) (types.EncryptionKey, error) {
	tkt := &apReq.Ticket
	switch {
	case cfg.Keytab != nil:
		serviceKey, _, err := cfg.Keytab.GetEncryptionKey(tkt.SName, tkt.Realm, tkt.EncPart.KVNO, tkt.EncPart.EType)
		if err != nil {
			return types.EncryptionKey{}, fmt.Errorf("keytab: no matching key for %v: %w", tkt.SName.PrincipalNameString(), err)
		}
		if err := tkt.Decrypt(serviceKey); err != nil {
			return types.EncryptionKey{}, fmt.Errorf("decrypt ticket (wrong keytab entry?): %w", err)
		}
		return tkt.DecryptedEncPart.Key, nil

	case cfg.CCache != nil:
		// Match by which cached session key actually decrypts the AP-REQ's
		// Authenticator, not by re-marshaling the observed ticket and
		// comparing its bytes to the ccache's stored copy. The Authenticator
		// is encrypted under the ticket's session key, so only the correct
		// entry decrypts it (integrity-checked - a wrong key errors cleanly
		// without corrupting apReq), and this avoids false misses from benign
		// DER re-encoding differences between the wire ticket and the ccache.
		// A ccache entry for any other service simply won't decrypt this
		// Authenticator, so trying every entry is unambiguous.
		for _, cred := range cfg.CCache.GetEntries() {
			if err := apReq.DecryptAuthenticator(cred.Key); err == nil {
				return cred.Key, nil
			}
		}
		return types.EncryptionKey{}, fmt.Errorf("ccache: no cached ticket's session key could decrypt the AP-REQ Authenticator for %v (is this the connecting user's own ccache, containing that service ticket?)", tkt.SName.PrincipalNameString())

	case cfg.RawSvcKey != nil:
		// The ticket's own declared encryption type (sent in the clear) is
		// authoritative for how to type the raw key - not a guess from the
		// key's byte length, which can't tell a 16-byte AES128 key from a
		// 16-byte RC4-HMAC one. This is what makes --decrypt-svc-key work for
		// an AES128 service key at all.
		eType := tkt.EncPart.EType
		if et, err := crypto.GetEtype(eType); err == nil {
			if want := et.GetKeyByteSize(); len(cfg.RawSvcKey) != want {
				return types.EncryptionKey{}, fmt.Errorf("--decrypt-svc-key is %d bytes, but the observed ticket uses encryption type %d, which needs a %d-byte key", len(cfg.RawSvcKey), eType, want)
			}
		}
		serviceKey := types.EncryptionKey{KeyType: eType, KeyValue: cfg.RawSvcKey}
		if err := tkt.Decrypt(serviceKey); err != nil {
			return types.EncryptionKey{}, fmt.Errorf("decrypt ticket (wrong --decrypt-svc-key?): %w", err)
		}
		return tkt.DecryptedEncPart.Key, nil

	case cfg.SvcPassword != "":
		serviceKey, err := deriveServiceKeyFromPassword(cfg, tkt)
		if err != nil {
			return types.EncryptionKey{}, err
		}
		if err := tkt.Decrypt(serviceKey); err != nil {
			return types.EncryptionKey{}, fmt.Errorf("decrypt ticket (wrong --decrypt-svc-password, or wrong salt - try --decrypt-salt): %w", err)
		}
		return tkt.DecryptedEncPart.Key, nil

	default:
		return types.EncryptionKey{}, errors.New("no --decrypt-svc-keytab/--decrypt-ccache/--decrypt-svc-key/--decrypt-svc-password supplied")
	}
}

// deriveServiceKeyFromPassword derives a service key for the ticket's own
// declared encryption type (tkt.EncPart.EType, sent in the clear as part of
// the ticket) directly from --decrypt-svc-password, without needing a keytab
// file - RC4-HMAC's key *is* the NT hash (derived from the password), and
// AES128/256 use RFC 3962's PBKDF2-based string2key, which gokrb5.fork's
// etype primitives already implement.
//
// The salt AES needs defaults to RFC 4120's generic convention (REALM + the
// ticket's own SPN components, via tkt.SName) when --decrypt-salt isn't
// given. A wrong salt derives a wrong key, which fails the ticket's
// integrity check cleanly rather than silently corrupting anything.
func deriveServiceKeyFromPassword(cfg Config, tkt *messages.Ticket) (types.EncryptionKey, error) {
	eType := tkt.EncPart.EType

	if eType == etypeID.RC4_HMAC {
		if cfg.SvcPassword == "" {
			return types.EncryptionKey{}, errors.New("ticket uses RC4-HMAC - --decrypt-svc-password is required")
		}
		return types.EncryptionKey{KeyType: etypeID.RC4_HMAC, KeyValue: NTHashFromPassword(cfg.SvcPassword)}, nil
	}

	if eType != etypeID.AES128_CTS_HMAC_SHA1_96 && eType != etypeID.AES256_CTS_HMAC_SHA1_96 {
		return types.EncryptionKey{}, fmt.Errorf("ticket uses encryption type %d - password-derived keys are only supported for RC4-HMAC and AES128/256", eType)
	}
	if cfg.SvcPassword == "" {
		return types.EncryptionKey{}, errors.New("ticket uses AES - --decrypt-svc-password is required")
	}

	et, err := crypto.GetEtype(eType)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("password-derived service key: %w", err)
	}
	salt := cfg.Salt
	if salt == "" {
		salt = tkt.SName.GetSalt(tkt.Realm)
	}
	keyValue, err := et.StringToKey(cfg.SvcPassword, salt, et.GetDefaultStringToKeyParams())
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("derive AES key from password: %w", err)
	}
	return types.EncryptionKey{KeyType: eType, KeyValue: keyValue}, nil
}

// parseRawKrb5Key decodes --decrypt-svc-key's hex value and validates it's
// one of the three AD-relevant Kerberos key sizes. The encryption type is
// deliberately not inferred here: a 16-byte key is ambiguous (AES128 vs
// RC4-HMAC/NT hash) and the observed ticket's own EncPart.EType resolves it
// authoritatively at decrypt time - see resolveSessionKey's RawSvcKey branch.
func parseRawKrb5Key(hexKey string) (key []byte, err error) {
	key, err = hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}

	switch len(key) {
	case 16, 24, 32:
		return key, nil
	default:
		return nil, fmt.Errorf("key is %d bytes - expected 16 (AES128 or RC4-HMAC), 24 (DES3), or 32 (AES256) bytes", len(key))
	}
}
