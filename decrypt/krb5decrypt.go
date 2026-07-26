package decrypt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Macmod/ldapx/log"

	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/chksumtype"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

var ETypeNames = map[int32]string{
	1:  "DES-CBC-CRC",
	3:  "DES-CBC-MD5",
	16: "DES3-CBC-SHA1-KD",
	17: "AES128-CTS-HMAC-SHA1-96",
	18: "AES256-CTS-HMAC-SHA1-96",
	19: "AES128-CTS-HMAC-SHA256-128",
	20: "AES256-CTS-HMAC-SHA384-192",
	23: "RC4-HMAC",
}

// This file is the Kerberos handshake-completion core: turn an observed
// AP-REQ (bare GSSAPI or SPNEGO-wrapped) into the session key for subsequent
// wrap/unwrap, resolve the AP-REP acceptor subkey when one is present, and
// classify the negotiated security layer. Credential resolution lives in
// config.go, the SPNEGO envelope parsing in spnego.go, and the per-message
// wrap/unwrap token layer in gsswrap.go.

// completeGSSAPI decrypts an observed AP-REQ's ticket via the configured
// credential source, decrypts its Authenticator, and returns the session
// key to use for subsequent GSS wrap/unwrap (the Authenticator's SubKey if
// present, per RFC 4120 §5.5.1, else the ticket's own session key) alongside
// the Authenticator's checksum, for the caller to classify via
// krb5SecurityLayer - the checksum only becomes readable once
// DecryptAuthenticator succeeds, so it can't be obtained independently
// without re-doing the ticket decryption here.
func completeGSSAPI(cfg Config, apReqBytes []byte) (types.EncryptionKey, types.Checksum, error) {
	var apReq messages.APReq
	if err := apReq.Unmarshal(apReqBytes); err != nil {
		return types.EncryptionKey{}, types.Checksum{}, fmt.Errorf("krb5decrypt: unmarshal AP-REQ: %w", err)
	}

	sessionKey, err := resolveSessionKey(cfg, &apReq)
	if err != nil {
		return types.EncryptionKey{}, types.Checksum{}, fmt.Errorf("krb5decrypt: %w", err)
	}

	if err := apReq.DecryptAuthenticator(sessionKey); err != nil {
		return types.EncryptionKey{}, types.Checksum{}, fmt.Errorf("krb5decrypt: decrypt authenticator: %w", err)
	}

	if len(apReq.Authenticator.SubKey.KeyValue) > 0 {
		log.Log.Print(
			decryptColor.Sprintf(
				"[+] Kerberos: using acceptor's subkey etype=%s (%d)",
				ETypeNames[apReq.Authenticator.SubKey.KeyType],
				apReq.Authenticator.SubKey.KeyType,
			),
		)
		return apReq.Authenticator.SubKey, apReq.Authenticator.Cksum, nil
	}

	log.Log.Print(
		decryptColor.Sprintf(
			"[+] Kerberos: using session key from ticket etype=%s (%d)",
			ETypeNames[sessionKey.KeyType],
			sessionKey.KeyType,
		),
	)
	return sessionKey, apReq.Authenticator.Cksum, nil
}

// completeSPNEGO extracts the inner Kerberos AP-REQ from a SPNEGO
// negotiation token and runs it through the same logic as completeGSSAPI -
// everything past the outer envelope reuses the GSSAPI path unchanged. Only
// the Kerberos-inside-SPNEGO case is handled - an NTLM token inside SPNEGO
// (a real possibility: SPNEGO can negotiate down to NTLM whenever Kerberos
// isn't usable, e.g. connecting by bare IP with no resolvable SPN) returns
// a clear "not handled" error rather than being silently ignored.
//
// tokenBytes is whichever negotiation token actually carries the mechanism
// token - the *last* one BindSession observed, not necessarily the first:
// only the first client message is a NegTokenInit (MechTypes + optional
// mechToken); any further rounds are NegTokenResp (ResponseToken instead of
// MechTokenBytes), so both shapes have to be handled, not just the first.
func completeSPNEGO(cfg Config, tokenBytes []byte) (types.EncryptionKey, types.Checksum, error) {
	// Some real clients send NTLM continuation rounds as a bare NTLM
	// message, not wrapped in a NegTokenResp at all - RFC 4178 expects
	// every round to be a NegotiationToken, but this is what's actually on
	// the wire once SPNEGO has negotiated NTLM as the chosen mechanism.
	// Detected up front so this hits the same clear "not handled" error as
	// a properly-wrapped NTLM mechToken would, instead of a confusing
	// ASN.1 parse failure.
	if bytes.HasPrefix(tokenBytes, ntlmSignature) {
		return types.EncryptionKey{}, types.Checksum{}, errors.New("krb5decrypt: SPNEGO negotiated NTLM, not Kerberos (NTLM-inside-SPNEGO is not handled by the Kerberos decrypt path)")
	}

	mechTokenBytes, err := unmarshalSPNEGOMechToken(tokenBytes)
	if err != nil {
		return types.EncryptionKey{}, types.Checksum{}, err
	}
	if len(mechTokenBytes) == 0 {
		return types.EncryptionKey{}, types.Checksum{}, errors.New("krb5decrypt: SPNEGO negotiation token carries no mechanism token")
	}

	apReq, err := apReqFromMechToken(mechTokenBytes)
	if err != nil {
		return types.EncryptionKey{}, types.Checksum{}, err
	}
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return types.EncryptionKey{}, types.Checksum{}, fmt.Errorf("krb5decrypt: re-marshal extracted AP-REQ: %w", err)
	}
	return completeGSSAPI(cfg, apReqBytes)
}

// apRepKeyCandidates builds findAPRepSubkey's candidate key list: the
// already-resolved key (Authenticator subkey or ticket session key) plus,
// if different, the ticket's own session key re-derived independently via
// resolveSessionKey. See findAPRepSubkey's doc comment for why both are
// tried rather than trusting one fixed reading of which key encrypts the
// AP-REP.
func apRepKeyCandidates(cfg Config, apReq *messages.APReq, key types.EncryptionKey) []types.EncryptionKey {
	candidates := []types.EncryptionKey{key}
	if sessionKey, err := resolveSessionKey(cfg, apReq); err == nil && !bytes.Equal(sessionKey.KeyValue, key.KeyValue) {
		candidates = append(candidates, sessionKey)
	}
	return candidates
}

// extractAPRep tries to parse roundBytes as a Kerberos AP-REP, tolerating a
// bare GSS mechanism token (as sent directly in bare SASL/GSSAPI's own
// framing) and one nested inside a SPNEGO NegTokenInit/NegTokenResp (SASL/
// GSS-SPNEGO's framing). Per RFC 2743 §3.1, only the *initial* context token
// needs the OID-tagged "Initial Context Token" wrapper - a real AP-REP,
// being a later token in the exchange, may or may not carry it, so both
// forms (wrapped via spnego.KRB5Token, and a bare TOK_ID-prefixed AP-REP)
// are tried directly, alongside the case where it's the mechanism token
// nested inside SPNEGO's own envelope.
func extractAPRep(roundBytes []byte) (*messages.APRep, bool) {
	var tok spnego.KRB5Token
	if err := tok.Unmarshal(roundBytes); err == nil && tok.IsAPRep() {
		return &tok.APRep, true
	}
	if len(roundBytes) > 2 && roundBytes[0] == 0x02 && roundBytes[1] == 0x00 {
		var a messages.APRep
		if err := a.Unmarshal(roundBytes[2:]); err == nil {
			return &a, true
		}
	}
	if isInit, negTok, err := spnego.UnmarshalNegToken(roundBytes); err == nil {
		var inner []byte
		if isInit {
			inner = negTok.(spnego.NegTokenInit).MechTokenBytes
		} else {
			inner = negTok.(spnego.NegTokenResp).ResponseToken
		}
		if len(inner) > 0 {
			if apRep, ok := extractAPRep(inner); ok {
				return apRep, true
			}
		}
	}
	return nil, false
}

// findAPRepSubkey scans every observed round for a Kerberos AP-REP and, if
// one is found and its EncPart decrypts with any of candidateKeys, returns
// its Subkey. Per RFC 4121 §2, the AP-REP's own subkey - when the acceptor
// supplies one - takes precedence over the Authenticator's subkey (or the
// ticket's session key) for the rest of the GSS context: Windows Server
// 2022 DCs commonly include one whenever mutual authentication is used, so
// the AP-REP must be examined to recover the correct key, even though the
// AP-REQ's own Ticket/Authenticator decrypt fine without it.
//
// candidateKeys takes more than one entry because which key actually
// encrypts the AP-REP - the Authenticator's own subkey if the initiator
// supplied one, or the ticket's session key otherwise - is a real
// discrepancy between RFC 4120 §5.5.2's text and observed behavior against a
// Windows Server 2022 DC's mutual-authentication AP-REP; trying every
// candidate avoids hard-coding a single reading that may not match every
// real peer.
func findAPRepSubkey(pending [][]byte, candidateKeys []types.EncryptionKey) (types.EncryptionKey, bool) {
	for _, round := range pending {
		apRep, ok := extractAPRep(round)
		if !ok {
			continue
		}
		for _, key := range candidateKeys {
			if err := apRep.DecryptEncPart(key); err != nil {
				continue
			}
			if len(apRep.DecryptedEncPart.Subkey.KeyValue) > 0 {
				return apRep.DecryptedEncPart.Subkey, true
			}
			break
		}
	}
	return types.EncryptionKey{}, false
}

// gssChecksumFlags parses the RFC 4121 §4.1.1.1 GSS-API checksum embedded in
// a Kerberos Authenticator's Cksum field: Lgth(4 bytes LE) + Bnd(Lgth bytes)
// + Flags(4 bytes LE). ok is false - rather than a guessed zero value - if
// cksum isn't this checksum type, or its bytes are too short to hold the
// Flags field its own Lgth claims.
func gssChecksumFlags(cksum types.Checksum) (flags uint32, ok bool) {
	if cksum.CksumType != chksumtype.GSSAPI {
		return 0, false
	}
	b := cksum.Checksum
	if len(b) < 4 {
		return 0, false
	}
	flagsOffset := 4 + int(binary.LittleEndian.Uint32(b[:4]))
	if len(b) < flagsOffset+4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[flagsOffset : flagsOffset+4]), true
}

// krb5SecurityLayer classifies an Authenticator's GSS checksum flags the
// same way ntlmSecurityLayer classifies NTLM's negotiated flags. For
// SASL/GSS-SPNEGO this reflects the actual per-message layer choice; for
// bare SASL/GSSAPI (RFC 4752), a conformant client always requests the
// maximum here regardless of what it ends up choosing in the separate
// RFC 4752 §3.3 post-AP-REP security-layer-negotiation round, which this
// does not parse - so for that mechanism specifically, this reports the
// requested capability, not necessarily the final per-message layer.
// Advisory information only either way, same as SecurityLayer generally.
func krb5SecurityLayer(cksum types.Checksum) SecurityLayer {
	flags, ok := gssChecksumFlags(cksum)
	if !ok {
		return LayerUnknown
	}
	seal := flags&gssapi.ContextFlagConf != 0
	sign := flags&gssapi.ContextFlagInteg != 0
	switch {
	case seal && sign:
		return LayerSignSeal
	case seal:
		return LayerSealOnly
	case sign:
		return LayerSignOnly
	default:
		return LayerNone
	}
}
