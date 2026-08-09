package decrypt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/chksumtype"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// Channel binding injection into a Kerberos bind. The value goes in the
// Bnd field of the RFC 4121 §4.1.1.1 GSS-API checksum inside the AP-REQ's
// Authenticator, which is encrypted under the ticket's session key.

// gssChecksumBndLen is the fixed length of the checksum's Bnd field (RFC
// 4121 §4.1.1.1): the MD5 of a gss_channel_bindings_struct.
const gssChecksumBndLen = 16

// apReqFromBindCreds extracts the AP-REQ from SASL credentials, covering
// both bare SASL/GSSAPI and SASL/GSS-SPNEGO.
func apReqFromBindCreds(credBytes []byte) (*messages.APReq, error) {
	var tok spnego.KRB5Token
	if err := tok.Unmarshal(credBytes); err == nil && tok.IsAPReq() {
		return &tok.APReq, nil
	}
	return apReqFromSPNEGOToken(credBytes)
}

// authenticatorKeyUsage returns the RFC 4120 §7.5.1 key usage for an
// AP-REQ Authenticator, which differs for TGS tickets.
func authenticatorKeyUsage(sname types.PrincipalName) uint32 {
	if len(sname.NameString) > 0 && sname.NameString[0] == "krbtgt" {
		return keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR
	}
	return keyusage.AP_REQ_AUTHENTICATOR
}

// rewriteKerberosChannelBindings substitutes token into the Bnd field of
// the AP-REQ Authenticator's GSS-API checksum. Returns nil credentials and
// no error when the round has nothing to rewrite. The substitution is made
// at the byte level so every enclosing length stays as the client encoded
// it.
func rewriteKerberosChannelBindings(credBytes []byte, cfg Config, token []byte) ([]byte, error) {
	apReq, err := apReqFromBindCreds(credBytes)
	if err != nil {
		return nil, nil
	}

	sessionKey, err := resolveSessionKey(cfg, apReq)
	if err != nil {
		return nil, err
	}

	usage := authenticatorKeyUsage(apReq.Ticket.SName)
	plaintext, err := crypto.DecryptEncPart(apReq.EncryptedAuthenticator, sessionKey, usage)
	if err != nil {
		return nil, fmt.Errorf("decrypt authenticator: %w", err)
	}

	var authenticator types.Authenticator
	if err := authenticator.Unmarshal(plaintext); err != nil {
		return nil, fmt.Errorf("unmarshal authenticator: %w", err)
	}

	cksum := authenticator.Cksum.Checksum
	if authenticator.Cksum.CksumType != chksumtype.GSSAPI || len(cksum) < 4 {
		return nil, nil
	}
	if binary.LittleEndian.Uint32(cksum[:4]) != gssChecksumBndLen || len(cksum) < 4+gssChecksumBndLen {
		return nil, nil
	}
	if bytes.Equal(cksum[4:4+gssChecksumBndLen], token) {
		return nil, nil
	}

	patched, err := substituteOnce(plaintext, cksum, replaceBnd(cksum, token))
	if err != nil {
		return nil, fmt.Errorf("locate GSS-API checksum in authenticator: %w", err)
	}

	encrypted, err := crypto.GetEncryptedData(patched, sessionKey, usage, apReq.Ticket.EncPart.KVNO)
	if err != nil {
		return nil, fmt.Errorf("re-encrypt authenticator: %w", err)
	}
	// The substitution below depends on the re-encrypted authenticator
	// being the same length as the original.
	if len(encrypted.Cipher) != len(apReq.EncryptedAuthenticator.Cipher) {
		return nil, fmt.Errorf("re-encrypted authenticator is %d bytes, expected %d", len(encrypted.Cipher), len(apReq.EncryptedAuthenticator.Cipher))
	}

	newCreds, err := substituteOnce(credBytes, apReq.EncryptedAuthenticator.Cipher, encrypted.Cipher)
	if err != nil {
		return nil, fmt.Errorf("locate encrypted authenticator in SASL credentials: %w", err)
	}
	return newCreds, nil
}

// replaceBnd returns cksum with token in place of its Bnd field.
func replaceBnd(cksum, token []byte) []byte {
	out := append([]byte(nil), cksum...)
	copy(out[4:4+gssChecksumBndLen], token)
	return out
}

// substituteOnce returns b with old replaced by new, requiring old to
// occur exactly once and be the same length as new.
func substituteOnce(b, old, new []byte) ([]byte, error) {
	if len(old) != len(new) {
		return nil, errors.New("replacement differs in length")
	}
	idx := bytes.Index(b, old)
	if idx < 0 {
		return nil, errors.New("not found")
	}
	if bytes.Contains(b[idx+1:], old) {
		return nil, errors.New("found more than once")
	}
	out := append([]byte(nil), b...)
	copy(out[idx:], new)
	return out, nil
}
