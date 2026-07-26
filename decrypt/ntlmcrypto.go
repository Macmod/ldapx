package decrypt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
)

// This file implements the MS-NLMP key-derivation chain (NTOWFv2 -> KXKEY ->
// SIGNKEY/SEALKEY) needed to derive NTLMv2 session keys as a third party who
// knows the account's NT hash (or password) and has observed the three
// wire messages (NEGOTIATE_MESSAGE/CHALLENGE_MESSAGE/AUTHENTICATE_MESSAGE) -
// not as the client or server themselves. No existing Go NTLM library
// implements this specific role, so this is hand-rolled directly from the
// spec.

const (
	ntlmNegotiateKeyExch            = 1 << 30 // NTLMSSP_NEGOTIATE_KEY_EXCH
	ntlmNegotiateExtendedSessionSec = 1 << 19 // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	ntlmNegotiateSign               = 1 << 4  // NTLMSSP_NEGOTIATE_SIGN
	ntlmNegotiateSeal               = 1 << 5  // NTLMSSP_NEGOTIATE_SEAL
	ntlmNegotiate128                = 1 << 29 // NTLMSSP_NEGOTIATE_128
	ntlmNegotiate56                 = 1 << 31 // NTLMSSP_NEGOTIATE_56
)

func hmacMD5(key, msg []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func md4Sum(b []byte) []byte {
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

// utf16le encodes a string as UTF-16LE, matching MS-NLMP's UNICODE().
func utf16le(s string) []byte {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	b, _ := enc.Bytes([]byte(s))
	return b
}

// NTHashFromPassword derives the NT hash (MD4 of UTF-16LE password) - used
// when the operator supplies --decrypt-password instead of a hash.
func NTHashFromPassword(password string) []byte {
	return md4Sum(utf16le(password))
}

// NTOWFv2 per MS-NLMP §3.3.2: HMAC_MD5(NTHash, UNICODE(Upper(User) + UserDom)).
func ntowfv2(ntHash []byte, user, domain string) []byte {
	return hmacMD5(ntHash, utf16le(strings.ToUpper(user)+domain))
}

// ntlmv2SessionKeys holds everything derived from a single NTLMv2 handshake
// needed to seal/unseal (or sign) subsequent traffic.
type ntlmv2SessionKeys struct {
	NegotiateFlags     uint32
	ExportedSessionKey []byte
	ClientSigningKey   []byte
	ServerSigningKey   []byte
	ClientSealingKey   []byte
	ServerSealingKey   []byte
}

// deriveNTLMv2SessionKeys implements the MS-NLMP §3.3.2/§3.4.5 chain given
// the NT hash and the material observed on the wire across the three NTLM
// messages: user/domain and NtChallengeResponse from AUTHENTICATE_MESSAGE,
// serverChallenge from CHALLENGE_MESSAGE, and the final negotiated flags
// (also from AUTHENTICATE_MESSAGE, which reflects what was actually agreed).
func deriveNTLMv2SessionKeys(ntHash []byte, user, domain string, serverChallenge, ntChallengeResponse, encryptedRandomSessionKey []byte, negFlg uint32) (*ntlmv2SessionKeys, error) {
	if len(serverChallenge) != 8 {
		return nil, errors.New("ntlmcrypto: server challenge must be 8 bytes")
	}
	if len(ntChallengeResponse) < 16 {
		return nil, errors.New("ntlmcrypto: NtChallengeResponse too short to contain NTProofStr")
	}

	responseKeyNT := ntowfv2(ntHash, user, domain)

	ntProofStr := ntChallengeResponse[:16]
	temp := ntChallengeResponse[16:]

	// NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp) - verify
	// the observed NTProofStr matches what our derived ResponseKeyNT (i.e.
	// the supplied hash) predicts, which is also how we detect a wrong hash
	// early and precisely, rather than only failing much later at Unwrap().
	expectedProof := hmacMD5(responseKeyNT, concatBytes(serverChallenge, temp))
	if !hmac.Equal(expectedProof, ntProofStr) {
		return nil, errors.New("ntlmcrypto: NTProofStr mismatch - wrong NT hash/password")
	}

	// SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
	sessionBaseKey := hmacMD5(responseKeyNT, ntProofStr)

	// KXKEY: for NTLMv2, KeyExchangeKey MUST be set to SessionBaseKey directly.
	keyExchangeKey := sessionBaseKey

	exportedSessionKey := keyExchangeKey
	if negFlg&ntlmNegotiateKeyExch != 0 {
		if len(encryptedRandomSessionKey) != 16 {
			return nil, errors.New("ntlmcrypto: NEGOTIATE_KEY_EXCH set but no 16-byte encrypted session key present")
		}
		c, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return nil, err
		}
		exportedSessionKey = make([]byte, 16)
		c.XORKeyStream(exportedSessionKey, encryptedRandomSessionKey) // RC4 is symmetric: decrypt == encrypt
	}

	keys := &ntlmv2SessionKeys{
		NegotiateFlags:     negFlg,
		ExportedSessionKey: exportedSessionKey,
	}
	keys.ClientSigningKey = SignKey(negFlg, exportedSessionKey, "Client")
	keys.ServerSigningKey = SignKey(negFlg, exportedSessionKey, "Server")
	keys.ClientSealingKey = SealKey(negFlg, exportedSessionKey, "Client")
	keys.ServerSealingKey = SealKey(negFlg, exportedSessionKey, "Server")
	return keys, nil
}

// SignKey implements MS-NLMP §3.4.5.2. Returns nil if extended session
// security wasn't negotiated (no signing keys are available in that case).
func SignKey(negFlg uint32, exportedSessionKey []byte, mode string) []byte {
	if negFlg&ntlmNegotiateExtendedSessionSec == 0 {
		return nil
	}
	var magic string
	if mode == "Client" {
		magic = "session key to client-to-server signing key magic constant\x00"
	} else {
		magic = "session key to server-to-client signing key magic constant\x00"
	}
	sum := md5.Sum(concatBytes(exportedSessionKey, []byte(magic)))
	return sum[:]
}

// SealKey implements MS-NLMP §3.4.5.3, extended-session-security branch only
// (the only branch reachable for NTLMv2, which always negotiates it in
// practice - the other two branches are NTLMv1-only paths this proxy
// doesn't need).
func SealKey(negFlg uint32, exportedSessionKey []byte, mode string) []byte {
	if negFlg&ntlmNegotiateExtendedSessionSec == 0 {
		return exportedSessionKey
	}

	var base []byte
	switch {
	case negFlg&ntlmNegotiate128 != 0:
		base = exportedSessionKey
	case negFlg&ntlmNegotiate56 != 0:
		base = exportedSessionKey[:7]
	default:
		base = exportedSessionKey[:5]
	}

	var magic string
	if mode == "Client" {
		magic = "session key to client-to-server sealing key magic constant\x00"
	} else {
		magic = "session key to server-to-client sealing key magic constant\x00"
	}
	sum := md5.Sum(concatBytes(base, []byte(magic)))
	return sum[:]
}

func concatBytes(parts ...[]byte) []byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ntlmSecurityLayer reports what kind of ongoing security layer, if any, the
// negotiated flags imply - advisory information only (debug logging /
// cross-check), never the sole gate for whether an unwrap is attempted.
func ntlmSecurityLayer(negFlg uint32) SecurityLayer {
	seal := negFlg&ntlmNegotiateSeal != 0
	sign := negFlg&ntlmNegotiateSign != 0
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

// little-endian helpers for parsing NTLM message fixed fields.
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func le32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// NTLMDirectionCipher implements MS-NLMP §3.4.2/§3.4.3 (SIGN/SEAL) for one
// direction of an NTLM session (client->server or server->client) plus a
// per-message incrementing sequence number used in the HMAC checksum. ldapx
// keeps exactly one of these alive per direction for the life of a
// connection; since it originates every message it forwards in that
// direction (having decrypted-then-possibly-modified-then-resealed each one
// in order), its own keystream position naturally stays in lockstep with
// what the real receiving endpoint will independently derive - no separate
// synchronization is needed beyond forwarding exactly one resealed message
// per received message, in order.
//
// Two keystream disciplines, selected by datagram:
//
//   - Connection-oriented (datagram=false): a single continuous RC4 stream,
//     never re-initialized per message. This is what MS-NLMP §3.4.3
//     ("Session Security Details") says connection-oriented transports like
//     LDAP use - the sealing key "is computed only once per session" - and
//     it's what real Windows uses whenever SIGN is negotiated (signonly or
//     signseal).
//   - Datagram-style rekey (datagram=true): a fresh RC4 handle per message,
//     keyed by SealingKey' = MD5(SealingKey || le32(seqNum)) per MS-NLMP
//     §3.4.3. That formula is *documented only for connectionless
//     (datagram) mode* - connection-oriented LDAP is supposed to use the
//     continuous stream, but in reality Windows does NOT: for the
//     SEAL-without-SIGN case (the sealed-only security layer), a Windows
//     Server 2022 DC re-keys per message with this connectionless formula
//     even over a connection-oriented LDAP transport, which no Microsoft
//     spec documents. Confirmed byte-for-byte against a live capture from a
//     Windows Server 2022 DC: the server's first sealed response decrypts
//     and its MAC verifies only under this rekey. Without matching it, the
//     DC can't decrypt a continuously-sealed client request (it replies with
//     an unsolicited "Error decrypting ldap message") and unwrapping the
//     DC's replies produces garbage.
type NTLMDirectionCipher struct {
	sealKey   []byte      // base sealing key; retained for the datagram per-message rekey
	signKey   []byte
	rc4Stream *rc4.Cipher // continuous keystream; nil in datagram mode (re-keyed per message)
	datagram  bool
	seqNum    uint32
}

// startSeq is 0 for every mechanism except SPNEGO-negotiated NTLM with a
// mechListMIC (RFC 4178/MS-SPNG's post-negotiation integrity check over the
// mechTypes list): a real client signs that MIC with a separate, throwaway
// RC4 handle (so the connection's real keystream position is untouched) but
// still advances the *numeric* per-message sequence counter embedded in
// every NTLMSSP_MESSAGE_SIGNATURE to account for it - confirmed against a
// live capture, where post-bind traffic in that case starts at seqNum=1 in
// both directions, not 0.
//
// datagram must be true only for the SEAL-without-SIGN (sealed-only) case -
// see the type doc comment for why Windows deviates from its own
// connection-oriented rule there.
func NewNTLMDirectionCipher(sealKey, signKey []byte, startSeq uint32, datagram bool) (*NTLMDirectionCipher, error) {
	d := &NTLMDirectionCipher{sealKey: sealKey, signKey: signKey, datagram: datagram, seqNum: startSeq}
	if !datagram {
		c, err := rc4.NewCipher(sealKey)
		if err != nil {
			return nil, err
		}
		d.rc4Stream = c
	}
	return d, nil
}

// messageHandle returns the RC4 handle to use for the current message: the
// persistent connection-oriented stream, or a fresh handle re-keyed from the
// sequence number (SealingKey' = MD5(SealingKey || le32(seqNum))) in datagram
// mode. Both the body seal and the MAC checksum for one message use this same
// handle, so the checksum keystream continues from wherever the body left off.
func (d *NTLMDirectionCipher) messageHandle() *rc4.Cipher {
	if !d.datagram {
		return d.rc4Stream
	}
	sum := md5.Sum(concatBytes(d.sealKey, le32Bytes(d.seqNum)))
	c, _ := rc4.NewCipher(sum[:]) // 16-byte key: rc4.NewCipher never errors here
	return c
}

// checksum computes MAC()'s 8-byte RC4-encrypted HMAC on the given handle -
// shared by Seal, Unseal, and Sign, since MAC() always consumes Handle
// regardless of whether the message body itself is sealed (MS-NLMP §3.4.4).
func (d *NTLMDirectionCipher) checksum(h *rc4.Cipher, message []byte) []byte {
	mac := hmacMD5(d.signKey, concatBytes(le32Bytes(d.seqNum), message))[:8]
	encrypted := make([]byte, 8)
	h.XORKeyStream(encrypted, mac)
	return encrypted
}

func buildSignature(encryptedChecksum []byte, seqNum uint32) []byte {
	sig := make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[0:4], 1) // Version, always 1
	copy(sig[4:12], encryptedChecksum)
	binary.LittleEndian.PutUint32(sig[12:16], seqNum)
	return sig
}

// Seal encrypts plaintext and produces its NTLMSSP_MESSAGE_SIGNATURE - MS-NLMP §3.4.3.
func (d *NTLMDirectionCipher) Seal(plaintext []byte) (sealed, signature []byte) {
	h := d.messageHandle()
	sealed = make([]byte, len(plaintext))
	h.XORKeyStream(sealed, plaintext)
	encryptedChecksum := d.checksum(h, plaintext)
	signature = buildSignature(encryptedChecksum, d.seqNum)
	d.seqNum++
	return sealed, signature
}

// Unseal decrypts sealed data and verifies its accompanying signature.
func (d *NTLMDirectionCipher) Unseal(sealed, signature []byte) (plaintext []byte, err error) {
	if len(signature) != 16 {
		return nil, errors.New("ntlmcrypto: signature must be 16 bytes")
	}
	h := d.messageHandle()
	plaintext = make([]byte, len(sealed))
	h.XORKeyStream(plaintext, sealed)
	encryptedChecksum := d.checksum(h, plaintext)
	d.seqNum++
	if !hmac.Equal(encryptedChecksum, signature[4:12]) {
		return nil, errors.New("ntlmcrypto: signature verification failed")
	}
	return plaintext, nil
}

// Sign produces a signature for an unsealed (sign-only, no confidentiality)
// message - the message body itself is never passed through RC4, only the
// checksum is (MAC() always consumes Handle per MS-NLMP §3.4.4).
func (d *NTLMDirectionCipher) Sign(message []byte) (signature []byte) {
	h := d.messageHandle()
	encryptedChecksum := d.checksum(h, message)
	signature = buildSignature(encryptedChecksum, d.seqNum)
	d.seqNum++
	return signature
}

// Verify checks a sign-only message's signature without attempting to
// decrypt anything (there's nothing encrypted to decrypt in this mode).
func (d *NTLMDirectionCipher) Verify(message, signature []byte) error {
	if len(signature) != 16 {
		return errors.New("ntlmcrypto: signature must be 16 bytes")
	}
	h := d.messageHandle()
	encryptedChecksum := d.checksum(h, message)
	d.seqNum++
	if !hmac.Equal(encryptedChecksum, signature[4:12]) {
		return errors.New("ntlmcrypto: signature verification failed")
	}
	return nil
}
