package decrypt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"hash/crc32"
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
// direction of an NTLM session with a per-message sequence number.
//
// Two keystream disciplines, selected by datagram:
//
//   - Connection-oriented (datagram=false): a single continuous RC4 stream.
//     Used whenever SIGN is negotiated.
//   - Datagram-style rekey (datagram=true): a fresh RC4 handle per message,
//     keyed by SealingKey' = MD5(SealingKey || le32(seqNum)) per MS-NLMP
//     §3.4.3. Windows Server 2022 uses this for SEAL-without-SIGN even over
//     connection-oriented LDAP, which no Microsoft spec documents.
type NTLMDirectionCipher struct {
	sealKey   []byte // base sealing key; retained for the datagram per-message rekey
	signKey   []byte
	rc4Stream *rc4.Cipher // continuous keystream; nil in datagram mode (re-keyed per message)
	datagram  bool
	// Whether NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY was negotiated.
	// It selects the whole per-message regime.
	ess    bool
	seqNum uint32
}

// startSeq is 0 except for SPNEGO-negotiated NTLM with a mechListMIC
// (RFC 4178/MS-SPNG), where the throwaway MIC signing handle advances the
// numeric per-message sequence counter.
//
// datagram must be true only for the SEAL-without-SIGN (sealed-only) case.
func NewNTLMDirectionCipher(sealKey, signKey []byte, startSeq uint32, datagram, ess bool) (*NTLMDirectionCipher, error) {
	d := &NTLMDirectionCipher{sealKey: sealKey, signKey: signKey, datagram: datagram, ess: ess, seqNum: startSeq}
	if !datagram {
		c, err := rc4.NewCipher(sealKey)
		if err != nil {
			return nil, err
		}
		d.rc4Stream = c
	}
	return d, nil
}

// messageHandle returns the RC4 handle for the current message: the
// persistent stream, or a fresh handle re-keyed from the sequence number
// (SealingKey' = MD5(SealingKey || le32(seqNum))) in datagram mode.
func (d *NTLMDirectionCipher) messageHandle() *rc4.Cipher {
	if !d.datagram {
		return d.rc4Stream
	}
	key := d.sealKey
	if d.ess {
		// The per-message rekey belongs to extended session security.
		sum := md5.Sum(concatBytes(key, le32Bytes(d.seqNum)))
		key = sum[:]
	}
	c, _ := rc4.NewCipher(key) // 16-byte key: rc4.NewCipher never errors here
	return c
}

// signatureHandle returns the handle that masks this message's signature.
// Datagram mode without ESS is the exception: the signature gets its own
// handle.
func (d *NTLMDirectionCipher) signatureHandle(body *rc4.Cipher) *rc4.Cipher {
	if d.datagram && !d.ess {
		return d.messageHandle()
	}
	return body
}

// legacySignature builds MS-NLMP §3.4.4.1's signature (used without ESS):
// Version(4) || RandomPad(4) || Checksum(4) || SeqNum(4), where the checksum
// is CRC32 and the trailing twelve bytes are masked by the sealing keystream.
func (d *NTLMDirectionCipher) legacySignature(h *rc4.Cipher, message []byte) []byte {
	sig := make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[0:4], 1) // Version, always 1
	binary.LittleEndian.PutUint32(sig[8:12], crc32.ChecksumIEEE(message))
	binary.LittleEndian.PutUint32(sig[12:16], d.seqNum)
	h.XORKeyStream(sig[4:16], sig[4:16])
	copy(sig[4:8], make([]byte, 4))
	return sig
}

// legacyVerify checks a §3.4.4.1 signature, comparing the checksum field
// alone. RandomPad is not reproducible and SeqNum is masked, so only the
// checksum is meaningful.
func (d *NTLMDirectionCipher) legacyVerify(h *rc4.Cipher, message, signature []byte) error {
	expected := d.legacySignature(h, message)
	if !hmac.Equal(expected[8:12], signature[8:12]) {
		return errors.New("ntlmcrypto: signature verification failed")
	}
	return nil
}

// checksum computes MAC()'s 8-byte RC4-encrypted HMAC on the given handle
// (MS-NLMP §3.4.4).
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
	if !d.ess {
		signature = d.legacySignature(d.signatureHandle(h), plaintext)
	} else {
		signature = buildSignature(d.checksum(h, plaintext), d.seqNum)
	}
	d.seqNum++
	return sealed, signature
}

// Unseal decrypts sealed data and verifies its accompanying signature.
func (d *NTLMDirectionCipher) Unseal(sealed, signature []byte) (plaintext []byte, err error) {
	if len(signature) != 16 {
		return nil, errors.New("ntlmcrypto: signature must be 16 bytes")
	}
	// Datagram mode keys every message independently off the sequence number,
	// so the receiver uses the number from the signature, not its own count.
	if d.datagram {
		d.seqNum = binary.LittleEndian.Uint32(signature[12:16])
	}
	h := d.messageHandle()
	plaintext = make([]byte, len(sealed))
	h.XORKeyStream(plaintext, sealed)
	if !d.ess {
		err = d.legacyVerify(d.signatureHandle(h), plaintext, signature)
		d.seqNum++
		if err != nil {
			return nil, err
		}
		return plaintext, nil
	}
	encryptedChecksum := d.checksum(h, plaintext)
	d.seqNum++
	if !hmac.Equal(encryptedChecksum, signature[4:12]) {
		return nil, errors.New("ntlmcrypto: signature verification failed")
	}
	return plaintext, nil
}

// Sign produces a signature for a sign-only message (no confidentiality).
func (d *NTLMDirectionCipher) Sign(message []byte) (signature []byte) {
	h := d.messageHandle()
	if !d.ess {
		signature = d.legacySignature(d.signatureHandle(h), message)
	} else {
		signature = buildSignature(d.checksum(h, message), d.seqNum)
	}
	d.seqNum++
	return signature
}

// Verify checks a sign-only message's signature.
func (d *NTLMDirectionCipher) Verify(message, signature []byte) error {
	if len(signature) != 16 {
		return errors.New("ntlmcrypto: signature must be 16 bytes")
	}
	h := d.messageHandle()
	if !d.ess {
		err := d.legacyVerify(d.signatureHandle(h), message, signature)
		d.seqNum++
		return err
	}
	encryptedChecksum := d.checksum(h, message)
	d.seqNum++
	if !hmac.Equal(encryptedChecksum, signature[4:12]) {
		return errors.New("ntlmcrypto: signature verification failed")
	}
	return nil
}
