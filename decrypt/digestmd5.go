package decrypt

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// This file implements SASL DIGEST-MD5 (RFC 2831) key derivation and
// per-message wrap/unwrap for the auth-int and auth-conf QOP levels,
// analogous to ntlmcrypto.go's role for the NTLM family.
//
// DIGEST-MD5 is a challenge-response mechanism where both sides derive
// session keys from H(A1), which itself depends on the user's plaintext
// password (not just a hash). The proxy observes the server challenge and
// the client response on the wire, re-derives H(A1) from the configured
// password, and then derives the four per-direction keys (Kic/Kis for
// signing, Kcc/Kcs for RC4 sealing) per RFC 2831 §2.2.2.
//
// Wire formats (inside the 4-byte SASL length frame that proxy.go already
// strips/adds):
//
//   auth-int:            encoded_message || MAC(10) || 0x0001(2) || seqnum(4 BE)
//   auth-conf (rc4*):    RC4(encoded_message || MAC(10)) || 0x0001(2) || seqnum(4 BE)
//   auth-conf (des/3des): CBC(encoded_message || pad || MAC(10)) || 0x0001(2) || seqnum(4 BE)
//
// MAC = first 10 bytes of HMAC-MD5(signing_key, seqnum(4 BE) ++ message),
// always computed over the unpadded message. For auth-conf, the MAC travels
// inside the ciphertext; the 0x0001 and seqnum are always cleartext after it.
// The block-cipher variants pad between the message and the MAC so the
// encrypted unit is a whole number of blocks, each pad byte holding the pad
// length.

// RFC 2831 §2.2.2 magic constants for key derivation.
var (
	digestKICMagic = []byte("Digest session key to client-to-server signing key magic constant")
	digestKISMagic = []byte("Digest session key to server-to-client signing key magic constant")
	digestKCCMagic = []byte("Digest H(A1) to client-to-server sealing key magic constant")
	digestKCSMagic = []byte("Digest H(A1) to server-to-client sealing key magic constant")
)

// digestMD5Keys holds the four per-direction keys derived from H(A1).
type digestMD5Keys struct {
	ClientSignKey []byte // Kic
	ServerSignKey []byte // Kis
	ClientSealKey []byte // Kcc
	ServerSealKey []byte // Kcs
}

// digestMD5SealKeyLen returns how many leading bytes of H(A1) feed the
// sealing-key derivation for the negotiated cipher, per RFC 2831 §2.2.2:
// 5 for `rc4-40`, 7 for `rc4-56`, and the full 16 for everything else. The
// same 40/56/128-bit staging MS-NLMP applies in SealKey (see ntlmcrypto.go),
// and it applies to the *sealing* keys only - Kic/Kis always hash the whole
// of H(A1) regardless of which cipher was negotiated.
func digestMD5SealKeyLen(cipher string) int {
	switch strings.ToLower(cipher) {
	case "rc4-40":
		return 5
	case "rc4-56":
		return 7
	default:
		return 16
	}
}

// digestMD5CipherSupported reports whether the negotiated auth-conf cipher is
// one this implementation can seal with: every cipher RFC 2831 §2.4 defines.
// The three rc4 variants share one keystream path; `des` and `3des` take the
// separate CBC path (block padding and a chained IV) - a different wire shape,
// not merely a different key size.
func digestMD5CipherSupported(cipher string) bool {
	switch strings.ToLower(cipher) {
	case "rc4", "rc4-40", "rc4-56", "des", "3des":
		return true
	}
	return false
}

// deriveDigestMD5Keys derives the four session keys from H(A1) per RFC 2831
// §2.2.2. a1Hash is MD5(H(username:realm:password) : nonce : cnonce), and
// cipher is the auth-conf cipher the client selected (ignored for auth-int,
// which has no sealing keys to derive).
func deriveDigestMD5Keys(a1Hash []byte, cipher string) *digestMD5Keys {
	kic := md5.Sum(concatBytes(a1Hash, digestKICMagic))
	kis := md5.Sum(concatBytes(a1Hash, digestKISMagic))
	sealBase := a1Hash[:digestMD5SealKeyLen(cipher)]
	kcc := md5.Sum(concatBytes(sealBase, digestKCCMagic))
	kcs := md5.Sum(concatBytes(sealBase, digestKCSMagic))
	return &digestMD5Keys{
		ClientSignKey: kic[:],
		ServerSignKey: kis[:],
		ClientSealKey: kcc[:],
		ServerSealKey: kcs[:],
	}
}

// desExpandKey spreads a 7-byte (56-bit) string across the 8 bytes of a DES
// key, leaving the low bit of each output byte as the (unused) parity bit.
// RFC 2831 says only that the DES key is "the first 7 bytes of Kcc/Kcs" and
// never states this expansion, so the bit layout here is taken from the
// reference implementation everything interoperates with - Cyrus SASL's
// `slidebits()` in plugins/digestmd5.c - rather than from the RFC.
func desExpandKey(in []byte) []byte {
	out := make([]byte, 8)
	out[0] = in[0]
	out[1] = (in[0] << 7) | (in[1] >> 1)
	out[2] = (in[1] << 6) | (in[2] >> 2)
	out[3] = (in[2] << 5) | (in[3] >> 3)
	out[4] = (in[3] << 4) | (in[4] >> 4)
	out[5] = (in[4] << 3) | (in[5] >> 5)
	out[6] = (in[5] << 2) | (in[6] >> 6)
	out[7] = in[6] << 1
	return out
}

// newDigestMD5Block builds the DES or DES-EDE2 block cipher for an auth-conf
// direction from its 16-byte sealing key. Per Cyrus SASL: `des` takes
// slidebits(Kc[0:7]) as its key, `3des` additionally takes slidebits(Kc[7:14])
// as a second subkey and runs two-key EDE (so the third subkey repeats the
// first), and both take Kc[8:16] as the initial CBC IV. None of the three is
// stated by RFC 2831 - see desExpandKey.
func newDigestMD5Block(cipherName string, sealKey []byte) (block cipher.Block, iv []byte, err error) {
	if len(sealKey) < 16 {
		return nil, nil, fmt.Errorf("digestmd5: %s needs a 16-byte sealing key, got %d", cipherName, len(sealKey))
	}
	switch strings.ToLower(cipherName) {
	case "des":
		block, err = des.NewCipher(desExpandKey(sealKey[0:7]))
	case "3des":
		k1 := desExpandKey(sealKey[0:7])
		k2 := desExpandKey(sealKey[7:14])
		block, err = des.NewTripleDESCipher(concatBytes(k1, k2, k1))
	default:
		return nil, nil, fmt.Errorf("digestmd5: %q is not a block cipher", cipherName)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("digestmd5: build %s cipher: %w", cipherName, err)
	}
	return block, sealKey[8:16], nil
}

// DigestMD5DirectionCipher implements per-message wrap/unwrap for one
// direction of a DIGEST-MD5 session (client->server or server->client).
// Like NTLMDirectionCipher, it maintains a per-direction sequence number and,
// for auth-conf, cipher state that persists across messages: a continuous RC4
// keystream for the rc4 variants, or a CBC chain for des/3des. The CBC chain
// carrying over between messages (rather than restarting from the derived IV
// each time) matches Cyrus SASL, which stores the trailing ciphertext block
// back into its IV after every message; RFC 2831 states this only for RC4.
type DigestMD5DirectionCipher struct {
	signKey []byte      // Kic (client->server) or Kis (server->client)
	sealKey []byte      // Kcc or Kcs; nil for auth-int (no sealing)
	rc4     *rc4.Cipher // continuous RC4 stream; nil unless an rc4 variant is in use
	// CBC state for des/3des, nil otherwise. Two BlockModes, not one: each
	// direction of this proxy both decrypts what it received and re-encrypts
	// what it forwards, and a BlockMode carries its own chaining state.
	cbcEnc    cipher.BlockMode
	cbcDec    cipher.BlockMode
	blockSize int  // 0 unless a block cipher is in use
	conf      bool // true for auth-conf, false for auth-int
	seqNum    uint32
}

// NewDigestMD5DirectionCipher creates a cipher for one direction. cipherName
// is the auth-conf cipher the client selected; it is ignored when conf is
// false, since auth-int seals nothing. If sealKey is nil, only integrity
// (auth-int) is active.
func NewDigestMD5DirectionCipher(signKey, sealKey []byte, conf bool, cipherName string) (*DigestMD5DirectionCipher, error) {
	d := &DigestMD5DirectionCipher{
		signKey: signKey,
		sealKey: sealKey,
		conf:    conf,
	}
	if !conf {
		return d, nil
	}
	if sealKey == nil {
		return nil, errors.New("digestmd5: auth-conf requires a sealing key")
	}

	switch strings.ToLower(cipherName) {
	case "des", "3des":
		block, iv, err := newDigestMD5Block(cipherName, sealKey)
		if err != nil {
			return nil, err
		}
		d.blockSize = block.BlockSize()
		d.cbcEnc = cipher.NewCBCEncrypter(block, iv)
		d.cbcDec = cipher.NewCBCDecrypter(block, iv)
	default:
		// rc4/rc4-40/rc4-56 all key RC4 with the whole 16-byte Kcc/Kcs - the
		// reduced variants weaken the derivation (see digestMD5SealKeyLen),
		// not the key length handed to RC4.
		c, err := rc4.NewCipher(sealKey)
		if err != nil {
			return nil, err
		}
		d.rc4 = c
	}
	return d, nil
}

// mac computes the first 10 bytes of HMAC-MD5(signKey, seqnum(4 BE) || msg).
func (d *DigestMD5DirectionCipher) mac(msg []byte) []byte {
	seq := make([]byte, 4)
	binary.BigEndian.PutUint32(seq, d.seqNum)
	m := hmac.New(md5.New, d.signKey)
	m.Write(seq)
	m.Write(msg)
	return m.Sum(nil)[:10]
}

// Unwrap decrypts and verifies a wrapped message from the peer.
//
// auth-int:  wrapped = msg || MAC(10) || 0x0001(2) || seqnum(4)
// auth-conf: wrapped = RC4(msg || MAC(10)) || 0x0001(2) || seqnum(4)
//
// The trailing 6 bytes (0x0001 + seqnum) are always cleartext.
//
// The MAC is recomputed over this direction's own sequence counter rather
// than the one carried in the frame's trailer, so a desynchronized counter
// surfaces here as a verification failure instead of silently producing a
// frame the real peer would have rejected - the same discipline
// NTLMDirectionCipher.Unseal follows. A failure is not recoverable: ldapx
// re-MACs everything it forwards with its own copy of the keys, so
// accepting an unverified frame would relay it onward carrying a valid
// MAC.
func (d *DigestMD5DirectionCipher) Unwrap(wrapped []byte) ([]byte, error) {
	if len(wrapped) < 16 {
		return nil, fmt.Errorf("digestmd5: wrapped frame too short (%d bytes, need >= 16)", len(wrapped))
	}

	if d.cbcDec != nil {
		// auth-conf with a block cipher: msg || pad || MAC(10), CBC-encrypted
		// as a unit, then the 6-byte cleartext trailer.
		ciphertext := wrapped[:len(wrapped)-6]
		if len(ciphertext) == 0 || len(ciphertext)%d.blockSize != 0 {
			return nil, fmt.Errorf("digestmd5: ciphertext of %d bytes is not a multiple of the %d-byte block size", len(ciphertext), d.blockSize)
		}
		plaintext := make([]byte, len(ciphertext))
		d.cbcDec.CryptBlocks(plaintext, ciphertext)
		if len(plaintext) < 11 {
			return nil, errors.New("digestmd5: decrypted frame too short to contain padding and MAC")
		}
		padded := plaintext[:len(plaintext)-10]
		padLen := int(padded[len(padded)-1])
		if padLen < 1 || padLen > d.blockSize || padLen > len(padded) {
			return nil, fmt.Errorf("digestmd5: invalid padding length %d", padLen)
		}
		msg := padded[:len(padded)-padLen]
		if !hmac.Equal(d.mac(msg), plaintext[len(plaintext)-10:]) {
			return nil, errors.New("digestmd5: MAC verification failed")
		}
		d.seqNum++
		return msg, nil
	}

	if d.conf {
		// auth-conf with RC4: everything except the trailing 6 bytes is
		// ciphertext, and there is no padding (a keystream needs none).
		ciphertext := wrapped[:len(wrapped)-6]
		plaintext := make([]byte, len(ciphertext))
		d.rc4.XORKeyStream(plaintext, ciphertext)
		// plaintext = message || MAC(10)
		if len(plaintext) < 10 {
			return nil, errors.New("digestmd5: decrypted frame too short to contain MAC")
		}
		msg := plaintext[:len(plaintext)-10]
		if !hmac.Equal(d.mac(msg), plaintext[len(plaintext)-10:]) {
			return nil, errors.New("digestmd5: MAC verification failed")
		}
		d.seqNum++
		return msg, nil
	}

	// auth-int: wrapped = msg || MAC(10) || 0x0001(2) || seqnum(4)
	msg := wrapped[:len(wrapped)-16]
	if !hmac.Equal(d.mac(msg), wrapped[len(wrapped)-16:len(wrapped)-6]) {
		return nil, errors.New("digestmd5: MAC verification failed")
	}
	d.seqNum++
	return msg, nil
}

// Wrap produces a wrapped message to send to the peer.
//
// auth-int:  msg || MAC(10) || 0x0001(2) || seqnum(4)
// auth-conf: RC4(msg || MAC(10)) || 0x0001(2) || seqnum(4)
func (d *DigestMD5DirectionCipher) Wrap(msg []byte) []byte {
	mac := d.mac(msg)
	var payload []byte
	switch {
	case d.cbcEnc != nil:
		// msg || pad || MAC, padded so the whole unit is a multiple of the
		// block size. Cyrus SASL computes blockSize - ((len(msg)+10) %
		// blockSize), which yields a full block of padding rather than none
		// when the two already align - so the pad is never empty and its
		// length is always recoverable from its own last byte.
		padLen := d.blockSize - ((len(msg) + 10) % d.blockSize)
		buf := make([]byte, 0, len(msg)+padLen+len(mac))
		buf = append(buf, msg...)
		for i := 0; i < padLen; i++ {
			buf = append(buf, byte(padLen))
		}
		buf = append(buf, mac...)
		d.cbcEnc.CryptBlocks(buf, buf)
		payload = buf
	case d.conf:
		plaintext := concatBytes(msg, mac)
		ciphertext := make([]byte, len(plaintext))
		d.rc4.XORKeyStream(ciphertext, plaintext)
		payload = ciphertext
	default:
		payload = concatBytes(msg, mac)
	}
	// Trailing: 0x0001 (2 bytes) + seqnum (4 bytes BE)
	trailer := make([]byte, 6)
	binary.BigEndian.PutUint16(trailer[0:2], 1)
	binary.BigEndian.PutUint32(trailer[2:6], d.seqNum)
	d.seqNum++
	return append(payload, trailer...)
}

// digestMD5Challenge holds the parsed fields from the server's
// DIGEST-MD5 challenge (RFC 2831 §2.1.1).
type digestMD5Challenge struct {
	Nonce  string
	Realm  string
	QOP    string
	Cipher string
}

// parseDigestMD5Challenge parses the comma-separated key=value server
// challenge (RFC 2831 §2.1.1). Values may be quoted strings or bare tokens.
func parseDigestMD5Challenge(challengeBytes []byte) (*digestMD5Challenge, error) {
	text := string(challengeBytes)
	pairs := parseDigestMD5Pairs(text)

	ch := &digestMD5Challenge{
		Nonce:  pairs["nonce"],
		Realm:  pairs["realm"],
		QOP:    pairs["qop"],
		Cipher: pairs["cipher"],
	}
	if ch.Nonce == "" {
		return nil, errors.New("digestmd5: server challenge missing nonce")
	}
	if ch.QOP == "" {
		ch.QOP = "auth"
	}
	return ch, nil
}

// digestMD5Response holds the parsed fields from the client's DIGEST-MD5
// response (RFC 2831 §2.1.3).
type digestMD5Response struct {
	Username  string
	Realm     string
	Nonce     string
	Cnonce    string
	NC        string
	QOP       string
	DigestURI string
	Cipher    string
	Response  string
}

// parseDigestMD5Response parses the comma-separated key=value client
// response (RFC 2831 §2.1.3).
func parseDigestMD5Response(responseBytes []byte) (*digestMD5Response, error) {
	text := string(responseBytes)
	pairs := parseDigestMD5Pairs(text)

	r := &digestMD5Response{
		Username:  pairs["username"],
		Realm:     pairs["realm"],
		Nonce:     pairs["nonce"],
		Cnonce:    pairs["cnonce"],
		NC:        pairs["nc"],
		QOP:       pairs["qop"],
		DigestURI: pairs["digest-uri"],
		Cipher:    pairs["cipher"],
		Response:  pairs["response"],
	}
	if r.Username == "" {
		return nil, errors.New("digestmd5: client response missing username")
	}
	if r.Cnonce == "" {
		return nil, errors.New("digestmd5: client response missing cnonce")
	}
	if r.Nonce == "" {
		return nil, errors.New("digestmd5: client response missing nonce")
	}
	if r.QOP == "" {
		r.QOP = "auth"
	}
	return r, nil
}

// digestMD5PairRe matches key=value pairs where value is either a
// quoted string (with possible escaped chars) or a bare token.
var digestMD5PairRe = regexp.MustCompile(`([\w-]+)=(?:"((?:[^"\\]|\\.)*)"|([^,]+))`)

// parseDigestMD5Pairs parses the comma-separated key=value format shared
// by both challenges and responses.
func parseDigestMD5Pairs(text string) map[string]string {
	pairs := make(map[string]string)
	for _, m := range digestMD5PairRe.FindAllStringSubmatch(text, -1) {
		key := m[1]
		val := m[2]
		if val == "" {
			val = strings.TrimSpace(m[3])
		}
		pairs[key] = val
	}
	return pairs
}

// computeDigestMD5A1 computes H(A1) per RFC 2831 §2.1.2:
//
//	A1 = H(username : realm : password) : nonce : cnonce
//	H(A1) = MD5(A1)
func computeDigestMD5A1(username, realm, password, nonce, cnonce string) []byte {
	inner := md5.Sum([]byte(username + ":" + realm + ":" + password))
	a1 := append(inner[:], []byte(":"+nonce+":"+cnonce)...)
	a1Hash := md5.Sum(a1)
	return a1Hash[:]
}

// verifyDigestMD5Response recomputes the client's response value and checks
// it against the one observed on the wire. This validates the password
// before we commit to deriving session keys from it.
//
// A2 = "AUTHENTICATE:" + digest-uri [+ ":00000000000000000000000000000000"]
// (the 32-zero-hex suffix is appended for auth-int and auth-conf).
//
// response = H( H(A1)_hex : nonce : nc : cnonce : qop : H(A2)_hex )
// where H(A1)_hex and H(A2)_hex are the *hex string representations* of the
// MD5 digests, not the raw bytes (the classic RFC 2069 convention).
func verifyDigestMD5Response(username, realm, password, nonce, cnonce, nc, qop, digestURI, expectedResponse string) error {
	a1Hash := computeDigestMD5A1(username, realm, password, nonce, cnonce)

	a2 := "AUTHENTICATE:" + digestURI
	if qop != "auth" {
		a2 += ":00000000000000000000000000000000"
	}
	a2Hash := md5.Sum([]byte(a2))

	kd := md5.Sum([]byte(
		hex.EncodeToString(a1Hash) + ":" +
			nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" +
			hex.EncodeToString(a2Hash[:]),
	))
	computed := hex.EncodeToString(kd[:])

	if !strings.EqualFold(computed, expectedResponse) {
		return fmt.Errorf("digestmd5: response mismatch (expected %s, computed %s) - wrong password?", expectedResponse, computed)
	}
	return nil
}

// digestMD5SecurityLayer classifies the QOP value into a SecurityLayer.
func digestMD5SecurityLayer(qop string) SecurityLayer {
	switch qop {
	case "auth-conf":
		return LayerSignSeal
	case "auth-int":
		return LayerSignOnly
	default:
		return LayerNone
	}
}

// completeDigestMD5 finishes a SASL DIGEST-MD5 handshake given the buffered
// challenge and response, deriving session keys from the user's plaintext
// password (which DIGEST-MD5 requires, unlike NTLM which can work from a
// hash alone).
//
// bs.pending is expected to contain at least:
//   - the server challenge (from a BindResponse serverSaslCreds)
//   - the client response (from a BindRequest SASL credentials)
//
// in that order. The proxy observes both as they pass through.
func (bs *BindSession) completeDigestMD5(password string) error {
	if len(bs.pending) < 2 {
		return errors.New("bindsession: incomplete DIGEST-MD5 handshake (missing challenge or response)")
	}

	// Find the server challenge and client response in pending.
	// The challenge comes from a BindResponse (serverSaslCreds), the
	// response from a BindRequest. They interleave in pending in the
	// order they were observed: challenge (round 1 response), then
	// response (round 2 request).
	//
	// However, the first pending entry for DIGEST-MD5 is the round-1
	// BindRequest with empty credentials (which we skip - empty creds
	// aren't buffered), so pending[0] is the server challenge and
	// pending[1] is the client response.
	challengeBytes := bs.pending[0]
	responseBytes := bs.pending[1]

	challenge, err := parseDigestMD5Challenge(challengeBytes)
	if err != nil {
		return fmt.Errorf("bindsession: parse DIGEST-MD5 challenge: %w", err)
	}

	response, err := parseDigestMD5Response(responseBytes)
	if err != nil {
		return fmt.Errorf("bindsession: parse DIGEST-MD5 response: %w", err)
	}

	// Verify the nonce matches between challenge and response.
	if response.Nonce != challenge.Nonce {
		return fmt.Errorf("bindsession: DIGEST-MD5 nonce mismatch (challenge=%s, response=%s)", challenge.Nonce, response.Nonce)
	}

	// Use the realm from the response (which the client chose), falling
	// back to the challenge's realm.
	realm := response.Realm
	if realm == "" {
		realm = challenge.Realm
	}

	// Verify the client's response value against our password.
	if err := verifyDigestMD5Response(
		response.Username, realm, password,
		response.Nonce, response.Cnonce, response.NC,
		response.QOP, response.DigestURI, response.Response,
	); err != nil {
		return err
	}

	conf := response.QOP == "auth-conf"

	// A client that negotiated auth-conf is required to echo the cipher it
	// picked from the challenge's list (RFC 2831 §2.1.3). Absent, assume
	// `rc4` - the only one an omitting client could have meant in practice,
	// and the value this code derived keys for unconditionally before the
	// cipher was honored at all.
	cipherName := response.Cipher
	if conf {
		if cipherName == "" {
			cipherName = "rc4"
		}
		if !digestMD5CipherSupported(cipherName) {
			return fmt.Errorf("bindsession: DIGEST-MD5 auth-conf cipher %q is not supported (only rc4, rc4-40, rc4-56, des and 3des)", cipherName)
		}
	}

	// Derive session keys from H(A1).
	a1Hash := computeDigestMD5A1(response.Username, realm, password, response.Nonce, response.Cnonce)
	keys := deriveDigestMD5Keys(a1Hash, cipherName)

	// Create four per-direction ciphers, exactly like NTLM:
	// clientRecv/clientSend use client keys; serverRecv/serverSend use
	// server keys. Each has its own independent cipher state (RC4 keystream
	// or CBC chain, for auth-conf) and sequence counter.
	var err2 error
	newCipher := func(signKey, sealKey []byte) *DigestMD5DirectionCipher {
		if err2 != nil {
			return nil
		}
		c, e := NewDigestMD5DirectionCipher(signKey, sealKey, conf, cipherName)
		if e != nil {
			err2 = e
		}
		return c
	}

	if conf {
		bs.digestClientRecv = newCipher(keys.ClientSignKey, keys.ClientSealKey)
		bs.digestClientSend = newCipher(keys.ClientSignKey, keys.ClientSealKey)
		bs.digestServerRecv = newCipher(keys.ServerSignKey, keys.ServerSealKey)
		bs.digestServerSend = newCipher(keys.ServerSignKey, keys.ServerSealKey)
	} else {
		// auth-int: no sealing key, no RC4
		bs.digestClientRecv = newCipher(keys.ClientSignKey, nil)
		bs.digestClientSend = newCipher(keys.ClientSignKey, nil)
		bs.digestServerRecv = newCipher(keys.ServerSignKey, nil)
		bs.digestServerSend = newCipher(keys.ServerSignKey, nil)
	}
	if err2 != nil {
		return err2
	}

	bs.layer = digestMD5SecurityLayer(response.QOP)
	bs.negotiated = true
	return nil
}

// resolvePassword returns the configured plaintext password, if available.
// DIGEST-MD5 requires the plaintext password (not just a hash) because
// H(A1) = MD5(MD5(username:realm:password) : nonce : cnonce).
func (c Config) resolvePassword() (string, bool) {
	if c.Password != "" {
		return c.Password, true
	}
	return "", false
}
