package decrypt

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oiweiwei/go-msrpc/ssp/krb5/crypto/rfc1964"
	"github.com/oiweiwei/go-msrpc/ssp/krb5/crypto/rfc4757"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// This file implements the RFC 4757 RC4-HMAC GSS_Wrap token layer for an
// established GSSAPI/SPNEGO(-Kerberos) session whose session key is RC4-HMAC
// (etype 23). RC4 uses an entirely different token format from the RFC 4121
// CFX tokens that gsswrap.go's AES path handles: a 32-byte header
// (TOK_ID 0x0201 + SGN_ALG + SEAL_ALG + Filler + SND_SEQ[8] + SGN_CKSUM[8] +
// Confounder[8]) followed by the (optionally encrypted) payload, with
// HMAC-MD5 for integrity and RC4 for confidentiality - not the AES
// key-derivation and CFX framing the AES path uses.
//
// Per-message RC4 tokens are additionally OID-wrapped ([APPLICATION 0] +
// KRB5 OID) in both directions on the wire - a legacy Windows convention
// confirmed live against a Windows Server 2022 DC. The negotiation reply
// (RFC 4752 §3.3) travels bare, but every subsequent LDAP-level wrapped
// message is OID-wrapped, so rc4Unwrap strips the OID if present and
// rc4Wrap adds it.

// rc4WrapTokenSize is the fixed size of an RFC 4757 Wrap token header
// (TOK_ID + SGN_ALG + SEAL_ALG + Filler + SND_SEQ + SGN_CKSUM + Confounder).
const rc4WrapTokenSize = 32

// rc4TOKID is the RFC 4757 Wrap token identifier (big-endian 0x0201).
const rc4TOKID = rfc1964.WrapTokenID // 0x0201

// rc4SealAlgRC4 is the SEAL_ALG value indicating RC4 encryption (0x1000).
const rc4SealAlgRC4 = rfc4757.SealAlgorithmRC4

// rc4SealAlgNone is the SEAL_ALG value indicating no encryption (0xFFFF).
const rc4SealAlgNone = rfc1964.SealAlgorithmNone

// rc4SignAlgHMAC is the SGN_ALG value for HMAC-MD5 (0x1100).
const rc4SignAlgHMAC = rfc4757.SignAlgorithmHMAC

// isRC4Key reports whether key is an RC4-HMAC key (etype 23).
func isRC4Key(key types.EncryptionKey) bool {
	return key.KeyType == etypeID.RC4_HMAC
}

// isRC4WrapToken reports whether wrapped begins with an RFC 4757 Wrap token
// (TOK_ID 0x0201), distinguishing it from RFC 4121 CFX tokens (TOK_ID 0x0504).
func isRC4WrapToken(wrapped []byte) bool {
	if len(wrapped) < 2 {
		return false
	}
	return binary.BigEndian.Uint16(wrapped[0:2]) == rc4TOKID
}

// rc4Unwrap reverses an RFC 4757 RC4-HMAC GSS_Wrap token, returning the
// plaintext payload and the decrypted sequence number. fromAcceptor selects
// the direction marker in SND_SEQ (0x00 for initiator, 0xFF for acceptor)
// used during sequence-number decryption. The trailing 0x01 marker that
// GSS_Wrap_LDAP appends to the plaintext before wrapping is stripped if
// present.
//
// The token may or may not be OID-wrapped ([APPLICATION 0]+KRB5 OID prefix);
// rc4StripOID removes it if present before parsing.
func rc4Unwrap(key types.EncryptionKey, wrapped []byte, fromAcceptor bool) (payload []byte, seqNum uint32, err error) {
	tokBytes := rc4StripOID(wrapped)
	if len(tokBytes) < rc4WrapTokenSize {
		return nil, 0, fmt.Errorf("krb5decrypt: rc4 unwrap: token too short (%d bytes)", len(tokBytes))
	}

	tok := rfc4757.NewWrapToken()
	if err := tok.Unmarshal(tokBytes[:rc4WrapTokenSize]); err != nil {
		return nil, 0, fmt.Errorf("krb5decrypt: rc4 unwrap: unmarshal: %w", err)
	}
	if tok.TokenID != rc4TOKID {
		return nil, 0, fmt.Errorf("krb5decrypt: rc4 unwrap: expected TOK_ID 0x%04x, got 0x%04x", rc4TOKID, tok.TokenID)
	}

	data := tokBytes[rc4WrapTokenSize:]
	keyBytes := key.KeyValue

	sealed := tok.SealAlgorithm == rc4SealAlgRC4

	if sealed {
		plain, err := rc4DecryptSealed(keyBytes, tok, data)
		if err != nil {
			return nil, 0, fmt.Errorf("krb5decrypt: rc4 unwrap: %w", err)
		}
		seq := binary.BigEndian.Uint32(tok.SequenceNumber[:4])
		return rc4StripTrailingMarker(plain), seq, nil
	}

	// Unsealed (sign-only): verify the checksum over header[:8] +
	// Confounder + data, then decrypt SND_SEQ to confirm integrity.
	header8 := tokBytes[:8]
	expected, err := rfc4757.ComputeWrapChecksum(keyBytes, header8, tok.Confounder, data)
	if err != nil {
		return nil, 0, fmt.Errorf("krb5decrypt: rc4 unwrap: checksum: %w", err)
	}
	if len(expected) < 8 || !hmac.Equal(expected[:8], tok.Checksum) {
		return nil, 0, errors.New("krb5decrypt: rc4 unwrap: checksum mismatch")
	}
	if err := rfc4757.XORSequenceNumber(keyBytes, tok.Checksum, tok.SequenceNumber); err != nil {
		return nil, 0, fmt.Errorf("krb5decrypt: rc4 unwrap: seq decrypt: %w", err)
	}
	seq := binary.BigEndian.Uint32(tok.SequenceNumber[:4])
	return rc4StripTrailingMarker(data), seq, nil
}

// rc4DecryptSealed decrypts a sealed RC4 Wrap token's confounder+data and
// verifies its checksum. The decryption order follows GSS_Wrap_LDAP
// (encrypt=False): first decrypt SND_SEQ using Kseq (derived from
// SGN_CKSUM), then derive Kcrypt from the decrypted sequence number's
// first 4 bytes, then decrypt confounder+data with Kcrypt. The checksum is
// verified over header[:8] + decrypted Confounder + data (with the trailing
// 0x01 marker still attached).
func rc4DecryptSealed(keyBytes []byte, tok *rfc4757.WrapToken, data []byte) ([]byte, error) {
	// Step 1: Decrypt SND_SEQ using Kseq derived from SGN_CKSUM.
	// XORSequenceNumber decrypts tok.SequenceNumber in place.
	if err := rfc4757.XORSequenceNumber(keyBytes, tok.Checksum, tok.SequenceNumber); err != nil {
		return nil, fmt.Errorf("seq decrypt: %w", err)
	}

	// Step 2: Derive Kcrypt from the decrypted sequence number's first 4 bytes.
	cipher, err := rfc4757.NewCipher(keyBytes, tok.SequenceNumber)
	if err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}

	// Step 3: Decrypt confounder + data in one RC4 stream.
	plain := make([]byte, len(tok.Confounder)+len(data))
	cipher.XORKeyStream(plain[:len(tok.Confounder)], tok.Confounder)
	cipher.XORKeyStream(plain[len(tok.Confounder):], data)
	confounder := plain[:len(tok.Confounder)]
	payload := plain[len(tok.Confounder):]

	// Step 4: Verify the checksum over header[:8] + decrypted Confounder + data.
	header8 := make([]byte, 8)
	binary.BigEndian.PutUint16(header8[0:2], tok.TokenID)
	binary.BigEndian.PutUint16(header8[2:4], tok.SignatureAlgorithm)
	binary.BigEndian.PutUint16(header8[4:6], tok.SealAlgorithm)
	copy(header8[6:8], tok.Filler[:])

	expected, err := rfc4757.ComputeWrapChecksum(keyBytes, header8, confounder, payload)
	if err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	if len(expected) < 8 || !hmac.Equal(expected[:8], tok.Checksum) {
		return nil, errors.New("checksum mismatch")
	}

	return payload, nil
}

// rc4Wrap builds an RFC 4757 RC4-HMAC GSS_Wrap token for payload, sealed or
// sign-only per the seal flag. asAcceptor selects the direction marker in
// SND_SEQ (0x00 for initiator, 0xFF for acceptor). The result is OID-wrapped
// ([APPLICATION 0]+KRB5 OID) to match the legacy Windows per-message
// convention. A trailing 0x01 marker is appended to the payload before
// wrapping, matching the GSS_Wrap_LDAP convention.
func rc4Wrap(key types.EncryptionKey, payload []byte, asAcceptor, seal bool, seqNum uint32) ([]byte, error) {
	keyBytes := key.KeyValue

	// Append the trailing 0x01 marker that GSS_Wrap_LDAP adds.
	data := make([]byte, len(payload)+1)
	copy(data, payload)
	data[len(payload)] = 0x01

	tok := rfc4757.NewWrapToken()
	tok.SignatureAlgorithm = rc4SignAlgHMAC
	if seal {
		tok.SealAlgorithm = rc4SealAlgRC4
	} else {
		tok.SealAlgorithm = rc4SealAlgNone
	}
	// SetSequenceNumber's isLocal parameter is true for the initiator
	// (SND_SEQ direction marker 0x00000000) and false for the acceptor
	// (0xFFFFFFFF). asAcceptor has the opposite polarity, so invert it.
	tok.SetSequenceNumber(seqNum, !asAcceptor)

	// Random 8-byte confounder.
	confounder := make([]byte, 8)
	if _, err := rand.Read(confounder); err != nil {
		return nil, fmt.Errorf("krb5decrypt: rc4 wrap: confounder: %w", err)
	}
	copy(tok.Confounder, confounder)

	// Compute the checksum over header[:8] + Confounder + data.
	header8 := tok.Header()
	checksum, err := rfc4757.ComputeWrapChecksum(keyBytes, header8, confounder, data)
	if err != nil {
		return nil, fmt.Errorf("krb5decrypt: rc4 wrap: checksum: %w", err)
	}
	copy(tok.Checksum, checksum[:8])

	var body []byte
	if seal {
		// Derive Kcrypt from the plaintext sequence number's first 4
		// bytes (before XORSequenceNumber encrypts SND_SEQ in place).
		seqBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(seqBytes, seqNum)
		cipher, err := rfc4757.NewCipher(keyBytes, seqBytes)
		if err != nil {
			return nil, fmt.Errorf("krb5decrypt: rc4 wrap: derive key: %w", err)
		}
		// Encrypt confounder + data in one RC4 stream.
		encConfounder := make([]byte, 8)
		cipher.XORKeyStream(encConfounder, confounder)
		encData := make([]byte, len(data))
		cipher.XORKeyStream(encData, data)
		copy(tok.Confounder, encConfounder)
		body = encData
	} else {
		body = data
	}

	// Encrypt SND_SEQ with Kseq (derived from the checksum) - must happen
	// after Kcrypt derivation, since XORSequenceNumber mutates tok.SequenceNumber.
	if err := rfc4757.XORSequenceNumber(keyBytes, tok.Checksum, tok.SequenceNumber); err != nil {
		return nil, fmt.Errorf("krb5decrypt: rc4 wrap: seq encrypt: %w", err)
	}

	tokenBytes := tok.Marshal()
	result := append(tokenBytes, body...)
	return rc4WrapOID(result), nil
}

// rc4WrapOID wraps a raw RC4 token in the [APPLICATION 0]+KRB5 OID framing
// that legacy Windows per-message GSS_Wrap traffic uses.
func rc4WrapOID(token []byte) []byte {
	// [APPLICATION 0] CONSTRUCTED = 0x60, followed by OID + length + data.
	// KRB5 OID: 1.2.840.113554.1.2.2 = 06 09 2a 86 48 86 f7 12 01 02 02
	oid := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	content := append(oid, token...)
	// Encode length (DER).
	length := len(content)
	var lenBytes []byte
	if length < 128 {
		lenBytes = []byte{byte(length)}
	} else {
		lb := encodeDERLength(length)
		lenBytes = lb
	}
	result := make([]byte, 0, 1+len(lenBytes)+len(content))
	result = append(result, 0x60)
	result = append(result, lenBytes...)
	result = append(result, content...)
	return result
}

// rc4StripOID removes the [APPLICATION 0]+KRB5 OID framing if present,
// returning the raw token bytes. If the token isn't OID-wrapped (e.g. the
// bare negotiation reply), it's returned unchanged.
func rc4StripOID(wrapped []byte) []byte {
	if len(wrapped) < 2 || wrapped[0] != 0x60 {
		return wrapped
	}
	// Skip the 0x60 tag and DER length.
	b := wrapped[1:]
	if len(b) == 0 {
		return wrapped
	}
	var contentLen int
	var skip int
	if b[0] < 0x80 {
		contentLen = int(b[0])
		skip = 1
	} else {
		nb := int(b[0]) - 0x80
		if 1+nb > len(b) {
			return wrapped
		}
		for i := 0; i < nb; i++ {
			contentLen = (contentLen << 8) | int(b[1+i])
		}
		skip = 1 + nb
	}
	content := b[skip:]
	if len(content) < contentLen {
		return wrapped
	}
	content = content[:contentLen]
	// Skip the KRB5 OID (06 09 2a 86 48 86 f7 12 01 02 02 = 11 bytes).
	if len(content) < 11 || content[0] != 0x06 {
		return wrapped
	}
	oidLen := int(content[1])
	if 2+oidLen > len(content) {
		return wrapped
	}
	return content[2+oidLen:]
}

// rc4StripTrailingMarker removes the trailing 0x01 byte that GSS_Wrap_LDAP
// appends to the plaintext before wrapping.
func rc4StripTrailingMarker(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == 0x01 {
		return data[:len(data)-1]
	}
	return data
}

func encodeDERLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	var buf []byte
	for length > 0 {
		buf = append([]byte{byte(length & 0xff)}, buf...)
		length >>= 8
	}
	return append([]byte{0x80 | byte(len(buf))}, buf...)
}
