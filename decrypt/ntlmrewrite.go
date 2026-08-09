package decrypt

import (
	"bytes"
	"crypto/hmac"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
)

// Channel binding injection into an NTLM bind. The value goes in an AV_PAIR
// inside the NTLMv2 response's TargetInfo (MS-NLMP §2.2.2.1), which is
// covered by NTProofStr - so injecting it invalidates the response and
// everything derived from it. The whole chain from NTProofStr down is
// recomputed, requiring the account's NT hash. ExportedSessionKey survives
// unchanged.

// MS-NLMP §2.2.2.1. MsvAvChannelBindings carries the same MD5 of a
// gss_channel_bindings_struct as Kerberos puts in its checksum's Bnd field.
// An all-zero value means no channel binding, which is what gets replaced.
const (
	msvAvEOL             uint16 = 0x0000
	msvAvFlags           uint16 = 0x0006
	msvAvChannelBindings uint16 = 0x000a
)

// msvAvFlagMIC is the MsvAvFlags bit by which a client declares it "is
// providing message integrity in the MIC field".
const msvAvFlagMIC uint32 = 0x00000002

// NTLMSSP_NEGOTIATE_VERSION - present here (rather than in ntlmcrypto.go's
// list) because only message layout cares about it.
const ntlmNegotiateVersion = 1 << 25

// ntlmv2TempPrefixLen is the fixed part of the NTLMv2 blob ahead of the
// AV_PAIR list (MS-NLMP §2.2.2.7: RespType, HiRespType, Reserved1,
// Reserved2, TimeStamp, ChallengeFromClient, Reserved3).
const ntlmv2TempPrefixLen = 28

// ntlmv2TargetInfoBounds locates the AV_PAIR list inside an NTLMv2 blob,
// returning its start and end (including the MsvAvEOL terminator) so the
// caller can preserve whatever follows.
func ntlmv2TargetInfoBounds(temp []byte) (start, end int, err error) {
	if len(temp) < ntlmv2TempPrefixLen+4 {
		return 0, 0, errors.New("NTLMv2 response too short to hold an AV_PAIR list")
	}
	for off := ntlmv2TempPrefixLen; off+4 <= len(temp); {
		avID := binary.LittleEndian.Uint16(temp[off : off+2])
		avLen := int(binary.LittleEndian.Uint16(temp[off+2 : off+4]))
		if avID == msvAvEOL {
			return ntlmv2TempPrefixLen, off + 4, nil
		}
		if off+4+avLen > len(temp) {
			break
		}
		off += 4 + avLen
	}
	return 0, 0, errors.New("AV_PAIR list has no MsvAvEOL terminator")
}

// avPairsFind returns the value of the first AV_PAIR with the given ID.
func avPairsFind(targetInfo []byte, id uint16) ([]byte, bool) {
	for off := 0; off+4 <= len(targetInfo); {
		avID := binary.LittleEndian.Uint16(targetInfo[off : off+2])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[off+2 : off+4]))
		if off+4+avLen > len(targetInfo) {
			return nil, false
		}
		if avID == msvAvEOL {
			return nil, false
		}
		if avID == id {
			return targetInfo[off+4 : off+4+avLen], true
		}
		off += 4 + avLen
	}
	return nil, false
}

// avPairsSet returns targetInfo with the given AV_PAIR set, replacing any
// existing pair of that ID and preserving the order and contents of the
// rest. The new pair goes immediately before the terminator: MS-NLMP
// §2.2.2.1 requires MsvAvEOL to be last and leaves every other pair free to
// appear in any order.
func avPairsSet(targetInfo []byte, id uint16, value []byte) ([]byte, error) {
	out := make([]byte, 0, len(targetInfo)+4+len(value))
	terminated := false

	for off := 0; off+4 <= len(targetInfo); {
		avID := binary.LittleEndian.Uint16(targetInfo[off : off+2])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[off+2 : off+4]))
		if off+4+avLen > len(targetInfo) {
			return nil, errors.New("AV_PAIR extends past end of TargetInfo")
		}
		if avID == msvAvEOL {
			terminated = true
			break
		}
		if avID != id {
			out = append(out, targetInfo[off:off+4+avLen]...)
		}
		off += 4 + avLen
	}
	if !terminated {
		return nil, errors.New("TargetInfo has no MsvAvEOL terminator")
	}

	pair := make([]byte, 4)
	binary.LittleEndian.PutUint16(pair[0:2], id)
	binary.LittleEndian.PutUint16(pair[2:4], uint16(len(value)))
	out = append(out, pair...)
	out = append(out, value...)

	return append(out, 0x00, 0x00, 0x00, 0x00), nil // MsvAvEOL
}

// ntlmHeaderLen returns the size of a message's fixed header (where its
// payload begins). The AUTHENTICATE_MESSAGE's MIC has no flag of its own
// (MS-NLMP §2.2.1.3), so it is inferred from the payload offset.
func ntlmHeaderLen(msg []byte) (int, error) {
	if len(msg) < 12 {
		return 0, errors.New("message too short")
	}
	switch le32(msg[8:12]) {
	case 1:
		if len(msg) < 16 {
			return 0, errors.New("NEGOTIATE_MESSAGE too short")
		}
		return 32 + versionLen(le32(msg[12:16])), nil
	case 2:
		if len(msg) < 24 {
			return 0, errors.New("CHALLENGE_MESSAGE too short")
		}
		return 48 + versionLen(le32(msg[20:24])), nil
	case 3:
		if len(msg) < 64 {
			return 0, errors.New("AUTHENTICATE_MESSAGE too short")
		}
		base := 64 + versionLen(le32(msg[60:64]))
		if minPayloadOffset(msg, ntlmAuthFieldOffsets) >= base+16 {
			base += 16
		}
		return base, nil
	}
	return 0, errors.New("unrecognized NTLM message type")
}

func versionLen(flags uint32) int {
	if flags&ntlmNegotiateVersion != 0 {
		return 8
	}
	return 0
}

var (
	ntlmNegotiateFieldOffsets = []int{16, 24}
	ntlmChallengeFieldOffsets = []int{12, 40}
	ntlmAuthFieldOffsets      = []int{12, 20, 28, 36, 44, 52}
)

// minPayloadOffset returns the lowest offset any populated field descriptor
// points at, or 0 when the message carries no payload at all.
func minPayloadOffset(msg []byte, descriptors []int) int {
	best := 0
	for _, at := range descriptors {
		if at+8 > len(msg) {
			continue
		}
		length := int(binary.LittleEndian.Uint16(msg[at : at+2]))
		offset := int(le32(msg[at+4 : at+8]))
		if length == 0 {
			continue
		}
		if best == 0 || offset < best {
			best = offset
		}
	}
	return best
}

// ntlmMessageLength returns how many of msg's bytes belong to the NTLM
// message itself (a message in a SPNEGO envelope may be followed by more).
func ntlmMessageLength(msg []byte) (int, error) {
	header, err := ntlmHeaderLen(msg)
	if err != nil {
		return 0, err
	}

	var descriptors []int
	switch le32(msg[8:12]) {
	case 1:
		descriptors = ntlmNegotiateFieldOffsets
	case 2:
		descriptors = ntlmChallengeFieldOffsets
	case 3:
		descriptors = ntlmAuthFieldOffsets
	}

	end := header
	for _, at := range descriptors {
		if at+8 > len(msg) {
			continue
		}
		length := int(binary.LittleEndian.Uint16(msg[at : at+2]))
		offset := int(le32(msg[at+4 : at+8]))
		if offset+length > end {
			end = offset + length
		}
	}
	if end > len(msg) {
		return 0, errors.New("NTLM message extends past the bytes carrying it")
	}
	return end, nil
}

// putNTLMField writes a field descriptor (Len, MaxLen, Offset).
func putNTLMField(msg []byte, at, offset, length int) {
	binary.LittleEndian.PutUint16(msg[at:at+2], uint16(length))
	binary.LittleEndian.PutUint16(msg[at+2:at+4], uint16(length))
	binary.LittleEndian.PutUint32(msg[at+4:at+8], uint32(offset))
}

// buildNTLMAuthenticate re-lays out an AUTHENTICATE_MESSAGE with replacement
// NtChallengeResponse and EncryptedRandomSessionKey. The fixed header is
// carried over verbatim; payload fields are re-emitted in order with
// recomputed descriptors.
func buildNTLMAuthenticate(orig []byte, ntResponse, sessionKey []byte) ([]byte, error) {
	header, err := ntlmHeaderLen(orig)
	if err != nil {
		return nil, err
	}
	if len(orig) < header {
		return nil, errors.New("AUTHENTICATE_MESSAGE shorter than its own header")
	}

	lm, err := ntlmField(orig, 12)
	if err != nil {
		return nil, err
	}
	domain, err := ntlmField(orig, 28)
	if err != nil {
		return nil, err
	}
	user, err := ntlmField(orig, 36)
	if err != nil {
		return nil, err
	}
	workstation, err := ntlmField(orig, 44)
	if err != nil {
		return nil, err
	}

	out := make([]byte, header)
	copy(out, orig[:header])

	offset := header
	for _, f := range []struct {
		at   int
		data []byte
	}{
		{12, lm},
		{20, ntResponse},
		{28, domain},
		{36, user},
		{44, workstation},
		{52, sessionKey},
	} {
		putNTLMField(out, f.at, offset, len(f.data))
		out = append(out, f.data...)
		offset += len(f.data)
	}
	return out, nil
}

// ntlmMICOffset returns the MIC offset and whether the field is present,
// decided by the header being long enough to hold one (MS-NLMP §2.2.1.3).
func ntlmMICOffset(msg []byte) (int, bool) {
	header, err := ntlmHeaderLen(msg)
	if err != nil || header < 88 {
		return 0, false
	}
	return header - 16, true
}

// rewriteNTLMChannelBindings substitutes token into the
// AUTHENTICATE_MESSAGE's MsvAvChannelBindings AV_PAIR. Returns nil
// credentials and no error when there is nothing to rewrite.
func rewriteNTLMChannelBindings(credBytes []byte, cfg Config, token []byte, pending [][]byte) ([]byte, error) {
	authMsg, ok := ntlmMessageOfType(credBytes, 3)
	if !ok {
		return nil, nil
	}

	ntHash, haveHash := cfg.resolveNTHash()
	if !haveHash {
		return nil, errors.New("no --decrypt-hash/--decrypt-password supplied")
	}

	auth, err := parseNTLMAuthenticate(authMsg)
	if err != nil {
		return nil, err
	}

	// NTLMv2 only: an NTLMv1 response is 24 bytes with no AV_PAIR list.
	if len(auth.NtChallengeResponse) < 16+ntlmv2TempPrefixLen+4 {
		return nil, nil
	}

	challengeMsg, ok := findNTLMMessage(pending, 2)
	if !ok {
		return nil, errors.New("no CHALLENGE_MESSAGE observed on this connection")
	}
	challenge, err := parseNTLMChallenge(challengeMsg)
	if err != nil {
		return nil, err
	}

	oldProof := auth.NtChallengeResponse[:16]
	temp := auth.NtChallengeResponse[16:]
	infoStart, infoEnd, err := ntlmv2TargetInfoBounds(temp)
	if err != nil {
		return nil, err
	}
	targetInfo := temp[infoStart:infoEnd]

	if existing, found := avPairsFind(targetInfo, msvAvChannelBindings); found && bytes.Equal(existing, token) {
		return nil, nil
	}

	newTargetInfo, err := avPairsSet(targetInfo, msvAvChannelBindings, token)
	if err != nil {
		return nil, fmt.Errorf("set MsvAvChannelBindings: %w", err)
	}
	newTemp := concatBytes(temp[:infoStart], newTargetInfo, temp[infoEnd:])

	responseKeyNT := ntowfv2(ntHash, auth.User, auth.Domain)
	if !hmac.Equal(hmacMD5(responseKeyNT, concatBytes(challenge.ServerChallenge, temp)), oldProof) {
		return nil, errors.New("NTProofStr mismatch - wrong NT hash/password")
	}

	newProof := hmacMD5(responseKeyNT, concatBytes(challenge.ServerChallenge, newTemp))
	oldKeyExchangeKey := hmacMD5(responseKeyNT, oldProof)
	newKeyExchangeKey := hmacMD5(responseKeyNT, newProof)

	// Recover ExportedSessionKey under the old key exchange key and
	// re-encrypt it under the new one. Without NEGOTIATE_KEY_EXCH the
	// exchange key is the session key.
	newSessionKey := auth.EncryptedRandomSessionKey
	exportedSessionKey := newKeyExchangeKey
	if auth.NegotiateFlags&ntlmNegotiateKeyExch != 0 {
		if len(auth.EncryptedRandomSessionKey) != 16 {
			return nil, errors.New("NEGOTIATE_KEY_EXCH set but no 16-byte encrypted session key present")
		}
		exportedSessionKey, err = rc4Crypt(oldKeyExchangeKey, auth.EncryptedRandomSessionKey)
		if err != nil {
			return nil, err
		}
		newSessionKey, err = rc4Crypt(newKeyExchangeKey, exportedSessionKey)
		if err != nil {
			return nil, err
		}
	}

	newAuthMsg, err := buildNTLMAuthenticate(authMsg, concatBytes(newProof, newTemp), newSessionKey)
	if err != nil {
		return nil, err
	}

	if micOffset, present := ntlmMICOffset(newAuthMsg); present {
		negotiateMsg, ok := findNTLMMessage(pending, 1)
		if !ok {
			return nil, errors.New("AUTHENTICATE_MESSAGE carries a MIC but no NEGOTIATE_MESSAGE was observed")
		}
		// MS-NLMP §3.1.5.1.2: the MIC covers the three messages concatenated,
		// with its own bytes zeroed while it is computed.
		for i := micOffset; i < micOffset+16; i++ {
			newAuthMsg[i] = 0
		}
		mic := hmacMD5(exportedSessionKey, concatBytes(negotiateMsg, challengeMsg, newAuthMsg))
		copy(newAuthMsg[micOffset:micOffset+16], mic)
	}

	return replaceNTLMMessage(credBytes, newAuthMsg)
}

func rc4Crypt(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

// ntlmMessageOfType returns the NTLM message of the given type from one
// round's raw credentials, whether bare or wrapped in a SPNEGO token.
func ntlmMessageOfType(credBytes []byte, msgType uint32) ([]byte, bool) {
	idx := bytes.Index(credBytes, ntlmSignature)
	if idx < 0 {
		return nil, false
	}
	msg := credBytes[idx:]
	if len(msg) < 12 || le32(msg[8:12]) != msgType {
		return nil, false
	}
	length, err := ntlmMessageLength(msg)
	if err != nil {
		return nil, false
	}
	return msg[:length], true
}

// findNTLMMessage scans the rounds observed so far, most recent first, for a
// message of the given type.
func findNTLMMessage(pending [][]byte, msgType uint32) ([]byte, bool) {
	for i := len(pending) - 1; i >= 0; i-- {
		if msg, ok := ntlmMessageOfType(pending[i], msgType); ok {
			return msg, true
		}
	}
	return nil, false
}

// replaceNTLMMessage puts newMsg back into whatever carried the original.
// A SPNEGO envelope is re-encoded field by field to preserve elements a
// struct re-marshal would invent (e.g. omitted negState).
func replaceNTLMMessage(credBytes, newMsg []byte) ([]byte, error) {
	if bytes.HasPrefix(credBytes, ntlmSignature) {
		return newMsg, nil
	}

	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(credBytes, &outer); err != nil {
		return nil, fmt.Errorf("credentials are neither a bare NTLM message nor a negotiation token: %w", err)
	}
	if outer.Class != asn1.ClassContextSpecific || outer.Tag != 1 {
		return nil, errors.New("unsupported NTLM carrier: expected a bare message or a NegTokenResp")
	}

	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &seq); err != nil {
		return nil, fmt.Errorf("NegTokenResp is not a SEQUENCE: %w", err)
	}

	var rebuilt []byte
	replaced := false
	for rest := seq.Bytes; len(rest) > 0; {
		var element asn1.RawValue
		remainder, err := asn1.Unmarshal(rest, &element)
		if err != nil {
			return nil, fmt.Errorf("NegTokenResp element: %w", err)
		}
		if element.Tag == 2 && element.Class == asn1.ClassContextSpecific {
			token, err := asn1.Marshal(newMsg)
			if err != nil {
				return nil, err
			}
			encoded, err := asn1.Marshal(asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        2,
				IsCompound: true,
				Bytes:      token,
			})
			if err != nil {
				return nil, err
			}
			rebuilt = append(rebuilt, encoded...)
			replaced = true
		} else {
			rebuilt = append(rebuilt, element.FullBytes...)
		}
		rest = remainder
	}
	if !replaced {
		return nil, errors.New("NegTokenResp carries no responseToken to replace")
	}

	inner, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rebuilt,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      inner,
	})
}
