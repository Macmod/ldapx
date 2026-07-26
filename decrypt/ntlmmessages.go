package decrypt

import (
	"encoding/binary"
	"errors"

	"golang.org/x/text/encoding/unicode"
)

// Minimal MS-NLMP §2.2.1.2/§2.2.1.3 message parsing - only the fields this
// proxy actually needs (session-key derivation and mechanism identification),
// not a full NTLM implementation.

var ntlmSignature = []byte("NTLMSSP\x00")

func utf16leDecode(b []byte) (string, error) {
	dec := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	out, err := dec.Bytes(b)
	return string(out), err
}

// field reads an MS-NLMP "...Fields" trio (Len uint16, MaxLen uint16, Offset uint32).
func ntlmField(msg []byte, at int) (data []byte, err error) {
	if at+8 > len(msg) {
		return nil, errors.New("ntlmmessages: truncated field descriptor")
	}
	length := binary.LittleEndian.Uint16(msg[at : at+2])
	offset := binary.LittleEndian.Uint32(msg[at+4 : at+8])
	end := uint64(offset) + uint64(length)
	if end > uint64(len(msg)) {
		return nil, errors.New("ntlmmessages: field extends past end of message")
	}
	return msg[offset:end], nil
}

func checkSignatureAndType(msg []byte, wantType uint32) error {
	if len(msg) < 12 {
		return errors.New("ntlmmessages: message too short")
	}
	if string(msg[0:8]) != string(ntlmSignature) {
		return errors.New("ntlmmessages: bad NTLMSSP signature")
	}
	if le32(msg[8:12]) != wantType {
		return errors.New("ntlmmessages: unexpected MessageType")
	}
	return nil
}

type ntlmChallenge struct {
	ServerChallenge []byte // 8 bytes
	NegotiateFlags  uint32
	TargetInfo      []byte
}

// parseNTLMChallenge parses a CHALLENGE_MESSAGE (MS-NLMP §2.2.1.2). Layout:
// Signature(8) MessageType(4) TargetNameFields(8) NegotiateFlags(4)
// ServerChallenge(8) Reserved(8) TargetInfoFields(8) [Version(8)] Payload.
func parseNTLMChallenge(msg []byte) (*ntlmChallenge, error) {
	if err := checkSignatureAndType(msg, 2); err != nil {
		return nil, err
	}
	if len(msg) < 48 {
		return nil, errors.New("ntlmmessages: CHALLENGE_MESSAGE too short")
	}
	negotiateFlags := le32(msg[20:24])
	serverChallenge := msg[24:32]
	targetInfo, err := ntlmField(msg, 40)
	if err != nil {
		return nil, err
	}
	return &ntlmChallenge{
		ServerChallenge: serverChallenge,
		NegotiateFlags:  negotiateFlags,
		TargetInfo:      targetInfo,
	}, nil
}

type ntlmAuthenticate struct {
	NegotiateFlags            uint32
	Domain                    string
	User                      string
	NtChallengeResponse       []byte
	EncryptedRandomSessionKey []byte // may be nil if NEGOTIATE_KEY_EXCH wasn't negotiated
}

// parseNTLMAuthenticate parses an AUTHENTICATE_MESSAGE (MS-NLMP §2.2.1.3).
// Layout: Signature(8) MessageType(4) LmChallengeResponseFields(8)
// NtChallengeResponseFields(8) DomainNameFields(8) UserNameFields(8)
// WorkstationFields(8) EncryptedRandomSessionKeyFields(8) NegotiateFlags(4)
// [Version(8)] [MIC(16)] Payload.
func parseNTLMAuthenticate(msg []byte) (*ntlmAuthenticate, error) {
	if err := checkSignatureAndType(msg, 3); err != nil {
		return nil, err
	}
	if len(msg) < 64 {
		return nil, errors.New("ntlmmessages: AUTHENTICATE_MESSAGE too short")
	}

	ntResponse, err := ntlmField(msg, 20)
	if err != nil {
		return nil, err
	}
	domainBytes, err := ntlmField(msg, 28)
	if err != nil {
		return nil, err
	}
	userBytes, err := ntlmField(msg, 36)
	if err != nil {
		return nil, err
	}
	sessionKeyBytes, err := ntlmField(msg, 52)
	if err != nil {
		return nil, err
	}
	negotiateFlags := le32(msg[60:64])

	domain, err := utf16leDecode(domainBytes)
	if err != nil {
		return nil, err
	}
	user, err := utf16leDecode(userBytes)
	if err != nil {
		return nil, err
	}

	var sessionKey []byte
	if len(sessionKeyBytes) > 0 {
		sessionKey = sessionKeyBytes
	}

	return &ntlmAuthenticate{
		NegotiateFlags:            negotiateFlags,
		Domain:                    domain,
		User:                      user,
		NtChallengeResponse:       ntResponse,
		EncryptedRandomSessionKey: sessionKey,
	}, nil
}
