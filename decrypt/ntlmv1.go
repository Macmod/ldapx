package decrypt

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"errors"
	"fmt"
)

// NTLMv1 session-key derivation (MS-NLMP §3.3.1 and §3.4.5.1).

const (
	ntlmNegotiateLMKey         = 1 << 7  // NTLMSSP_NEGOTIATE_LM_KEY
	ntlmRequestNonNTSessionKey = 1 << 22 // NTLMSSP_REQUEST_NON_NT_SESSION_KEY
)

// ntlmv1ResponseLen is the size of an NTLMv1 NtChallengeResponse: DESL's
// three 8-byte DES blocks.
const ntlmv1ResponseLen = 24

// ntlmResponseIsV2 reports whether an NtChallengeResponse is the NTLMv2
// form (MS-NLMP §3.2.5.1.2: length above 0x18).
func ntlmResponseIsV2(ntChallengeResponse []byte) bool {
	return len(ntChallengeResponse) > ntlmv1ResponseLen
}

// desl implements MS-NLMP §6's DESL(K, D): the 16-byte key is zero-padded to
// 21 bytes and split into three 7-byte DES keys, each encrypting the same
// 8-byte block.
func desl(key, data []byte) ([]byte, error) {
	if len(data) != 8 {
		return nil, errors.New("ntlmv1: DESL input must be 8 bytes")
	}
	padded := make([]byte, 21)
	copy(padded, key)

	out := make([]byte, 0, 24)
	for i := 0; i < 3; i++ {
		block, err := des.NewCipher(desExpandKey(padded[i*7 : i*7+7]))
		if err != nil {
			return nil, err
		}
		dst := make([]byte, 8)
		block.Encrypt(dst, data)
		out = append(out, dst...)
	}
	return out, nil
}

// expectedNTLMv1Response recomputes the NtChallengeResponse a client with
// this NT hash would have produced. With extended session security the
// response covers a digest of both challenges (MS-NLMP §3.3.1).
func expectedNTLMv1Response(ntHash, serverChallenge, lmChallengeResponse []byte, negFlg uint32) ([]byte, error) {
	if negFlg&ntlmNegotiateExtendedSessionSec == 0 {
		return desl(ntHash, serverChallenge)
	}
	if len(lmChallengeResponse) < 8 {
		return nil, errors.New("ntlmv1: extended session security needs an 8-byte client challenge in LmChallengeResponse")
	}
	sum := md5.Sum(concatBytes(serverChallenge, lmChallengeResponse[:8]))
	return desl(ntHash, sum[:8])
}

// deriveNTLMv1SessionKeys is deriveNTLMv2SessionKeys' NTLMv1 counterpart,
// returning the same key set so callers need not care which was used.
func deriveNTLMv1SessionKeys(ntHash []byte, serverChallenge, ntChallengeResponse, lmChallengeResponse, encryptedRandomSessionKey []byte, negFlg uint32) (*ntlmv2SessionKeys, error) {
	if len(serverChallenge) != 8 {
		return nil, errors.New("ntlmv1: server challenge must be 8 bytes")
	}
	if len(ntChallengeResponse) != ntlmv1ResponseLen {
		return nil, fmt.Errorf("ntlmv1: NtChallengeResponse is %d bytes, expected %d", len(ntChallengeResponse), ntlmv1ResponseLen)
	}

	expected, err := expectedNTLMv1Response(ntHash, serverChallenge, lmChallengeResponse, negFlg)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(expected, ntChallengeResponse) {
		return nil, errors.New("ntlmcrypto: NTLMv1 response mismatch - wrong NT hash/password")
	}

	// SessionBaseKey = MD4(NTOWFv1), and NTOWFv1 is the NT hash itself.
	sessionBaseKey := md4Sum(ntHash)

	keyExchangeKey, err := ntlmv1KeyExchangeKey(sessionBaseKey, serverChallenge, lmChallengeResponse, negFlg)
	if err != nil {
		return nil, err
	}

	exportedSessionKey := keyExchangeKey
	if negFlg&ntlmNegotiateKeyExch != 0 {
		if len(encryptedRandomSessionKey) != 16 {
			return nil, errors.New("ntlmv1: NEGOTIATE_KEY_EXCH set but no 16-byte encrypted session key present")
		}
		c, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return nil, err
		}
		exportedSessionKey = make([]byte, 16)
		c.XORKeyStream(exportedSessionKey, encryptedRandomSessionKey)
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

// ntlmv1KeyExchangeKey implements KXKEY's NTLMv1 branches (MS-NLMP
// §3.4.5.1). LM-hash-based branches are reported as errors since the
// decryption flags carry only the NT hash.
func ntlmv1KeyExchangeKey(sessionBaseKey, serverChallenge, lmChallengeResponse []byte, negFlg uint32) ([]byte, error) {
	if negFlg&ntlmNegotiateExtendedSessionSec != 0 {
		if len(lmChallengeResponse) < 8 {
			return nil, errors.New("ntlmv1: LmChallengeResponse too short for the key exchange key")
		}
		return hmacMD5(sessionBaseKey, concatBytes(serverChallenge, lmChallengeResponse[:8])), nil
	}
	switch {
	case negFlg&ntlmNegotiateLMKey != 0:
		return nil, errors.New("ntlmv1: NTLMSSP_NEGOTIATE_LM_KEY needs the account's LM hash, which the decryption flags do not carry")
	case negFlg&ntlmRequestNonNTSessionKey != 0:
		return nil, errors.New("ntlmv1: NTLMSSP_REQUEST_NON_NT_SESSION_KEY needs the account's LM hash, which the decryption flags do not carry")
	default:
		return sessionBaseKey, nil
	}
}
