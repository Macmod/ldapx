package decrypt

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Macmod/ldapx/log"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// BindMechanism identifies which (if any) of the three handled auth
// mechanisms a connection's bind is using.
type BindMechanism int

const (
	MechNone BindMechanism = iota
	MechSicilyNTLM
	MechSaslNTLM
	MechSaslGSSAPI
	MechSaslSPNEGO
	MechSaslDigestMD5
)

func (m BindMechanism) String() string {
	switch m {
	case MechSicilyNTLM:
		return "NTLMSSP (Sicily)"
	case MechSaslNTLM:
		return "SASL/NTLM"
	case MechSaslGSSAPI:
		return "SASL/GSSAPI"
	case MechSaslSPNEGO:
		return "SASL/GSS-SPNEGO"
	case MechSaslDigestMD5:
		return "SASL/DIGEST-MD5"
	default:
		return "none"
	}
}

// SecurityLayer reflects what the handshake actually negotiated, not what
// ldapx is capable of - a connection can authenticate-only with no
// confidentiality or integrity layer at all. This is advisory information
// only (debug logging / cross-check) - the authoritative decision for
// whether a given message needs unwrapping is a per-message check against
// its actual wire shape, not this value.
type SecurityLayer int

const (
	LayerUnknown SecurityLayer = iota
	LayerNone
	LayerSignOnly
	LayerSealOnly // confidentiality without integrity
	LayerSignSeal // confidentiality and integrity together
)

func (l SecurityLayer) String() string {
	switch l {
	case LayerNone:
		return "none"
	case LayerSignOnly:
		return "sign-only"
	case LayerSealOnly:
		return "sealed-only (no signing)"
	case LayerSignSeal:
		return "signed+sealed"
	default:
		return "unknown"
	}
}

// BindSession is per-connection state tracking a single bind's mechanism,
// negotiated security layer, and (once negotiated) the keys needed to
// unwrap/rewrap subsequent traffic in each direction independently.
// BindSession is touched from both the C->T and T->C goroutines of the same
// connection (the bind handshake interleaves request/response processing
// across both, and post-bind both sides need to read whether negotiation
// completed) - mu guards every field, and every exported method below takes
// it itself rather than expecting callers to.
type BindSession struct {
	mu sync.Mutex

	// mech/negotiated/layer describe the security layer currently protecting
	// traffic. Replaced when a new authentication succeeds, not when one begins.
	mech       BindMechanism
	negotiated bool
	layer      SecurityLayer

	// hsMech is the mechanism of the authentication currently being observed.
	hsMech BindMechanism

	// Four independent cipher instances: unwrapping and re-sealing are each
	// their own RC4 stream advancement.
	ntlmClientRecv *NTLMDirectionCipher // unwraps incoming-from-client (client keys)
	ntlmClientSend *NTLMDirectionCipher // re-seals outgoing-to-target (client keys)
	ntlmServerRecv *NTLMDirectionCipher // unwraps incoming-from-target (server keys)
	ntlmServerSend *NTLMDirectionCipher // re-seals outgoing-to-client (server keys)

	// DIGEST-MD5: same four-direction pattern as NTLM.
	digestClientRecv *DigestMD5DirectionCipher
	digestClientSend *DigestMD5DirectionCipher
	digestServerRecv *DigestMD5DirectionCipher
	digestServerSend *DigestMD5DirectionCipher

	gss *gssSessionContext

	// buffers negotiation tokens as they pass through.
	pending [][]byte

	// loggedFraming guards the one-time framing log line.
	loggedFraming bool

	// cbLogged/cbFailLogged guard the one-time channel-binding log lines.
	cbLogged     bool
	cbFailLogged bool

	// lastAuthChoiceSicily records whether the most recent BindRequest was a
	// sicilyResponse [11]. Sicily has no in-progress result code, so
	// completion is inferred from the request type, not the response code.
	lastAuthChoiceSicily bool

	// mechAnnounced guards the one-time mechanism identification log line.
	mechAnnounced bool

	// handshakeObserved is set once the bind's final response has been seen.
	handshakeObserved bool

	// bindComplete records that the authentication being observed has ended.
	bindComplete bool

	// pendingCompletion holds a finished handshake whose keys are not
	// installed yet.
	pendingCompletion *pendingCompletion
}

// pendingCompletion is a handshake that has been fully observed but whose
// derived layer must not take effect until the BindResponse concluding it
// has been forwarded.
type pendingCompletion struct {
	mech BindMechanism
	cfg  Config
}

// FinishPendingHandshake installs the layer derived from a completed
// handshake. Called after the concluding BindResponse has been forwarded.
// No-op when no handshake is waiting.
func (bs *BindSession) FinishPendingHandshake() {
	bs.mu.Lock()
	p := bs.pendingCompletion
	bs.pendingCompletion = nil
	bs.mu.Unlock()
	if p == nil {
		return
	}
	completeHandshake(bs, p.mech, p.cfg)
}

func NewBindSession() *BindSession {
	return &BindSession{}
}

// resetHandshake discards what was observed of the previous authentication.
// Leaves mech/negotiated/layer/ciphers/gss alone (the active layer has a
// separate lifetime). Caller holds bs.mu.
func (bs *BindSession) resetHandshake() {
	bs.pending = nil
	bs.hsMech = MechNone
	bs.mechAnnounced = false
	bs.lastAuthChoiceSicily = false
	bs.handshakeObserved = false
	bs.bindComplete = false
}

// State returns a snapshot of negotiated/layer/mech in a single lock.
func (bs *BindSession) State() (negotiated bool, layer SecurityLayer, mech BindMechanism) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.negotiated, bs.layer, bs.mech
}

// ShouldLogFraming reports whether the caller should emit its one-time
// framing log line, marking it as logged if so. Gated on the bind's final
// response having been observed, not on key derivation succeeding.
func (bs *BindSession) ShouldLogFraming() bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if !bs.handshakeObserved || bs.loggedFraming {
		return false
	}
	bs.loggedFraming = true
	return true
}

// completeNTLM finishes an NTLM handshake: derives session keys and sets
// up per-direction ciphers from the CHALLENGE_MESSAGE and
// AUTHENTICATE_MESSAGE bytes.
//
// clientMechListMIC and serverMechListMIC must be true when the
// corresponding side sent a SPNEGO mechListMIC (RFC 4178 §4.2.2). The
// mechListMIC is signed with a throwaway cipher handle, but the numeric
// per-message sequence counter still advances. The two sides advance
// independently and differ in when they count one: a client numbers past
// its own mechListMIC whether or not SIGN was negotiated, while a DC counts
// its own only when SIGN was negotiated.
//
// gssWrapped must be true when the NTLM is carried inside GSS-API. It only
// matters for the sealed-only (SEAL without SIGN) layer: a Windows Server
// 2022 DC re-keys its RC4 sealing per message for GSS-wrapped NTLM but keeps
// the continuous stream for raw Sicily NTLM with the same flags.
func (bs *BindSession) completeNTLM(ntHash []byte, challenge, authenticate []byte, clientMechListMIC, serverMechListMIC, gssWrapped bool) error {
	ch, err := parseNTLMChallenge(challenge)
	if err != nil {
		return fmt.Errorf("bindsession: parse CHALLENGE_MESSAGE: %w", err)
	}
	auth, err := parseNTLMAuthenticate(authenticate)
	if err != nil {
		return fmt.Errorf("bindsession: parse AUTHENTICATE_MESSAGE: %w", err)
	}

	// The chain is decided from the response's own length (MS-NLMP
	// §3.2.5.1.2), not from anything negotiated.
	var keys *ntlmv2SessionKeys
	if ntlmResponseIsV2(auth.NtChallengeResponse) {
		keys, err = deriveNTLMv2SessionKeys(ntHash, auth.User, auth.Domain, ch.ServerChallenge, auth.NtChallengeResponse, auth.EncryptedRandomSessionKey, auth.NegotiateFlags)
	} else {
		keys, err = deriveNTLMv1SessionKeys(ntHash, ch.ServerChallenge, auth.NtChallengeResponse, auth.LmChallengeResponse, auth.EncryptedRandomSessionKey, auth.NegotiateFlags)
	}
	if err != nil {
		return err
	}

	var clientStartSeq, serverStartSeq uint32
	if clientMechListMIC {
		clientStartSeq = 1
	}
	// A DC counts its own mechListMIC only when SIGN was negotiated.
	if serverMechListMIC && auth.NegotiateFlags&ntlmNegotiateSign != 0 {
		serverStartSeq = 1
	}

	// Sealed-only (SEAL without SIGN) over GSS-wrapped NTLM uses datagram
	// per-message rekeying; raw NTLM keeps the continuous stream.
	datagram := gssWrapped && auth.NegotiateFlags&ntlmNegotiateSeal != 0 && auth.NegotiateFlags&ntlmNegotiateSign == 0

	ess := auth.NegotiateFlags&ntlmNegotiateExtendedSessionSec != 0

	var err2 error
	newCipher := func(seal, sign []byte, startSeq uint32) *NTLMDirectionCipher {
		if err2 != nil {
			return nil
		}
		c, e := NewNTLMDirectionCipher(seal, sign, startSeq, datagram, ess)
		if e != nil {
			err2 = e
		}
		return c
	}
	if ess {
		bs.ntlmClientRecv = newCipher(keys.ClientSealingKey, keys.ClientSigningKey, clientStartSeq)
		bs.ntlmClientSend = newCipher(keys.ClientSealingKey, keys.ClientSigningKey, clientStartSeq)
		bs.ntlmServerRecv = newCipher(keys.ServerSealingKey, keys.ServerSigningKey, serverStartSeq)
		bs.ntlmServerSend = newCipher(keys.ServerSealingKey, keys.ServerSigningKey, serverStartSeq)
	} else {
		// Without ESS, MS-NLMP §3.4 uses a single sealing key half-duplex
		// with a shared sequence number. Each leg (client-facing and
		// target-facing) gets one cipher shared by both directions.
		clientLeg := newCipher(keys.ClientSealingKey, keys.ClientSigningKey, 0)
		targetLeg := newCipher(keys.ClientSealingKey, keys.ClientSigningKey, 0)
		bs.ntlmClientRecv, bs.ntlmServerSend = clientLeg, clientLeg
		bs.ntlmClientSend, bs.ntlmServerRecv = targetLeg, targetLeg
	}
	if err2 != nil {
		return err2
	}

	bs.layer = ntlmSecurityLayer(keys.NegotiateFlags)
	bs.negotiated = true
	return nil
}

// completeGSSAPI finishes a SASL/GSSAPI handshake: recovers the session key
// from the buffered AP-REQ and classifies the security layer from the
// Authenticator's GSS checksum flags.
//
// Bare "GSSAPI" may negotiate NTLM rather than Kerberos, so each pending
// round is checked for an embedded NTLM message first. Genuine Kerberos
// credentials are a GSS-API Initial Context Token (RFC 2743 §3.1),
// unwrapped via spnego.KRB5Token to reach the AP-REQ.
func (bs *BindSession) completeGSSAPI(cfg Config) error {
	if len(bs.pending) == 0 {
		return errors.New("bindsession: no AP-REQ observed")
	}

	var ntlmMessages [][]byte
	for _, round := range bs.pending {
		if msg, ok := extractGSSAPINTLMMessage(round); ok {
			ntlmMessages = append(ntlmMessages, msg)
		}
	}
	if len(ntlmMessages) >= 2 {
		challenge := ntlmMessages[len(ntlmMessages)-2]
		authenticate := ntlmMessages[len(ntlmMessages)-1]
		if h := logNetNTLMHash(challenge, authenticate); h != "" {
			log.Log.Print(decryptColor.Sprintf("[+] NetNTLM hash: %s", h))
		}
		ntHash, haveHash := cfg.resolveNTHash()
		if !haveHash {
			return errors.New("bindsession: SASL/GSSAPI negotiated NTLM, but no --decrypt-hash/--decrypt-password supplied")
		}
		if err := bs.completeNTLM(ntHash, challenge, authenticate, false, false, true); err != nil {
			return err
		}
		bs.mech = MechSaslNTLM
		return nil
	}

	var tok spnego.KRB5Token
	if err := tok.Unmarshal(bs.pending[0]); err != nil {
		return fmt.Errorf("bindsession: unmarshal GSS-API token: %w", err)
	}
	if !tok.IsAPReq() {
		return errors.New("bindsession: GSS-API token is not a Kerberos AP-REQ")
	}
	apReqBytes, err := tok.APReq.Marshal()
	if err != nil {
		return fmt.Errorf("bindsession: re-marshal extracted AP-REQ: %w", err)
	}

	key, cksum, err := completeGSSAPI(cfg, apReqBytes)
	if err != nil {
		return err
	}
	candidates := apRepKeyCandidates(cfg, &tok.APReq, key)
	// A second entry means key is the Authenticator's subkey, not the
	// ticket's session key.
	isSubKey := len(candidates) == 2
	if subkey, ok := findAPRepSubkey(bs.pending, candidates); ok {
		key = subkey
		isSubKey = true
	}
	gss, err := newGSSSessionContext(key, isSubKey)
	if err != nil {
		return err
	}
	bs.gss = gss
	bs.layer = krb5SecurityLayer(cksum)
	if rfc4752Layer := parseRFC4752Layer(gss, bs.pending); rfc4752Layer != LayerUnknown {
		bs.layer = rfc4752Layer
	}
	bs.negotiated = true
	return nil
}

// completeSPNEGO is completeGSSAPI's counterpart for SASL/GSS-SPNEGO - each
// bs.pending entry holds the raw bytes of one round's SASL credentials
// field (a whole SPNEGO negotiation token, not a bare AP-REQ and not even a
// mechToken/ResponseToken sub-field directly - completeSPNEGO unwraps both
// layers).
//
// SPNEGO can negotiate NTLM instead of Kerberos, so every pending round is
// checked for an embedded NTLM message first. If at least two are found,
// this reuses completeNTLM directly and reclassifies bs.mech to
// MechSaslNTLM: per RFC 4178 §5, per-message protection after negotiation
// uses the negotiated mechanism's own native format.
func (bs *BindSession) completeSPNEGO(cfg Config) error {
	if len(bs.pending) == 0 {
		return errors.New("bindsession: no SPNEGO mechanism token observed")
	}

	var ntlmMessages [][]byte
	clientMechListMIC := false
	serverMechListMIC := false
	for i, round := range bs.pending {
		if msg, ok := extractSPNEGONTLMMessage(round); ok {
			ntlmMessages = append(ntlmMessages, msg)
		}
		if detectedClient, detectedServer := detectMechListMIC(round, i%2 == 0); detectedClient {
			clientMechListMIC = true
		} else if detectedServer {
			serverMechListMIC = true
		}
	}
	if len(ntlmMessages) >= 2 {
		challenge := ntlmMessages[len(ntlmMessages)-2]
		authenticate := ntlmMessages[len(ntlmMessages)-1]
		if h := logNetNTLMHash(challenge, authenticate); h != "" {
			log.Log.Print(decryptColor.Sprintf("[+] NetNTLM hash: %s", h))
		}
		ntHash, haveHash := cfg.resolveNTHash()
		if !haveHash {
			return errors.New("bindsession: SPNEGO negotiated NTLM, but no --decrypt-hash/--decrypt-password supplied")
		}
		if err := bs.completeNTLM(ntHash, challenge, authenticate, clientMechListMIC, serverMechListMIC, true); err != nil {
			return err
		}
		bs.mech = MechSaslNTLM
		return nil
	}

	// Not simply the last observed round: bs.pending interleaves client
	// BindRequest credentials with server BindResponse serverSaslCreds, and
	// for a single-round bind (the common case) the last entry is the
	// server's own accept response, not the client's AP-REQ - see
	// selectSPNEGOAPReqToken.
	tokenBytes, err := selectSPNEGOAPReqToken(bs.pending)
	if err != nil {
		return err
	}
	key, cksum, err := completeSPNEGO(cfg, tokenBytes)
	if err != nil {
		return err
	}
	candidates := []types.EncryptionKey{key}
	isSubKey := false
	if apReq, err := apReqFromSPNEGOToken(tokenBytes); err == nil {
		candidates = apRepKeyCandidates(cfg, apReq, key)
		isSubKey = len(candidates) == 2
	}
	if subkey, ok := findAPRepSubkey(bs.pending, candidates); ok {
		key = subkey
		isSubKey = true
	}
	gss, err := newGSSSessionContext(key, isSubKey)
	if err != nil {
		return err
	}
	bs.gss = gss
	bs.layer = krb5SecurityLayer(cksum)
	bs.negotiated = true
	return nil
}

// UnwrapFromClient/WrapToTarget/UnwrapFromTarget/WrapToClient dispatch to
// the right mechanism's implementation without callers needing to know
// which one is active - only meaningful once negotiated, and only for
// wrapped (non-plain-BER) traffic.
//
// NTLM/Sicily's native wrapped-message framing puts the 16-byte
// NTLMSSP_MESSAGE_SIGNATURE (Version(4)=1 | Checksum(8) | SeqNum(4)) *first*,
// followed by the sealed payload - the opposite order from RFC 4752's
// GSS_Wrap convention (payload then trailing MIC).

func (bs *BindSession) UnwrapFromClient(wrapped []byte) ([]byte, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	switch bs.mech {
	case MechSicilyNTLM, MechSaslNTLM:
		if len(wrapped) < 16 {
			return nil, fmt.Errorf("bindsession: unwrap: NTLM frame too short (%d bytes, need >= 16)", len(wrapped))
		}
		return bs.ntlmClientRecv.Unseal(wrapped[16:], wrapped[:16])
	case MechSaslGSSAPI, MechSaslSPNEGO:
		return bs.gss.UnwrapFromClient(wrapped)
	case MechSaslDigestMD5:
		return bs.digestClientRecv.Unwrap(wrapped)
	default:
		return nil, fmt.Errorf("bindsession: unwrap: unhandled mechanism %s", bs.mech)
	}
}

func (bs *BindSession) WrapToTarget(plain []byte) ([]byte, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	switch bs.mech {
	case MechSicilyNTLM, MechSaslNTLM:
		sealed, sig := bs.ntlmClientSend.Seal(plain)
		return append(append([]byte{}, sig...), sealed...), nil
	case MechSaslGSSAPI, MechSaslSPNEGO:
		return bs.gss.WrapToTarget(plain)
	case MechSaslDigestMD5:
		return bs.digestClientSend.Wrap(plain), nil
	default:
		return nil, fmt.Errorf("bindsession: wrap: unhandled mechanism %s", bs.mech)
	}
}

func (bs *BindSession) UnwrapFromTarget(wrapped []byte) ([]byte, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	switch bs.mech {
	case MechSicilyNTLM, MechSaslNTLM:
		if len(wrapped) < 16 {
			return nil, fmt.Errorf("bindsession: unwrap: NTLM frame too short (%d bytes, need >= 16)", len(wrapped))
		}
		return bs.ntlmServerRecv.Unseal(wrapped[16:], wrapped[:16])
	case MechSaslDigestMD5:
		return bs.digestServerRecv.Unwrap(wrapped)
	case MechSaslGSSAPI, MechSaslSPNEGO:
		return bs.gss.UnwrapFromTarget(wrapped)
	default:
		return nil, fmt.Errorf("bindsession: unwrap: unhandled mechanism %s", bs.mech)
	}
}

func (bs *BindSession) WrapToClient(plain []byte) ([]byte, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	switch bs.mech {
	case MechSicilyNTLM, MechSaslNTLM:
		sealed, sig := bs.ntlmServerSend.Seal(plain)
		return append(append([]byte{}, sig...), sealed...), nil
	case MechSaslGSSAPI, MechSaslSPNEGO:
		return bs.gss.WrapToClient(plain)
	case MechSaslDigestMD5:
		return bs.digestServerSend.Wrap(plain), nil
	default:
		return nil, fmt.Errorf("bindsession: wrap: unhandled mechanism %s", bs.mech)
	}
}

// detectMechListMIC checks a SPNEGO negotiation round's bytes for a
// MechListMIC field and attributes it to the correct side. Returns
// (client=true, false) for a client-side MIC, (false, server=true) for a
// server-side MIC, or (false, false) if no MIC is present.
//
// Uses gokrb5.fork's SPNEGOToken.Unmarshal first (handles both NegTokenInit
// and NegTokenResp). When that fails — which it does for real-world
// NegTokenResp continuation rounds sent from a client without NegState
// (RFC 4178 makes NegState optional; gokrb5.fork's struct requires it) —
// falls back to the same lenient ASN.1 parse parseNegTokenRespLenient uses.
func detectMechListMIC(roundBytes []byte, clientRound bool) (client, server bool) {
	var tok spnego.SPNEGOToken
	if err := tok.Unmarshal(roundBytes); err == nil {
		if tok.Init && len(tok.NegTokenInit.MechListMIC) > 0 {
			return true, false // NegTokenInit is always from the client.
		}
		if tok.Resp && len(tok.NegTokenResp.MechListMIC) > 0 {
			if clientRound {
				return true, false
			}
			return false, true
		}
		return false, false
	}
	// Lenient fallback: NegTokenResp with optional NegState.
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(roundBytes, &outer); err != nil || outer.Tag != 1 {
		return false, false
	}
	var n fullyOptionalNegTokenResp
	if _, err := asn1.Unmarshal(outer.Bytes, &n); err != nil {
		return false, false
	}
	if len(n.MechListMIC) > 0 {
		if clientRound {
			return true, false
		}
		return false, true
	}
	return false, false
}
