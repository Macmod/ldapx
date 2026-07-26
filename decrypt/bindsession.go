package decrypt

import (
	"errors"
	"fmt"
	"sync"

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

	mech       BindMechanism
	negotiated bool
	layer      SecurityLayer

	// Four independent cipher instances, not two: unwrapping a message and
	// re-sealing it are each their own RC4 stream advancement even though
	// both use the same key (client keys for the C->T leg, server keys for
	// T->C). Reusing one instance for both would double-advance the stream
	// per message and desync from what the real receiving endpoint expects.
	ntlmClientRecv *NTLMDirectionCipher // unwraps incoming-from-client (client keys)
	ntlmClientSend *NTLMDirectionCipher // (re)seals outgoing-to-target, on the client's behalf (client keys, independent stream)
	ntlmServerRecv *NTLMDirectionCipher // unwraps incoming-from-target (server keys)
	ntlmServerSend *NTLMDirectionCipher // (re)seals outgoing-to-client, on the target's behalf (server keys, independent stream)

	// DIGEST-MD5: same four-direction pattern as NTLM (stateful per-direction
	// sequence numbers and, for auth-conf, continuous RC4 streams).
	digestClientRecv *DigestMD5DirectionCipher
	digestClientSend *DigestMD5DirectionCipher
	digestServerRecv *DigestMD5DirectionCipher
	digestServerSend *DigestMD5DirectionCipher

	gss *gssSessionContext

	// buffers negotiation tokens as they pass through, so the
	// AUTHENTICATE_MESSAGE (which needs the preceding CHALLENGE's data) can
	// be processed once the full exchange is visible.
	pending [][]byte

	// loggedFraming is set the first time ShouldLogFraming runs for this
	// connection, so the caller's one-line "post-bind traffic:
	// plaintext/unwrapping" log fires once, not per message.
	loggedFraming bool

	// lastAuthChoiceSicily records whether the most recent BindRequest was
	// specifically a sicilyResponse [11] - unlike SASL's saslBindInProgress
	// (14), Sicily has no "not done yet" signal of its own: every successful
	// step (package discovery, negotiate, response) returns the same
	// resultCode 0, so completion can only be inferred from having just sent
	// the *last* step of the exchange, not from the response code alone.
	lastAuthChoiceSicily bool

	// mechAnnounced guards the one-time "[+] Bind mechanism identified: ..."
	// log line. mech alone can't serve as that guard: MechNone means both
	// "not observed yet" and "this is a simple bind" (itself a valid,
	// permanent identification), so a separate flag is needed to tell those
	// two apart.
	mechAnnounced bool

	// handshakeObserved is set once the bind's final response has been
	// seen, regardless of whether key derivation from it succeeded. mech
	// alone isn't enough to gate post-bind-only reporting (see
	// ShouldLogFraming): it's set as soon as the mechanism name is known,
	// from the *first* round of a multi-round handshake, well before any
	// later round or genuinely post-bind traffic.
	handshakeObserved bool
}

func NewBindSession() *BindSession {
	return &BindSession{}
}

// State returns a snapshot of the negotiated/layer/mech fields in a single
// lock, for callers (logging, framing decisions) that need a consistent
// read of all three together.
func (bs *BindSession) State() (negotiated bool, layer SecurityLayer, mech BindMechanism) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.negotiated, bs.layer, bs.mech
}

// ShouldLogFraming reports whether the caller should emit its one-time
// "post-bind traffic: plaintext/unwrapping" log line for this connection,
// marking it as logged if so. Gated on the bind's final response having
// been observed (bs.handshakeObserved), not on key negotiation having
// succeeded - plaintext vs. wrapped is observable straight off the wire
// regardless of whether a credential was available to actually derive keys.
// Simple binds and unhandled SASL mechanisms never reach a final response
// through completeHandshake, so they never set this and never get this
// line.
func (bs *BindSession) ShouldLogFraming() bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if !bs.handshakeObserved || bs.loggedFraming {
		return false
	}
	bs.loggedFraming = true
	return true
}

// completeNTLM finishes an NTLM handshake given its CHALLENGE_MESSAGE and
// AUTHENTICATE_MESSAGE bytes and the supplied NT hash: derives session keys
// and sets up per-direction ciphers. Callers extract challenge/authenticate
// from wherever they were observed - Sicily/SASL-NTLM's own bs.pending
// entries directly, or (via completeSPNEGO) the NTLM messages found nested
// inside a SPNEGO negotiation, since the messages themselves are identical
// regardless of which mechanism carried them.
//
// clientMechListMIC and serverMechListMIC control the initial per-message
// sequence number for the client and server cipher sets respectively.
// They must be true when the corresponding side sent a SPNEGO mechListMIC
// (RFC 4178 §4.2.2) during the handshake - the mechListMIC is signed with a
// throwaway cipher handle that leaves the real keystream untouched, but the
// numeric per-message sequence counter embedded in every NTLMSSP_MESSAGE_
// SIGNATURE still advances to account for it. The two sides advance
// independently: a client that did NOT send a mechListMIC starts its
// post-bind sequence at 0, while a server that DID starts at 1, and vice
// versa. Both clientMechListMIC and serverMechListMIC are only meaningful
// when the AUTHENTICATE_MESSAGE's negotiated flags include NTLMSSP_NEGOTIATE_
// SIGN (the sign flag) - setting them without SIGN is harmless (no mechList
// MIC is ever sent when SIGN isn't negotiated).
//
// gssWrapped must be true when the NTLM is carried inside GSS-API (bare
// SASL/GSSAPI or SASL/GSS-SPNEGO), false for raw NTLMSSP (Sicily or bare
// SASL/NTLM). It only matters for the sealed-only (SEAL without SIGN) layer:
// confirmed live that a Windows Server 2022 DC re-keys its RC4 sealing per
// message (the
// connectionless MD5(SealKey||seq) discipline - see NTLMDirectionCipher)
// only for GSS-wrapped NTLM, while raw Sicily NTLM keeps the continuous
// connection-oriented stream even for the same flags. The two LDAP carriers
// dispatch to the SSP differently, so the same SEAL-without-SIGN negotiation
// seals differently on the wire.
func (bs *BindSession) completeNTLM(ntHash []byte, challenge, authenticate []byte, clientMechListMIC, serverMechListMIC, gssWrapped bool) error {
	ch, err := parseNTLMChallenge(challenge)
	if err != nil {
		return fmt.Errorf("bindsession: parse CHALLENGE_MESSAGE: %w", err)
	}
	auth, err := parseNTLMAuthenticate(authenticate)
	if err != nil {
		return fmt.Errorf("bindsession: parse AUTHENTICATE_MESSAGE: %w", err)
	}

	keys, err := deriveNTLMv2SessionKeys(ntHash, auth.User, auth.Domain, ch.ServerChallenge, auth.NtChallengeResponse, auth.EncryptedRandomSessionKey, auth.NegotiateFlags)
	if err != nil {
		return err
	}

	sign := auth.NegotiateFlags&ntlmNegotiateSign != 0
	var clientStartSeq, serverStartSeq uint32
	if clientMechListMIC && sign {
		clientStartSeq = 1
	}
	if serverMechListMIC && sign {
		serverStartSeq = 1
	}

	// Sealed-without-signing (SEAL set, SIGN not) over GSS-wrapped NTLM makes
	// a Windows Server 2022 DC re-key its RC4 sealing per message with the
	// connectionless formula MD5(SealingKey || seqNum), even over
	// connection-oriented LDAP - see NTLMDirectionCipher's doc comment. Raw
	// (Sicily/SASL) NTLM keeps the continuous stream for the same flags, so
	// this is gated on the carrier too. Every direction must follow suit or
	// nothing decrypts.
	datagram := gssWrapped && auth.NegotiateFlags&ntlmNegotiateSeal != 0 && auth.NegotiateFlags&ntlmNegotiateSign == 0

	var err2 error
	newCipher := func(seal, sign []byte, startSeq uint32) *NTLMDirectionCipher {
		if err2 != nil {
			return nil
		}
		c, e := NewNTLMDirectionCipher(seal, sign, startSeq, datagram)
		if e != nil {
			err2 = e
		}
		return c
	}
	bs.ntlmClientRecv = newCipher(keys.ClientSealingKey, keys.ClientSigningKey, clientStartSeq)
	bs.ntlmClientSend = newCipher(keys.ClientSealingKey, keys.ClientSigningKey, clientStartSeq)
	bs.ntlmServerRecv = newCipher(keys.ServerSealingKey, keys.ServerSigningKey, serverStartSeq)
	bs.ntlmServerSend = newCipher(keys.ServerSealingKey, keys.ServerSigningKey, serverStartSeq)
	if err2 != nil {
		return err2
	}

	bs.layer = ntlmSecurityLayer(keys.NegotiateFlags)
	bs.negotiated = true
	return nil
}

// completeGSSAPI finishes a SASL/GSSAPI handshake: recovers the session key
// from the buffered AP-REQ via the configured credential source, and
// classifies the negotiated security layer from the AP-REQ Authenticator's
// own GSS checksum flags (krb5SecurityLayer) - see that function's doc
// comment for the caveat specific to this mechanism (as opposed to
// GSS-SPNEGO, where the same flags are authoritative).
//
// A Windows client offered only bare "GSSAPI" (no "GSS-SPNEGO") falls back
// to NTLM under the hood rather than Kerberos, the same way SPNEGO can
// negotiate NTLM instead of Kerberos (see completeSPNEGO) - the difference
// is bare GSSAPI has no standard envelope of its own for this, so at least
// one real client's continuation rounds carry an ad-hoc wrapper (the
// mechanism name and the NTLM message as sibling context-tagged fields)
// instead of any GSS/SPNEGO framing. Every pending round is checked for an
// embedded NTLM message first, exactly like completeSPNEGO does.
//
// Genuine Kerberos's credentials field is a GSS-API "Initial Context Token"
// (RFC 2743 §3.1: an OID-tagged wrapper identifying the mechanism, carrying
// the mechanism-specific token) - not a bare AP-REQ - so it needs the same
// spnego.KRB5Token unwrap completeSPNEGO applies to its own inner mechanism
// token before the bare AP-REQ bytes are reachable. Unlike SPNEGO, bare
// GSSAPI's first round always carries the complete token (Kerberos doesn't
// need a server challenge first the way NTLM does), so the first pending
// round - not the last - is the one that matters here.
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
		ntHash, haveHash := cfg.resolveNTHash()
		if !haveHash {
			return errors.New("bindsession: SASL/GSSAPI negotiated NTLM, but no --decrypt-hash/--decrypt-password supplied")
		}
		challenge := ntlmMessages[len(ntlmMessages)-2]
		authenticate := ntlmMessages[len(ntlmMessages)-1]
		// GSSAPI NTLM fallback has no SPNEGO envelope, so no mechListMIC
		// from either side.
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
	// apRepKeyCandidates only appends the ticket's own session key when it
	// differs from key - so a second entry means key is the Authenticator's
	// subkey, not the ticket's session key.
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
// SPNEGO can negotiate NTLM instead of Kerberos whenever Kerberos isn't
// usable (e.g. connecting by bare IP with no resolvable SPN), so every
// pending round is checked for an embedded NTLM message first. If at least
// two are found (a CHALLENGE_MESSAGE and an AUTHENTICATE_MESSAGE), this
// reuses completeNTLM directly and reclassifies bs.mech to MechSaslNTLM:
// SPNEGO's own job ends at carrying the negotiation, and per RFC 4178 §5,
// per-message protection after that point uses the negotiated mechanism's
// own native format - for NTLM, exactly the same wire framing
// Sicily/SASL-NTLM already implement, so nothing else needs to change.
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
		ntHash, haveHash := cfg.resolveNTHash()
		if !haveHash {
			return errors.New("bindsession: SPNEGO negotiated NTLM, but no --decrypt-hash/--decrypt-password supplied")
		}
		challenge := ntlmMessages[len(ntlmMessages)-2]
		authenticate := ntlmMessages[len(ntlmMessages)-1]
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
