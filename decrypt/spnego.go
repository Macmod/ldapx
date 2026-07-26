package decrypt

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
)

// This file handles the SPNEGO / GSS-API envelope layer: given the raw bytes
// of one observed handshake round, dig out the inner mechanism token (an
// AP-REQ, or an embedded NTLM message). The Kerberos handshake completion
// that consumes these tokens lives in krb5decrypt.go.

// fullyOptionalNegTokenResp mirrors gokrb5.fork/v9/spnego's own
// marshalNegTokenResp shape, except NegState is also marked optional -
// RFC 4178's own ASN.1 (NegTokenResp ::= SEQUENCE { negState [0]
// ENUMERATED OPTIONAL, ... }) already makes it optional, but gokrb5.fork's
// struct tag omits "optional" on that one field. A real client's own
// continuation round (just ResponseToken[2], optionally MechListMIC[3] -
// NegState/SupportedMech are server-only fields) fails gokrb5.fork's
// stricter decode outright rather than treating the leading fields as
// absent, so parseNegTokenRespLenient below is tried as a fallback.
type fullyOptionalNegTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"explicit,optional,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,omitempty,tag:3"`
}

// parseNegTokenRespLenient extracts a NegTokenResp's ResponseToken field
// without requiring NegState to be present - see fullyOptionalNegTokenResp.
func parseNegTokenRespLenient(tokenBytes []byte) (responseToken []byte, ok bool) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(tokenBytes, &outer); err != nil || outer.Tag != 1 {
		return nil, false
	}
	var n fullyOptionalNegTokenResp
	if _, err := asn1.Unmarshal(outer.Bytes, &n); err != nil {
		return nil, false
	}
	return n.ResponseToken, len(n.ResponseToken) > 0
}

// unmarshalSPNEGOMechToken extracts a SPNEGO negotiation token's inner
// mechanism-token bytes (MechTokenBytes for a NegTokenInit, ResponseToken
// for a NegTokenResp). Unlike calling spnego.UnmarshalNegToken directly,
// this goes through spnego.SPNEGOToken.Unmarshal, which - per RFC 2743
// §3.1/RFC 4178 §4.2.1 - knows to strip the outer GSS-API "Initial Context
// Token" [APPLICATION 0]+OID envelope a real client's first round is wrapped
// in (only NegTokenResp rounds, which never carry that envelope, can be
// unmarshalled directly): the raw envelope's ASN.1 shape doesn't match
// NegTokenInit's own SEQUENCE at all, so skipping this step doesn't
// misparse quietly - it fails hard with a tag mismatch. Falls back to
// parseNegTokenRespLenient for a real client's own NegState-less
// continuation round, which gokrb5.fork's stricter struct rejects outright.
func unmarshalSPNEGOMechToken(tokenBytes []byte) (mechTokenBytes []byte, err error) {
	var tok spnego.SPNEGOToken
	if err := tok.Unmarshal(tokenBytes); err != nil {
		if rt, ok := parseNegTokenRespLenient(tokenBytes); ok {
			return rt, nil
		}
		return nil, fmt.Errorf("krb5decrypt: unmarshal SPNEGO negotiation token: %w", err)
	}
	if tok.Init {
		return tok.NegTokenInit.MechTokenBytes, nil
	}
	return tok.NegTokenResp.ResponseToken, nil
}

// apReqFromMechToken extracts the AP-REQ from a SPNEGO mechToken/
// ResponseToken payload, tolerating two wire shapes: the RFC 1964 §1 /
// RFC 4178-compliant one (an OID+TOK_ID-tagged spnego.KRB5Token wrapping the
// AP-REQ) and a bare AP-REQ with no such wrapper at all - confirmed live
// against a Windows Server 2022 DC: some SPNEGO clients set
// NegTokenInit's MechToken field directly to the raw AP-REQ bytes, not a
// KRB5Token. A Windows Server 2022 DC accepts both, so this does too rather
// than only handling the spec-strict form.
func apReqFromMechToken(mechTokenBytes []byte) (*messages.APReq, error) {
	var tok spnego.KRB5Token
	if err := tok.Unmarshal(mechTokenBytes); err == nil && tok.IsAPReq() {
		return &tok.APReq, nil
	}
	var apReq messages.APReq
	if err := apReq.Unmarshal(mechTokenBytes); err != nil {
		return nil, errors.New("krb5decrypt: SPNEGO mechanism token is not a Kerberos AP-REQ")
	}
	return &apReq, nil
}

// apReqFromSPNEGOToken extracts the AP-REQ from a SPNEGO negotiation token,
// mirroring completeSPNEGO's own unwrap - needed separately so
// apRepKeyCandidates can independently re-derive the ticket's session key
// (which, for the ccache path, means re-testing candidate keys against this
// AP-REQ's Authenticator) without threading extra return values through
// completeSPNEGO itself.
func apReqFromSPNEGOToken(tokenBytes []byte) (*messages.APReq, error) {
	mechTokenBytes, err := unmarshalSPNEGOMechToken(tokenBytes)
	if err != nil {
		return nil, err
	}
	return apReqFromMechToken(mechTokenBytes)
}

// selectSPNEGOAPReqToken scans pending's rounds from the most recent
// backward for the one that actually carries a Kerberos AP-REQ mechanism
// token. BindSession's pending buffer interleaves client BindRequest
// credentials with server BindResponse serverSaslCreds - for a single-round
// SPNEGO/Kerberos bind (no mutual authentication requested, the common
// case: the DC's success response carries no ResponseToken at all, or one
// with no AP-REP), the *last* entry is that server round, not the client's
// AP-REQ. Scanning backward for the first entry that actually parses to an
// AP-REQ finds the right round regardless of how many non-carrying rounds
// (server acks, empty continuations) came after it.
func selectSPNEGOAPReqToken(pending [][]byte) ([]byte, error) {
	lastErr := errors.New("krb5decrypt: no SPNEGO round carried a Kerberos AP-REQ mechanism token")
	for i := len(pending) - 1; i >= 0; i-- {
		tokenBytes := pending[i]
		if bytes.HasPrefix(tokenBytes, ntlmSignature) {
			continue
		}
		mechTokenBytes, err := unmarshalSPNEGOMechToken(tokenBytes)
		if err != nil {
			lastErr = err
			continue
		}
		if len(mechTokenBytes) == 0 {
			continue
		}
		if _, err := apReqFromMechToken(mechTokenBytes); err != nil {
			lastErr = err
			continue
		}
		return tokenBytes, nil
	}
	return nil, lastErr
}

// extractSPNEGONTLMMessage returns the raw NTLM message embedded in one
// SPNEGO negotiation round, if any. Tolerates both the RFC 4178-compliant
// case (the NTLM message wrapped in a NegTokenInit/NegTokenResp) and the
// real-world case observed live where at least one client sends NTLM
// continuation rounds completely unwrapped, despite RFC 4178 expecting
// every round to be a NegotiationToken. Returns ok=false for a round that
// doesn't carry an NTLM message at all (e.g. it's Kerberos, or an
// intermediate round with no token yet).
func extractSPNEGONTLMMessage(roundBytes []byte) (msg []byte, ok bool) {
	if bytes.HasPrefix(roundBytes, ntlmSignature) {
		return roundBytes, true
	}
	inner, err := unmarshalSPNEGOMechToken(roundBytes)
	if err != nil {
		return nil, false
	}
	if bytes.HasPrefix(inner, ntlmSignature) {
		return inner, true
	}
	return nil, false
}

// extractGSSAPINTLMMessage returns the raw NTLM message embedded in one
// round of a bare SASL/GSSAPI exchange, if any. The NTLM signature is
// searched for directly rather than parsed structurally, since it tolerates
// both a bare NTLM message with no wrapper and at least one real client's
// ad-hoc wrapper around it uniformly - an 8-byte magic string collision
// inside legitimate Kerberos/GSS binary data isn't a realistic concern.
func extractGSSAPINTLMMessage(roundBytes []byte) (msg []byte, ok bool) {
	if idx := bytes.Index(roundBytes, ntlmSignature); idx >= 0 {
		return roundBytes[idx:], true
	}
	return nil, false
}
