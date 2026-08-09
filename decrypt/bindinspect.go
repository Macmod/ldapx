package decrypt

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/Macmod/ldapx/log"
	"github.com/fatih/color"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
)

var decryptColor = color.New(color.FgHiBlue)
var failColor = color.New(color.FgRed)

// Context-specific tags on the BindRequest's authentication field.
const (
	authChoiceSimple                 ber.Tag = 0
	authChoiceSicilyPackageDiscovery ber.Tag = 9
	authChoiceSicilyNegotiate        ber.Tag = 10
	authChoiceSicilyResponse         ber.Tag = 11
	authChoiceSASL                   ber.Tag = 3
)

// serverSaslCredsTag is BindResponse's optional serverSaslCreds [7] field
// (RFC 4511 §4.2.2).
const serverSaslCredsTag ber.Tag = 7

// resultSaslBindInProgress is RFC 4511 §4.1.9's saslBindInProgress.
const resultSaslBindInProgress int64 = 14

// primitiveBytes returns a primitive packet's raw content bytes regardless
// of class. ber.ReadPacket only populates .ByteValue for ClassUniversal
// primitives; context-tagged primitives only get their content in .Data.
func primitiveBytes(p *ber.Packet) []byte {
	if len(p.ByteValue) > 0 {
		return p.ByteValue
	}
	return p.Data.Bytes()
}

// Known GSS-API mechanism OIDs for diagnostic logging.
var (
	oidGSSAPIKRB5   = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
	oidGSSAPIMSKS5  = asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
	oidGSSAPINTLM   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	oidGSSAPISPENGO = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
)

func mechOIDName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidGSSAPIKRB5):
		return "Kerberos (RFC 1964)"
	case oid.Equal(oidGSSAPIMSKS5):
		return "Kerberos (MS Legacy)"
	case oid.Equal(oidGSSAPINTLM):
		return "NTLM"
	case oid.Equal(oidGSSAPISPENGO):
		return "SPNEGO"
	default:
		return fmt.Sprintf("OID %s", oid.String())
	}
}

// inspectGSSAPICreds tries to parse credBytes as a GSSAPI Initial Context
// Token ([APPLICATION 0] MechIndepToken wrapping an OID + inner token) and
// returns the human-readable name of the mechanism, or empty if parsing fails.
func inspectGSSAPICreds(credBytes []byte) string {
	var mech asn1.ObjectIdentifier
	if _, err := asn1.UnmarshalWithParams(credBytes, &mech, "application,explicit,tag:0"); err != nil {
		// Fallback: check for NTLMSSP signature in the inner bytes.
		if bytes.Contains(credBytes, []byte("NTLMSSP")) {
			return "NTLM"
		}
		return ""
	}
	return mechOIDName(mech)
}

// inspectSPNEGOInit tries to parse credBytes as a SPNEGO Negotiation Token
// and returns a formatted string of the offered mechTypes (human-readable
// names from the NegTokenInit), or empty if parsing fails.
func inspectSPNEGOInit(credBytes []byte) string {
	var tok spnego.SPNEGOToken
	if err := tok.Unmarshal(credBytes); err != nil {
		return ""
	}
	if !tok.Init {
		return ""
	}
	names := make([]string, len(tok.NegTokenInit.MechTypes))
	for i, m := range tok.NegTokenInit.MechTypes {
		names[i] = mechOIDName(m)
	}
	return strings.Join(names, ", ")
}

// inspectSPNEGOResp tries to parse the server's SPNEGO NegTokenResp from
// raw bytes and returns the human-readable name of the selected mechanism
// (SupportedMech), or empty if parsing fails.
func inspectSPNEGOResp(respBytes []byte) string {
	// NegTokenResp bytes are wrapped in [APPLICATION 1] (tag 0xA1) for
	// the full SPNEGO token, or appear as a raw NegTokenResp when inside
	// serverSaslCreds. Use the SPNEGOToken unmarshal which handles both.
	var tok spnego.SPNEGOToken
	if err := tok.Unmarshal(respBytes); err != nil {
		return ""
	}
	if !tok.Resp {
		return ""
	}
	oid := tok.NegTokenResp.SupportedMech
	if len(oid) == 0 {
		return ""
	}
	return mechOIDName(oid)
}

// InspectBindRequest observes (never modifies) a client's BindRequest,
// identifying the mechanism on first sight and buffering handshake tokens
// as they pass through so the full exchange is available once it completes.
func InspectBindRequest(bs *BindSession, packet *ber.Packet) {
	if len(packet.Children) < 2 {
		return
	}
	bindReq := packet.Children[1]
	if len(bindReq.Children) < 3 {
		return
	}
	auth := bindReq.Children[2]

	bs.mu.Lock()
	defer bs.mu.Unlock()

	// A bind after the previous one finished starts a new authentication.
	if bs.bindComplete {
		bs.resetHandshake()
	}

	switch {
	case auth.ClassType == ber.ClassContext && auth.Tag == authChoiceSimple:
		if !bs.mechAnnounced {
			bs.mechAnnounced = true

			if len(auth.Data.Bytes()) == 0 {
				log.Log.Print(decryptColor.Sprintf("[+] Bind mechanism identified: simple (anonymous)"))
			} else {
				log.Log.Print(decryptColor.Sprintf("[+] Bind mechanism identified: simple (user/password)"))
			}
		}

	case auth.ClassType == ber.ClassContext && auth.Tag == authChoiceSicilyNegotiate:
		bs.lastAuthChoiceSicily = false
		if !bs.mechAnnounced {
			bs.hsMech = MechSicilyNTLM
			bs.mechAnnounced = true
			log.Log.Print(decryptColor.Sprintf("[+] Bind mechanism identified: %s", bs.hsMech))
		}
		if b := primitiveBytes(auth); len(b) > 0 {
			bs.pending = append(bs.pending, b)
		}

	case auth.ClassType == ber.ClassContext && auth.Tag == authChoiceSicilyResponse:
		bs.lastAuthChoiceSicily = true
		if b := primitiveBytes(auth); len(b) > 0 {
			bs.pending = append(bs.pending, b)
		}

	case auth.ClassType == ber.ClassContext && auth.Tag == authChoiceSASL:
		if len(auth.Children) < 1 {
			return
		}
		mechName, _ := auth.Children[0].Value.(string)
		var credBytes []byte
		if len(auth.Children) > 1 {
			credBytes = primitiveBytes(auth.Children[1])
		}

		if !bs.mechAnnounced {
			switch mechName {
			case "GSSAPI":
				bs.hsMech = MechSaslGSSAPI
			case "GSS-SPNEGO":
				bs.hsMech = MechSaslSPNEGO
			case "NTLM", "NTLMSSP":
				bs.hsMech = MechSaslNTLM
			case "DIGEST-MD5":
				bs.hsMech = MechSaslDigestMD5
			default:
				bs.mechAnnounced = true
				log.Log.Print(decryptColor.Sprintf("[+] Bind mechanism identified: SASL/%s (unhandled - forwarding only, no decryption)", mechName))
				return
			}
			bs.mechAnnounced = true
			log.Log.Print(decryptColor.Sprintf("[+] Bind mechanism identified: %s", bs.hsMech))

			if len(credBytes) > 0 {
				switch mechName {
				case "GSSAPI":
					if proto := inspectGSSAPICreds(credBytes); proto != "" {
						log.Log.Print(decryptColor.Sprintf("[+] SASL/GSSAPI auth protocol identified: %s", proto))
					}
				case "GSS-SPNEGO":
					if mechs := inspectSPNEGOInit(credBytes); mechs != "" {
						log.Log.Print(decryptColor.Sprintf("[+] SASL/GSS-SPNEGO NegTokenInit offered: [%s]", mechs))
					}
				}
			}
		}

		if len(credBytes) > 0 {
			bs.pending = append(bs.pending, credBytes)
		}
	}
}

// InspectBindResponse observes a BindResponse/SicilyBindResponse, capturing
// any server-side handshake payload and, on the handshake's final success,
// attempting key derivation via whichever --decrypt-* credential applies.
func InspectBindResponse(bs *BindSession, packet *ber.Packet, cfg Config) {
	if len(packet.Children) < 2 {
		return
	}
	resp := packet.Children[1]
	if len(resp.Children) < 1 {
		return
	}

	bs.mu.Lock()
	mech := bs.hsMech
	alreadyObserved := bs.handshakeObserved
	sicilyDone := bs.lastAuthChoiceSicily
	bs.mu.Unlock()

	resultCode, ok := resp.Children[0].Value.(int64)

	// Record the end of this authentication. Sicily has no in-progress code,
	// so its final step is the one answering a sicilyResponse.
	if ok && resultCode != resultSaslBindInProgress {
		if resultCode != 0 || mech != MechSicilyNTLM || sicilyDone {
			bs.mu.Lock()
			bs.bindComplete = true
			bs.mu.Unlock()
		}
	}

	if mech == MechNone || alreadyObserved {
		return
	}

	captureBindResponsePayload(bs, mech, resp)

	if !ok || resultCode != 0 {
		return // not a final success yet (or a SASL continuation) - keep waiting
	}

	// Sicily has no in-progress code; only the response to a sicilyResponse
	// request is final.
	if mech == MechSicilyNTLM && !sicilyDone {
		return
	}

	// Deferred: the BindResponse hasn't been written back yet and still
	// belongs to the previous layer.
	bs.mu.Lock()
	bs.pendingCompletion = &pendingCompletion{mech: mech, cfg: cfg}
	bs.mu.Unlock()
}

func captureBindResponsePayload(bs *BindSession, mech BindMechanism, resp *ber.Packet) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	switch mech {
	case MechSicilyNTLM:
		// SicilyBindResponse's documented shape is resultCode/serverCreds/
		// errorMessage, in that order - no matchedDN, unlike a normal
		// BindResponse.
		if len(resp.Children) >= 2 {
			if b := primitiveBytes(resp.Children[1]); len(b) > 0 {
				bs.pending = append(bs.pending, b)
			}
		}
	default:
		for _, child := range resp.Children {
			if child.ClassType == ber.ClassContext && child.Tag == serverSaslCredsTag {
				if b := primitiveBytes(child); len(b) > 0 {
					bs.pending = append(bs.pending, b)

					// For SPNEGO, log the server's selected mechanism from
					// the NegTokenResp's SupportedMech field.
					if mech == MechSaslSPNEGO {
						if sel := inspectSPNEGOResp(b); sel != "" {
							log.Log.Print(decryptColor.Sprintf("[+] SASL/GSS-SPNEGO server selected: %s", sel))
						}
					}
				}
				return
			}
		}
	}
}

func completeHandshake(bs *BindSession, mech BindMechanism, cfg Config) {
	bs.mu.Lock()
	bs.handshakeObserved = true
	// Set the mechanism now: completeGSSAPI/completeSPNEGO refine it further
	// (e.g. SASL carrying NTLM becomes MechSaslNTLM).
	prevMech := bs.mech
	bs.mech = mech
	bs.mu.Unlock()

	derived := false
	defer func() {
		if !derived {
			bs.mu.Lock()
			bs.mech = prevMech
			bs.mu.Unlock()
		}
	}()

	var err error

	switch mech {
	case MechSicilyNTLM, MechSaslNTLM:
		ntHash, haveHash := cfg.resolveNTHash()
		bs.mu.Lock()
		if len(bs.pending) < 2 {
			err = errors.New("bindsession: incomplete NTLM handshake (missing challenge or authenticate message)")
		} else {
			challenge := bs.pending[len(bs.pending)-2]
			authenticate := bs.pending[len(bs.pending)-1]
			if h := logNetNTLMHash(challenge, authenticate); h != "" {
				log.Log.Print(decryptColor.Sprintf("[+] NetNTLM hash: %s", h))
			}
			if haveHash {
				err = bs.completeNTLM(ntHash, challenge, authenticate, false, false, false)
			} else {
				// Hash captured above; without a credential no keys can be
				// derived, so stop here (don't fall through to "derived").
				bs.mu.Unlock()
				return
			}
		}
		bs.mu.Unlock()

	case MechSaslGSSAPI, MechSaslSPNEGO:
		if cfg.Keytab == nil && cfg.CCache == nil && cfg.RawSvcKey == nil && cfg.SvcPassword == "" && len(cfg.NTHash) == 0 {
			return
		}
		bs.mu.Lock()
		if mech == MechSaslGSSAPI {
			err = bs.completeGSSAPI(cfg)
		} else {
			err = bs.completeSPNEGO(cfg)
		}
		bs.mu.Unlock()

	case MechSaslDigestMD5:
		password, havePassword := cfg.resolvePassword()
		if !havePassword {
			return
		}
		bs.mu.Lock()
		err = bs.completeDigestMD5(password)
		bs.mu.Unlock()

	default:
		return
	}

	if err != nil {
		log.Log.Print(failColor.Sprintf("[-] Decryption failed: %v", strings.TrimRight(err.Error(), "\n\r")))
		return
	}

	derived = true

	bs.mu.Lock()
	mechStr, layerStr := bs.mech.String(), bs.layer.String()
	layerKnown := bs.layer != LayerUnknown
	bs.mu.Unlock()

	// NTLM/Sicily read their security layer from the AUTHENTICATE_MESSAGE.
	// GSSAPI/SPNEGO-Kerberos derives it from the Authenticator checksum flags.
	if layerKnown {
		log.Log.Print(decryptColor.Sprintf("[+] Security layer identified: %s", layerStr))
	} else {
		log.Log.Print(decryptColor.Sprintf("[+] %s session key derived - security layer will be confirmed on the first post-bind PDU", mechStr))
	}
}
