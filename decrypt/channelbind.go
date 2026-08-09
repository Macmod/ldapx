package decrypt

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"

	"github.com/Macmod/ldapx/log"
	ber "github.com/go-asn1-ber/asn1-ber"
)

// RFC 5929 `tls-server-end-point` channel binding injection into bind
// requests. The binding is recomputed over the target's certificate and
// substituted into the mechanism's carrier field so binds against servers
// enforcing channel bindings complete through the proxy.

// tlsServerEndPointPrefix is the RFC 5929 §4 channel binding type prefix.
const tlsServerEndPointPrefix = "tls-server-end-point:"

// certificateHash hashes cert per RFC 5929 §4.1: the hash is the one named
// by the certificate's own signatureAlgorithm, except that MD5 and SHA-1 are
// both upgraded to SHA-256.
func certificateHash(cert *x509.Certificate) []byte {
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		sum := sha512.Sum384(cert.Raw)
		return sum[:]
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		sum := sha512.Sum512(cert.Raw)
		return sum[:]
	default:
		sum := sha256.Sum256(cert.Raw)
		return sum[:]
	}
}

// ChannelBindingToken returns the MD5 of the RFC 2744 §3.11
// gss_channel_bindings_struct whose application data is the RFC 5929
// `tls-server-end-point` binding for cert.
func ChannelBindingToken(cert *x509.Certificate) []byte {
	appData := append([]byte(tlsServerEndPointPrefix), certificateHash(cert)...)

	buf := make([]byte, 20, 20+len(appData))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(len(appData)))
	buf = append(buf, appData...)

	sum := md5.Sum(buf)
	return sum[:]
}

// RewriteBindChannelBindings substitutes a channel binding computed over
// cert into the BindRequest's credentials. Returns the original packet
// unchanged on any failure.
func RewriteBindChannelBindings(bs *BindSession, packet *ber.Packet, cfg Config, cert *x509.Certificate) *ber.Packet {
	if cert == nil {
		return packet
	}

	bs.mu.Lock()
	negotiated := bs.negotiated
	bs.mu.Unlock()
	if negotiated {
		return packet
	}

	auth, carrier, credBytes, ok := bindCreds(packet)
	if !ok || len(credBytes) == 0 {
		return packet
	}

	bs.mu.Lock()
	pending := append([][]byte(nil), bs.pending...)
	bs.mu.Unlock()

	token := ChannelBindingToken(cert)

	var newCreds []byte
	var err error

	switch carrier.mech {
	case "GSSAPI", "GSS-SPNEGO":
		// Either mechanism name can carry Kerberos or NTLM.
		newCreds, err = rewriteKerberosChannelBindings(credBytes, cfg, token)
		if err == nil && newCreds == nil {
			newCreds, err = rewriteNTLMChannelBindings(credBytes, cfg, token, pending)
		}
	case "NTLM", "NTLMSSP", sicilyMech:
		newCreds, err = rewriteNTLMChannelBindings(credBytes, cfg, token, pending)
	default:
		return packet
	}

	switch {
	case err != nil:
		bs.logChannelBindingsOnce(true, failColor.Sprintf("[-] Channel bindings could not be injected into the %s bind: %v", carrier.label(), err))
		return packet
	case newCreds == nil:
		// This round carries nothing to rewrite - an intermediate round, or
		// a message with no field to hold a binding.
		return packet
	}

	carrier.write(packet, auth, newCreds)
	bs.logChannelBindingsOnce(false, decryptColor.Sprintf("[+] Channel bindings for the target's TLS certificate injected into the %s bind", carrier.label()))
	return packet
}

// logChannelBindingsOnce prints msg the first time it's called for the
// given outcome (success or failure), tracked separately.
func (bs *BindSession) logChannelBindingsOnce(failed bool, msg string) {
	bs.mu.Lock()
	flag := &bs.cbLogged
	if failed {
		flag = &bs.cbFailLogged
	}
	first := !*flag
	*flag = true
	bs.mu.Unlock()

	if first {
		log.Log.Print(msg)
	}
}

// sicilyMech is the label for Sicily's bind, which has no mechanism name
// field.
const sicilyMech = "Sicily/NTLM"

// bindCarrier abstracts the two places a bind puts its authentication token:
// SASL's credentials field, and Sicily's own authentication choice, which is
// a primitive holding the NTLM message directly.
type bindCarrier struct {
	mech   string
	sicily bool
}

func (c bindCarrier) label() string {
	if c.sicily {
		return sicilyMech
	}
	return "SASL/" + c.mech
}

// write puts newCreds where the token came from and rebuilds the encoded
// content of every enclosing packet, since ber.Packet serializes from its
// Data buffer which holds already-encoded children.
func (c bindCarrier) write(packet *ber.Packet, auth *ber.Packet, newCreds []byte) {
	leaf := auth
	if !c.sicily {
		leaf = auth.Children[1]
	}
	leaf.Data.Reset()
	leaf.Data.Write(newCreds)
	leaf.ByteValue = newCreds
	leaf.Value = string(newCreds)

	if !c.sicily {
		rebuildBerData(auth)
	}
	rebuildBerData(packet.Children[1])
	rebuildBerData(packet)
}

// bindCreds returns a BindRequest's authentication choice, its carrier,
// and raw token bytes. ok is false for binds with no channel-binding-capable
// token (simple bind, SASL without credentials).
func bindCreds(packet *ber.Packet) (auth *ber.Packet, carrier bindCarrier, credBytes []byte, ok bool) {
	if len(packet.Children) < 2 {
		return nil, carrier, nil, false
	}
	bindReq := packet.Children[1]
	if len(bindReq.Children) < 3 {
		return nil, carrier, nil, false
	}
	auth = bindReq.Children[2]
	if auth.ClassType != ber.ClassContext {
		return nil, carrier, nil, false
	}

	switch auth.Tag {
	case authChoiceSASL:
		if len(auth.Children) < 2 {
			return nil, carrier, nil, false
		}
		mechName, _ := auth.Children[0].Value.(string)
		return auth, bindCarrier{mech: mechName}, primitiveBytes(auth.Children[1]), true
	case authChoiceSicilyResponse:
		return auth, bindCarrier{mech: sicilyMech, sicily: true}, primitiveBytes(auth), true
	}
	return nil, carrier, nil, false
}

func rebuildBerData(packet *ber.Packet) {
	data := new(bytes.Buffer)
	for _, child := range packet.Children {
		data.Write(child.Bytes())
	}
	packet.Data = data
}
