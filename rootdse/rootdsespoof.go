package rootdse

import (
	"strings"

	"github.com/Macmod/ldapx/log"
	"github.com/fatih/color"
	ber "github.com/go-asn1-ber/asn1-ber"
)

// spoofColor marks feedback about --spoof-mechs actually taking effect on
// the wire - green, matching internal/app's own "changed" convention (this
// package can't reach that unexported var directly, so it defines its own
// instance of the same semantic color, same as decrypt package's
// decryptColor).
var spoofColor = color.New(color.FgGreen)
var yellow = color.New(color.FgYellow)

const spoofMechNone = "none" // reserved sentinel, not a real mechanism name

// saslMechAliases maps friendly, easy-to-type names to the exact wire-format
// strings MS-ADTS §3.1.1.3.4.5 defines.
var saslMechAliases = map[string]string{
	"gssapi":     "GSSAPI",
	"spnego":     "GSS-SPNEGO",
	"gss-spnego": "GSS-SPNEGO",
	"external":   "EXTERNAL",
	"digest-md5": "DIGEST-MD5",
	"digest":     "DIGEST-MD5",
}

// resolveSASLMech maps a user-supplied --spoof-mechs entry to its
// wire-format value via the alias table (case-insensitive); anything that
// doesn't match a known alias is passed through verbatim, so an operator
// can supply a custom/made-up string directly for edge-case testing.
func resolveSASLMech(v string) string {
	if resolved, ok := saslMechAliases[strings.ToLower(v)]; ok {
		return resolved
	}
	return v
}

// ProcessSearchResultEntry rewrites (or strips) the rootDSE's
// supportedSASLMechanisms attribute per --spoof-mechs, leaving every
// other SearchResultEntry - and every other attribute - completely
// untouched. packet is the full LDAPMessage
// (SEQUENCE{messageID, [APPLICATION 4]SearchResultEntry{objectName, attributes}, controls?}),
// matching the shape every other Process*Request/Response function in this
// codebase operates on. The returned bool reports whether spoofing actually
// took effect on this call, so the caller can track (and warn about) a bind
// happening without any prior successful spoof on the same connection.
func ProcessSearchResultEntry(packet *ber.Packet, spoofGiven bool, spoofMechs []string) (*ber.Packet, bool) {
	if !spoofGiven {
		return packet, false
	}
	if len(packet.Children) < 2 || len(packet.Children[1].Children) < 2 {
		return packet, false
	}

	entry := packet.Children[1]
	objectName := entry.Children[0]
	attributes := entry.Children[1]

	// The rootDSE is, and only is, the entry whose DN is empty (RFC 4511) -
	// stateless, no correlation with the request that produced this
	// response needed.
	if len(objectName.ByteValue) != 0 {
		return packet, false
	}

	idx := -1
	for i, attr := range attributes.Children {
		if len(attr.Children) == 0 {
			continue
		}
		name, ok := attr.Children[0].Value.(string)
		if !ok || !strings.EqualFold(name, "supportedSASLMechanisms") {
			continue
		}
		idx = i
		break
	}
	if idx == -1 {
		// Not present in this particular response (e.g. the client didn't
		// request it) - never inject an attribute a real server wouldn't
		// have sent for that request.
		return packet, false
	}

	var oldValues []string
	if len(attributes.Children[idx].Children) > 1 {
		for _, v := range attributes.Children[idx].Children[1].Children {
			if s, ok := v.Value.(string); ok {
				oldValues = append(oldValues, s)
			}
		}
	}

	remove, values := resolveSpoofValues(spoofMechs)

	// ber.Packet.Bytes() serializes from a .Data buffer that AppendChild
	// snapshots at call time - it is NOT re-derived live from .Children, so
	// mutating attributes.Children in place would never actually reach the
	// wire (only ldapx's own in-memory inspection of the tree would see
	// it). Every ancestor whose content changes has to be rebuilt via fresh
	// AppendChild calls instead, all the way up to the top-level message,
	// matching how every other Process* function in this codebase already
	// builds its output.
	newAttributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for i, attr := range attributes.Children {
		if i != idx {
			newAttributes.AppendChild(attr)
			continue
		}
		if remove {
			continue
		}
		newAttr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
		newAttr.AppendChild(attr.Children[0]) // attribute name, unchanged
		valSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
		for _, v := range values {
			valSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "AttributeValue"))
		}
		newAttr.AppendChild(valSet)
		newAttributes.AppendChild(newAttr)
	}

	newEntry := ber.Encode(entry.ClassType, entry.TagType, entry.Tag, nil, entry.Description)
	newEntry.AppendChild(objectName)
	newEntry.AppendChild(newAttributes)
	for _, c := range entry.Children[2:] {
		newEntry.AppendChild(c)
	}

	newPacket := ber.Encode(packet.ClassType, packet.TagType, packet.Tag, nil, packet.Description)
	newPacket.AppendChild(packet.Children[0])
	newPacket.AppendChild(newEntry)
	for _, c := range packet.Children[2:] {
		newPacket.AppendChild(c)
	}

	if remove {
		log.Log.Print(spoofColor.Sprintf("[+] rootDSE supportedSASLMechanisms spoofed: %v -> removed", oldValues))
	} else {
		log.Log.Print(spoofColor.Sprintf("[+] rootDSE supportedSASLMechanisms spoofed: %v -> %v", oldValues, values))
	}

	return newPacket, true
}

// resolveSpoofValues implements the rewrite-behavior rules: "none" (a
// reserved sentinel, case-insensitive) or an empty list both mean "remove
// the attribute entirely" rather than leaving it present with zero values
// (not a real LDAP shape a server would send). "none" combined with other
// values wins over them, with a warning, rather than silently picking an
// interpretation.
func resolveSpoofValues(spoofMechs []string) (remove bool, values []string) {
	hasNone := false
	for _, m := range spoofMechs {
		if strings.EqualFold(m, spoofMechNone) {
			hasNone = true
			continue
		}
		values = append(values, resolveSASLMech(m))
	}

	if hasNone && len(values) > 0 {
		log.Log.Print(yellow.Sprintf("[-] --spoof-mechs: 'none' given with other values - removing the attribute entirely, ignoring the rest"))
		return true, nil
	}
	if hasNone || len(spoofMechs) == 0 {
		return true, nil
	}
	return false, values
}
