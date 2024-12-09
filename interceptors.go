package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"

	"github.com/Macmod/ldapx/log"
	"github.com/Macmod/ldapx/parser"
	ber "github.com/go-asn1-ber/asn1-ber"
)

// General logic behind the transformations that ldapx
// is capable of applying to each LDAP operation.
func TransformSearchRequest(filter parser.Filter, baseDN string, attrs []string) (parser.Filter, string, []string) {
	newFilter := fc.Execute(filter, true)
	newAttrs := ac.Execute(attrs, true)
	newBaseDN := bc.Execute(baseDN, true)

	return newFilter, newBaseDN, newAttrs
}

func TransformModifyRequest(targetDN string) string {
	return bc.Execute(targetDN, true)
}

func TransformAddRequest(targetDN string, entries parser.AttrEntries) (string, parser.AttrEntries) {
	newTargetDN := bc.Execute(targetDN, true)
	newEntries := ec.Execute(entries, true)

	return newTargetDN, newEntries
}

func TransformDeleteRequest(targetDN string) string {
	return bc.Execute(targetDN, true)
}

func TransformModifyDNRequest(entry string, newRDN string, delOld bool, newSuperior string) (string, string, bool, string) {
	newEntry := bc.Execute(entry, true)
	newNSuperior := bc.Execute(newSuperior, true)
	newNRDN := bc.Execute(newRDN, true)
	newDelOld := delOld // Not processed

	return newEntry, newNRDN, newDelOld, newNSuperior
}

// Basic packet processing logic behind the transformations that ldapx
// is capable of applying to each LDAP operation.

func ProcessSearchRequest(packet *ber.Packet, searchRequestMap map[string]*ber.Packet) *ber.Packet {
	if tracking {
		// Handle possible cookie desync by tracking the original corresponding request
		// If the current search request is paged and has a cookie, forward the original request
		// that generated the paging, including the current paging control
		if len(packet.Children) > 2 {
			controls := packet.Children[2].Children
			for _, control := range controls {
				if len(control.Children) > 1 && control.Children[0].Value == "1.2.840.113556.1.4.319" {
					// RFC2696 - LDAP Control Extension for Simple Paged Results Manipulation
					searchControlValue := ber.DecodePacket(control.Children[1].Data.Bytes())
					cookie := searchControlValue.Children[1].Data.Bytes()

					if len(cookie) > 0 {
						// Hash the search message (packet.Children[1]) to retrieve the correct search packet from the map
						searchMessage := packet.Children[1].Bytes()
						searchMessageHash := fmt.Sprintf("%x", sha256.Sum256(searchMessage))
						searchPacket, ok := searchRequestMap[searchMessageHash]

						if ok {
							forwardPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
							forwardPacket.AppendChild(packet.Children[0])
							forwardPacket.AppendChild(searchPacket.Children[1])
							forwardPacket.AppendChild(packet.Children[2])

							log.Log.Printf("[+] [Paging] Search Request Forwarded\n")

							return forwardPacket
						} else {
							log.Log.Printf("[-] Error finding previous packet (tracking algorithm)")
						}
					}
				}
			}
		}

		searchMessage := packet.Children[1].Bytes()
		searchMessageHash := fmt.Sprintf("%x", sha256.Sum256(searchMessage))
		searchRequestMap[searchMessageHash] = packet
	}

	baseDN := packet.Children[1].Children[0].Value.(string)
	filterData := packet.Children[1].Children[6]
	attrs := BerChildrenToList(packet.Children[1].Children[7])

	filter, err := parser.PacketToFilter(filterData)
	if err != nil {
		red.Printf("[ERROR] %s\n", err)
		return packet
	}

	oldFilterStr, err := parser.FilterToQuery(filter)
	if err != nil {
		yellow.Printf("[WARNING] %s\n", err)
	}

	blue.Printf(
		"Intercepted Search\n    BaseDN: '%s'\n    Filter: %s\n    Attributes: %s\n",
		baseDN, oldFilterStr, prettyList(attrs),
	)

	newFilter, newBaseDN, newAttrs := TransformSearchRequest(
		filter, baseDN, attrs,
	)

	newFilterStr, err := parser.FilterToQuery(newFilter)
	if err != nil {
		yellow.Printf("[WARNING] %s\n", err)
	}

	// Change the fields that need to be changed
	updatedFlag := false
	if newBaseDN != baseDN {
		UpdateBerChildLeaf(packet.Children[1], 0, EncodeBaseDN(newBaseDN))
		updatedFlag = true
	}

	// TODO: Compare the Filter structures instead to minimize the risk of bugs
	if oldFilterStr != newFilterStr {
		UpdateBerChildLeaf(packet.Children[1], 6, parser.FilterToPacket(newFilter))
		updatedFlag = true
	}

	if !reflect.DeepEqual(attrs, newAttrs) {
		UpdateBerChildLeaf(packet.Children[1], 7, EncodeAttributeList(newAttrs))
		updatedFlag = true
	}

	if updatedFlag {
		green.Printf("Changed Search\n    BaseDN: '%s'\n    Filter: %s\n    Attributes: %s\n", newBaseDN, newFilterStr, prettyList(newAttrs))

		// We need to copy it to refresh the internal Data of the parent packet
		return CopyBerPacket(packet)
	} else {
		blue.Printf("Nothing changed in the request\n")
	}

	return packet
}

// https://ldap.com/ldapv3-wire-protocol-reference-modify/
func ProcessModifyRequest(packet *ber.Packet) *ber.Packet {
	if len(packet.Children) > 1 {
		modPacket := packet.Children[1]
		targetDN := string(modPacket.Children[0].Data.Bytes())

		blue.Printf("Intercepted Modify\n    TargetDN: '%s'\n", targetDN)

		newTargetDN := TransformModifyRequest(targetDN)

		updatedFlag := false
		if newTargetDN != targetDN {
			newEncodedDN := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, newTargetDN, "")
			UpdateBerChildLeaf(packet.Children[1], 0, newEncodedDN)

			updatedFlag = true
		}

		// TODO: What to do with the attributes list? :)

		if updatedFlag {
			green.Printf("Changed Modify Request\n    TargetDN: '%s'\n", newTargetDN)

			// We need to copy it to refresh the internal Data of the parent packet
			return CopyBerPacket(packet)
		} else {
			blue.Printf("Nothing changed in the request\n")
		}
	} else {
		red.Printf("Malformed request (missing required fields)\n")
	}

	return packet
}

// https://ldap.com/ldapv3-wire-protocol-reference-add/
func ProcessAddRequest(packet *ber.Packet) *ber.Packet {
	if len(packet.Children) > 1 {
		addPacket := packet.Children[1]
		targetDN := string(addPacket.Children[0].Data.Bytes())
		entryAttrs := addPacket.Children[1]

		var targetAttrEntries parser.AttrEntries
		for _, attr := range entryAttrs.Children {
			attrName := attr.Children[0].Data.String()

			attrVals := attr.Children[1]
			for _, attrVal := range attrVals.Children {
				targetAttrEntries.AddValue(attrName, attrVal.Data.String())
			}
		}

		blue.Printf("Intercepted Add Request\n    TargetDN: '%s'\n    Attributes: \n", targetDN)
		for _, attrEntry := range targetAttrEntries {
			for _, attrVal := range attrEntry.Values {
				blue.Printf("      '%s': '%s'\n", attrEntry.Name, attrVal)
			}
		}

		updatedFlag := false

		newTargetDN, newTargetAttrEntries := TransformAddRequest(targetDN, targetAttrEntries)
		if newTargetDN != targetDN {
			newEncodedDN := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, newTargetDN, "")
			UpdateBerChildLeaf(packet.Children[1], 0, newEncodedDN)
			updatedFlag = true
		}

		if !reflect.DeepEqual(newTargetAttrEntries, targetAttrEntries) {
			// Construct a new packet to hold the attribute entries
			newEntryAttrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "AttributeList")
			for _, attr := range newTargetAttrEntries {
				attrSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
				attrSeq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr.Name, "Attribute Name"))

				valSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
				for _, val := range attr.Values {
					valSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, val, "AttributeValue"))
				}
				attrSeq.AppendChild(valSet)

				newEntryAttrs.AppendChild(attrSeq)
			}
			UpdateBerChildLeaf(packet.Children[1], 1, newEntryAttrs)

			updatedFlag = true
		}

		if updatedFlag {
			green.Printf("Changed Add Request\n    TargetDN: '%s'\n    Attributes: \n", newTargetDN)
			for _, attrEntry := range newTargetAttrEntries {
				for _, attrVal := range attrEntry.Values {
					green.Printf("      '%s': '%s'\n", attrEntry.Name, attrVal)
				}
			}

			// We need to copy it to refresh the internal Data of the parent packet
			return CopyBerPacket(packet)
		} else {
			blue.Printf("Nothing changed in the request\n")
		}
	} else {
		red.Printf("Malformed request (missing required fields)\n")
	}

	return packet
}

// https://ldap.com/ldapv3-wire-protocol-reference-delete/
func ProcessDeleteRequest(packet *ber.Packet) *ber.Packet {
	if len(packet.Children) > 1 {
		targetDN := string(packet.Children[1].Data.Bytes())

		blue.Printf("Intercepted Delete\n    TargetDN: '%s'\n", targetDN)

		newTargetDN := TransformDeleteRequest(targetDN)
		newEncodedDN := ber.NewString(ber.ClassApplication, ber.TypePrimitive, 0x0A, newTargetDN, "")
		if newTargetDN != targetDN {
			green.Printf("Changed Delete\n    TargetDN: '%s'\n", newTargetDN)
			UpdateBerChildLeaf(packet, 1, newEncodedDN)
		} else {
			blue.Printf("Nothing changed in the request\n")
		}
	} else {
		red.Printf("Malformed request (missing required fields)\n")
	}

	return packet
}

// https://ldap.com/ldapv3-wire-protocol-reference-modify-dn/
func ProcessModifyDNRequest(packet *ber.Packet) *ber.Packet {
	if len(packet.Children) > 1 {
		modDNPacket := packet.Children[1]

		if len(modDNPacket.Children) > 3 {
			entry := string(modDNPacket.Children[0].Data.Bytes())
			newRDN := string(modDNPacket.Children[1].Data.Bytes())
			delOld := len(modDNPacket.Children[2].Data.Bytes()) > 0 && modDNPacket.Children[3].Data.Bytes()[0] != byte(0)
			newSuperior := string(modDNPacket.Children[3].Data.Bytes())

			blue.Printf("Intercepted ModifyDN\n    Entry: '%s'\n    NewRDN: '%s'\n    DeleteOldRDN: '%t'\n    NewSuperior: '%s'\n", entry, newRDN, delOld, newSuperior)

			newEntry, newNRDN, newDelOld, newNSuperior := TransformModifyDNRequest(entry, newRDN, delOld, newSuperior)

			updatedFlag := false
			if newEntry != entry {
				newEncodedEntry := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, newEntry, "")
				UpdateBerChildLeaf(packet.Children[1], 0, newEncodedEntry)
				updatedFlag = true
			}

			if newNRDN != newRDN {
				newEncodedRDN := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, newNRDN, "")
				UpdateBerChildLeaf(packet.Children[1], 1, newEncodedRDN)
				updatedFlag = true
			}

			if newDelOld != delOld {
				newEncodedDelOld := ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, newDelOld, "")
				UpdateBerChildLeaf(packet.Children[1], 2, newEncodedDelOld)
				updatedFlag = true
			}

			if newNSuperior != newSuperior {
				newEncodedNSuperior := ber.NewString(ber.ClassContext, ber.TypePrimitive, 0x0, newNSuperior, "")
				UpdateBerChildLeaf(packet.Children[1], 3, newEncodedNSuperior)
				updatedFlag = true
			}

			if updatedFlag {
				green.Printf("Changed ModifyDN\n    Entry: '%s'\n    NewRDN: '%s'\n    DeleteOldRDN: '%t'\n    NewSuperior: '%s'\n", newEntry, newNRDN, newDelOld, newNSuperior)
				return CopyBerPacket(packet)
			} else {
				blue.Printf("Nothing changed in the request\n")
			}
		} else {
			red.Printf("Malformed request (missing required fields)\n")
		}
	} else {
		red.Printf("Malformed request (missing required fields)\n")
	}

	return packet
}
