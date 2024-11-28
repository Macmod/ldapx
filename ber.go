package main

import (
	"bytes"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func CopyBerPacket(packet *ber.Packet) *ber.Packet {
	newPacket := ber.Encode(packet.ClassType, packet.TagType, packet.Tag, packet.Value, packet.Description)
	for _, child := range packet.Children {
		if len(child.Children) == 0 {
			newPacket.AppendChild(child)
		} else {
			newPacket.AppendChild(CopyBerPacket(child))
		}
	}

	return newPacket
}

// TODO: Generalize this method to "non-leaves"
func UpdateBerChildLeaf(packet *ber.Packet, idx int, newChild *ber.Packet) error {
	if idx >= len(packet.Children) {
		return fmt.Errorf("Error updating BER packet: index out of bounds")
	}

	(*packet).Children[idx] = newChild

	updatedData := new(bytes.Buffer)
	for x := 0; x < idx; x++ {
		updatedData.Write(packet.Children[x].Bytes())
	}
	updatedData.Write(newChild.Bytes())
	for x := idx + 1; x < len(packet.Children); x++ {
		updatedData.Write(packet.Children[x].Bytes())
	}

	(*packet).Data = updatedData

	return nil
}

func BerChildrenToList(packet *ber.Packet) []string {
	attrs := make([]string, 0)

	for _, child := range packet.Children {
		attrs = append(attrs, child.Data.String())
	}

	return attrs
}

func EncodeAttributeList(attrs []string) *ber.Packet {
	seq := ber.NewSequence("Attribute List")
	for _, attr := range attrs {
		seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "Attribute"))
	}
	return seq
}

func EncodeBaseDN(baseDN string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "Base DN")
}

/*
func reencodeBerDataRecursive(packet *ber.Packet) {
	// Recursively process the children first
	for _, child := range packet.Children {
		reencodeBerData(child)
	}

	// Compute the new Data field based on the packet's type and value
	if packet.Value != nil {
		v := reflect.ValueOf(packet.Value)

		if packet.ClassType == ber.ClassUniversal {
			switch packet.Tag {
			case ber.TagOctetString:
				sv, ok := v.Interface().(string)
				if ok {
					packet.Data.Reset()
					packet.Data.Write([]byte(sv))
				}
			case ber.TagEnumerated:
				bv, ok := v.Interface().([]byte)
				if ok {
					packet.Data.Reset()
					packet.Data.Write(bv)
				}
			case ber.TagEmbeddedPDV:
				bv, ok := v.Interface().([]byte)
				if ok {
					packet.Data.Reset()
					packet.Data.Write(bv)
				}
			}
		} else if packet.ClassType == ber.ClassContext {
			switch packet.Tag {
			case ber.TagEnumerated:
				bv, ok := v.Interface().([]byte)
				if ok {
					packet.Data.Reset()
					packet.Data.Write(bv)
				}
			case ber.TagEmbeddedPDV:
				bv, ok := v.Interface().([]byte)
				if ok {
					packet.Data.Reset()
					packet.Data.Write(bv)
				}
			}
		}
	}

	// Handle constructed types
	if packet.ClassType == ber.ClassUniversal {
		switch packet.Tag {
		case ber.TagSequence:
			packet.Data.Reset()
			for _, child := range packet.Children {
				packet.Data.Write(child.Bytes())
			}
		case ber.TagSet:
			packet.Data.Reset()
			for _, child := range packet.Children {
				packet.Data.Write(child.Bytes())
			}
		}
	}
}
*/
