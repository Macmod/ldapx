package main

import (
	"bufio"
	"flag"
	"log"
	"net"
	"os"

	"github.com/Macmod/ldapx/ldaplib"
	"github.com/Macmod/ldapx/middlewares"
	"github.com/Macmod/ldapx/parser"
	"github.com/fatih/color"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

var green = color.New(color.FgGreen)
var red = color.New(color.FgRed)
var yellow = color.New(color.FgYellow)
var blue = color.New(color.FgBlue)

var (
	debug          bool
	fc             *middlewares.FilterMiddlewareChain
	proxyLDAPAddr  string
	targetLDAPAddr string
	filterChain    string
	attrChain      string
	baseChain      string
)

func init() {
	flag.StringVar(&proxyLDAPAddr, "port", ":389", "Address & port to listen on for incoming LDAP connections")
	flag.StringVar(&targetLDAPAddr, "target", "", "Target LDAP server address")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.StringVar(&filterChain, "fc", "", "Chain of search filter middlewares")
	flag.StringVar(&attrChain, "ac", "", "Chain of attribute list middlewares")
	flag.StringVar(&baseChain, "bc", "", "Chain of baseDN middlewares")
}

func copyBerPacket(packet *ber.Packet) *ber.Packet {
	newPacket := ber.Encode(packet.ClassType, packet.TagType, packet.Tag, packet.Value, packet.Description)
	for _, child := range packet.Children {
		if len(child.Children) == 0 {
			newPacket.AppendChild(child)
		} else {
			newPacket.AppendChild(copyBerPacket(child))
		}
	}

	return newPacket
}

func extractAttributeSelection(subpacket *ber.Packet) []string {
	attrs := make([]string, 0)

	for _, child := range subpacket.Children {
		attrs = append(attrs, child.Data.String())
	}

	return attrs
}

func handleLDAPConnection(conn net.Conn) {
	defer conn.Close()

	// Connect to target conn
	targetConn, err := net.Dial("tcp", targetLDAPAddr)
	if err != nil {
		log.Printf("Failed to connect to target LDAP server: %v\n", err)
		return
	}
	defer targetConn.Close()

	done := make(chan struct{}) // Channel to signal when either goroutine is done

	go func() {
		// Close `done` channel when done to signal response goroutine to exit
		defer close(done)

		bufConn := bufio.NewReader(conn)
		for {
			packet, err := ber.ReadPacket(bufConn)
			if err != nil {
				log.Printf("Error reading LDAP request: %v\n", err)
				return
			}

			ldaplib.AddLDAPDescriptions(packet)
			reqMessageID := packet.Children[0].Value.(int64)
			reqMessageType := packet.Children[1].Description

			if reqMessageType == "Search Request" {
				base := packet.Children[1].Children[0].Value
				/*
					scope := packet.Children[1].Children[1]
					derefAliases := packet.Children[1].Children[2]
					sizeLimit := packet.Children[1].Children[3]
					timeLimit := packet.Children[1].Children[4]
					typesOnly := packet.Children[1].Children[5]
				*/
				filterData := packet.Children[1].Children[6]
				attrs := extractAttributeSelection(packet.Children[1].Children[7])

				filter, err := parser.PacketToFilter(filterData)
				if err != nil {
					red.Printf("[ERROR] %s\n", err)
					continue
				}

				oldFilterStr, err := ldaplib.DecompileFilter(filterData)
				if err != nil {
					red.Printf("[ERROR] %s\n", err)
				}

				blue.Printf("[MessageID=%d] Search Request Intercepted:\n Base='%s'\n Attrs=%v\n Filter=%s\n", reqMessageID, base, attrs, oldFilterStr)

				newFilter := fc.Execute(filter, true)
				newFilterPacket := parser.FilterToPacket(newFilter)

				newFilterStr, err := ldaplib.DecompileFilter(newFilterPacket)
				if err != nil {
					red.Printf("[ERROR] %s\n", err)
				}

				green.Printf("[MessageID=%d] Search Request Changed:\n Base='%s'\n Attrs=%v\n Filter=%s\n", reqMessageID, base, attrs, newFilterStr)

				// Update the filter in the packet
				packet.Children[1].Children[6] = newFilterPacket
			}

			newPacket := copyBerPacket(packet)

			if _, err := targetConn.Write(newPacket.Bytes()); err != nil {
				log.Printf("Error forwarding LDAP request: %v\n", err)
				return
			}

			if debug {
				logger.Printf("[C->T] [%d - %s]\n", reqMessageID, reqMessageType)
				//ber.WritePacket(logger.Writer(), packet)
			}
		}
	}()

	go func() {
		bufTargetConn := bufio.NewReader(targetConn)

		for {
			select {
			case <-done:
				return // Exit if the request goroutine is done
			default:
				responsePacket, err := ber.ReadPacket(bufTargetConn)
				if err != nil {
					log.Printf("Error reading LDAP response: %v\n", err)
					return
				}

				ldaplib.AddLDAPDescriptions(responsePacket)
				respMessageID := responsePacket.Children[0].Value.(int64)
				respMessageType := responsePacket.Children[1].Description

				responseBytes := responsePacket.Bytes()
				if _, err := conn.Write(responseBytes); err != nil {
					log.Printf("Error sending response back to client: %v\n", err)
					return
				}

				if debug {
					logger.Printf("[C<-T] [%d - %s] (%d bytes)\n", respMessageID, respMessageType, len(responseBytes))
				}
			}
		}
	}()

	<-done
}

func main() {
	flag.Parse()

	fc = &middlewares.FilterMiddlewareChain{}
	// TODO: attrChain
	// TODO: baseChain

	/*
		filterMidFlags := mao[rune][string]{
			'S': "Spacing",
			'T': "Timestamp",
			'B': "AddBool",
			'D': "DblNegBool",
			'M': "DeMorganBool",
			//'N': "NamesToANR",
			//'A': "EqApproxMatch",
			//'W': "Wildcard",
			//'G': "Garbage",
			'O': "OIDAttribute",
			'C': "Case",
			'X': "HexValue",
			'R': "ReorderBool",
			'b': "ExactBitwiseBreakout",
			'I': "EqInclusion",
			'E': "EqExclusion",
			'd': "BitwiseDecomposition",
		}*/

	appliedMiddlewares := []string{
		//"Spacing",
		//"Timestamp",
		//"ExactBitwiseBreakout",
		//"BitwiseDecomposition",
		//"Case",
		//"AddBool",
		//"DblNegBool",
		//"DeMorganBool",
		//"ReorderBool",
		//"HexValue",
		//"OIDAttribute",
		//"EqInclusion",
		"Garbage",
	}

	for _, val := range appliedMiddlewares {
		fc.Add(middlewares.FilterMiddlewareDefinition{
			Name: val,
			Func: filterMidMap[val],
		})
	}

	listener, err := net.Listen("tcp", proxyLDAPAddr)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v\n", proxyLDAPAddr, err)
	}
	defer listener.Close()

	logger.Printf("[+] LDAP Proxy listening on '%s', forwarding to '%s' (T)\n", proxyLDAPAddr, targetLDAPAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v\n", err)
			continue
		}

		handleLDAPConnection(conn)
	}
}
