package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/Macmod/ldapx/ldaplib"
	attrlistmid "github.com/Macmod/ldapx/middlewares/attrlist"
	basednmid "github.com/Macmod/ldapx/middlewares/basedn"
	filtermid "github.com/Macmod/ldapx/middlewares/filter"
	"github.com/Macmod/ldapx/parser"
	"github.com/fatih/color"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

var green = color.New(color.FgGreen)
var red = color.New(color.FgRed)
var yellow = color.New(color.FgYellow)
var blue = color.New(color.FgBlue)

var insecureTlsConfig = &tls.Config{
	InsecureSkipVerify: true,
}

var (
	shutdownChan = make(chan struct{})
	debug        bool
	ldaps        bool
	noShell      bool

	fc *filtermid.FilterMiddlewareChain
	ac *attrlistmid.AttrListMiddlewareChain
	bc *basednmid.BaseDNMiddlewareChain

	proxyLDAPAddr  string
	targetLDAPAddr string
	filterChain    string
	attrChain      string
	baseChain      string
)

func init() {
	flag.StringVar(&proxyLDAPAddr, "listen", ":389", "Address & port to listen on for incoming LDAP connections")
	flag.StringVar(&targetLDAPAddr, "target", "", "Target LDAP server address")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.BoolVar(&ldaps, "ldaps", false, "Connect to target over LDAPS (ignoring cert. validation)")
	flag.BoolVar(&noShell, "no-shell", false, "Don't show the ldapx shell")
	flag.StringVar(&filterChain, "f", "", "Chain of search filter middlewares")
	flag.StringVar(&attrChain, "a", "", "Chain of attribute list middlewares")
	flag.StringVar(&baseChain, "b", "", "Chain of baseDN middlewares")
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

func encodeAttributeList(attrs []string) *ber.Packet {
	seq := ber.NewSequence("Attribute List")
	for _, attr := range attrs {
		seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "Attribute"))
	}
	return seq
}

func encodeBaseDN(baseDN string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "Base DN")
}

func connectToTarget(addr string) (net.Conn, error) {
	var targetConn net.Conn
	var err error
	var dialer net.Dialer

	if ldaps {
		targetConn, err = tls.DialWithDialer(&dialer, "tcp", addr, insecureTlsConfig)
	} else {
		targetConn, err = net.Dial("tcp", addr)
	}

	return targetConn, err
}

func handleLDAPConnection(conn net.Conn) {
	defer conn.Close()

	// Connect to target conn
	targetConn, err := connectToTarget(targetLDAPAddr)
	if err != nil {
		fmt.Println("")
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
				fmt.Println("")
				logger.Printf("Error reading LDAP request: %v\n", err)
				return
			}

			ldaplib.AddLDAPDescriptions(packet)
			reqMessageID := packet.Children[0].Value.(int64)
			reqMessageType := packet.Children[1].Description

			if reqMessageType == "Search Request" {
				fmt.Println("\n" + strings.Repeat("─", 55))
				logger.Printf("[+] Search Request Intercepted (%d)\n", reqMessageID)
				baseDN := packet.Children[1].Children[0].Value.(string)
				filterData := packet.Children[1].Children[6]
				attrs := extractAttributeSelection(packet.Children[1].Children[7])

				filter, err := parser.PacketToFilter(filterData)
				if err != nil {
					red.Printf("[ERROR] %s\n", err)
					continue
				}

				oldFilterStr, err := ldaplib.DecompileFilter(filterData)
				if err != nil {
					yellow.Printf("[WARNING] %s\n", err)
				}

				blue.Printf("Intercepted Request\n    BaseDN: %s\n    Attributes: %v\n    Filter: %s\n", baseDN, attrs, oldFilterStr)

				newFilter, newBaseDN, newAttrs := TransformSearchRequest(
					filter, baseDN, attrs, fc, ac, bc,
				)

				newFilterStr, err := ldaplib.DecompileFilter(parser.FilterToPacket(newFilter))
				if err != nil {
					yellow.Printf("[WARNING] %s\n", err)
				}

				green.Printf("Changed Request\n    BaseDN: %s\n    Attributes: %v\n    Filter: %s\n", newBaseDN, newAttrs, newFilterStr)

				packet.Children[1].Children[6] = parser.FilterToPacket(newFilter)
				packet.Children[1].Children[7] = encodeAttributeList(newAttrs)
				packet.Children[1].Children[0] = encodeBaseDN(newBaseDN)
			}

			newPacket := copyBerPacket(packet)

			if _, err := targetConn.Write(newPacket.Bytes()); err != nil {
				fmt.Printf("\n")
				logger.Printf("Error forwarding LDAP request: %v\n", err)
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
					fmt.Println("")
					logger.Printf("Error reading LDAP response: %v\n", err)
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

func updateFilterChain(chain string) {
	filterChain = chain
	fc = &filtermid.FilterMiddlewareChain{}
	for _, c := range filterChain {
		if middlewareName, exists := filterMidFlags[rune(c)]; exists {
			fc.Add(filtermid.FilterMiddlewareDefinition{
				Name: middlewareName,
				Func: filterMidMap[middlewareName],
			})
		}
	}
}

func updateBaseDNChain(chain string) {
	baseChain = chain
	bc = &basednmid.BaseDNMiddlewareChain{}
	for _, c := range baseChain {
		if middlewareName, exists := baseDNMidFlags[rune(c)]; exists {
			bc.Add(basednmid.BaseDNMiddlewareDefinition{
				Name: middlewareName,
				Func: baseDNMidMap[middlewareName],
			})
		}
	}
}

func updateAttrListChain(chain string) {
	attrChain = chain
	ac = &attrlistmid.AttrListMiddlewareChain{}
	for _, c := range attrChain {
		if middlewareName, exists := attrListMidFlags[rune(c)]; exists {
			ac.Add(attrlistmid.AttrListMiddlewareDefinition{
				Name: middlewareName,
				Func: attrListMidMap[middlewareName],
			})
		}
	}
}

func main() {
	flag.Parse()

	SetupFilterMidMap("")

	// Registering middlewares
	updateFilterChain(filterChain)
	updateBaseDNChain(baseChain)
	updateAttrListChain(attrChain)

	// Filter middlewares
	appliedFilterMiddlewares := []string{}
	for _, c := range filterChain {
		if middlewareName, exists := filterMidFlags[rune(c)]; exists {
			appliedFilterMiddlewares = append(appliedFilterMiddlewares, middlewareName)
		}
	}

	// AttrList middlewares
	appliedAttrListMiddlewares := []string{}
	for _, c := range attrChain {
		if middlewareName, exists := attrListMidFlags[rune(c)]; exists {
			appliedAttrListMiddlewares = append(appliedAttrListMiddlewares, middlewareName)
		}
	}

	// BaseDN middlewares
	appliedBaseDNMiddlewares := []string{}
	for _, c := range baseChain {
		if middlewareName, exists := baseDNMidFlags[rune(c)]; exists {
			appliedBaseDNMiddlewares = append(appliedBaseDNMiddlewares, middlewareName)
		}
	}
	listener, err := net.Listen("tcp", proxyLDAPAddr)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v\n", proxyLDAPAddr, err)
	}
	defer listener.Close()

	logger.Printf("[+] LDAP Proxy listening on '%s', forwarding to '%s' (T)\n", proxyLDAPAddr, targetLDAPAddr)
	logger.Printf("[+] FilterMiddlewares: [%s]", strings.Join(appliedFilterMiddlewares, ","))
	logger.Printf("[+] AttrListMiddlewares: [%s]", strings.Join(appliedAttrListMiddlewares, ","))
	logger.Printf("[+] BaseDNMiddlewares: [%s]", strings.Join(appliedBaseDNMiddlewares, ","))

	// Start interactive shell in background
	if !noShell {
		go RunShell()
	}

	// Main proxy loop
	for {
		select {
		case <-shutdownChan:
			listener.Close()
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v\n", err)
				continue
			}
			go handleLDAPConnection(conn)
		}
	}
}
