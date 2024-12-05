package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"reflect"
	"strings"

	"github.com/Macmod/ldapx/parser"
	ber "github.com/go-asn1-ber/asn1-ber"
)

func startProxyLoop() {
	listener, err := net.Listen("tcp", proxyLDAPAddr)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v\n", proxyLDAPAddr, err)
	}
	defer listener.Close()

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

func reconnectTarget() error {
	// Close the existing target connection
	if targetConn != nil {
		targetConn.Close()
	}

	// Connect to the new target
	var err error
	targetConn, err = connect(targetLDAPAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to target LDAP server: %v", err)
	}

	return nil
}

func connect(addr string) (net.Conn, error) {
	var conn net.Conn
	var err error
	var dialer net.Dialer

	if ldaps {
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, insecureTlsConfig)
	} else {
		conn, err = net.Dial("tcp", addr)
	}

	return conn, err
}

func handleLDAPConnection(conn net.Conn) {
	defer conn.Close()

	// Connect to target conn
	var err error
	targetConn, err = connect(targetLDAPAddr)

	if err != nil {
		fmt.Println("")
		log.Printf("Failed to connect to target LDAP server: %v\n", err)
		return
	}
	defer targetConn.Close()

	targetConnReader := bufio.NewReader(targetConn)
	targetConnWriter := bufio.NewWriter(targetConn)

	done := make(chan struct{}) // Channel to signal when either goroutine is done

	connReader := bufio.NewReader(conn)
	connWriter := bufio.NewWriter(conn)

	sendPacketForward := func(packet *ber.Packet) {
		if _, err := targetConnWriter.Write(packet.Bytes()); err != nil {
			fmt.Printf("\n")
			logger.Printf("[-] Error forwarding LDAP request: %v\n", err)
			return
		}
		globalStats.Lock()
		globalStats.Forward.PacketsSent++
		globalStats.Forward.BytesSent += uint64(len(packet.Bytes()))
		globalStats.Unlock()

		if err := targetConnWriter.Flush(); err != nil {
			fmt.Printf("\n")
			logger.Printf("[-] Error flushing LDAP response: %v\n", err)
			return
		}
	}

	sendPacketReverse := func(packet *ber.Packet) {
		responseBytes := packet.Bytes()
		if _, err := connWriter.Write(responseBytes); err != nil {
			logger.Printf("[-] Error sending response back to client: %v\n", err)
			return
		}
		globalStats.Lock()
		globalStats.Reverse.PacketsSent++
		globalStats.Reverse.BytesSent += uint64(len(responseBytes))
		globalStats.Unlock()

		connWriter.Flush()
	}

	go func() {
		// Close `done` channel when done to signal response goroutine to exit
		defer close(done)

		var searchRequestMap = make(map[string]*ber.Packet)

	ForwardLoop:
		for {
			packet, err := ber.ReadPacket(connReader)
			if err != nil {
				fmt.Println("")
				logger.Printf("[-] Error reading LDAP request: %v\n", err)
				return
			}

			globalStats.Lock()
			globalStats.Forward.PacketsReceived++
			globalStats.Forward.BytesReceived += uint64(len(packet.Bytes()))
			application := uint8(packet.Children[1].Tag)
			globalStats.Forward.CountsByType[int(application)]++
			globalStats.Unlock()

			reqMessageID := packet.Children[0].Value.(int64)
			applicationText, ok := parser.ApplicationMap[application]
			if !ok {
				applicationText = fmt.Sprintf("Unknown Application '%d'", application)
			}

			if application == parser.ApplicationSearchRequest {
				fmt.Println("\n" + strings.Repeat("─", 55))

				if tracking {
					// Handle possible cookie corruption by tracking the original corresponding request
					if len(packet.Children) > 2 {
						controls := packet.Children[2].Children
						for _, control := range controls {
							if len(control.Children) > 1 && control.Children[0].Value == "1.2.840.113556.1.4.319" {
								cookie := control.Children[1].Data.Bytes()

								if len(cookie) > 8 {
									// Hash the search message (packet.Children[1]) to retrieve the correct search packet from the map
									searchMessage := packet.Children[1].Bytes()
									searchMessageHash := fmt.Sprintf("%x", sha256.Sum256(searchMessage))
									searchPacket, ok := searchRequestMap[searchMessageHash]

									if ok {
										logger.Printf("[+] [Paging] Sarch Request Intercepted (%d)\n", reqMessageID)

										forwardPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
										forwardPacket.AppendChild(packet.Children[0])
										forwardPacket.AppendChild(searchPacket.Children[1])
										forwardPacket.AppendChild(packet.Children[2])

										sendPacketForward(forwardPacket)
										logger.Printf("[+] [Paging] Search Request Forwarded (%d)\n", reqMessageID)

										continue ForwardLoop
									} else {
										logger.Printf("[-] Error finding previous packet (tracking algorithm)")
									}
								}
							}
						}
					}

					searchMessage := packet.Children[1].Bytes()
					searchMessageHash := fmt.Sprintf("%x", sha256.Sum256(searchMessage))
					searchRequestMap[searchMessageHash] = packet
				}

				logger.Printf("[+] Search Request Intercepted (%d)\n", reqMessageID)
				baseDN := packet.Children[1].Children[0].Value.(string)
				filterData := packet.Children[1].Children[6]
				attrs := BerChildrenToList(packet.Children[1].Children[7])

				filter, err := parser.PacketToFilter(filterData)
				if err != nil {
					red.Printf("[ERROR] %s\n", err)
					continue
				}

				oldFilterStr, err := parser.FilterToQuery(filter)
				if err != nil {
					yellow.Printf("[WARNING] %s\n", err)
				}

				blue.Printf("Intercepted Request\n    BaseDN: '%s'\n    Filter: %s\n    Attributes: %s\n", baseDN, oldFilterStr, prettyList(attrs))

				newFilter, newBaseDN, newAttrs := TransformSearchRequest(
					filter, baseDN, attrs, fc, ac, bc,
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
					green.Printf("Changed Request\n    BaseDN: '%s'\n    Filter: %s\n    Attributes: %s\n", newBaseDN, newFilterStr, prettyList(newAttrs))
				} else {
					blue.Printf("Nothing changed in the request\n")
				}

				// We need to copy it to refresh the internal Data of the parent packet
				packet = CopyBerPacket(packet)
			}

			ber.PrintPacket(packet)

			sendPacketForward(packet)

			if debug {
				logger.Printf("[C->T] [%d - %s]\n", reqMessageID, applicationText)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-done:
				return // Exit if the request goroutine is done
			default:
				responsePacket, err := ber.ReadPacket(targetConnReader)
				if err != nil {
					fmt.Println("")
					logger.Printf("[-] Error reading LDAP response: %v\n", err)
					return
				}

				globalStats.Lock()
				globalStats.Reverse.PacketsReceived++
				globalStats.Reverse.BytesReceived += uint64(len(responsePacket.Bytes()))
				application := uint8(responsePacket.Children[1].Tag)
				globalStats.Reverse.CountsByType[int(application)]++
				globalStats.Unlock()

				respMessageID := responsePacket.Children[0].Value.(int64)
				applicationText, ok := parser.ApplicationMap[application]
				if !ok {
					applicationText = fmt.Sprintf("Unknown Application '%d'", application)
				}

				sendPacketReverse(responsePacket)

				if debug {
					logger.Printf("[C<-T] [%d - %s] (%d bytes)\n", respMessageID, applicationText, len(responsePacket.Bytes()))
				}
			}
		}
	}()

	<-done
}
