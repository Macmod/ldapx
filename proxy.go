package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/Macmod/ldapx/log"
	"github.com/Macmod/ldapx/parser"
	ber "github.com/go-asn1-ber/asn1-ber"
)

func startProxyLoop(listener net.Listener) {
	for {
		select {
		case <-shutdownChan:
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				// log.Log.Printf("[-] Failed to accept connection: %v\n", err)
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
		log.Log.Printf("Failed to connect to target LDAP server: %v\n", err)
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
			log.Log.Printf("[-] Error forwarding LDAP request: %v\n", err)
			return
		}
		globalStats.Lock()
		globalStats.Forward.PacketsSent++
		globalStats.Forward.BytesSent += uint64(len(packet.Bytes()))
		globalStats.Unlock()

		if err := targetConnWriter.Flush(); err != nil {
			fmt.Printf("\n")
			log.Log.Printf("[-] Error flushing LDAP response: %v\n", err)
			return
		}
	}

	sendPacketReverse := func(packet *ber.Packet) {
		responseBytes := packet.Bytes()
		if _, err := connWriter.Write(responseBytes); err != nil {
			log.Log.Printf("[-] Error sending response back to client: %v\n", err)
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
				log.Log.Printf("[-] Error reading LDAP request: %v\n", err)
				return
			}

			fmt.Println("\n" + strings.Repeat("─", 55))

			if verbFwd > 1 {
				log.Log.Printf("[DEBUG] Packet Dump (Received From Client)")
				ber.PrintPacket(packet)
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

			if verbFwd > 0 {
				log.Log.Printf("[C->T] [%d - %s]\n", reqMessageID, applicationText)
			}

			switch application {
			case parser.ApplicationSearchRequest:
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
										log.Log.Printf("[+] [Paging] Sarch Request Intercepted (%d)\n", reqMessageID)

										forwardPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
										forwardPacket.AppendChild(packet.Children[0])
										forwardPacket.AppendChild(searchPacket.Children[1])
										forwardPacket.AppendChild(packet.Children[2])

										sendPacketForward(forwardPacket)
										log.Log.Printf("[+] [Paging] Search Request Forwarded (%d)\n", reqMessageID)

										continue ForwardLoop
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

				log.Log.Printf("[+] Search Request Intercepted (%d)\n", reqMessageID)
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
				} else {
					blue.Printf("Nothing changed in the request\n")
				}

				// We need to copy it to refresh the internal Data of the parent packet
				packet = CopyBerPacket(packet)

				sendPacketForward(packet)
			case parser.ApplicationAddRequest:
				log.Log.Printf("[+] Add Request Intercepted (%d)\n", reqMessageID)

				if len(packet.Children) > 1 {
					addPacket := packet.Children[1]
					targetDN := string(addPacket.Children[0].Data.Bytes())
					blue.Printf("Intercepted Add\n    TargetDN: '%s'\n", targetDN)

					newTargetDN := TransformAddRequest(targetDN)
					if newTargetDN != targetDN {
						green.Printf("Changed Add Request\n    TargetDN: '%s'", newTargetDN)

						newEncodedDN := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, newTargetDN, "")
						UpdateBerChildLeaf(packet.Children[1], 0, newEncodedDN)

						// TODO: What to do with the attributes list? :)

						// We need to copy it to refresh the internal Data of the parent packet
						packet = CopyBerPacket(packet)
					} else {
						blue.Printf("Nothing changed in the request\n")
					}
				} else {
					red.Printf("Malformed request (missing required fields)\n")
				}

				sendPacketForward(packet)
			case parser.ApplicationModifyRequest:
				log.Log.Printf("[+] Modify Request Intercepted (%d)\n", reqMessageID)
				if len(packet.Children) > 1 {
					modPacket := packet.Children[1]
					targetDN := string(modPacket.Children[0].Data.Bytes())
					blue.Printf("Intercepted Modify\n    TargetDN: '%s'\n", targetDN)
					newTargetDN := TransformModifyRequest(targetDN)
					if newTargetDN != targetDN {
						green.Printf("Changed Modify Request\n    TargetDN: '%s'", newTargetDN)

						newEncodedDN := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, newTargetDN, "")
						UpdateBerChildLeaf(packet.Children[1], 0, newEncodedDN)

						// TODO: What to do with the attributes list? :)

						// We need to copy it to refresh the internal Data of the parent packet
						packet = CopyBerPacket(packet)
					} else {
						blue.Printf("Nothing changed in the request\n")
					}
				} else {
					red.Printf("Malformed request (missing required fields)\n")
				}

				sendPacketForward(packet)
			case parser.ApplicationDelRequest:
				log.Log.Printf("[+] Delete Request Intercepted (%d)\n", reqMessageID)

				if len(packet.Children) > 1 {
					targetDN := string(packet.Children[1].Data.Bytes())
					blue.Printf("Intercepted Delete\n    TargetDN: '%s'\n", targetDN)
					newTargetDN := TransformDeleteRequest(targetDN)
					newEncodedDN := ber.NewString(ber.ClassApplication, ber.TypePrimitive, 0x0A, newTargetDN, "")
					if newTargetDN != targetDN {
						green.Printf("Changed Delete\n    TargetDN: '%s'", newTargetDN)
						UpdateBerChildLeaf(packet, 1, newEncodedDN)
					} else {
						blue.Printf("Nothing changed in the request\n")
					}
				} else {
					red.Printf("Malformed request (missing required fields)\n")
				}

				sendPacketForward(packet)
			default:
				sendPacketForward(packet)
			}

			if verbFwd > 1 {
				log.Log.Printf("[DEBUG] Packet Dump (Sent To Target)")
				ber.PrintPacket(packet)
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
					log.Log.Printf("[-] Error reading LDAP response: %v\n", err)
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

				if verbRev > 0 {
					log.Log.Printf("[C<-T] [%d - %s] (%d bytes)\n", respMessageID, applicationText, len(responsePacket.Bytes()))

					if verbRev > 1 {
						log.Log.Printf("[DEBUG] Packet Dump (Received From Target)")
						ber.PrintPacket(responsePacket)
					}
				}
			}
		}
	}()

	<-done
}
