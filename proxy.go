package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/Macmod/ldapx/log"
	"github.com/Macmod/ldapx/parser"
	ber "github.com/go-asn1-ber/asn1-ber"
	"h12.io/socks"
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

func connect(addr string) (net.Conn, error) {
	var conn net.Conn
	var err error
	var dialer net.Dialer

	_, socksServer, useLdaps := runtimeConfig.GetConnectionConfig()

	if socksServer != "" {
		dialSocksProxy := socks.Dial(socksServer)

		// First establish connection through SOCKS proxy
		conn, err = dialSocksProxy("tcp", addr)
		if err != nil {
			return nil, err
		}

		if useLdaps {
			// Wrap the SOCKS connection with TLS
			tlsConn := tls.Client(conn, insecureTlsConfig)
			if err = tlsConn.Handshake(); err != nil {
				conn.Close()
				return nil, err
			}
			conn = tlsConn
		}
	} else {
		// Original non-proxy connection logic
		if useLdaps {
			conn, err = tls.DialWithDialer(&dialer, "tcp", addr, insecureTlsConfig)
		} else {
			conn, err = net.Dial("tcp", addr)
		}
	}

	return conn, err
}

func handleLDAPConnection(conn net.Conn) {
	defer conn.Close()

	// Get target address from config
	targetAddr, _, _ := runtimeConfig.GetConnectionConfig()

	// Connect to target conn - local variable for this connection only
	localTargetConn, err := connect(targetAddr)
	if err != nil {
		fmt.Println("")
		log.Log.Printf("Failed to connect to target LDAP server: %v\n", err)
		return
	}
	defer localTargetConn.Close()

	targetConnReader := bufio.NewReader(localTargetConn)
	targetConnWriter := bufio.NewWriter(localTargetConn)

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

		for {
			packet, err := ber.ReadPacket(connReader)
			if err != nil {
				fmt.Println("")
				log.Log.Printf("[-] Error reading LDAP request: %v\n", err)
				return
			}

			fmt.Println("\n" + strings.Repeat("─", 55))

			verbFwd, _ := runtimeConfig.GetVerbosity()

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

			intercepts := runtimeConfig.GetInterceptFlags()

			switch application {
			case parser.ApplicationSearchRequest:
				if intercepts.Search {
					log.Log.Printf("[+] Search Request Intercepted (%d)\n", reqMessageID)
					packet = ProcessSearchRequest(packet, searchRequestMap)
				}
			case parser.ApplicationModifyRequest:
				if intercepts.Modify {
					log.Log.Printf("[+] Modify Request Intercepted (%d)\n", reqMessageID)
					packet = ProcessModifyRequest(packet)
				}
			case parser.ApplicationAddRequest:
				if intercepts.Add {
					log.Log.Printf("[+] Add Request Intercepted (%d)\n", reqMessageID)
					packet = ProcessAddRequest(packet)
				}
			case parser.ApplicationDelRequest:
				if intercepts.Delete {
					log.Log.Printf("[+] Delete Request Intercepted (%d)\n", reqMessageID)
					packet = ProcessDeleteRequest(packet)
				}
			case parser.ApplicationModifyDNRequest:
				if intercepts.ModifyDN {
					log.Log.Printf("[+] ModifyDN Request Intercepted (%d)\n", reqMessageID)
					packet = ProcessModifyDNRequest(packet)
				}
			}

			sendPacketForward(packet)

			verbFwd, _ = runtimeConfig.GetVerbosity()

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

				_, verbRev := runtimeConfig.GetVerbosity()

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
