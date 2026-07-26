package app

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Macmod/ldapx/decrypt"
	"github.com/Macmod/ldapx/log"
	"github.com/Macmod/ldapx/parser"
	"github.com/Macmod/ldapx/rootdse"
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

func connect(addr string, tlsCfg *tls.Config) (net.Conn, error) {
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
			tlsConn := tls.Client(conn, tlsCfg)
			if err = tlsConn.Handshake(); err != nil {
				conn.Close()
				return nil, err
			}
			conn = tlsConn
		}
	} else {
		// Original non-proxy connection logic
		if useLdaps {
			conn, err = tls.DialWithDialer(&dialer, "tcp", addr, tlsCfg)
		} else {
			conn, err = net.Dial("tcp", addr)
		}
	}

	return conn, err
}

// loadPrivateKeyFromFile reads a PEM-encoded private key from the given path
// and returns it as a crypto.PrivateKey. Supports PKCS#8 (the default for
// openssl, modern ECDSA/Ed25519), EC SEC 1 (openssl ec), and RSA PKCS#1
// (openssl rsa) formats.
func loadPrivateKeyFromFile(path string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found in key file")
	}
	// Try PKCS#8 first (most common — openssl default, ECDSA, Ed25519)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	// Try EC SEC 1
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	// Try RSA PKCS#1
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key format (expected PKCS#8, EC SEC 1, or RSA PKCS#1 PEM)")
}

// dirTag returns the "[C->T] "/"[C<-T] " prefix for a message concerning
// the forward (fromClient=true, client-to-target) or reverse
// (fromClient=false, target-to-client) leg of the proxy.
func dirTag(fromClient bool) string {
	if fromClient {
		return "[C->T] "
	}
	return "[C<-T] "
}

// dirPrintf logs one line about wrapping/unwrapping or other per-message
// activity, colored and prefixed by direction (cyan "[C->T]" for the
// forward leg, magenta "[C<-T]" for the reverse leg) - the same convention
// used for the [C->T]/[C<-T] summary and [DEBUG] Packet Dump lines. Gated
// on that direction's own verbosity level being at least 1 (0 stays fully
// silent), matching how the summary lines are gated - for informational/
// debug-tier messages only; see dirErrorf for failures.
func dirPrintf(fromClient bool, format string, args ...interface{}) {
	fwd, rev := runtimeConfig.GetVerbosity()
	c, verb := magenta, rev
	if fromClient {
		c, verb = cyan, fwd
	}
	if verb == 0 {
		return
	}
	msg := c.Sprintf(dirTag(fromClient)+format, args...)
	log.Log.Print(strings.TrimRight(msg, "\n\r"))
}

// dirErrorf logs one error line, prefixed by direction like dirPrintf but
// colored red (matching this codebase's existing error convention, e.g.
// interceptors.go's "Malformed request" messages) rather than the
// direction's cyan/magenta - errors shouldn't be visually softened into an
// informational color. Always printed regardless of verbosity: a real
// failure (a dropped connection, an unreadable message) shouldn't be
// silently hidden by a verbosity setting the way routine info/debug output
// can be - notably, --vr/-R defaults to 0, so gating reverse-leg errors the
// same way as dirPrintf would silence them by default.
func dirErrorf(fromClient bool, format string, args ...interface{}) {
	msg := red.Sprintf(dirTag(fromClient)+format, args...)
	log.Log.Print(strings.TrimRight(msg, "\n\r"))
}

// readLDAPMessage reads the next unit of traffic from reader, transparently
// unwrapping it first if (and only if) it turns out to actually be wrapped -
// the leading byte is peeked (never consumed blindly) to decide which
// framing applies, so a stream that turns out to be plain LDAP BER is read
// with zero risk of misconsuming bytes on a wrong guess. bs may be nil (no
// decryption ever possible on this connection) or not yet negotiated, in
// which case only the plaintext path is ever taken.
//
// Returns a slice, not a single packet: a SASL-sealed buffer can contain
// more than one LDAPMessage (Windows AD DCs routinely pack a
// SearchResultEntry with its terminating SearchResultDone into one sealed
// buffer), so all messages in the buffer are parsed and returned together.
func readLDAPMessage(reader *bufio.Reader, bs *decrypt.BindSession, fromClient bool) ([]*ber.Packet, error) {
	first, err := reader.Peek(1)
	if err != nil {
		return nil, err
	}

	// A plain top-level LDAPMessage is always a universal, constructed
	// SEQUENCE - tag byte 0x30. Wrapped traffic (a 4-byte big-endian length
	// prefix per RFC 4752 §3.5, whether followed by an NTLM signature/seal
	// blob or a GSS wrap token) essentially never coincidentally starts
	// with that exact byte
	if first[0] == 0x30 {
		packet, err := ber.ReadPacket(reader)
		if err != nil {
			return nil, err
		}
		logFramingOnce(bs, false, fromClient)
		return []*ber.Packet{packet}, nil
	}

	if bs == nil {
		return nil, fmt.Errorf("unexpected non-BER leading byte %#x and no active decryption session to unwrap with", first[0])
	}

	negotiated, layer, mech := bs.State()

	if !negotiated {
		if mech != decrypt.MechNone {
			return nil, fmt.Errorf("received wrapped traffic under %s but no decryption key was ever established (missing or incorrect --decrypt-* flags)", mech)
		}
		return nil, fmt.Errorf("unexpected non-BER leading byte %#x on a connection with no negotiated decryption session", first[0])
	}

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(reader, lenBuf); err != nil {
		return nil, fmt.Errorf("read wrapped message length: %w", err)
	}
	wrappedLen := binary.BigEndian.Uint32(lenBuf)
	if wrappedLen > 64<<20 {
		// Sanity cap: a garbage length here (corrupt stream, mid-connection
		// desync) would otherwise make io.ReadFull below block indefinitely
		// waiting for bytes that will never arrive - bail out fast instead.
		// 64MB gives generous headroom over real AD traffic (e.g. a full
		// schema search response, observed well over 1MB in practice) while
		// AD's own default MaxReceiveBuffer policy tops out around 10MB.
		return nil, fmt.Errorf("wrapped message length %d looks implausible (>64MB)", wrappedLen)
	}
	wrapped := make([]byte, wrappedLen)
	if _, err := io.ReadFull(reader, wrapped); err != nil {
		return nil, fmt.Errorf("read wrapped message body: %w", err)
	}

	var plain []byte
	if fromClient {
		plain, err = bs.UnwrapFromClient(wrapped)
	} else {
		plain, err = bs.UnwrapFromTarget(wrapped)
	}
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}

	logFramingOnce(bs, true, fromClient)
	if layer == decrypt.LayerNone {
		dirPrintf(fromClient, "[-] Warning: negotiation indicated %s (%s) but a post-bind PDU required unwrapping - decryption logic may have misread the handshake", mech, layer)
	}

	r := bytes.NewReader(plain)
	var packets []*ber.Packet
	for r.Len() > 0 {
		p, err := ber.ReadPacket(r)
		if err != nil {
			return nil, fmt.Errorf("parse LDAPMessage #%d from unwrapped buffer (%d bytes total, %d unparsed): %w", len(packets)+1, len(plain), r.Len(), err)
		}
		packets = append(packets, p)
	}
	if len(packets) == 0 {
		return nil, fmt.Errorf("unwrapped buffer (%d bytes) contained no LDAP messages", len(plain))
	}
	if len(packets) > 1 {
		dirPrintf(fromClient, "[+] Unwrapped buffer contained %d LDAP messages - will be re-sealed and forwarded as one bundle", len(packets))
	}
	return packets, nil
}

// logFramingOnce announces, once per connection, whether post-bind traffic
// turned out to be wrapped or plaintext - skipped once the layer is already
// known (NTLM/Sicily reads it straight from the AUTHENTICATE_MESSAGE), since
// only GSSAPI/SPNEGO's LayerUnknown case makes this line new information. A
// mismatch between what was negotiated and what's actually observed is
// reported separately, via the unconditional "[-] Warning: negotiation
// indicated..." line in readLDAPMessage.
//
// bs.ShouldLogFraming's one-shot flag is shared across the forward and
// reverse goroutines, which both call this concurrently - checking this
// direction's own verbosity before consuming that flag prevents a
// zero-verbosity direction from winning the race and silently burning the
// connection's only shot at the line.
func logFramingOnce(bs *decrypt.BindSession, wasWrapped bool, fromClient bool) {
	if bs == nil {
		return
	}
	fwd, rev := runtimeConfig.GetVerbosity()
	verb := rev
	if fromClient {
		verb = fwd
	}
	if verb == 0 || !bs.ShouldLogFraming() {
		return
	}
	if _, layer, _ := bs.State(); layer != decrypt.LayerUnknown {
		return
	}
	if wasWrapped {
		dirPrintf(fromClient, "[+] Post-bind traffic: unwrapping active")
	} else {
		dirPrintf(fromClient, "[+] Post-bind traffic: plaintext (no wrapping detected)")
	}
}

// writeLDAPMessages writes a batch of packets back out as a unit, wrapping
// them together into a single sealed frame if they arrived wrapped
// (wasWrapped, threaded through from the matching readLDAPMessage call) -
// mirroring the original sender's own bundling (one seal/sequence-number
// advance per bundle) instead of re-sealing each message as its own
// separate frame. A batch that arrived plaintext is written out as the
// individual messages it already was - readLDAPMessage's plaintext path
// never bundles, so this is always a single-element batch in that case.
//
// When --split-wrapped is active and a multi-message wrapped buffer was
// read, each message is sealed and written as its own independent frame
// rather than being bundled together - useful when a receiving peer
// expects exactly one LDAPMessage per sealed frame. The policy is:
// "in" splits client->target (toClient=false), "out" splits target->client
// (toClient=true), "both" splits both directions.
func writeLDAPMessages(w *bufio.Writer, bs *decrypt.BindSession, packets []*ber.Packet, wasWrapped, toClient bool) ([]byte, error) {
	if !wasWrapped {
		var out []byte
		for _, p := range packets {
			b := p.Bytes()
			if _, err := w.Write(b); err != nil {
				return out, err
			}
			out = append(out, b...)
		}
		return out, nil
	}

	// Check --split-wrapped policy: should we write each packet as its own
	// individual sealed frame instead of bundling them together?
	split := runtimeConfig.GetSplitWrapped()
	doSplit := split == "both" || (split == "in" && !toClient) || (split == "out" && toClient)

	if doSplit && len(packets) > 1 {
		var sentBytes []byte
		for _, p := range packets {
			plain := p.Bytes()
			var wrapped []byte
			var err error
			if toClient {
				wrapped, err = bs.WrapToClient(plain)
			} else {
				wrapped, err = bs.WrapToTarget(plain)
			}
			if err != nil {
				return sentBytes, fmt.Errorf("split-wrap: %w", err)
			}
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(wrapped)))
			frame := append(lenBuf, wrapped...)
			if _, err := w.Write(frame); err != nil {
				return sentBytes, err
			}
			sentBytes = append(sentBytes, plain...)
		}
		dirPrintf(!toClient, "[+] Split %d bundled messages into individual seal frames", len(packets))
		return sentBytes, nil
	}

	var plain []byte
	for _, p := range packets {
		plain = append(plain, p.Bytes()...)
	}

	var wrapped []byte
	var err error
	if toClient {
		wrapped, err = bs.WrapToClient(plain)
	} else {
		wrapped, err = bs.WrapToTarget(plain)
	}
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(wrapped)))
	full := append(lenBuf, wrapped...)
	_, err = w.Write(full)
	return plain, err
}

func handleLDAPConnection(conn net.Conn) {
	defer conn.Close()

	// Get target address from config
	targetAddr, _, _ := runtimeConfig.GetConnectionConfig()

	// Build upstream TLS config:
	// - If the client connected over TLS and presented a certificate AND
	//   --key was provided, pair the peer cert with the loaded private key
	//   to authenticate as a TLS client to the upstream server.
	// - Otherwise fall back to the global upstreamTlsConfig (insecure,
	//   no client cert).
	upstreamCfg := upstreamTlsConfig
	if tlsConn, ok := conn.(*tls.Conn); ok && upstreamClientKey != nil {
		// The TLS handshake is *lazy* in Go's tls.Listener - Accept()
		// returns the *tls.Conn before the handshake completes, and
		// ConnectionState() only has PeerCertificates after the handshake.
		if err := tlsConn.Handshake(); err != nil {
			log.Log.Printf("[-] TLS handshake with client failed: %v", err)
			return
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			clientCert := tls.Certificate{
				Certificate: [][]byte{state.PeerCertificates[0].Raw},
				PrivateKey:  upstreamClientKey,
			}
			upstreamCfg = &tls.Config{
				Certificates:       []tls.Certificate{clientCert},
				InsecureSkipVerify: true,
			}
		} else {
			fmt.Println()
			log.Log.Print(yellow.Sprintf("[!] Certificate key was provided but the client did not present a certificate: upstream client cert auth will not work"))
		}
	}

	// Connect to target conn - local variable for this connection only
	localTargetConn, err := connect(targetAddr, upstreamCfg)
	if err != nil {
		log.Log.Printf("Failed to connect to target LDAP server: %v", err)
		return
	}
	defer localTargetConn.Close()

	targetConnReader := bufio.NewReader(localTargetConn)
	targetConnWriter := bufio.NewWriter(localTargetConn)

	done := make(chan struct{}) // Channel to signal when either goroutine is done
	// closeDone lets either direction's goroutine signal shutdown - both can
	// hit a fatal error independently (client vs target read/unwrap
	// failures), and closing an already-closed channel panics, so the
	// actual close is guarded by closeDoneOnce rather than only ever
	// happening via one hardcoded goroutine's defer.
	var closeDoneOnce sync.Once
	closeDone := func() { closeDoneOnce.Do(func() { close(done) }) }

	connReader := bufio.NewReader(conn)
	connWriter := bufio.NewWriter(conn)

	bs := decrypt.NewBindSession()
	decryptCfg := runtimeConfig.GetDecryptionConfig()

	// spoofApplied is set by the reverse goroutine, read by the forward
	// goroutine on the client's first BindRequest - hence the atomic.
	// bindMechCheckDone is only ever touched by the forward goroutine.
	var spoofApplied atomic.Bool
	bindMechCheckDone := false

	// Both return ok=false on any write/flush failure so their caller's loop
	// can terminate the connection (via its own defer closeDone()) instead
	// of silently swallowing the error and looping back around to read the
	// next message as if nothing happened - a broken write means the peer
	// on that leg is no longer receiving anything, so continuing to forward
	// more traffic into it can only produce more of the same silent drops.
	sendPacketsForward := func(packets []*ber.Packet, wasWrapped bool) bool {
		b, err := writeLDAPMessages(targetConnWriter, bs, packets, wasWrapped, false)
		if err != nil {
			dirErrorf(true, "[-] Error forwarding LDAP request: %v", err)
			return false
		}
		globalStats.Lock()
		globalStats.Forward.PacketsSent += uint64(len(packets))
		globalStats.Forward.BytesSent += uint64(len(b))
		globalStats.Unlock()

		if err := targetConnWriter.Flush(); err != nil {
			dirErrorf(true, "[-] Error flushing LDAP request: %v", err)
			return false
		}
		return true
	}

	sendPacketsReverse := func(packets []*ber.Packet, wasWrapped bool) bool {
		b, err := writeLDAPMessages(connWriter, bs, packets, wasWrapped, true)
		if err != nil {
			dirErrorf(false, "[-] Error sending response back to client: %v", err)
			return false
		}
		globalStats.Lock()
		globalStats.Reverse.PacketsSent += uint64(len(packets))
		globalStats.Reverse.BytesSent += uint64(len(b))
		globalStats.Unlock()

		if err := connWriter.Flush(); err != nil {
			dirErrorf(false, "[-] Error flushing response back to client: %v", err)
			return false
		}
		return true
	}

	go func() {
		// Signals the response goroutine (and handleLDAPConnection's own
		// final <-done wait) to exit whenever this goroutine does, on any
		// path - including a read/unwrap error, not just a clean loop exit.
		defer closeDone()

		var searchRequestMap = make(map[string]*ber.Packet)

		for {
			result, wrapErr := readLDAPMessageSafe(connReader, bs, true)
			if wrapErr != nil {
				dirErrorf(true, "[-] Error reading LDAP request: %v", wrapErr)
				return
			}
			wasWrapped := result.wrapped
			var processedPackets []*ber.Packet

			for _, packet2 := range result.pkts {
				if len(packet2.Children) < 2 {
					dirErrorf(true, "[-] Malformed LDAP request (missing protocolOp) - dropping connection")
					return
				}

				fmt.Println("\n" + strings.Repeat("─", 55))

				verbFwd, _ := runtimeConfig.GetVerbosity()

				if verbFwd > 1 {
					log.Log.Print(cyan.Sprintf("[C->T] [DEBUG] Packet Dump"))
					ber.PrintPacket(packet2)
				}

				globalStats.Lock()
				globalStats.Forward.PacketsReceived++
				globalStats.Forward.BytesReceived += uint64(len(packet2.Bytes()))
				application := uint8(packet2.Children[1].Tag)
				globalStats.Forward.CountsByType[int(application)]++
				globalStats.Unlock()

				reqMessageID, _ := packet2.Children[0].Value.(int64)
				applicationText, ok := parser.ApplicationMap[application]
				if !ok {
					applicationText = fmt.Sprintf("Unknown Application '%d'", application)
				}

				if verbFwd > 0 {
					log.Log.Print(cyan.Sprintf("[C->T] [%d - %s]", reqMessageID, applicationText))
				}

				intercepts := runtimeConfig.GetInterceptFlags()

				switch application {
				case parser.ApplicationBindRequest:
					decrypt.InspectBindRequest(bs, packet2)
					if !bindMechCheckDone {
						bindMechCheckDone = true
						_, spoofGiven := runtimeConfig.GetSpoofMechConfig()
						if spoofGiven && !spoofApplied.Load() {
							log.Log.Print(yellow.Sprintf("[-] Warning: client sent a bind without checking rootDSE for supportedSASLMechanisms (--spoof-mechs had no effect)"))
						}
					}
				case parser.ApplicationSearchRequest:
					if intercepts.Search {
						log.Log.Print(cyan.Sprintf("[+] Search Request Intercepted (%d)", reqMessageID))
						packet2 = ProcessSearchRequest(packet2, searchRequestMap)
					}
				case parser.ApplicationModifyRequest:
					if intercepts.Modify {
						log.Log.Print(cyan.Sprintf("[+] Modify Request Intercepted (%d)", reqMessageID))
						packet2 = ProcessModifyRequest(packet2)
					}
				case parser.ApplicationAddRequest:
					if intercepts.Add {
						log.Log.Print(cyan.Sprintf("[+] Add Request Intercepted (%d)", reqMessageID))
						packet2 = ProcessAddRequest(packet2)
					}
				case parser.ApplicationDelRequest:
					if intercepts.Delete {
						log.Log.Print(cyan.Sprintf("[+] Delete Request Intercepted (%d)", reqMessageID))
						packet2 = ProcessDeleteRequest(packet2)
					}
				case parser.ApplicationModifyDNRequest:
					if intercepts.ModifyDN {
						log.Log.Print(cyan.Sprintf("[+] ModifyDN Request Intercepted (%d)", reqMessageID))
						packet2 = ProcessModifyDNRequest(packet2)
					}
				}

				verbFwd, _ = runtimeConfig.GetVerbosity()

				if verbFwd > 1 {
					log.Log.Print(cyan.Sprintf("[C->T] [DEBUG] Packet Dump"))
					ber.PrintPacket(packet2)
				}

				processedPackets = append(processedPackets, packet2)
			}

			if !sendPacketsForward(processedPackets, wasWrapped) {
				return
			}
		}
	}()

	go func() {
		// Mirrors the request goroutine's own defer: a read/unwrap error on
		// this side must unblock handleLDAPConnection's final <-done wait
		// too, not just this loop - otherwise the request goroutine stays
		// blocked forever on its own read (the client has nothing more to
		// send once its request went unanswered), and neither connection
		// ever gets closed.
		defer closeDone()

		for {
			select {
			case <-done:
				return // Exit if the request goroutine is done
			default:
				result, wrapErr := readLDAPMessageSafe(targetConnReader, bs, false)
				if wrapErr != nil {
					dirErrorf(false, "[-] Error reading LDAP response: %v", wrapErr)
					return
				}
				wasWrapped := result.wrapped
				var processedPackets []*ber.Packet

				for _, responsePacket := range result.pkts {
					if len(responsePacket.Children) < 2 {
						dirErrorf(false, "[-] Malformed LDAP response (missing protocolOp) - dropping connection")
						return
					}

					globalStats.Lock()
					globalStats.Reverse.PacketsReceived++
					globalStats.Reverse.BytesReceived += uint64(len(responsePacket.Bytes()))
					application := uint8(responsePacket.Children[1].Tag)
					globalStats.Reverse.CountsByType[int(application)]++
					globalStats.Unlock()

					respMessageID, _ := responsePacket.Children[0].Value.(int64)
					applicationText, ok := parser.ApplicationMap[application]
					if !ok {
						applicationText = fmt.Sprintf("Unknown Application '%d'", application)
					}

					switch application {
					case parser.ApplicationBindResponse:
						decrypt.InspectBindResponse(bs, responsePacket, decryptCfg)
					case parser.ApplicationSearchResultEntry:
						spoofMechs, spoofGiven := runtimeConfig.GetSpoofMechConfig()
						var applied bool
						responsePacket, applied = rootdse.ProcessSearchResultEntry(responsePacket, spoofGiven, spoofMechs)
						if applied {
							spoofApplied.Store(true)
						}
					}

					_, verbRev := runtimeConfig.GetVerbosity()

					if verbRev > 0 {
						log.Log.Print(magenta.Sprintf("[C<-T] [%d - %s] (%d bytes)", respMessageID, applicationText, len(responsePacket.Bytes())))

						if verbRev > 1 {
							log.Log.Print(magenta.Sprintf("[C<-T] [DEBUG] Packet Dump"))
							ber.PrintPacket(responsePacket)
						}
					}

					processedPackets = append(processedPackets, responsePacket)
				}

				if !sendPacketsReverse(processedPackets, wasWrapped) {
					return
				}
			}
		}
	}()

	<-done
}

// readResult bundles the parsed packet(s) from one read with whether they
// arrived wrapped, so the caller can write each back out the same way.
// Usually one packet; a wrapped read can yield several if the sealed buffer
// contained more than one concatenated LDAPMessage.
type readResult struct {
	pkts    []*ber.Packet
	wrapped bool
}

// readLDAPMessageSafe wraps readLDAPMessage with the same
// recover()-protected pattern parser/packet.go's pretty-printer already
// uses - a SicilyBindResponse's different shape (no matchedDN) can make
// generic packet-shape assumptions elsewhere panic, so this converts a
// panic from unexpectedly-shaped input into a plain error instead of
// taking down the connection's goroutine uncontrolled.
func readLDAPMessageSafe(reader *bufio.Reader, bs *decrypt.BindSession, fromClient bool) (result readResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic while reading/parsing message: %v", r)
		}
	}()

	first, peekErr := reader.Peek(1)
	wasWrapped := peekErr == nil && first[0] != 0x30

	pkts, readErr := readLDAPMessage(reader, bs, fromClient)
	if readErr != nil {
		return readResult{}, readErr
	}
	return readResult{pkts: pkts, wrapped: wasWrapped}, nil
}
