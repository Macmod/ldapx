package decrypt

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	msrpccrypto "github.com/oiweiwei/go-msrpc/ssp/krb5/crypto"
	"github.com/oiweiwei/go-msrpc/ssp/krb5/crypto/rfc4757"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// This file implements the GSS per-message wrap/unwrap token layer for an
// established GSSAPI/SPNEGO(-Kerberos) session: integrity-only (sign) tokens
// via gokrb5.fork's WrapToken, and AES confidentiality (sealed) tokens via
// go-msrpc's RFC 4121 CFX cipher. The two halves are the sealing primitives
// (newSealCipher/sealWrap/sealUnwrap) and the token layer that routes
// between them (gssDirectionCipher/gssSessionContext). RC4-HMAC sessions use
// a structurally different token format and are routed out to rc4wrap.go.

// newSealCipher builds an RFC 4121 §4.2.4 confidentiality ("sealed" GSS_Wrap)
// cipher for one fixed role (initiator or acceptor) of a GSSAPI/SPNEGO
// session, or (nil, nil) for any etype this cipher doesn't cover. A nil
// return does not mean "no confidentiality available": RC4-HMAC also returns
// nil here yet is sealed by rc4wrap.go, so the choice between the two paths
// is made on gssDirectionCipher.isRC4, never on sealCipher == nil alone.
//
// Reused rather than reimplemented from the RFC: gokrb5.fork/v9's own
// WrapToken never implements the encryption half of RFC 4121, so this is
// an upstream limitation shared by every known fork.
// go-msrpc (same author, oiweiwei) separately implements the full RFC 4121
// CFX wrap token - confounder placement, EC/RRC rotation, Ke/Ki derivation -
// for its own DCERPC-over-Kerberos transport.
//
// Only AES128/AES256-CTS-HMAC-SHA1-96 take this CFX path. RC4-HMAC's
// confidentiality is the older, ASN.1-wrapped RFC 4757 token format, built
// on go-msrpc's rfc4757/rfc1964 primitives directly in rc4wrap.go rather
// than through this cipher - go-msrpc's own RC4 Cipher hardcodes
// DCE-RPC-style length framing that doesn't match plain SASL GSS_Wrap's
// single self-contained blob. Every remaining etype (DES, DES3, AES-SHA2)
// has no sealing implementation at all and reaches
// errGSSSealingUnsupported.
//
// isSubKey must reflect whether key is a subkey (Authenticator's or the
// AP-REP's) rather than the ticket's own session key: it's cryptographically
// bound into the CFX header (WrapHeader sets the AcceptorSubKey flag bit
// from it, and that header is itself part of what gets hashed/encrypted),
// so a mismatch here doesn't just misreport a flag - it produces a header a
// real peer already tracking IsSubKey internally rejects even though the
// key value itself is correct.
func newSealCipher(key types.EncryptionKey, asAcceptor, isSubKey bool) (msrpccrypto.Cipher, error) {
	if key.KeyType != etypeID.AES128_CTS_HMAC_SHA1_96 && key.KeyType != etypeID.AES256_CTS_HMAC_SHA1_96 {
		// RC4-HMAC (etype 23) uses a completely different token format
		// (RFC 4757) handled by rc4wrap.go, not the CFX cipher returned here.
		return nil, nil
	}
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("krb5decrypt: seal cipher: %w", err)
	}
	cipher, err := msrpccrypto.NewCipher(context.Background(), msrpccrypto.CipherSetting{
		Key:      key,
		Type:     et,
		IsLocal:  !asAcceptor,
		IsSubKey: isSubKey,
	})
	if err != nil {
		return nil, fmt.Errorf("krb5decrypt: seal cipher: %w", err)
	}
	return cipher, nil
}

// sealWrap builds a full, self-contained CFX Wrap token for payload - the
// "textbook" GSS_Wrap() semantics RFC 4752 §3.5 needs (one opaque blob to
// send as-is), not go-msrpc's own DCE-RPC-oriented in-place scatter/gather
// calling convention. go-msrpc's Cipher.Wrap mutates its payload argument in
// place (overwriting it with ciphertext) and returns only the token's
// fixed-size header+trailer prefix, on the assumption its caller already
// holds a stable reference to the (now-mutated) payload buffer to
// concatenate afterward - reconstructed into one contiguous token here by
// operating on a copy of payload, then appending that mutated copy to the
// returned prefix. Always sealed (conf=true) - sign-only tokens use
// gokrb5.fork's WrapToken instead (see verifyAndExtract/wrap below), since a
// real sign-only token doesn't use this CFX confounder/rotation framing at
// all.
func sealWrap(cipher msrpccrypto.Cipher, seqNum uint64, payload []byte) ([]byte, error) {
	buf := append([]byte{}, payload...)
	prefix, err := cipher.Wrap(context.Background(), seqNum, buf, true)
	if err != nil {
		return nil, fmt.Errorf("krb5decrypt: seal wrap: %w", err)
	}
	return append(prefix, buf...), nil
}

// sealUnwrap reverses sealWrap: wrapped is the complete wire-format token
// (16-byte cleartext header onward). go-msrpc's Cipher.Unwrap, given an
// empty sgn, parses that header itself (reading EC/RRC to find the token's
// internal prefix/payload boundary, exactly mirroring sealWrap's layout)
// and decrypts the payload portion in place - so a mutable copy of the
// whole token is handed in, and the plaintext is read back out of that same
// copy's tail once Unwrap returns and reports the prefix length via sgn.
func sealUnwrap(cipher msrpccrypto.Cipher, seqNum uint64, wrapped []byte) ([]byte, error) {
	buf := append([]byte{}, wrapped...)
	sgn, ok, err := cipher.Unwrap(context.Background(), seqNum, buf, nil)
	if err != nil {
		return nil, fmt.Errorf("krb5decrypt: seal unwrap: %w", err)
	}
	if !ok {
		return nil, errors.New("krb5decrypt: seal unwrap: integrity check failed")
	}
	if len(sgn) > len(buf) {
		return nil, fmt.Errorf("krb5decrypt: seal unwrap: signature (%d bytes) longer than token (%d bytes)", len(sgn), len(buf))
	}
	return buf[len(sgn):], nil
}

// gssDirectionCipher implements BindSession's Wrap/Unwrap contract for one
// direction of an established GSSAPI/SPNEGO(-Kerberos) session, using the
// session key recovered by completeGSSAPI.
//
// Two forms of protection are implemented: integrity-only (sign, no
// confidentiality), via gokrb5.fork/v9's WrapToken; and confidentiality
// (sealed), via go-msrpc's RFC 4121 CFX wrap token implementation (AES) or
// the RFC 4757 RC4-HMAC path in rc4wrap.go (RC4). Sealed DES, DES3 and
// AES-SHA2 sessions have no implementation and return
// errGSSSealingUnsupported; those etypes still verify sign-only tokens
// normally, since that path only needs gokrb5.fork's own etype primitives.
type gssDirectionCipher struct {
	key        types.EncryptionKey
	sealCipher msrpccrypto.Cipher // AES only; nil for every other etype, RC4 included (it seals via isRC4/rc4wrap.go)
	isRC4      bool               // true if key is RC4-HMAC (etype 23), handled by rc4wrap.go
	// isSubKey mirrors whatever was observed on the wire (the Authenticator's
	// or AP-REP's subkey vs. the ticket's own session key) - needed again
	// when constructing an outbound sign-only WrapToken's Flags byte (see
	// wrap): the AcceptorSubkey bit isn't optional decoration, a real peer
	// tracking it internally cross-checks it against which key it expects
	// to be in use.
	isSubKey bool
}

func newGSSDirectionCipher(key types.EncryptionKey, asAcceptor bool, isSubKey bool) (*gssDirectionCipher, error) {
	sealCipher, err := newSealCipher(key, asAcceptor, isSubKey)
	if err != nil {
		return nil, err
	}
	return &gssDirectionCipher{key: key, sealCipher: sealCipher, isRC4: isRC4Key(key), isSubKey: isSubKey}, nil
}

var errGSSSealingUnsupported = errors.New("krb5decrypt: GSS_Wrap confidentiality (sealed GSSAPI/SPNEGO) is not implemented for this encryption type - only AES128/AES256 (CFX) and RC4-HMAC (RFC 4757) confidentiality, sign-only GSSAPI/SPNEGO, and all NTLM/Sicily modes are supported")

// unrotateWrapToken restores an RFC 4121 §4.2.5 RRC-rotated Wrap token to
// its canonical (RRC=0) DATA|CHECKSUM layout, so gokrb5.fork's WrapToken -
// which reads the RRC field but never applies it - slices the right bytes
// regardless of which RRC value the sender actually used. Returns wrapped
// unchanged if it's too short to hold a header or if RRC is already 0 (the
// common case for a real client's own outbound tokens).
func unrotateWrapToken(wrapped []byte) []byte {
	if len(wrapped) < gssapi.HdrLen {
		return wrapped
	}
	rrc := int(binary.BigEndian.Uint16(wrapped[6:8]))
	if rrc == 0 || rrc > len(wrapped)-gssapi.HdrLen {
		return wrapped
	}
	body := wrapped[gssapi.HdrLen:]
	canonical := make([]byte, len(wrapped))
	copy(canonical, wrapped[:gssapi.HdrLen])
	binary.BigEndian.PutUint16(canonical[6:8], 0)
	n := copy(canonical[gssapi.HdrLen:], body[rrc:])
	copy(canonical[gssapi.HdrLen+n:], body[:rrc])
	return canonical
}

// verifyAndExtract checks a received WrapToken and returns its payload,
// decrypting it first if the token's Sealed flag is set and a seal cipher
// is available for this session's etype. sealed reports which path was
// taken, so the caller can mirror it when constructing the corresponding
// outbound traffic (see gssSessionContext's clientSealed/targetSealed).
// seqNum is the token's own SndSeqNum, read directly off the wire (present
// in the 16-byte header regardless of whether the token is sealed). The
// caller uses the first one it sees to anchor its own outbound counter for
// that direction (see gssSessionContext): ldapx doesn't originate a GSS
// context, so it can't assume numbering starts at 0 - bare SASL/GSSAPI's own
// RFC 4752 §3.3 post-AP-REP security-layer negotiation passes through
// untouched during the bind and already consumes number 0 on the wire before
// the first LDAP-level wrapped message ever reaches ldapx's Wrap/Unwrap
// logic. Later tokens' numbers are observed but not re-anchored, so the
// outbound stream stays contiguous even when one received bundle is relayed
// as several frames.
//
// Sealed AES128/256 tokens (d.sealCipher != nil) go through go-msrpc's CFX
// cipher, which already handles RRC rotation. Sign-only tokens use
// gokrb5.fork's own WrapToken, which does not: its Unmarshal reads the RRC
// field into wt.RRC but never applies it, always slicing the canonical
// (unrotated) DATA|CHECKSUM layout straight off the wire - wrong whenever
// RRC != 0. Confirmed live against a Windows Server 2022 DC: its own
// sign-only responses use RRC=EC (rotating the checksum to sit immediately
// after the header, matching go-msrpc's sealed-path convention), while a
// real client's own outbound replies use RRC=0 - both legal per RFC 4121
// §4.2.5, but only one of them happens to match gokrb5.fork's hardcoded
// assumption. unrotateWrapToken restores the canonical layout before
// handing the bytes to gokrb5.fork, rather than duplicating its header
// validation here.
func (d *gssDirectionCipher) verifyAndExtract(wrapped []byte, fromAcceptor bool) (payload []byte, sealed bool, seqNum uint64, err error) {
	// RC4-HMAC (etype 23) uses RFC 4757 tokens (TOK_ID 0x0201), not the
	// RFC 4121 CFX tokens (TOK_ID 0x0504) that gokrb5.fork's WrapToken
	// parses. Route to the RC4 path before attempting CFX unmarshal.
	if d.isRC4 || isRC4WrapToken(wrapped) {
		return d.rc4VerifyAndExtract(wrapped, fromAcceptor)
	}

	var tok gssapi.WrapToken
	if err := tok.Unmarshal(unrotateWrapToken(wrapped), fromAcceptor); err != nil {
		return nil, false, 0, fmt.Errorf("krb5decrypt: unmarshal wrap token: %w", err)
	}
	sealedFlag := tok.Flags&0x02 != 0 // RFC 4121 §4.2.2

	if sealedFlag {
		if d.sealCipher == nil {
			return nil, true, tok.SndSeqNum, errGSSSealingUnsupported
		}
		plain, err := sealUnwrap(d.sealCipher, tok.SndSeqNum, wrapped)
		if err != nil {
			return nil, true, tok.SndSeqNum, err
		}
		return plain, true, tok.SndSeqNum, nil
	}

	// RFC 4121 §4.2.4: a Wrap token's checksum always uses the "seal"
	// key-usage numbers (22/24), never "sign" (23/25) - those are reserved
	// for the separate GSS_GetMIC token type (RFC 4121 §4.2.6.1), which
	// isn't in play here regardless of whether this particular Wrap token
	// happens to be sealed. Confirmed by round-tripping sign-only Wrap
	// tokens against a Windows Server 2022 DC using exactly this pairing.
	usage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	if fromAcceptor {
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	// Verify reports failure two ways - an error for a malformed token, and
	// ok=false with a nil error for one that parsed fine but whose checksum
	// simply didn't match. Kept separate so the second case (the one an
	// operator hits with a wrong credential) doesn't render its nil error as
	// "%!w(<nil>)".
	ok, err := tok.Verify(d.key, usage)
	if err != nil {
		return nil, false, tok.SndSeqNum, fmt.Errorf("krb5decrypt: wrap token checksum verification failed: %w", err)
	}
	if !ok {
		return nil, false, tok.SndSeqNum, errors.New("krb5decrypt: wrap token checksum verification failed (wrong session key?)")
	}
	return tok.Payload, false, tok.SndSeqNum, nil
}

// rc4VerifyAndExtract handles RFC 4757 RC4-HMAC Wrap tokens, sealed or
// sign-only. The sealed flag is read from SEAL_ALG (0x1000 = sealed,
// 0xFFFF = sign-only), and the sequence number from the decrypted SND_SEQ
// field (first 4 bytes, big-endian).
func (d *gssDirectionCipher) rc4VerifyAndExtract(wrapped []byte, fromAcceptor bool) (payload []byte, sealed bool, seqNum uint64, err error) {
	tokBytes := rc4StripOID(wrapped)
	if len(tokBytes) < rc4WrapTokenSize {
		return nil, false, 0, fmt.Errorf("krb5decrypt: rc4 token too short (%d bytes)", len(tokBytes))
	}
	tok := rfc4757.NewWrapToken()
	if err := tok.Unmarshal(tokBytes[:rc4WrapTokenSize]); err != nil {
		return nil, false, 0, fmt.Errorf("krb5decrypt: rc4 unmarshal: %w", err)
	}
	sealed = tok.SealAlgorithm == rc4SealAlgRC4
	plain, seq, err := rc4Unwrap(d.key, wrapped, fromAcceptor)
	if err != nil {
		return nil, sealed, 0, err
	}
	return plain, sealed, uint64(seq), nil
}

// wrap builds an outbound WrapToken, either sign-only or sealed depending on
// seal - mirroring what a real initiator/acceptor would send. seqNum comes
// from the caller's per-direction counter, which is anchored to the relayed
// party's own numbering on the first token observed and then advanced once
// per emitted frame (see gssSessionContext).
//
// Sealed AES output uses go-msrpc's CFX cipher and sign-only output uses
// gokrb5.fork's WrapToken, matching verifyAndExtract's own routing (see its
// doc comment for the caveat this carries for sign-only specifically).
// RC4-HMAC leaves through rc4wrap.go for both, before either applies.
func (d *gssDirectionCipher) wrap(payload []byte, asAcceptor, seal bool, seqNum uint64) ([]byte, error) {
	// RC4-HMAC (etype 23) uses RFC 4757 tokens, not CFX.
	if d.isRC4 {
		return rc4Wrap(d.key, payload, asAcceptor, seal, uint32(seqNum))
	}

	if seal {
		if d.sealCipher == nil {
			return nil, errGSSSealingUnsupported
		}
		return sealWrap(d.sealCipher, seqNum, payload)
	}

	encType, err := crypto.GetEtype(d.key.KeyType)
	if err != nil {
		return nil, err
	}
	// See verifyAndExtract's matching comment: Wrap tokens always use the
	// "seal" key-usage numbers for their checksum, sealed or not.
	usage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	var flags byte
	if d.isSubKey {
		flags |= 0x04 // RFC 4121 §4.2.2 AcceptorSubkey
	}
	if asAcceptor {
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
		flags |= 0x01
	}
	tok := gssapi.WrapToken{
		Flags:     flags,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		SndSeqNum: seqNum,
		Payload:   payload,
	}
	if err := tok.SetCheckSum(d.key, usage); err != nil {
		return nil, err
	}
	return tok.Marshal()
}

// gssSessionContext is BindSession's mechanism-agnostic view of an
// established GSSAPI (or Kerberos-inside-SPNEGO) session: the client is the
// GSS initiator, the target/DC is the acceptor.
//
// Whether outbound traffic should be sealed or sign-only isn't known ahead
// of time the way NTLM's is (NTLM reads NEGOTIATE_SEAL straight out of the
// AUTHENTICATE_MESSAGE at handshake completion) - GSSAPI/SPNEGO's actual
// negotiation lives in a checksum extension inside the AP-REQ's Authenticator
// that ldapx doesn't parse. Rather than add that parsing, outbound wrapping
// mirrors whatever was most recently *observed* from the corresponding
// party: clientSealed (read from the client's own wrapped messages) decides
// how traffic toward the target is wrapped, and targetSealed (read from the
// target's) decides how traffic toward the client is wrapped. This is never a
// cold guess in practice - every message ldapx wraps for one party is a relay
// of a message it just unwrapped from the other, so by the time a direction
// needs to wrap, it has always already observed that same message's own
// Sealed flag moments earlier in the same call chain. Defaults to sign-only
// (false) only for the unreachable-in-practice case of wrapping before
// anything was ever unwrapped.
//
// Only two ciphers, not one per direction: unlike NTLM's four stateful RC4
// streams, a gssDirectionCipher carries no per-message mutable state
// (key/sealCipher/isSubKey are all immutable, and both the gokrb5 WrapToken
// path and go-msrpc's CFX cipher take the sequence number as an explicit
// per-call argument). So one cipher can serve both jobs of a single GSS
// party: the initiator both verifies the client's tokens and produces the
// ones relayed to the target; the acceptor does the same for the target/
// client side.
type gssSessionContext struct {
	initiator *gssDirectionCipher // GSS initiator role: verifies client tokens, produces tokens toward the target
	acceptor  *gssDirectionCipher // GSS acceptor role: verifies target tokens, produces tokens toward the client

	clientSealed bool // mirrors the Sealed flag last observed from the client
	targetSealed bool // mirrors the Sealed flag last observed from the target

	// Sequence numbers are anchored, then counted. ldapx doesn't originate
	// this GSS context, so it can't start numbering at 0: earlier tokens may
	// already have consumed sequence numbers before bs.gss existed - bare
	// SASL/GSSAPI's RFC 4752 §3.3 post-AP-REP layer negotiation passes
	// through untouched during the bind and burns number 0 on the wire. The
	// first token observed in each direction therefore sets the anchor, and
	// every token emitted afterward advances the counter by one.
	//
	// Mirroring the observed number on every relay instead would be correct
	// only while the relay stays 1:1. It isn't: --split-wrapped fans one
	// received bundle out into several frames, and a real peer rejects the
	// repeated sequence number that mirroring would produce for all of them.
	// Counting keeps a split contiguous, and keeps the frame *after* a split
	// contiguous too - the offset has to persist past the bundle, or the next
	// message collides with the last frame of the one before it.
	clientSeqNum uint64 // next sequence number to emit toward the target
	targetSeqNum uint64 // next sequence number to emit toward the client
	clientSeqSet bool   // clientSeqNum has been anchored to the client's own numbering
	targetSeqSet bool   // targetSeqNum has been anchored to the target's own numbering
}

func newGSSSessionContext(key types.EncryptionKey, isSubKey bool) (*gssSessionContext, error) {
	initiator, err := newGSSDirectionCipher(key, false, isSubKey)
	if err != nil {
		return nil, err
	}
	acceptor, err := newGSSDirectionCipher(key, true, isSubKey)
	if err != nil {
		return nil, err
	}
	return &gssSessionContext{
		initiator: initiator,
		acceptor:  acceptor,
	}, nil
}

func (g *gssSessionContext) UnwrapFromClient(wrapped []byte) ([]byte, error) {
	plain, sealed, seqNum, err := g.initiator.verifyAndExtract(wrapped, false)
	if err != nil {
		return nil, err
	}
	g.clientSealed = sealed
	if !g.clientSeqSet {
		g.clientSeqNum = seqNum
		g.clientSeqSet = true
	}
	return plain, nil
}

func (g *gssSessionContext) WrapToTarget(plain []byte) ([]byte, error) {
	seqNum := g.clientSeqNum
	g.clientSeqNum++
	return g.initiator.wrap(plain, false, g.clientSealed, seqNum)
}

func (g *gssSessionContext) UnwrapFromTarget(wrapped []byte) ([]byte, error) {
	plain, sealed, seqNum, err := g.acceptor.verifyAndExtract(wrapped, true)
	if err != nil {
		return nil, err
	}
	g.targetSealed = sealed
	if !g.targetSeqSet {
		g.targetSeqNum = seqNum
		g.targetSeqSet = true
	}
	return plain, nil
}

func (g *gssSessionContext) WrapToClient(plain []byte) ([]byte, error) {
	seqNum := g.targetSeqNum
	g.targetSeqNum++
	return g.acceptor.wrap(plain, true, g.targetSealed, seqNum)
}

// parseRFC4752Layer scans the buffered SASL rounds for a GSS Wrap token
// from the RFC 4752 §3.3 post-AP-REP security-layer negotiation and
// returns the actual per-message layer choice from its payload's first
// byte. For bare SASL/GSSAPI, the AP-REQ checksum flags always advertise
// both SIGN+SEAL — the real layer is chosen separately in this round
// (0x01=plain, 0x02=signonly, 0x04=seal/signseal). Returns LayerUnknown
// if no such token can be verified (e.g. one-round bind, or the initiator
// cipher hasn't been set up yet).
//
// verifyAndExtract is stateless (gssDirectionCipher carries no mutable
// state — all fields are immutable after construction, and seqNum is an
// explicit per-call argument), so calling it on historical tokens from
// bs.pending is safe and won't corrupt the session's seqNum tracking.
func parseRFC4752Layer(g *gssSessionContext, pending [][]byte) SecurityLayer {
	for _, round := range pending {
		plain, _, _, err := g.initiator.verifyAndExtract(round, false)
		if err != nil || len(plain) < 1 {
			continue
		}
		switch {
		case plain[0]&0x04 != 0:
			return LayerSignSeal
		case plain[0]&0x02 != 0:
			return LayerSignOnly
		case plain[0]&0x01 != 0:
			return LayerNone
		}
	}
	return LayerUnknown
}
