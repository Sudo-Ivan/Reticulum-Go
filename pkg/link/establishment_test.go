package link

import (
	"testing"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

func TestEphemeralKeyGeneration(t *testing.T) {
	link := &Link{}
	
	if err := link.generateEphemeralKeys(); err != nil {
		t.Fatalf("Failed to generate ephemeral keys: %v", err)
	}
	
	if len(link.prv) != KEYSIZE {
		t.Errorf("Expected private key length %d, got %d", KEYSIZE, len(link.prv))
	}
	
	if len(link.pub) != KEYSIZE {
		t.Errorf("Expected public key length %d, got %d", KEYSIZE, len(link.pub))
	}
	
	if len(link.sigPriv) != 64 {
		t.Errorf("Expected signing private key length 64, got %d", len(link.sigPriv))
	}
	
	if len(link.sigPub) != 32 {
		t.Errorf("Expected signing public key length 32, got %d", len(link.sigPub))
	}
}

func TestSignallingBytes(t *testing.T) {
	mtu := 500
	mode := byte(MODE_AES256_CBC)
	
	bytes := signallingBytes(mtu, mode)
	
	if len(bytes) != LINK_MTU_SIZE {
		t.Errorf("Expected signalling bytes length %d, got %d", LINK_MTU_SIZE, len(bytes))
	}
	
	extractedMTU := (int(bytes[0]&0x1F) << 16) | (int(bytes[1]) << 8) | int(bytes[2])
	if extractedMTU != mtu {
		t.Errorf("Expected MTU %d, got %d", mtu, extractedMTU)
	}
	
	extractedMode := (bytes[0] & MODE_BYTEMASK) >> 5
	if extractedMode != mode {
		t.Errorf("Expected mode %d, got %d", mode, extractedMode)
	}
}

func TestLinkIDGeneration(t *testing.T) {
	responderIdent, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create responder identity: %v", err)
	}

	cfg := &common.ReticulumConfig{}
	transportInstance := transport.NewTransport(cfg)

	dest, err := destination.New(responderIdent, destination.IN, destination.SINGLE, "test", transportInstance, "link")
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	link := &Link{
		destination: dest,
		transport:   transportInstance,
		initiator:   true,
	}

	if err := link.generateEphemeralKeys(); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	link.mode = MODE_DEFAULT
	link.mtu = 500

	signalling := signallingBytes(link.mtu, link.mode)
	requestData := make([]byte, 0, ECPUBSIZE+LINK_MTU_SIZE)
	requestData = append(requestData, link.pub...)
	requestData = append(requestData, link.sigPub...)
	requestData = append(requestData, signalling...)

	pkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeLinkReq,
		TransportType:   0,
		Context:         packet.ContextNone,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: dest.GetType(),
		DestinationHash: dest.GetHash(),
		Data:            requestData,
	}

	if err := pkt.Pack(); err != nil {
		t.Fatalf("Failed to pack packet: %v", err)
	}

	linkID := linkIDFromPacket(pkt)
	
	if len(linkID) != 16 {
		t.Errorf("Expected link ID length 16, got %d", len(linkID))
	}
	
	t.Logf("Generated link ID: %x", linkID)
}

func TestHandshake(t *testing.T) {
	link1 := &Link{}
	link2 := &Link{}
	
	if err := link1.generateEphemeralKeys(); err != nil {
		t.Fatalf("Failed to generate keys for link1: %v", err)
	}
	
	if err := link2.generateEphemeralKeys(); err != nil {
		t.Fatalf("Failed to generate keys for link2: %v", err)
	}
	
	link1.peerPub = link2.pub
	link2.peerPub = link1.pub
	
	link1.linkID = []byte("test-link-id-abc")
	link2.linkID = []byte("test-link-id-abc")
	
	link1.mode = MODE_AES256_CBC
	link2.mode = MODE_AES256_CBC
	
	if err := link1.performHandshake(); err != nil {
		t.Fatalf("Link1 handshake failed: %v", err)
	}
	
	if err := link2.performHandshake(); err != nil {
		t.Fatalf("Link2 handshake failed: %v", err)
	}
	
	if string(link1.sharedKey) != string(link2.sharedKey) {
		t.Error("Shared keys do not match")
	}
	
	if string(link1.derivedKey) != string(link2.derivedKey) {
		t.Error("Derived keys do not match")
	}
	
	if link1.status != STATUS_HANDSHAKE {
		t.Errorf("Expected link1 status HANDSHAKE, got %d", link1.status)
	}
	
	if link2.status != STATUS_HANDSHAKE {
		t.Errorf("Expected link2 status HANDSHAKE, got %d", link2.status)
	}
}

func TestLinkEstablishment(t *testing.T) {
	responderIdent, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create responder identity: %v", err)
	}

	cfg := &common.ReticulumConfig{}
	transportInstance := transport.NewTransport(cfg)

	dest, err := destination.New(responderIdent, destination.IN, destination.SINGLE, "test", transportInstance, "link")
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	initiatorLink := &Link{
		destination: dest,
		transport:   transportInstance,
		initiator:   true,
	}

	responderLink := &Link{
		transport: transportInstance,
		initiator: false,
	}

	if err := initiatorLink.generateEphemeralKeys(); err != nil {
		t.Fatalf("Failed to generate initiator keys: %v", err)
	}

	initiatorLink.mode = MODE_DEFAULT
	initiatorLink.mtu = 500

	signalling := signallingBytes(initiatorLink.mtu, initiatorLink.mode)
	requestData := make([]byte, 0, ECPUBSIZE+LINK_MTU_SIZE)
	requestData = append(requestData, initiatorLink.pub...)
	requestData = append(requestData, initiatorLink.sigPub...)
	requestData = append(requestData, signalling...)

	linkRequestPkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeLinkReq,
		TransportType:   0,
		Context:         packet.ContextNone,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: dest.GetType(),
		DestinationHash: dest.GetHash(),
		Data:            requestData,
	}

	if err := linkRequestPkt.Pack(); err != nil {
		t.Fatalf("Failed to pack link request: %v", err)
	}

	initiatorLink.linkID = linkIDFromPacket(linkRequestPkt)
	initiatorLink.requestTime = time.Now()
	initiatorLink.status = STATUS_PENDING

	t.Logf("Initiator link request created, link_id=%x", initiatorLink.linkID)

	responderLink.peerPub = linkRequestPkt.Data[0:KEYSIZE]
	responderLink.peerSigPub = linkRequestPkt.Data[KEYSIZE:ECPUBSIZE]
	responderLink.linkID = linkIDFromPacket(linkRequestPkt)
	responderLink.initiator = false
	
	t.Logf("Responder link ID=%x (len=%d)", responderLink.linkID, len(responderLink.linkID))
	
	if len(responderLink.linkID) == 0 {
		t.Fatal("Responder link ID is empty!")
	}

	if len(linkRequestPkt.Data) >= ECPUBSIZE+LINK_MTU_SIZE {
		mtuBytes := linkRequestPkt.Data[ECPUBSIZE : ECPUBSIZE+LINK_MTU_SIZE]
		responderLink.mtu = (int(mtuBytes[0]&0x1F) << 16) | (int(mtuBytes[1]) << 8) | int(mtuBytes[2])
		responderLink.mode = (mtuBytes[0] & MODE_BYTEMASK) >> 5
	}

	if err := responderLink.generateEphemeralKeys(); err != nil {
		t.Fatalf("Failed to generate responder keys: %v", err)
	}

	if err := responderLink.performHandshake(); err != nil {
		t.Fatalf("Responder handshake failed: %v", err)
	}

	responderLink.status = STATUS_ACTIVE
	responderLink.establishedAt = time.Now()

	if string(responderLink.linkID) != string(initiatorLink.linkID) {
		t.Error("Link IDs do not match between initiator and responder")
	}

	t.Logf("Responder handshake successful, shared_key_len=%d", len(responderLink.sharedKey))
}

func TestLinkProofValidation(t *testing.T) {
	responderIdent, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create responder identity: %v", err)
	}

	cfg := &common.ReticulumConfig{}
	transportInstance := transport.NewTransport(cfg)

	dest, err := destination.New(responderIdent, destination.IN, destination.SINGLE, "test", transportInstance, "link")
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	initiatorLink := &Link{
		destination: dest,
		transport:   transportInstance,
		initiator:   true,
	}

	responderLink := &Link{
		transport: transportInstance,
		initiator: false,
	}

	if err := initiatorLink.generateEphemeralKeys(); err != nil {
		t.Fatalf("Failed to generate initiator keys: %v", err)
	}

	initiatorLink.mode = MODE_DEFAULT
	initiatorLink.mtu = 500

	signalling := signallingBytes(initiatorLink.mtu, initiatorLink.mode)
	requestData := make([]byte, 0, ECPUBSIZE+LINK_MTU_SIZE)
	requestData = append(requestData, initiatorLink.pub...)
	requestData = append(requestData, initiatorLink.sigPub...)
	requestData = append(requestData, signalling...)

	linkRequestPkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeLinkReq,
		TransportType:   0,
		Context:         packet.ContextNone,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: dest.GetType(),
		DestinationHash: dest.GetHash(),
		Data:            requestData,
	}

	if err := linkRequestPkt.Pack(); err != nil {
		t.Fatalf("Failed to pack link request: %v", err)
	}

	initiatorLink.linkID = linkIDFromPacket(linkRequestPkt)
	initiatorLink.requestTime = time.Now()
	initiatorLink.status = STATUS_PENDING

	responderLink.peerPub = linkRequestPkt.Data[0:KEYSIZE]
	responderLink.peerSigPub = linkRequestPkt.Data[KEYSIZE:ECPUBSIZE]
	responderLink.linkID = linkIDFromPacket(linkRequestPkt)
	responderLink.initiator = false

	if len(linkRequestPkt.Data) >= ECPUBSIZE+LINK_MTU_SIZE {
		mtuBytes := linkRequestPkt.Data[ECPUBSIZE : ECPUBSIZE+LINK_MTU_SIZE]
		responderLink.mtu = (int(mtuBytes[0]&0x1F) << 16) | (int(mtuBytes[1]) << 8) | int(mtuBytes[2])
		responderLink.mode = (mtuBytes[0] & MODE_BYTEMASK) >> 5
	} else {
		responderLink.mtu = 500
		responderLink.mode = MODE_DEFAULT
	}

	if err := responderLink.generateEphemeralKeys(); err != nil {
		t.Fatalf("Failed to generate responder keys: %v", err)
	}

	if err := responderLink.performHandshake(); err != nil {
		t.Fatalf("Responder handshake failed: %v", err)
	}

	proofPkt, err := responderLink.GenerateLinkProof(responderIdent)
	if err != nil {
		t.Fatalf("Failed to generate link proof: %v", err)
	}

	if err := initiatorLink.ValidateLinkProof(proofPkt); err != nil {
		t.Fatalf("Initiator failed to validate link proof: %v", err)
	}

	if initiatorLink.status != STATUS_ACTIVE {
		t.Errorf("Expected initiator status ACTIVE, got %d", initiatorLink.status)
	}

	if string(initiatorLink.sharedKey) != string(responderLink.sharedKey) {
		t.Error("Shared keys do not match after full handshake")
	}

	if string(initiatorLink.derivedKey) != string(responderLink.derivedKey) {
		t.Error("Derived keys do not match after full handshake")
	}

	t.Logf("Full link establishment successful")
	t.Logf("Link ID: %x", initiatorLink.linkID)
	t.Logf("Shared key length: %d", len(initiatorLink.sharedKey))
	t.Logf("Derived key length: %d", len(initiatorLink.derivedKey))
	t.Logf("RTT: %.3f seconds", initiatorLink.rtt)
}

