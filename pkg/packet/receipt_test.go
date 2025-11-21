package packet

import (
	"testing"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
)

func TestPacketReceiptCreation(t *testing.T) {
	testIdent, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	destHash := testIdent.Hash()
	data := []byte("test packet data")

	pkt := &Packet{
		HeaderType:      HeaderType1,
		PacketType:      PacketTypeData,
		TransportType:   0,
		Context:         ContextNone,
		ContextFlag:     FlagUnset,
		Hops:            0,
		DestinationType: 0x00,
		DestinationHash: destHash,
		Data:            data,
		CreateReceipt:   true,
	}

	if err := pkt.Pack(); err != nil {
		t.Fatalf("Failed to pack packet: %v", err)
	}

	receipt := NewPacketReceipt(pkt)
	if receipt == nil {
		t.Fatal("Receipt creation failed")
	}

	if receipt.GetStatus() != RECEIPT_SENT {
		t.Errorf("Expected status SENT, got %d", receipt.GetStatus())
	}

	hash := receipt.GetHash()
	if len(hash) == 0 {
		t.Error("Receipt hash is empty")
	}
}

func TestPacketReceiptTimeout(t *testing.T) {
	testIdent, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	destHash := testIdent.Hash()
	data := []byte("test data")

	pkt := &Packet{
		HeaderType:      HeaderType1,
		PacketType:      PacketTypeData,
		TransportType:   0,
		Context:         ContextNone,
		ContextFlag:     FlagUnset,
		Hops:            0,
		DestinationType: 0x00,
		DestinationHash: destHash,
		Data:            data,
		CreateReceipt:   true,
	}

	if err := pkt.Pack(); err != nil {
		t.Fatalf("Failed to pack packet: %v", err)
	}

	receipt := NewPacketReceipt(pkt)
	receipt.SetTimeout(100 * time.Millisecond)

	time.Sleep(150 * time.Millisecond)

	if !receipt.IsTimedOut() {
		t.Error("Receipt should be timed out")
	}
}

func TestPacketReceiptProofValidation(t *testing.T) {
	testIdent, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	destHash := testIdent.Hash()
	data := []byte("test data")

	pkt := &Packet{
		HeaderType:      HeaderType1,
		PacketType:      PacketTypeData,
		TransportType:   0,
		Context:         ContextNone,
		ContextFlag:     FlagUnset,
		Hops:            0,
		DestinationType: 0x00,
		DestinationHash: destHash,
		Data:            data,
		CreateReceipt:   true,
	}

	if err := pkt.Pack(); err != nil {
		t.Fatalf("Failed to pack packet: %v", err)
	}

	receipt := NewPacketReceipt(pkt)
	receipt.SetDestinationIdentity(testIdent)

	packetHash := pkt.GetHash()
	t.Logf("Packet hash: %x", packetHash)
	
	signature := testIdent.Sign(packetHash)

	t.Logf("PacketHash length: %d", len(packetHash))
	t.Logf("Signature length: %d", len(signature))
	t.Logf("EXPL_LENGTH constant: %d", EXPL_LENGTH)
	
	if testIdent.Verify(packetHash, signature) {
		t.Log("Direct verification succeeded")
	} else {
		t.Error("Direct verification failed")
	}

	proof := make([]byte, 0, EXPL_LENGTH)
	proof = append(proof, packetHash...)
	proof = append(proof, signature...)

	t.Logf("Proof length: %d", len(proof))

	proofPacket := &Packet{
		PacketType: PacketTypeProof,
		Data:       proof,
	}

	if !receipt.ValidateProof(proof, proofPacket) {
		t.Errorf("Valid proof was rejected. Proof len=%d, expected=%d", len(proof), EXPL_LENGTH)
	}

	if receipt.GetStatus() != RECEIPT_DELIVERED {
		t.Errorf("Expected status DELIVERED, got %d", receipt.GetStatus())
	}

	if !receipt.IsDelivered() {
		t.Error("Receipt should be marked as delivered")
	}
}

func TestPacketReceiptCallbacks(t *testing.T) {
	testIdent, err := identity.NewIdentity()
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	destHash := testIdent.Hash()
	data := []byte("test data")

	pkt := &Packet{
		HeaderType:      HeaderType1,
		PacketType:      PacketTypeData,
		TransportType:   0,
		Context:         ContextNone,
		ContextFlag:     FlagUnset,
		Hops:            0,
		DestinationType: 0x00,
		DestinationHash: destHash,
		Data:            data,
		CreateReceipt:   true,
	}

	if err := pkt.Pack(); err != nil {
		t.Fatalf("Failed to pack packet: %v", err)
	}

	receipt := NewPacketReceipt(pkt)
	receipt.SetDestinationIdentity(testIdent)

	deliveryCalled := false
	receipt.SetDeliveryCallback(func(r *PacketReceipt) {
		deliveryCalled = true
	})

	packetHash := pkt.GetHash()
	signature := testIdent.Sign(packetHash)

	proof := make([]byte, 0, EXPL_LENGTH)
	proof = append(proof, packetHash...)
	proof = append(proof, signature...)

	proofPacket := &Packet{
		PacketType: PacketTypeProof,
		Data:       proof,
	}

	receipt.ValidateProof(proof, proofPacket)

	time.Sleep(10 * time.Millisecond)

	if !deliveryCalled {
		t.Error("Delivery callback was not called")
	}
}

