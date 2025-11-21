package packet

import (
	"fmt"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
)

const (
	RECEIPT_FAILED    = 0x00
	RECEIPT_SENT      = 0x01
	RECEIPT_DELIVERED = 0x02
	RECEIPT_CULLED    = 0xFF

	EXPL_LENGTH = (identity.HASHLENGTH + identity.SIGLENGTH) / 8
	IMPL_LENGTH = identity.SIGLENGTH / 8
)

type PacketReceipt struct {
	mutex sync.RWMutex

	hash          []byte
	truncatedHash []byte
	sent          bool
	sentAt        time.Time
	proved        bool
	status        byte
	destination   interface{}
	timeout       time.Duration
	concludedAt   time.Time
	proofPacket   *Packet
	
	deliveryCallback func(*PacketReceipt)
	timeoutCallback  func(*PacketReceipt)
	
	link              interface{}
	destinationHash   []byte
	destinationIdent  *identity.Identity
	timeoutCheckDone  chan bool
}

func NewPacketReceipt(pkt *Packet) *PacketReceipt {
	hash := pkt.Hash()
	receipt := &PacketReceipt{
		hash:             hash,
		truncatedHash:    pkt.TruncatedHash(),
		sent:             true,
		sentAt:           time.Now(),
		proved:           false,
		status:           RECEIPT_SENT,
		destination:      pkt.Destination,
		timeout:          calculateTimeout(pkt),
		timeoutCheckDone: make(chan bool, 1),
	}

	go receipt.timeoutWatchdog()
	
	debug.Log(debug.DEBUG_PACKETS, "Created packet receipt", "hash", fmt.Sprintf("%x", receipt.truncatedHash))
	return receipt
}

func calculateTimeout(pkt *Packet) time.Duration {
	baseTimeout := 15 * time.Second
	
	if pkt.Hops > 0 {
		baseTimeout += time.Duration(pkt.Hops) * (3 * time.Second)
	}
	
	return baseTimeout
}

func (pr *PacketReceipt) GetStatus() byte {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	return pr.status
}

func (pr *PacketReceipt) GetHash() []byte {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	return pr.hash
}

func (pr *PacketReceipt) IsDelivered() bool {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	return pr.status == RECEIPT_DELIVERED
}

func (pr *PacketReceipt) IsFailed() bool {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	return pr.status == RECEIPT_FAILED
}

func (pr *PacketReceipt) ValidateProofPacket(proofPacket *Packet) bool {
	if proofPacket.Link != nil {
		return pr.ValidateLinkProof(proofPacket.Data, proofPacket.Link, proofPacket)
	}
	return pr.ValidateProof(proofPacket.Data, proofPacket)
}

func (pr *PacketReceipt) ValidateLinkProof(proof []byte, link interface{}, proofPacket *Packet) bool {
	if len(proof) == EXPL_LENGTH {
		proofHash := proof[:identity.HASHLENGTH/8]
		signature := proof[identity.HASHLENGTH/8 : identity.HASHLENGTH/8+identity.SIGLENGTH/8]
		
		pr.mutex.RLock()
		hashMatch := string(proofHash) == string(pr.hash)
		pr.mutex.RUnlock()
		
		if !hashMatch {
			return false
		}

		proofValid := pr.validateLinkSignature(signature, link)
		if proofValid {
			pr.mutex.Lock()
			pr.status = RECEIPT_DELIVERED
			pr.proved = true
			pr.concludedAt = time.Now()
			pr.proofPacket = proofPacket
			callback := pr.deliveryCallback
			pr.mutex.Unlock()

			if callback != nil {
				go callback(pr)
			}

			debug.Log(debug.DEBUG_PACKETS, "Link proof validated", "hash", fmt.Sprintf("%x", pr.truncatedHash))
			return true
		}
	} else if len(proof) == IMPL_LENGTH {
		debug.Log(debug.DEBUG_TRACE, "Implicit link proof not yet implemented")
	}
	
	return false
}

func (pr *PacketReceipt) ValidateProof(proof []byte, proofPacket *Packet) bool {
	if len(proof) == EXPL_LENGTH {
		proofHash := proof[:identity.HASHLENGTH/8]
		signature := proof[identity.HASHLENGTH/8 : identity.HASHLENGTH/8+identity.SIGLENGTH/8]
		
		pr.mutex.RLock()
		hashMatch := string(proofHash) == string(pr.hash)
		ident := pr.destinationIdent
		pr.mutex.RUnlock()
		
		debug.Log(debug.DEBUG_PACKETS, "Explicit proof validation", "len", len(proof), "hashMatch", hashMatch, "hasIdent", ident != nil)
		
		if !hashMatch {
			debug.Log(debug.DEBUG_PACKETS, "Proof hash mismatch")
			return false
		}

		if ident == nil {
			debug.Log(debug.DEBUG_VERBOSE, "Cannot validate proof without destination identity")
			return false
		}

		proofValid := ident.Verify(pr.hash, signature)
		debug.Log(debug.DEBUG_PACKETS, "Signature verification result", "valid", proofValid)
		if proofValid {
			pr.mutex.Lock()
			pr.status = RECEIPT_DELIVERED
			pr.proved = true
			pr.concludedAt = time.Now()
			pr.proofPacket = proofPacket
			callback := pr.deliveryCallback
			pr.mutex.Unlock()

			if callback != nil {
				go callback(pr)
			}

			debug.Log(debug.DEBUG_PACKETS, "Proof validated", "hash", fmt.Sprintf("%x", pr.truncatedHash))
			return true
		}
	} else if len(proof) == IMPL_LENGTH {
		signature := proof[:identity.SIGLENGTH/8]
		
		pr.mutex.RLock()
		ident := pr.destinationIdent
		pr.mutex.RUnlock()

		if ident == nil {
			return false
		}

		proofValid := ident.Verify(pr.hash, signature)
		if proofValid {
			pr.mutex.Lock()
			pr.status = RECEIPT_DELIVERED
			pr.proved = true
			pr.concludedAt = time.Now()
			pr.proofPacket = proofPacket
			callback := pr.deliveryCallback
			pr.mutex.Unlock()

			if callback != nil {
				go callback(pr)
			}

			debug.Log(debug.DEBUG_PACKETS, "Implicit proof validated", "hash", fmt.Sprintf("%x", pr.truncatedHash))
			return true
		}
	}
	
	return false
}

func (pr *PacketReceipt) validateLinkSignature(signature []byte, link interface{}) bool {
	type linkValidator interface {
		Validate(signature, message []byte) bool
	}
	
	if validator, ok := link.(linkValidator); ok {
		return validator.Validate(signature, pr.hash)
	}
	
	debug.Log(debug.DEBUG_TRACE, "Link does not implement Validate method")
	return false
}

func (pr *PacketReceipt) GetRTT() time.Duration {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	if pr.concludedAt.IsZero() {
		return 0
	}
	
	return pr.concludedAt.Sub(pr.sentAt)
}

func (pr *PacketReceipt) IsTimedOut() bool {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	return time.Since(pr.sentAt) > pr.timeout
}

func (pr *PacketReceipt) checkTimeout() {
	pr.mutex.Lock()
	
	if pr.status != RECEIPT_SENT {
		pr.mutex.Unlock()
		return
	}
	
	if !pr.IsTimedOut() {
		pr.mutex.Unlock()
		return
	}
	
	if pr.timeout < 0 {
		pr.status = RECEIPT_CULLED
	} else {
		pr.status = RECEIPT_FAILED
	}
	
	pr.concludedAt = time.Now()
	callback := pr.timeoutCallback
	pr.mutex.Unlock()

	debug.Log(debug.DEBUG_VERBOSE, "Packet receipt timed out", "hash", fmt.Sprintf("%x", pr.truncatedHash))
	
	if callback != nil {
		go callback(pr)
	}
}

func (pr *PacketReceipt) timeoutWatchdog() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pr.checkTimeout()
			
			pr.mutex.RLock()
			status := pr.status
			pr.mutex.RUnlock()
			
			if status != RECEIPT_SENT {
				return
			}
		case <-pr.timeoutCheckDone:
			return
		}
	}
}

func (pr *PacketReceipt) SetTimeout(timeout time.Duration) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	pr.timeout = timeout
}

func (pr *PacketReceipt) SetDeliveryCallback(callback func(*PacketReceipt)) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	pr.deliveryCallback = callback
}

func (pr *PacketReceipt) SetTimeoutCallback(callback func(*PacketReceipt)) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	pr.timeoutCallback = callback
}

func (pr *PacketReceipt) SetDestinationIdentity(ident *identity.Identity) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	pr.destinationIdent = ident
}

func (pr *PacketReceipt) SetLink(link interface{}) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	pr.link = link
}

func (pr *PacketReceipt) Cancel() {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	
	if pr.status == RECEIPT_SENT {
		pr.status = RECEIPT_CULLED
		pr.concludedAt = time.Now()
	}
	
	select {
	case pr.timeoutCheckDone <- true:
	default:
	}
}

