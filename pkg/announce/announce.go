package announce

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

const (
	ANNOUNCE_NONE     = 0x00
	ANNOUNCE_PATH     = 0x01
	ANNOUNCE_IDENTITY = 0x02

	MAX_HOPS         = 128
	PROPAGATION_RATE = 0.02 // 2% of interface bandwidth
	RETRY_INTERVAL   = 300  // 5 minutes
	MAX_RETRIES      = 3
)

type AnnounceHandler interface {
	AspectFilter() []string
	ReceivedAnnounce(destinationHash []byte, announcedIdentity *identity.Identity, appData []byte) error
	ReceivePathResponses() bool
}

type Announce struct {
	mutex           sync.RWMutex
	destinationHash []byte
	identity       *identity.Identity
	appData        []byte
	hops           uint8
	timestamp      int64
	signature      []byte
	pathResponse   bool
	retries        int
	handlers       []AnnounceHandler
}

func New(dest *identity.Identity, appData []byte, pathResponse bool) (*Announce, error) {
	a := &Announce{
		identity:     dest,
		appData:      appData,
		hops:         0,
		timestamp:    time.Now().Unix(),
		pathResponse: pathResponse,
		retries:      0,
		handlers:     make([]AnnounceHandler, 0),
	}

	// Generate destination hash
	hash := sha256.New()
	hash.Write(dest.GetPublicKey())
	a.destinationHash = hash.Sum(nil)[:16] // Truncated hash

	// Sign the announce
	signData := append(a.destinationHash, a.appData...)
	a.signature = dest.Sign(signData)

	return a, nil
}

func (a *Announce) Propagate(interfaces []transport.Interface) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.hops >= MAX_HOPS {
		return errors.New("maximum hop count reached")
	}

	// Increment hop count
	a.hops++

	// Create announce packet
	packet := make([]byte, 0)
	packet = append(packet, a.destinationHash...)
	packet = append(packet, a.identity.GetPublicKey()...)
	packet = append(packet, byte(a.hops))
	
	if a.appData != nil {
		packet = append(packet, a.appData...)
	}
	
	packet = append(packet, a.signature...)

	// Propagate to all interfaces
	for _, iface := range interfaces {
		if err := iface.SendAnnounce(packet, a.pathResponse); err != nil {
			return err
		}
	}

	return nil
}

func (a *Announce) RegisterHandler(handler AnnounceHandler) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.handlers = append(a.handlers, handler)
}

func (a *Announce) DeregisterHandler(handler AnnounceHandler) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	for i, h := range a.handlers {
		if h == handler {
			a.handlers = append(a.handlers[:i], a.handlers[i+1:]...)
			break
		}
	}
}

func (a *Announce) HandleAnnounce(data []byte) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Validate announce data
	if len(data) < 16+32+1 { // Min size: hash + pubkey + hops
		return errors.New("invalid announce data")
	}

	// Extract fields
	destHash := data[:16]
	pubKey := data[16:48]
	hops := data[48]
	appData := data[49 : len(data)-64]
	signature := data[len(data)-64:]

	// Verify signature
	signData := append(destHash, appData...)
	if !a.identity.Verify(signData, signature) {
		return errors.New("invalid announce signature")
	}

	// Process announce with registered handlers
	for _, handler := range a.handlers {
		if handler.ReceivePathResponses() || !a.pathResponse {
			if err := handler.ReceivedAnnounce(destHash, a.identity, appData); err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *Announce) RequestPath(destHash []byte, onInterface transport.Interface) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Create path request packet
	packet := make([]byte, 0)
	packet = append(packet, destHash...)
	packet = append(packet, byte(0)) // Initial hop count

	// Send path request
	if err := onInterface.SendPathRequest(packet); err != nil {
		return err
	}

	return nil
} 