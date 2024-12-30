package destination

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

const (
	IN  = 0x01
	OUT = 0x02

	SINGLE = 0x00
	GROUP  = 0x01
	PLAIN  = 0x02

	PROVE_NONE = 0x00
	PROVE_ALL  = 0x01
	PROVE_APP  = 0x02

	ALLOW_NONE = 0x00
	ALLOW_ALL  = 0x01
	ALLOW_LIST = 0x02

	RATCHET_COUNT    = 512  // Default number of retained ratchet keys
	RATCHET_INTERVAL = 1800 // Minimum interval between ratchet rotations in seconds
)

type PacketCallback = common.PacketCallback
type ProofRequestedCallback = common.ProofRequestedCallback
type LinkEstablishedCallback = common.LinkEstablishedCallback

type RequestHandler struct {
	Path              string
	ResponseGenerator func(path string, data []byte, requestID []byte, linkID []byte, remoteIdentity *identity.Identity, requestedAt int64) []byte
	AllowMode         byte
	AllowedList       [][]byte
}

type Destination struct {
	identity        *identity.Identity
	direction       byte
	destType        byte
	appName         string
	aspects         []string
	hash           []byte
	
	acceptsLinks    bool
	proofStrategy   byte
	
	packetCallback  PacketCallback
	proofCallback   ProofRequestedCallback
	linkCallback    LinkEstablishedCallback
	
	ratchetsEnabled bool
	ratchetPath     string
	ratchetCount    int
	ratchetInterval int
	enforceRatchets bool
	
	defaultAppData  []byte
	mutex          sync.RWMutex

	requestHandlers map[string]*RequestHandler
	callbacks      struct {
		packetReceived    common.PacketCallback
		proofRequested    common.ProofRequestedCallback
		linkEstablished   common.LinkEstablishedCallback
	}
}

func New(id *identity.Identity, direction byte, destType byte, appName string, aspects ...string) (*Destination, error) {
	if id == nil {
		return nil, errors.New("identity cannot be nil")
	}

	d := &Destination{
		identity:        id,
		direction:       direction,
		destType:        destType,
		appName:         appName,
		aspects:         aspects,
		acceptsLinks:    false,
		proofStrategy:   PROVE_NONE,
		ratchetCount:    RATCHET_COUNT,
		ratchetInterval: RATCHET_INTERVAL,
		requestHandlers: make(map[string]*RequestHandler),
	}

	// Generate destination hash
	d.hash = d.Hash()
	
	return d, nil
}

func (d *Destination) Hash() []byte {
	nameHash := sha256.Sum256([]byte(d.ExpandName()))
	identityHash := sha256.Sum256(d.identity.GetPublicKey())
	
	combined := append(nameHash[:], identityHash[:]...)
	finalHash := sha256.Sum256(combined)
	
	return finalHash[:16] // Truncated to 128 bits
}

func (d *Destination) ExpandName() string {
	name := d.appName
	for _, aspect := range d.aspects {
		name += "." + aspect
	}
	return name
}

func (d *Destination) Announce(appData []byte) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// If no specific appData provided, use default
	if appData == nil {
		appData = d.defaultAppData
	}

	// Create announce packet
	packet := make([]byte, 0)

	// Add destination hash
	packet = append(packet, d.hash...)

	// Add identity public key
	packet = append(packet, d.identity.GetPublicKey()...)

	// Add flags byte
	flags := byte(0)
	if d.acceptsLinks {
		flags |= 0x01
	}
	if d.ratchetsEnabled {
		flags |= 0x02
	}
	packet = append(packet, flags)

	// Add proof strategy
	packet = append(packet, d.proofStrategy)

	// Add app data length and data if present
	if appData != nil {
		appDataLen := uint16(len(appData))
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, appDataLen)
		packet = append(packet, lenBytes...)
		packet = append(packet, appData...)
	} else {
		// No app data
		packet = append(packet, 0x00, 0x00)
	}

	// Add ratchet data if enabled
	if d.ratchetsEnabled {
		// Add ratchet interval
		intervalBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(intervalBytes, uint32(d.ratchetInterval))
		packet = append(packet, intervalBytes...)

		// Add current ratchet key
		ratchetKey := d.identity.GetCurrentRatchetKey()
		if ratchetKey == nil {
			return errors.New("failed to get current ratchet key")
		}
		packet = append(packet, ratchetKey...)
	}

	// Sign the announce packet
	signature, err := d.Sign(packet)
	if err != nil {
		return fmt.Errorf("failed to sign announce packet: %w", err)
	}
	packet = append(packet, signature...)

	// Send announce packet through transport layer
	// This will need to be implemented in the transport package
	return transport.SendAnnounce(packet)
}

func (d *Destination) AcceptsLinks(accepts bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.acceptsLinks = accepts
}

func (d *Destination) SetLinkEstablishedCallback(callback common.LinkEstablishedCallback) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.linkCallback = callback
}

func (d *Destination) SetPacketCallback(callback common.PacketCallback) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.packetCallback = callback
}

func (d *Destination) SetProofRequestedCallback(callback common.ProofRequestedCallback) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.proofCallback = callback
}

func (d *Destination) SetProofStrategy(strategy byte) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.proofStrategy = strategy
}

func (d *Destination) EnableRatchets(path string) bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	
	d.ratchetsEnabled = true
	d.ratchetPath = path
	return true
}

func (d *Destination) EnforceRatchets() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.enforceRatchets = true
}

func (d *Destination) SetRetainedRatchets(count int) bool {
	if count < 1 {
		return false
	}
	
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.ratchetCount = count
	return true
}

func (d *Destination) SetRatchetInterval(interval int) bool {
	if interval < 1 {
		return false
	}
	
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.ratchetInterval = interval
	return true
}

func (d *Destination) SetDefaultAppData(data []byte) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.defaultAppData = data
}

func (d *Destination) ClearDefaultAppData() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.defaultAppData = nil
}

func (d *Destination) RegisterRequestHandler(path string, responseGen func(string, []byte, []byte, []byte, *identity.Identity, int64) []byte, allow byte, allowedList [][]byte) error {
	if path == "" {
		return errors.New("path cannot be empty")
	}

	if allow != ALLOW_NONE && allow != ALLOW_ALL && allow != ALLOW_LIST {
		return errors.New("invalid allow mode")
	}

	if allow == ALLOW_LIST && (allowedList == nil || len(allowedList) == 0) {
		return errors.New("allowed list required for ALLOW_LIST mode")
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.requestHandlers[path] = &RequestHandler{
		Path:              path,
		ResponseGenerator: responseGen,
		AllowMode:         allow,
		AllowedList:       allowedList,
	}

	return nil
}

func (d *Destination) DeregisterRequestHandler(path string) bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, exists := d.requestHandlers[path]; exists {
		delete(d.requestHandlers, path)
		return true
	}
	return false
}

func (d *Destination) Encrypt(plaintext []byte) ([]byte, error) {
	if d.destType == PLAIN {
		return plaintext, nil
	}

	if d.identity == nil {
		return nil, errors.New("no identity available for encryption")
	}

	switch d.destType {
	case SINGLE:
		return d.identity.Encrypt(plaintext, nil)
	case GROUP:
		return d.identity.EncryptSymmetric(plaintext)
	default:
		return nil, errors.New("unsupported destination type for encryption")
	}
}

func (d *Destination) Decrypt(ciphertext []byte) ([]byte, error) {
	if d.destType == PLAIN {
		return ciphertext, nil
	}

	if d.identity == nil {
		return nil, errors.New("no identity available for decryption")
	}

	switch d.destType {
	case SINGLE:
		return d.identity.Decrypt(ciphertext, nil)
	case GROUP:
		return d.identity.DecryptSymmetric(ciphertext)
	default:
		return nil, errors.New("unsupported destination type for decryption")
	}
}

func (d *Destination) Sign(data []byte) ([]byte, error) {
	if d.identity == nil {
		return nil, errors.New("no identity available")
	}
	signature := d.identity.Sign(data)
	return signature, nil
} 