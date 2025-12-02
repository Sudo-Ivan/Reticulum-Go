package link

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/channel"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/cryptography"
	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/pathfinder"
	"github.com/Sudo-Ivan/reticulum-go/pkg/resolver"
	"github.com/Sudo-Ivan/reticulum-go/pkg/resource"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	CURVE = "Curve25519"

	ECPUBSIZE     = 64
	KEYSIZE       = 32
	LINK_MTU_SIZE = 3
	MTU_BYTEMASK  = 0xFFFFFF
	MODE_BYTEMASK = 0xE0

	ESTABLISHMENT_TIMEOUT_PER_HOP = 6
	KEEPALIVE_TIMEOUT_FACTOR      = 4
	STALE_GRACE                   = 2
	KEEPALIVE                     = 360
	STALE_TIME                    = 720
	TRAFFIC_TIMEOUT_FACTOR        = 6

	ACCEPT_NONE = 0x00
	ACCEPT_ALL  = 0x01
	ACCEPT_APP  = 0x02

	STATUS_PENDING   = 0x00
	STATUS_HANDSHAKE = 0x01
	STATUS_ACTIVE    = 0x02
	STATUS_STALE     = 0x03
	STATUS_CLOSED    = 0x04
	STATUS_FAILED    = 0x05

	PROVE_NONE = 0x00
	PROVE_ALL  = 0x01
	PROVE_APP  = 0x02

	MODE_AES128_CBC = 0x00
	MODE_AES256_CBC = 0x01
	MODE_DEFAULT    = MODE_AES256_CBC

	WATCHDOG_MIN_SLEEP = 0.025
	WATCHDOG_INTERVAL  = 0.1
)

func init() {
	destination.RegisterIncomingLinkHandler(func(pkt *packet.Packet, dest *destination.Destination, trans interface{}, networkIface common.NetworkInterface) (interface{}, error) {
		transportObj, ok := trans.(*transport.Transport)
		if !ok {
			return nil, errors.New("invalid transport type")
		}
		return HandleIncomingLinkRequest(pkt, dest, transportObj, networkIface)
	})
}

type Link struct {
	mutex            sync.RWMutex
	destination      *destination.Destination
	status           byte
	networkInterface common.NetworkInterface
	establishedAt    time.Time
	lastInbound      time.Time
	lastOutbound     time.Time
	lastDataReceived time.Time
	lastDataSent     time.Time
	pathFinder       *pathfinder.PathFinder

	remoteIdentity *identity.Identity
	sessionKey     []byte
	linkID         []byte

	rtt               float64
	establishmentRate float64

	establishedCallback func(*Link)
	closedCallback      func(*Link)
	packetCallback      func([]byte, *packet.Packet)
	identifiedCallback  func(*Link, *identity.Identity)

	teardownReason byte
	hmacKey        []byte
	transport      *transport.Transport

	rssi                      float64
	snr                       float64
	q                         float64
	resourceCallback          func(interface{}) bool
	resourceStartedCallback   func(interface{})
	resourceConcludedCallback func(interface{})
	resourceStrategy          byte
	proofStrategy             byte
	proofCallback             func(*packet.Packet) bool
	trackPhyStats             bool

	watchdogLock         bool
	watchdogActive       bool
	establishmentTimeout time.Duration
	keepalive            time.Duration
	staleTime            time.Duration
	initiator            bool

	prv           []byte
	sigPriv       ed25519.PrivateKey
	pub           []byte
	sigPub        ed25519.PublicKey
	peerPub       []byte
	peerSigPub    ed25519.PublicKey
	sharedKey     []byte
	derivedKey    []byte
	mode          byte
	mtu           int
	mdu           int
	requestTime   time.Time
	requestPacket *packet.Packet

	pendingRequests []*RequestReceipt
	requestMutex    sync.RWMutex

	channel      *channel.Channel
	channelMutex sync.RWMutex
}

func NewLink(dest *destination.Destination, transport *transport.Transport, networkIface common.NetworkInterface, establishedCallback func(*Link), closedCallback func(*Link)) *Link {
	return &Link{
		destination:         dest,
		status:              STATUS_PENDING,
		transport:           transport,
		networkInterface:    networkIface,
		establishedCallback: establishedCallback,
		closedCallback:      closedCallback,
		establishedAt:       time.Time{}, // Zero time until established
		lastInbound:         time.Time{},
		lastOutbound:        time.Time{},
		lastDataReceived:    time.Time{},
		lastDataSent:        time.Time{},
		pathFinder:          pathfinder.NewPathFinder(),

		watchdogLock:         false,
		watchdogActive:       false,
		establishmentTimeout: time.Duration(ESTABLISHMENT_TIMEOUT_PER_HOP * float64(time.Second)),
		keepalive:            time.Duration(KEEPALIVE * float64(time.Second)),
		staleTime:            time.Duration(STALE_TIME * float64(time.Second)),
		initiator:            false,
		pendingRequests:      make([]*RequestReceipt, 0),
	}
}

func HandleIncomingLinkRequest(pkt *packet.Packet, dest *destination.Destination, transport *transport.Transport, networkIface common.NetworkInterface) (*Link, error) {
	debug.Log(debug.DEBUG_INFO, "Creating link for incoming request", "dest_hash", fmt.Sprintf("%x", dest.GetHash()))

	l := NewLink(dest, transport, networkIface, nil, nil)
	l.status = STATUS_PENDING
	l.initiator = false // This is a responder link

	ownerIdentity := dest.GetIdentity()
	if ownerIdentity == nil {
		return nil, errors.New("destination has no identity")
	}

	if err := l.HandleLinkRequest(pkt, ownerIdentity); err != nil {
		debug.Log(debug.DEBUG_ERROR, "Failed to handle link request", "error", err)
		return nil, err
	}

	go l.startWatchdog()

	debug.Log(debug.DEBUG_INFO, "Link established for incoming request", "link_id", fmt.Sprintf("%x", l.linkID))
	return l, nil
}

func (l *Link) Establish() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_PENDING {
		debug.Log(debug.DEBUG_INFO, "Cannot establish link: invalid status", "status", l.status)
		return errors.New("link already established or failed")
	}

	if l.destination == nil {
		return errors.New("destination is nil")
	}

	l.initiator = true
	l.status = STATUS_PENDING
	l.requestTime = time.Now()

	if err := l.SendLinkRequest(); err != nil {
		return err
	}

	if l.transport != nil {
		l.transport.RegisterLink(l.linkID, l)
	}

	go l.startWatchdog()

	return nil
}

func (l *Link) Identify(id *identity.Identity) error {
	if !l.IsActive() {
		return errors.New("link not active")
	}

	p := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextLinkIdentify,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: l.destination.GetType(),
		DestinationHash: l.destination.GetHash(),
		Data:            id.GetPublicKey(),
		CreateReceipt:   true,
	}

	if err := p.Pack(); err != nil {
		return err
	}

	return l.transport.SendPacket(p)
}

func (l *Link) HandleIdentification(data []byte) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if len(data) < ed25519.PublicKeySize+ed25519.SignatureSize {
		debug.Log(debug.DEBUG_INFO, "Invalid identification data length", "length", len(data))
		return errors.New("invalid identification data length")
	}

	pubKey := data[:ed25519.PublicKeySize]
	signature := data[ed25519.PublicKeySize:]

	debug.Log(debug.DEBUG_VERBOSE, "Processing identification from public key", "public_key", fmt.Sprintf("%x", pubKey[:8]))

	remoteIdentity := identity.FromPublicKey(pubKey)
	if remoteIdentity == nil {
		debug.Log(debug.DEBUG_INFO, "Invalid remote identity from public key", "public_key", fmt.Sprintf("%x", pubKey[:8]))
		return errors.New("invalid remote identity")
	}

	signData := append(l.linkID, pubKey...)
	if !remoteIdentity.Verify(signData, signature) {
		debug.Log(debug.DEBUG_INFO, "Invalid signature from remote identity", "public_key", fmt.Sprintf("%x", pubKey[:8]))
		return errors.New("invalid signature")
	}

	debug.Log(debug.DEBUG_VERBOSE, "Remote identity verified successfully", "public_key", fmt.Sprintf("%x", pubKey[:8]))
	l.remoteIdentity = remoteIdentity

	if l.identifiedCallback != nil {
		debug.Log(debug.DEBUG_VERBOSE, "Executing identified callback for remote identity", "public_key", fmt.Sprintf("%x", pubKey[:8]))
		l.identifiedCallback(l, remoteIdentity)
	}

	return nil
}

func (l *Link) Request(path string, data []byte, timeout time.Duration) (*RequestReceipt, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_ACTIVE {
		return nil, errors.New("link not active")
	}

	pathHash := identity.TruncatedHash([]byte(path))
	requestData := []interface{}{time.Now().Unix(), pathHash, data}
	packedRequest, err := msgpack.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to pack request: %w", err)
	}

	if timeout <= 0 {
		timeout = time.Duration(l.rtt*TRAFFIC_TIMEOUT_FACTOR*float64(time.Second)) + time.Duration(resource.RESPONSE_MAX_GRACE_TIME*1.125*float64(time.Second))
	}

	requestID := identity.TruncatedHash(packedRequest)

	if len(packedRequest) <= l.mdu {
		reqPkt := &packet.Packet{
			HeaderType:      packet.HeaderType1,
			PacketType:      packet.PacketTypeData,
			TransportType:   0,
			Context:         packet.ContextRequest,
			ContextFlag:     packet.FlagUnset,
			Hops:            0,
			DestinationType: 0x03,
			DestinationHash: l.linkID,
			Data:            packedRequest,
			CreateReceipt:   false,
		}

		if err := reqPkt.Pack(); err != nil {
			return nil, err
		}

		encrypted, err := l.encrypt(packedRequest)
		if err != nil {
			return nil, err
		}

		reqPkt.Data = encrypted
		if err := reqPkt.Pack(); err != nil {
			return nil, err
		}

		if err := l.transport.SendPacket(reqPkt); err != nil {
			return nil, err
		}

		receipt := &RequestReceipt{
			link:      l,
			requestID: requestID,
			status:    STATUS_PENDING,
			sentAt:    time.Now(),
			timeout:   timeout,
		}

		l.requestMutex.Lock()
		l.pendingRequests = append(l.pendingRequests, receipt)
		l.requestMutex.Unlock()

		go receipt.startTimeout()

		return receipt, nil
	}

	return nil, errors.New("request too large, resource transfer not yet implemented")
}

type RequestReceipt struct {
	link       *Link
	mutex      sync.RWMutex
	requestID  []byte
	status     byte
	sentAt     time.Time
	receivedAt time.Time
	response   []byte
	timeout    time.Duration
	responseCb func(*RequestReceipt)
	failedCb   func(*RequestReceipt)
	progressCb func(*RequestReceipt)
}

func (r *RequestReceipt) GetRequestID() []byte {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return append([]byte{}, r.requestID...)
}

func (r *RequestReceipt) GetStatus() byte {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.status
}

func (r *RequestReceipt) GetResponse() []byte {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	if r.response == nil {
		return nil
	}
	return append([]byte{}, r.response...)
}

func (r *RequestReceipt) GetResponseTime() float64 {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	if r.receivedAt.IsZero() {
		return 0
	}
	return r.receivedAt.Sub(r.sentAt).Seconds()
}

func (r *RequestReceipt) Concluded() bool {
	status := r.GetStatus()
	return status == STATUS_ACTIVE || status == STATUS_FAILED
}

func (r *RequestReceipt) startTimeout() {
	time.Sleep(r.timeout)
	r.mutex.Lock()
	if r.status == STATUS_PENDING {
		r.status = STATUS_FAILED
		if r.failedCb != nil {
			go r.failedCb(r)
		}
	}
	r.mutex.Unlock()
}

func (r *RequestReceipt) SetResponseCallback(cb func(*RequestReceipt)) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.responseCb = cb
}

func (r *RequestReceipt) SetFailedCallback(cb func(*RequestReceipt)) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.failedCb = cb
}

func (r *RequestReceipt) SetProgressCallback(cb func(*RequestReceipt)) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.progressCb = cb
}

func (l *Link) TrackPhyStats(track bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.trackPhyStats = track
}

func (l *Link) UpdatePhyStats(rssi, snr, q float64) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.trackPhyStats {
		l.rssi = rssi
		l.snr = snr
		l.q = q
	}
}

func (l *Link) GetRSSI() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if !l.trackPhyStats {
		return 0
	}
	return l.rssi
}

func (l *Link) GetSNR() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if !l.trackPhyStats {
		return 0
	}
	return l.snr
}

func (l *Link) GetQ() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if !l.trackPhyStats {
		return 0
	}
	return l.q
}

func (l *Link) GetEstablishmentRate() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.establishmentRate
}

func (l *Link) GetAge() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if l.establishedAt.IsZero() {
		return 0
	}
	return time.Since(l.establishedAt).Seconds()
}

func (l *Link) NoInboundFor() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if l.lastInbound.IsZero() {
		return 0
	}
	return time.Since(l.lastInbound).Seconds()
}

func (l *Link) NoOutboundFor() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if l.lastOutbound.IsZero() {
		return 0
	}
	return time.Since(l.lastOutbound).Seconds()
}

func (l *Link) NoDataFor() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	lastData := l.lastDataReceived
	if l.lastDataSent.After(lastData) {
		lastData = l.lastDataSent
	}
	if lastData.IsZero() {
		return 0
	}
	return time.Since(lastData).Seconds()
}

func (l *Link) InactiveFor() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	lastActivity := l.lastInbound
	if l.lastOutbound.After(lastActivity) {
		lastActivity = l.lastOutbound
	}
	if lastActivity.IsZero() {
		return 0
	}
	return time.Since(lastActivity).Seconds()
}

func (l *Link) GetRemoteIdentity() *identity.Identity {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.remoteIdentity
}

func (l *Link) Teardown() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status == STATUS_ACTIVE {
		l.status = STATUS_CLOSED
		if l.closedCallback != nil {
			l.closedCallback(l)
		}
	}
}

func (l *Link) SetLinkClosedCallback(callback func(*Link)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.closedCallback = callback
}

func (l *Link) SetPacketCallback(callback func([]byte, *packet.Packet)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.packetCallback = callback
}

func (l *Link) SetResourceCallback(callback func(interface{}) bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceCallback = callback
}

func (l *Link) SetResourceStartedCallback(callback func(interface{})) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceStartedCallback = callback
}

func (l *Link) SetResourceConcludedCallback(callback func(interface{})) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceConcludedCallback = callback
}

func (l *Link) SetRemoteIdentifiedCallback(callback func(*Link, *identity.Identity)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.identifiedCallback = callback
}

func (l *Link) SetResourceStrategy(strategy byte) error {
	if strategy != ACCEPT_NONE && strategy != ACCEPT_ALL && strategy != ACCEPT_APP {
		return errors.New("unsupported resource strategy")
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceStrategy = strategy
	return nil
}

func (l *Link) SendPacket(data []byte) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_ACTIVE {
		debug.Log(debug.DEBUG_INFO, "Cannot send packet: link not active", "status", l.status)
		return errors.New("link not active")
	}

	debug.Log(debug.DEBUG_VERBOSE, "Encrypting packet", "bytes", len(data))
	encrypted, err := l.encrypt(data)
	if err != nil {
		debug.Log(debug.DEBUG_INFO, "Failed to encrypt packet", "error", err)
		return err
	}

	p := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextNone,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: l.destination.GetType(),
		DestinationHash: l.destination.GetHash(),
		Data:            encrypted,
		CreateReceipt:   false,
	}

	if err := p.Pack(); err != nil {
		return err
	}

	debug.Log(debug.DEBUG_VERBOSE, "Sending encrypted packet", "bytes", len(encrypted))
	l.lastOutbound = time.Now()
	l.lastDataSent = time.Now()

	return l.transport.SendPacket(p)
}

func (l *Link) HandleInbound(pkt *packet.Packet) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.watchdogLock = true
	defer func() {
		l.watchdogLock = false
	}()

	if l.status == STATUS_CLOSED {
		return errors.New("link is closed")
	}

	l.lastInbound = time.Now()
	if pkt.Context != packet.ContextKeepalive {
		l.lastDataReceived = time.Now()
	}

	if l.status == STATUS_STALE {
		l.status = STATUS_ACTIVE
	}

	if pkt.PacketType == packet.PacketTypeData {
		return l.handleDataPacket(pkt)
	} else if pkt.PacketType == packet.PacketTypeProof {
		if pkt.Context == packet.ContextLRProof {
			return l.handleLinkProof(pkt)
		} else if pkt.Context == packet.ContextLRRTT {
			return l.handleRTTPacket(pkt)
		}
	}

	return nil
}

func (l *Link) handleDataPacket(pkt *packet.Packet) error {
	if l.status != STATUS_ACTIVE && l.status != STATUS_HANDSHAKE {
		return errors.New("link not active")
	}

	var plaintext []byte
	var err error

	if l.sessionKey != nil {
		plaintext, err = l.decrypt(pkt.Data)
		if err != nil {
			debug.Log(debug.DEBUG_INFO, "Failed to decrypt packet", "error", err)
			return err
		}
	} else {
		plaintext = pkt.Data
	}

	switch pkt.Context {
	case packet.ContextNone:
		if l.packetCallback != nil {
			l.packetCallback(plaintext, pkt)
		}
	case packet.ContextRequest:
		return l.handleRequest(plaintext, pkt)
	case packet.ContextResponse:
		return l.handleResponse(plaintext)
	case packet.ContextLinkIdentify:
		return l.HandleIdentification(plaintext)
	case packet.ContextKeepalive:
		if !l.initiator && len(plaintext) == 1 && plaintext[0] == 0xFF {
			keepaliveResp := []byte{0xFE}
			keepalivePkt := &packet.Packet{
				HeaderType:      packet.HeaderType1,
				PacketType:      packet.PacketTypeData,
				TransportType:   0,
				Context:         packet.ContextKeepalive,
				ContextFlag:     packet.FlagUnset,
				Hops:            0,
				DestinationType: 0x03,
				DestinationHash: l.linkID,
				Data:            keepaliveResp,
				CreateReceipt:   false,
			}
			if err := keepalivePkt.Pack(); err != nil {
				return err
			}
			encrypted, err := l.encrypt(keepaliveResp)
			if err != nil {
				return err
			}
			keepalivePkt.Data = encrypted
			if err := keepalivePkt.Pack(); err != nil {
				return err
			}
			l.lastOutbound = time.Now()
			return l.transport.SendPacket(keepalivePkt)
		}
	case packet.ContextLinkClose:
		return l.handleTeardown(plaintext)
	case packet.ContextLRRTT:
		return l.handleRTTPacket(pkt)
	case packet.ContextResourceAdv:
		return l.handleResourceAdvertisement(pkt)
	case packet.ContextResourceReq:
		return l.handleResourceRequest(pkt)
	case packet.ContextResourceHMU:
		return l.handleResourceHashmapUpdate(pkt)
	case packet.ContextResourceICL:
		return l.handleResourceCancel(pkt)
	case packet.ContextResourceRCL:
		return l.handleResourceReject(pkt)
	case packet.ContextResource:
		return l.handleResourcePart(pkt)
	case packet.ContextChannel:
		return l.handleChannelPacket(pkt)
	}

	return nil
}

func (l *Link) GetChannel() *channel.Channel {
	l.channelMutex.Lock()
	defer l.channelMutex.Unlock()

	if l.channel == nil {
		l.channel = channel.NewChannel(l)
	}
	return l.channel
}

func (l *Link) handleChannelPacket(pkt *packet.Packet) error {
	plaintext, err := l.decrypt(pkt.Data)
	if err != nil {
		return err
	}

	l.channelMutex.RLock()
	ch := l.channel
	l.channelMutex.RUnlock()

	if ch != nil {
		return ch.HandleInbound(plaintext)
	}

	return nil
}

func (l *Link) handleResourceAdvertisement(pkt *packet.Packet) error {
	plaintext, err := l.decrypt(pkt.Data)
	if err != nil {
		return err
	}

	adv, err := resource.UnpackResourceAdvertisement(plaintext)
	if err != nil {
		debug.Log(debug.DEBUG_INFO, "Failed to unpack resource advertisement", "error", err)
		return err
	}

	if resource.IsRequestAdvertisement(plaintext) {
		requestID := resource.ReadRequestID(plaintext)
		if l.destination != nil {
			handler := l.destination.GetRequestHandler(requestID)
			if handler != nil {
				response := handler(requestID, nil, requestID, l.remoteIdentity, time.Now())
				if response != nil {
					return l.sendResourceResponse(requestID, response)
				}
			}
		}
		return nil
	}

	if resource.IsResponseAdvertisement(plaintext) {
		requestID := resource.ReadRequestID(plaintext)
		l.requestMutex.Lock()
		for i, req := range l.pendingRequests {
			if string(req.requestID) == string(requestID) {
				req.mutex.Lock()
				req.status = STATUS_ACTIVE
				req.receivedAt = time.Now()
				req.mutex.Unlock()

				if req.responseCb != nil {
					go req.responseCb(req)
				}

				l.pendingRequests = append(l.pendingRequests[:i], l.pendingRequests[i+1:]...)
				break
			}
		}
		l.requestMutex.Unlock()
		return nil
	}

	if l.resourceStrategy == ACCEPT_NONE {
		return nil
	}

	allowed := false
	if l.resourceStrategy == ACCEPT_ALL {
		allowed = true
	} else if l.resourceStrategy == ACCEPT_APP && l.resourceCallback != nil {
		allowed = l.resourceCallback(adv)
	}

	if allowed {
		if l.resourceStartedCallback != nil {
			l.resourceStartedCallback(adv)
		}
	} else {
		_ = l.rejectResource(adv.Hash) // #nosec G104 - best effort resource rejection
		debug.Log(debug.DEBUG_INFO, "Resource advertisement rejected")
	}

	return nil
}

func (l *Link) rejectResource(resourceHash []byte) error {
	rejectPkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextResourceRCL,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: 0x03,
		DestinationHash: l.linkID,
		Data:            resourceHash,
		CreateReceipt:   false,
	}
	encrypted, err := l.encrypt(resourceHash)
	if err != nil {
		return err
	}
	rejectPkt.Data = encrypted
	if err := rejectPkt.Pack(); err != nil {
		return err
	}
	l.lastOutbound = time.Now()
	return l.transport.SendPacket(rejectPkt)
}

func (l *Link) sendResourceResponse(requestID []byte, response interface{}) error {
	resData, ok := response.([]byte)
	if !ok {
		return errors.New("response must be []byte")
	}

	res, err := resource.New(resData, false)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	res.SetRequestID(requestID)
	res.SetIsResponse(true)

	return l.sendResourceAdvertisement(res)
}

func (l *Link) sendResourceAdvertisement(res *resource.Resource) error {
	adv := resource.NewResourceAdvertisement(res)
	if adv == nil {
		return errors.New("failed to create resource advertisement")
	}

	advData, err := adv.Pack(0)
	if err != nil {
		return fmt.Errorf("failed to pack advertisement: %w", err)
	}

	encrypted, err := l.encrypt(advData)
	if err != nil {
		return err
	}

	advPkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextResourceAdv,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: 0x03,
		DestinationHash: l.linkID,
		Data:            encrypted,
		CreateReceipt:   false,
	}

	if err := advPkt.Pack(); err != nil {
		return err
	}

	l.lastOutbound = time.Now()
	return l.transport.SendPacket(advPkt)
}

func (l *Link) handleResourceRequest(pkt *packet.Packet) error {
	plaintext, err := l.decrypt(pkt.Data)
	if err != nil {
		return err
	}

	if l.resourceStartedCallback != nil {
		l.resourceStartedCallback(plaintext)
	}

	return nil
}

func (l *Link) handleResourceHashmapUpdate(pkt *packet.Packet) error {
	plaintext, err := l.decrypt(pkt.Data)
	if err != nil {
		return err
	}

	if l.resourceStartedCallback != nil {
		l.resourceStartedCallback(plaintext)
	}

	return nil
}

func (l *Link) handleResourceCancel(pkt *packet.Packet) error {
	plaintext, err := l.decrypt(pkt.Data)
	if err != nil {
		return err
	}

	if l.resourceConcludedCallback != nil {
		l.resourceConcludedCallback(plaintext)
	}

	return nil
}

func (l *Link) handleResourceReject(pkt *packet.Packet) error {
	plaintext, err := l.decrypt(pkt.Data)
	if err != nil {
		return err
	}

	if l.resourceConcludedCallback != nil {
		l.resourceConcludedCallback(plaintext)
	}

	return nil
}

func (l *Link) handleResourcePart(pkt *packet.Packet) error {
	if l.resourceStartedCallback != nil {
		l.resourceStartedCallback(pkt.Data)
	}

	return nil
}

func (l *Link) handleRequest(plaintext []byte, pkt *packet.Packet) error {
	if l.destination == nil {
		return errors.New("no destination for request handling")
	}

	var requestData []interface{}
	if err := msgpack.Unmarshal(plaintext, &requestData); err != nil {
		return fmt.Errorf("failed to unpack request: %w", err)
	}

	if len(requestData) < 3 {
		return errors.New("invalid request format")
	}

	requestedAt := time.Unix(int64(requestData[0].(int64)), 0)
	pathHash := requestData[1].([]byte)
	requestPayload := requestData[2].([]byte)

	requestID := identity.TruncatedHash(plaintext)

	if l.destination != nil {
		handler := l.destination.GetRequestHandler(pathHash)
		if handler != nil {
			response := handler(pathHash, requestPayload, requestID, l.remoteIdentity, requestedAt)
			if response != nil {
				return l.sendResponse(requestID, response)
			}
		}
	}

	return nil
}

func (l *Link) handleResponse(plaintext []byte) error {
	var responseData []interface{}
	if err := msgpack.Unmarshal(plaintext, &responseData); err != nil {
		return fmt.Errorf("failed to unpack response: %w", err)
	}

	if len(responseData) < 2 {
		return errors.New("invalid response format")
	}

	requestID := responseData[0].([]byte)
	responsePayload := responseData[1].([]byte)

	l.requestMutex.Lock()
	for i, req := range l.pendingRequests {
		if string(req.requestID) == string(requestID) {
			req.mutex.Lock()
			req.status = STATUS_ACTIVE
			req.response = responsePayload
			req.receivedAt = time.Now()
			req.mutex.Unlock()

			if req.responseCb != nil {
				go req.responseCb(req)
			}

			l.pendingRequests = append(l.pendingRequests[:i], l.pendingRequests[i+1:]...)
			break
		}
	}
	l.requestMutex.Unlock()

	return nil
}

func (l *Link) sendResponse(requestID []byte, response interface{}) error {
	responseData := []interface{}{requestID, response}
	packedResponse, err := msgpack.Marshal(responseData)
	if err != nil {
		return fmt.Errorf("failed to pack response: %w", err)
	}

	if len(packedResponse) <= l.mdu {
		encrypted, err := l.encrypt(packedResponse)
		if err != nil {
			return err
		}

		respPkt := &packet.Packet{
			HeaderType:      packet.HeaderType1,
			PacketType:      packet.PacketTypeData,
			TransportType:   0,
			Context:         packet.ContextResponse,
			ContextFlag:     packet.FlagUnset,
			Hops:            0,
			DestinationType: 0x03,
			DestinationHash: l.linkID,
			Data:            encrypted,
			CreateReceipt:   false,
		}

		if err := respPkt.Pack(); err != nil {
			return err
		}

		l.lastOutbound = time.Now()
		l.lastDataSent = time.Now()
		return l.transport.SendPacket(respPkt)
	}

	return errors.New("response too large, resource transfer not yet implemented")
}

func (l *Link) handleRTTPacket(pkt *packet.Packet) error {
	if !l.initiator {
		measuredRTT := time.Since(l.requestTime).Seconds()
		plaintext, err := l.decrypt(pkt.Data)
		if err != nil {
			return err
		}

		var rtt float64
		if len(plaintext) >= 8 {
			rtt = float64(binary.BigEndian.Uint64(plaintext[:8])) / 1e9
		}

		l.rtt = max(measuredRTT, rtt)
		l.status = STATUS_ACTIVE
		l.establishedAt = time.Now()

		if l.transport != nil {
			l.transport.RegisterLink(l.linkID, l)
		}

		if l.rtt > 0 {
			l.updateKeepalive()
		}

		if l.establishedCallback != nil {
			go l.establishedCallback(l)
		}

		debug.Log(debug.DEBUG_INFO, "Link established (responder) after RTT", "link_id", fmt.Sprintf("%x", l.linkID), "rtt", fmt.Sprintf("%.3fs", l.rtt))
	}
	return nil
}

func (l *Link) updateKeepalive() {
	if l.rtt <= 0 {
		return
	}

	keepaliveMaxRTT := 1.75
	keepaliveMax := float64(KEEPALIVE)
	keepaliveMin := 5.0

	calculatedKeepalive := l.rtt * (keepaliveMax / keepaliveMaxRTT)
	if calculatedKeepalive > keepaliveMax {
		calculatedKeepalive = keepaliveMax
	}
	if calculatedKeepalive < keepaliveMin {
		calculatedKeepalive = keepaliveMin
	}

	l.keepalive = time.Duration(calculatedKeepalive * float64(time.Second))
	l.staleTime = time.Duration(float64(l.keepalive) * 2.0)
}

func (l *Link) handleLinkProof(pkt *packet.Packet) error {
	if l.initiator {
		return l.ValidateLinkProof(pkt)
	}
	return nil
}

func (l *Link) handleTeardown(plaintext []byte) error {
	if len(plaintext) == len(l.linkID) && string(plaintext) == string(l.linkID) {
		l.status = STATUS_CLOSED
		if l.initiator {
			l.teardownReason = STATUS_FAILED
		} else {
			l.teardownReason = STATUS_FAILED
		}
		if l.closedCallback != nil {
			l.closedCallback(l)
		}
	}
	return nil
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func (l *Link) encrypt(data []byte) ([]byte, error) {
	if l.sessionKey == nil {
		return nil, errors.New("no session key available")
	}

	block, err := aes.NewCipher(l.sessionKey)
	if err != nil {
		return nil, err
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Add PKCS7 padding
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := make([]byte, len(data)+padding)
	copy(padtext, data)
	for i := len(data); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv) // #nosec G407
	ciphertext := make([]byte, len(padtext))
	mode.CryptBlocks(ciphertext, padtext)

	// Prepend IV to ciphertext
	return append(iv, ciphertext...), nil
}

func (l *Link) decrypt(data []byte) ([]byte, error) {
	if l.sessionKey == nil {
		return nil, errors.New("no session key available")
	}

	block, err := aes.NewCipher(l.sessionKey)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, errors.New("invalid padding")
	}

	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}

	return plaintext[:len(plaintext)-padding], nil
}

func (l *Link) GetRTT() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.rtt
}

func (l *Link) RTT() float64 {
	return l.GetRTT()
}

func (l *Link) SetRTT(rtt float64) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.rtt = rtt
}

func (l *Link) GetStatus() byte {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.status
}

func (l *Link) Send(data []byte) interface{} {
	pkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextChannel,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: 0x03,
		DestinationHash: l.linkID,
		Data:            data,
		CreateReceipt:   false,
	}

	encrypted, err := l.encrypt(data)
	if err != nil {
		return nil
	}
	pkt.Data = encrypted

	if err := pkt.Pack(); err != nil {
		return nil
	}

	l.lastOutbound = time.Now()
	if err := l.transport.SendPacket(pkt); err != nil {
		return nil
	}

	return pkt
}

func (l *Link) SetPacketTimeout(pkt interface{}, callback func(interface{}), timeout time.Duration) {
	if packetObj, ok := pkt.(*packet.Packet); ok {
		go func() {
			time.Sleep(timeout)
			if callback != nil {
				callback(packetObj)
			}
		}()
	}
}

func (l *Link) SetPacketDelivered(pkt interface{}, callback func(interface{})) {
	if callback != nil {
		go callback(pkt)
	}
}

func (l *Link) Resend(pkt interface{}) error {
	packetObj, ok := pkt.(*packet.Packet)
	if !ok {
		return errors.New("invalid packet type")
	}

	if err := l.transport.SendPacket(packetObj); err != nil {
		return err
	}
	return nil
}

func (l *Link) GetLinkID() []byte {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.linkID
}

func (l *Link) IsActive() bool {
	return l.GetStatus() == STATUS_ACTIVE
}

func (l *Link) SendResource(res *resource.Resource) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_ACTIVE {
		l.teardownReason = STATUS_FAILED
		return errors.New("link not active")
	}

	// Activate the resource
	res.Activate()

	// Send the resource data as packets
	buffer := make([]byte, resource.DEFAULT_SEGMENT_SIZE)
	for {
		n, err := res.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			l.teardownReason = STATUS_FAILED
			return fmt.Errorf("error reading resource: %v", err)
		}

		if err := l.SendPacket(buffer[:n]); err != nil {
			l.teardownReason = STATUS_FAILED
			return fmt.Errorf("error sending resource packet: %v", err)
		}
	}

	return nil
}

func (l *Link) maintainLink() {
	ticker := time.NewTicker(time.Second * KEEPALIVE)
	defer ticker.Stop()

	for range ticker.C {
		if l.status != STATUS_ACTIVE {
			return
		}

		inactiveTime := l.InactiveFor()
		if inactiveTime > float64(STALE_TIME) {
			l.mutex.Lock()
			l.teardownReason = STATUS_FAILED
			l.mutex.Unlock()
			l.Teardown()
			return
		}

		noDataTime := l.NoDataFor()
		if noDataTime > float64(KEEPALIVE) {
			l.mutex.Lock()
			err := l.SendPacket([]byte{})
			if err != nil {
				l.teardownReason = STATUS_FAILED
				l.mutex.Unlock()
				l.Teardown()
				return
			}
			l.mutex.Unlock()
		}
	}
}

func (l *Link) Start() {
	go l.maintainLink()
}

func (l *Link) SetProofStrategy(strategy byte) error {
	if strategy != PROVE_NONE && strategy != PROVE_ALL && strategy != PROVE_APP {
		return errors.New("invalid proof strategy")
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.proofStrategy = strategy
	return nil
}

func (l *Link) SetProofCallback(callback func(*packet.Packet) bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.proofCallback = callback
}

func (l *Link) HandleProofRequest(packet *packet.Packet) bool {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	switch l.proofStrategy {
	case PROVE_NONE:
		return false
	case PROVE_ALL:
		return true
	case PROVE_APP:
		if l.proofCallback != nil {
			return l.proofCallback(packet)
		}
		return false
	default:
		return false
	}
}

func (l *Link) decodePacket(data []byte) {
	if len(data) < 1 {
		debug.Log(debug.DEBUG_ALL, "Invalid packet: zero length")
		return
	}

	packetType := data[0]
	debug.Log(debug.DEBUG_ALL, "Packet Analysis", "size", len(data), "type", fmt.Sprintf("0x%02x", packetType))

	switch packetType {
	case packet.PacketTypeData:
		debug.Log(debug.DEBUG_ALL, "Type Description: Data Packet", "payload_size", len(data)-1)

	case packet.PacketTypeLinkReq:
		debug.Log(debug.DEBUG_ALL, "Type Description: Link Management", "link_id", fmt.Sprintf("%x", data[1:33]))

	case packet.PacketTypeAnnounce:
		debug.Log(debug.DEBUG_ALL, "Received announce packet", "bytes", len(data))
		if len(data) < packet.MinAnnounceSize {
			debug.Log(debug.DEBUG_INFO, "Announce packet too short", "bytes", len(data))
			return
		}

		destHash := data[2:18]
		encKey := data[18:50]
		signKey := data[50:82]
		nameHash := data[82:92]
		randomHash := data[92:102]
		signature := data[102:166]
		appData := data[166:]

		pubKey := append(encKey, signKey...)

		validationData := make([]byte, 0, 164)
		validationData = append(validationData, destHash...)
		validationData = append(validationData, encKey...)
		validationData = append(validationData, signKey...)
		validationData = append(validationData, nameHash...)
		validationData = append(validationData, randomHash...)

		if identity.ValidateAnnounce(validationData, destHash, pubKey, signature, appData) {
			debug.Log(debug.DEBUG_VERBOSE, "Valid announce from", "public_key", fmt.Sprintf("%x", pubKey[:8]))
			if err := l.transport.HandleAnnounce(destHash, l.networkInterface); err != nil {
				debug.Log(debug.DEBUG_INFO, "Failed to handle announce", "error", err)
			}
		} else {
			debug.Log(debug.DEBUG_INFO, "Invalid announce signature from", "public_key", fmt.Sprintf("%x", pubKey[:8]))
		}

	case packet.PacketTypeProof:
		debug.Log(debug.DEBUG_ALL, "Type Description: RNS Discovery")
		if len(data) > 17 {
			searchHash := data[1:17]
			debug.Log(debug.DEBUG_ALL, "Searching for Hash", "search_hash", fmt.Sprintf("%x", searchHash))

			if id, err := resolver.ResolveIdentity(hex.EncodeToString(searchHash)); err == nil {
				debug.Log(debug.DEBUG_ALL, "Found matching identity", "identity_hash", id.GetHexHash())
			}
		}

	default:
		debug.Log(debug.DEBUG_ALL, "Type Description: Unknown", "type", fmt.Sprintf("0x%02x", packetType), "raw_hex", fmt.Sprintf("%x", data))
	}
}

func (l *Link) startWatchdog() {
	if l.watchdogActive {
		return
	}

	l.watchdogActive = true
	go l.watchdog()
}

func (l *Link) watchdog() {
	for l.status != STATUS_CLOSED {
		l.mutex.Lock()
		if l.watchdogLock {
			rttWait := 0.025
			if l.rtt > 0 {
				rttWait = l.rtt
			}
			if rttWait < 0.025 {
				rttWait = 0.025
			}
			l.mutex.Unlock()
			time.Sleep(time.Duration(rttWait * float64(time.Second)))
			continue
		}

		var sleepTime = WATCHDOG_INTERVAL

		if l.status == STATUS_PENDING {
			nextCheck := l.requestTime.Add(l.establishmentTimeout)
			sleepTime = time.Until(nextCheck).Seconds()
			if time.Now().After(nextCheck) {
				debug.Log(debug.DEBUG_INFO, "Link establishment timed out")
				l.status = STATUS_CLOSED
				l.teardownReason = STATUS_FAILED
				if l.closedCallback != nil {
					l.closedCallback(l)
				}
				sleepTime = 0.001
			}
		} else if l.status == STATUS_HANDSHAKE {
			nextCheck := l.requestTime.Add(l.establishmentTimeout)
			sleepTime = time.Until(nextCheck).Seconds()
			if time.Now().After(nextCheck) {
				if l.initiator {
					debug.Log(debug.DEBUG_INFO, "Timeout waiting for link request proof")
				} else {
					debug.Log(debug.DEBUG_INFO, "Timeout waiting for RTT packet from link initiator")
				}
				l.status = STATUS_CLOSED
				l.teardownReason = STATUS_FAILED
				if l.closedCallback != nil {
					l.closedCallback(l)
				}
				sleepTime = 0.001
			}
		} else if l.status == STATUS_ACTIVE {
			activatedAt := l.establishedAt
			if activatedAt.IsZero() {
				activatedAt = time.Time{}
			}
			lastInbound := l.lastInbound
			if lastInbound.Before(activatedAt) {
				lastInbound = activatedAt
			}
			now := time.Now()

			if now.After(lastInbound.Add(l.keepalive)) {
				if l.initiator {
					lastKeepalive := l.lastOutbound
					if now.After(lastKeepalive.Add(l.keepalive)) {
						_ = l.sendKeepalive() // #nosec G104 - best effort keepalive
					}
				}

				if now.After(lastInbound.Add(l.staleTime)) {
					sleepTime = l.rtt*KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE
					l.status = STATUS_STALE
				} else {
					sleepTime = float64(l.keepalive) / float64(time.Second)
				}
			} else {
				nextKeepalive := lastInbound.Add(l.keepalive)
				sleepTime = time.Until(nextKeepalive).Seconds()
			}
		} else if l.status == STATUS_STALE {
			sleepTime = 0.001
			_ = l.sendTeardownPacket() // #nosec G104 - best effort teardown
			l.status = STATUS_CLOSED
			l.teardownReason = STATUS_FAILED
			if l.closedCallback != nil {
				l.closedCallback(l)
			}
		}

		if sleepTime <= 0 {
			sleepTime = 0.1
		}
		if sleepTime > 5.0 {
			sleepTime = 5.0
		}

		l.mutex.Unlock()
		time.Sleep(time.Duration(sleepTime * float64(time.Second)))
	}
	l.watchdogActive = false
}

func (l *Link) sendKeepalive() error {
	keepaliveData := []byte{0xFF}
	keepalivePkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextKeepalive,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: 0x03,
		DestinationHash: l.linkID,
		Data:            keepaliveData,
		CreateReceipt:   false,
	}
	encrypted, err := l.encrypt(keepaliveData)
	if err != nil {
		return err
	}
	keepalivePkt.Data = encrypted
	if err := keepalivePkt.Pack(); err != nil {
		return err
	}
	l.lastOutbound = time.Now()
	return l.transport.SendPacket(keepalivePkt)
}

func (l *Link) sendTeardownPacket() error {
	teardownPkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextLinkClose,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: 0x03,
		DestinationHash: l.linkID,
		Data:            l.linkID,
		CreateReceipt:   false,
	}
	encrypted, err := l.encrypt(l.linkID)
	if err != nil {
		return err
	}
	teardownPkt.Data = encrypted
	if err := teardownPkt.Pack(); err != nil {
		return err
	}
	l.lastOutbound = time.Now()
	return l.transport.SendPacket(teardownPkt)
}

func (l *Link) Validate(signature, message []byte) bool {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if l.remoteIdentity == nil {
		return false
	}

	return l.remoteIdentity.Verify(message, signature)
}

func (l *Link) generateEphemeralKeys() error {
	priv, pub, err := cryptography.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate X25519 keypair: %w", err)
	}
	l.prv = priv
	l.pub = pub

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}
	l.sigPriv = privKey
	l.sigPub = pubKey

	return nil
}

func signallingBytes(mtu int, mode byte) []byte {
	bytes := make([]byte, LINK_MTU_SIZE)
	bytes[0] = byte((mtu >> 16) & 0xFF)
	bytes[1] = byte((mtu >> 8) & 0xFF)
	bytes[2] = byte(mtu & 0xFF)
	bytes[0] |= (mode << 5)
	return bytes
}

func (l *Link) SendLinkRequest() error {
	if err := l.generateEphemeralKeys(); err != nil {
		return err
	}

	l.mode = MODE_DEFAULT
	l.mtu = 500
	l.updateMDU()

	signalling := signallingBytes(l.mtu, l.mode)
	requestData := make([]byte, 0, ECPUBSIZE+LINK_MTU_SIZE)
	requestData = append(requestData, l.pub...)
	requestData = append(requestData, l.sigPub...)
	requestData = append(requestData, signalling...)

	pkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeLinkReq,
		TransportType:   0,
		Context:         packet.ContextNone,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: l.destination.GetType(),
		DestinationHash: l.destination.GetHash(),
		Data:            requestData,
		CreateReceipt:   false,
	}

	if err := pkt.Pack(); err != nil {
		return fmt.Errorf("failed to pack link request: %w", err)
	}

	l.linkID = linkIDFromPacket(pkt)
	l.requestPacket = pkt
	l.requestTime = time.Now()
	l.status = STATUS_PENDING

	if err := l.transport.SendPacket(pkt); err != nil {
		return fmt.Errorf("failed to send link request: %w", err)
	}

	debug.Log(debug.DEBUG_INFO, "Link request sent", "link_id", fmt.Sprintf("%x", l.linkID))
	return nil
}

func linkIDFromPacket(pkt *packet.Packet) []byte {
	hashablePart := make([]byte, 0, 1+16+1+ECPUBSIZE)
	hashablePart = append(hashablePart, pkt.Raw[0])

	if pkt.HeaderType == packet.HeaderType2 {
		startIndex := 18
		endIndex := startIndex + 16 + 1 + ECPUBSIZE
		if len(pkt.Raw) >= endIndex {
			hashablePart = append(hashablePart, pkt.Raw[startIndex:endIndex]...)
		}
	} else {
		startIndex := 2
		endIndex := startIndex + 16 + 1 + ECPUBSIZE
		if len(pkt.Raw) >= endIndex {
			hashablePart = append(hashablePart, pkt.Raw[startIndex:endIndex]...)
		}
	}
	return identity.TruncatedHash(hashablePart)
}

func (l *Link) HandleLinkRequest(pkt *packet.Packet, ownerIdentity *identity.Identity) error {
	if len(pkt.Data) < ECPUBSIZE {
		return errors.New("link request data too short")
	}

	peerPub := pkt.Data[0:KEYSIZE]
	peerSigPub := pkt.Data[KEYSIZE:ECPUBSIZE]

	l.peerPub = peerPub
	l.peerSigPub = peerSigPub
	l.linkID = linkIDFromPacket(pkt)
	l.initiator = false

	if len(pkt.Data) >= ECPUBSIZE+LINK_MTU_SIZE {
		mtuBytes := pkt.Data[ECPUBSIZE : ECPUBSIZE+LINK_MTU_SIZE]
		l.mtu = (int(mtuBytes[0]&0x1F) << 16) | (int(mtuBytes[1]) << 8) | int(mtuBytes[2])
		l.mode = (mtuBytes[0] & MODE_BYTEMASK) >> 5
		debug.Log(debug.DEBUG_VERBOSE, "Link request includes MTU", "mtu", l.mtu, "mode", l.mode)
	} else {
		l.mtu = 500
		l.mode = MODE_DEFAULT
	}

	if err := l.generateEphemeralKeys(); err != nil {
		return err
	}

	if err := l.performHandshake(); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	l.updateMDU()

	if err := l.sendLinkProof(ownerIdentity); err != nil {
		return fmt.Errorf("failed to send link proof: %w", err)
	}

	l.status = STATUS_HANDSHAKE
	l.lastInbound = time.Now()
	l.requestTime = time.Now()

	if l.transport != nil {
		l.transport.RegisterLink(l.linkID, l)
	}

	debug.Log(debug.DEBUG_INFO, "Link proof sent (responder), waiting for RTT", "link_id", fmt.Sprintf("%x", l.linkID))

	return nil
}

func (l *Link) updateMDU() {
	headerMaxSize := 64
	ifacMinSize := 4
	tokenOverhead := 16
	aesBlockSize := 16

	l.mdu = int(float64(l.mtu-headerMaxSize-ifacMinSize-tokenOverhead)/float64(aesBlockSize))*aesBlockSize - 1
	if l.mdu < 0 {
		l.mdu = 100
	}
}

func (l *Link) performHandshake() error {
	if len(l.peerPub) != KEYSIZE {
		return errors.New("invalid peer public key length")
	}

	sharedSecret, err := cryptography.DeriveSharedSecret(l.prv, l.peerPub)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}
	l.sharedKey = sharedSecret

	var derivedKeyLength int
	if l.mode == MODE_AES128_CBC {
		derivedKeyLength = 32
	} else if l.mode == MODE_AES256_CBC {
		derivedKeyLength = 64
	} else {
		return fmt.Errorf("invalid link mode: %d", l.mode)
	}

	derivedKey, err := cryptography.DeriveKey(l.sharedKey, l.linkID, nil, derivedKeyLength)
	if err != nil {
		return fmt.Errorf("HKDF failed: %w", err)
	}
	l.derivedKey = derivedKey

	if len(derivedKey) >= 32 {
		l.sessionKey = derivedKey[0:32]
	}
	if len(derivedKey) >= 64 {
		l.hmacKey = derivedKey[32:64]
	}

	l.status = STATUS_HANDSHAKE
	debug.Log(debug.DEBUG_VERBOSE, "Handshake completed", "key_material_bytes", len(derivedKey))
	return nil
}

func (l *Link) sendLinkProof(ownerIdentity *identity.Identity) error {
	debug.Log(debug.DEBUG_ERROR, "Generating link proof", "link_id", fmt.Sprintf("%x", l.linkID), "initiator", l.initiator, "has_interface", l.networkInterface != nil)

	proofPkt, err := l.GenerateLinkProof(ownerIdentity)
	if err != nil {
		return err
	}

	debug.Log(debug.DEBUG_ERROR, "Link proof packet created", "dest_hash", fmt.Sprintf("%x", proofPkt.DestinationHash), "packet_type", fmt.Sprintf("0x%02x", proofPkt.PacketType))

	// For responder links (not initiator), send proof directly through the receiving interface
	if !l.initiator && l.networkInterface != nil {
		if err := proofPkt.Pack(); err != nil {
			return fmt.Errorf("failed to pack proof packet: %w", err)
		}

		debug.Log(debug.DEBUG_ERROR, "Sending proof through interface", "raw_len", len(proofPkt.Raw), "interface", l.networkInterface.GetName())

		if err := l.networkInterface.Send(proofPkt.Raw, ""); err != nil {
			return fmt.Errorf("failed to send link proof through interface: %w", err)
		}
		debug.Log(debug.DEBUG_ERROR, "Link proof sent through interface", "link_id", fmt.Sprintf("%x", l.linkID), "interface", l.networkInterface.GetName())
		return nil
	}

	// For initiator links, use transport (path lookup)
	if l.transport != nil {
		if err := l.transport.SendPacket(proofPkt); err != nil {
			return fmt.Errorf("failed to send link proof: %w", err)
		}
		debug.Log(debug.DEBUG_INFO, "Link proof sent", "link_id", fmt.Sprintf("%x", l.linkID))
	}

	return nil
}

func (l *Link) GenerateLinkProof(ownerIdentity *identity.Identity) (*packet.Packet, error) {
	signalling := signallingBytes(l.mtu, l.mode)

	ownerSigPub := ownerIdentity.GetPublicKey()[KEYSIZE:ECPUBSIZE]

	signedData := make([]byte, 0, len(l.linkID)+KEYSIZE+len(ownerSigPub)+len(signalling))
	signedData = append(signedData, l.linkID...)
	signedData = append(signedData, l.pub...)
	signedData = append(signedData, ownerSigPub...)
	signedData = append(signedData, signalling...)

	signature := ownerIdentity.Sign(signedData)

	proofData := make([]byte, 0, len(signature)+KEYSIZE+len(signalling))
	proofData = append(proofData, signature...)
	proofData = append(proofData, l.pub...)
	proofData = append(proofData, signalling...)

	proofPkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeProof,
		TransportType:   0,
		Context:         packet.ContextLRProof,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: 0x03,
		DestinationHash: l.linkID,
		Data:            proofData,
		CreateReceipt:   false,
		Link:            l,
	}

	if err := proofPkt.Pack(); err != nil {
		return nil, fmt.Errorf("failed to pack link proof: %w", err)
	}

	return proofPkt, nil
}

func (l *Link) ValidateLinkProof(pkt *packet.Packet) error {
	if l.status != STATUS_PENDING && l.status != STATUS_HANDSHAKE {
		return fmt.Errorf("invalid link status for proof validation: %d", l.status)
	}

	if len(pkt.Data) < identity.SIGLENGTH/8+KEYSIZE {
		return errors.New("link proof data too short")
	}

	signature := pkt.Data[0 : identity.SIGLENGTH/8]
	peerPub := pkt.Data[identity.SIGLENGTH/8 : identity.SIGLENGTH/8+KEYSIZE]

	signalling := []byte{0, 0, 0}
	if len(pkt.Data) >= identity.SIGLENGTH/8+KEYSIZE+LINK_MTU_SIZE {
		signalling = pkt.Data[identity.SIGLENGTH/8+KEYSIZE : identity.SIGLENGTH/8+KEYSIZE+LINK_MTU_SIZE]
		mtu := (int(signalling[0]&0x1F) << 16) | (int(signalling[1]) << 8) | int(signalling[2])
		mode := (signalling[0] & MODE_BYTEMASK) >> 5
		l.mtu = mtu
		l.mode = mode
		debug.Log(debug.DEBUG_VERBOSE, "Link proof includes MTU", "mtu", mtu, "mode", mode)
	}

	l.peerPub = peerPub
	if l.destination != nil && l.destination.GetIdentity() != nil {
		destIdent := l.destination.GetIdentity()
		pubKey := destIdent.GetPublicKey()
		if len(pubKey) >= ECPUBSIZE {
			l.peerSigPub = pubKey[KEYSIZE:ECPUBSIZE]
		}
	}

	signedData := make([]byte, 0, len(l.linkID)+KEYSIZE+len(l.peerSigPub)+len(signalling))
	signedData = append(signedData, l.linkID...)
	signedData = append(signedData, peerPub...)
	signedData = append(signedData, l.peerSigPub...)
	signedData = append(signedData, signalling...)

	if l.destination == nil || l.destination.GetIdentity() == nil {
		return errors.New("no destination identity for proof validation")
	}

	if !l.destination.GetIdentity().Verify(signedData, signature) {
		return errors.New("link proof signature validation failed")
	}

	if err := l.performHandshake(); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	l.updateMDU()

	l.rtt = time.Since(l.requestTime).Seconds()
	l.status = STATUS_ACTIVE
	l.establishedAt = time.Now()

	if l.rtt > 0 {
		l.updateKeepalive()
	}

	rttData := make([]byte, 8)
	binary.BigEndian.PutUint64(rttData, uint64(l.rtt*1e9))
	rttPkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextLRRTT,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: 0x03,
		DestinationHash: l.linkID,
		Data:            rttData,
		CreateReceipt:   false,
	}
	encrypted, err := l.encrypt(rttData)
	if err == nil {
		rttPkt.Data = encrypted
		if err := rttPkt.Pack(); err == nil {
			l.transport.SendPacket(rttPkt)
			l.lastOutbound = time.Now()
		}
	}

	if l.transport != nil {
		l.transport.RegisterLink(l.linkID, l)
	}

	debug.Log(debug.DEBUG_INFO, "Link established (initiator)", "link_id", fmt.Sprintf("%x", l.linkID), "rtt", fmt.Sprintf("%.3fs", l.rtt))

	if l.establishedCallback != nil {
		go l.establishedCallback(l)
	}

	return nil
}
