package channel

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

const (
	// Window sizes and thresholds
	WindowInitial     = 2
	WindowMin         = 2
	WindowMinSlow     = 2
	WindowMinMedium   = 5
	WindowMinFast     = 16
	WindowMaxSlow     = 5
	WindowMaxMedium   = 12
	WindowMaxFast     = 48
	WindowMax         = WindowMaxFast
	WindowFlexibility = 4

	// RTT thresholds
	RTTFast   = 0.18
	RTTMedium = 0.75
	RTTSlow   = 1.45

	// Sequence numbers
	SeqMax     uint16 = 0xFFFF
	SeqModulus uint16 = SeqMax

	FastRateThreshold = 10
)

// MessageState represents the state of a message
type MessageState int

const (
	MsgStateNew MessageState = iota
	MsgStateSent
	MsgStateDelivered
	MsgStateFailed
)

// MessageBase defines the interface for messages that can be sent over a channel
type MessageBase interface {
	Pack() ([]byte, error)
	Unpack([]byte) error
	GetType() uint16
}

// Channel manages reliable message delivery over a transport link
type Channel struct {
	link            transport.LinkInterface
	mutex           sync.RWMutex
	txRing          []*Envelope
	rxRing          []*Envelope
	window          int
	windowMax       int
	windowMin       int
	windowFlex      int
	nextSequence    uint16
	nextRxSequence  uint16
	maxTries        int
	fastRateRounds  int
	medRateRounds   int
	messageHandlers []func(MessageBase) bool
}

// Envelope wraps a message with metadata for transmission
type Envelope struct {
	Sequence  uint16
	Message   MessageBase
	Raw       []byte
	Packet    interface{}
	Tries     int
	Timestamp time.Time
}

// NewChannel creates a new Channel instance
func NewChannel(link transport.LinkInterface) *Channel {
	return &Channel{
		link:            link,
		messageHandlers: make([]func(MessageBase) bool, 0),
		mutex:           sync.RWMutex{},
		windowMax:       WindowMaxSlow,
		windowMin:       WindowMinSlow,
		window:          WindowInitial,
		maxTries:        3,
	}
}

// Send transmits a message over the channel
func (c *Channel) Send(msg MessageBase) error {
	if c.link.GetStatus() != transport.STATUS_ACTIVE {
		return errors.New("link not ready")
	}

	env := &Envelope{
		Sequence:  c.nextSequence,
		Message:   msg,
		Timestamp: time.Now(),
	}

	c.mutex.Lock()
	c.nextSequence = (c.nextSequence + 1) % SeqModulus
	c.txRing = append(c.txRing, env)
	c.mutex.Unlock()

	data, err := msg.Pack()
	if err != nil {
		return err
	}

	env.Raw = data
	packet := c.link.Send(data)
	env.Packet = packet
	env.Tries++

	timeout := c.getPacketTimeout(env.Tries)
	c.link.SetPacketTimeout(packet, c.handleTimeout, timeout)
	c.link.SetPacketDelivered(packet, c.handleDelivered)

	return nil
}

// handleTimeout handles packet timeout events
func (c *Channel) handleTimeout(packet interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, env := range c.txRing {
		if env.Packet == packet {
			if env.Tries >= c.maxTries {
				// Remove from ring and notify failure
				return
			}
			env.Tries++
			if err := c.link.Resend(packet); err != nil { // #nosec G104
				// Handle resend error, e.g., log it or mark envelope as failed
				debug.Log(debug.DEBUG_INFO, "Failed to resend packet", "error", err)
				// Optionally, mark the envelope as failed or remove it from txRing
				// env.State = MsgStateFailed
				// c.txRing = append(c.txRing[:i], c.txRing[i+1:]...)
				return
			}
			timeout := c.getPacketTimeout(env.Tries)
			c.link.SetPacketTimeout(packet, c.handleTimeout, timeout)
			break
		}
	}
}

// handleDelivered handles packet delivery confirmations
func (c *Channel) handleDelivered(packet interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for i, env := range c.txRing {
		if env.Packet == packet {
			c.txRing = append(c.txRing[:i], c.txRing[i+1:]...)
			break
		}
	}
}

func (c *Channel) getPacketTimeout(tries int) time.Duration {
	rtt := c.link.GetRTT()
	if rtt < 0.025 {
		rtt = 0.025
	}

	timeout := math.Pow(1.5, float64(tries-1)) * rtt * 2.5 * float64(len(c.txRing)+2)
	return time.Duration(timeout * float64(time.Second))
}

func (c *Channel) AddMessageHandler(handler func(MessageBase) bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.messageHandlers = append(c.messageHandlers, handler)
}

func (c *Channel) RemoveMessageHandler(handler func(MessageBase) bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for i, h := range c.messageHandlers {
		if &h == &handler {
			c.messageHandlers = append(c.messageHandlers[:i], c.messageHandlers[i+1:]...)
			break
		}
	}
}

func (c *Channel) updateRateThresholds() {
	rtt := c.link.RTT()

	if rtt > RTTFast {
		c.fastRateRounds = 0

		if rtt > RTTMedium {
			c.medRateRounds = 0
		} else {
			c.medRateRounds++
			if c.windowMax < WindowMaxMedium && c.medRateRounds == FastRateThreshold {
				c.windowMax = WindowMaxMedium
				c.windowMin = WindowMinMedium
			}
		}
	} else {
		c.fastRateRounds++
		if c.windowMax < WindowMaxFast && c.fastRateRounds == FastRateThreshold {
			c.windowMax = WindowMaxFast
			c.windowMin = WindowMinFast
		}
	}
}

func (c *Channel) HandleInbound(data []byte) error {
	if len(data) < 6 {
		return errors.New("channel packet too short")
	}

	msgType := uint16(data[0])<<8 | uint16(data[1])
	sequence := uint16(data[2])<<8 | uint16(data[3])
	length := uint16(data[4])<<8 | uint16(data[5])
	
	if len(data) < 6+int(length) {
		return errors.New("channel packet incomplete")
	}

	msgData := data[6 : 6+length]

	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, handler := range c.messageHandlers {
		if handler != nil {
			msg := &GenericMessage{
				Type:    msgType,
				Data:    msgData,
				Seq:     sequence,
			}
			if handler(msg) {
				break
			}
		}
	}

	return nil
}

type GenericMessage struct {
	Type uint16
	Data []byte
	Seq  uint16
}

func (g *GenericMessage) Pack() ([]byte, error) {
	return g.Data, nil
}

func (g *GenericMessage) Unpack(data []byte) error {
	g.Data = data
	return nil
}

func (g *GenericMessage) GetType() uint16 {
	return g.Type
}

func (c *Channel) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// Cleanup resources
	return nil
}
