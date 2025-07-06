package buffer

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"encoding/binary"
	"io"
	"sync"

	"github.com/Sudo-Ivan/reticulum-go/pkg/channel"
)

const (
	StreamIDMax   = 0x3fff // 16383
	MaxChunkLen   = 16 * 1024
	MaxDataLen    = 457 // MDU - 2 - 6 (2 for stream header, 6 for channel envelope)
	CompressTries = 4
)

type StreamDataMessage struct {
	StreamID   uint16
	Data       []byte
	EOF        bool
	Compressed bool
}

func (m *StreamDataMessage) Pack() ([]byte, error) {
	headerVal := uint16(m.StreamID & StreamIDMax)
	if m.EOF {
		headerVal |= 0x8000
	}
	if m.Compressed {
		headerVal |= 0x4000
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, headerVal); err != nil { // #nosec G104
		return nil, err // Or handle the error appropriately
	}
	buf.Write(m.Data)
	return buf.Bytes(), nil
}

func (m *StreamDataMessage) GetType() uint16 {
	return 0x01 // Assign appropriate message type constant
}

func (m *StreamDataMessage) Unpack(data []byte) error {
	if len(data) < 2 {
		return io.ErrShortBuffer
	}

	header := binary.BigEndian.Uint16(data[:2])
	m.StreamID = header & StreamIDMax
	m.EOF = (header & 0x8000) != 0
	m.Compressed = (header & 0x4000) != 0
	m.Data = data[2:]

	return nil
}

type RawChannelReader struct {
	streamID  int
	channel   *channel.Channel
	buffer    *bytes.Buffer
	eof       bool
	callbacks []func(int)
	mutex     sync.RWMutex
}

func NewRawChannelReader(streamID int, ch *channel.Channel) *RawChannelReader {
	reader := &RawChannelReader{
		streamID:  streamID,
		channel:   ch,
		buffer:    bytes.NewBuffer(nil),
		callbacks: make([]func(int), 0),
	}

	ch.AddMessageHandler(reader.HandleMessage)
	return reader
}

func (r *RawChannelReader) AddReadyCallback(cb func(int)) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.callbacks = append(r.callbacks, cb)
}

func (r *RawChannelReader) RemoveReadyCallback(cb func(int)) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for i, fn := range r.callbacks {
		if &fn == &cb {
			r.callbacks = append(r.callbacks[:i], r.callbacks[i+1:]...)
			break
		}
	}
}

func (r *RawChannelReader) Read(p []byte) (n int, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.buffer.Len() == 0 && r.eof {
		return 0, io.EOF
	}

	n, err = r.buffer.Read(p)
	if err == io.EOF && !r.eof {
		err = nil
	}
	return
}

func (r *RawChannelReader) HandleMessage(msg channel.MessageBase) bool {
	if streamMsg, ok := msg.(*StreamDataMessage); ok && streamMsg.StreamID == uint16(r.streamID) { // #nosec G115
		r.mutex.Lock()
		defer r.mutex.Unlock()

		if streamMsg.Compressed {
			decompressed := decompressData(streamMsg.Data)
			r.buffer.Write(decompressed)
		} else {
			r.buffer.Write(streamMsg.Data)
		}

		if streamMsg.EOF {
			r.eof = true
		}

		// Notify callbacks
		for _, cb := range r.callbacks {
			cb(r.buffer.Len())
		}

		return true
	}
	return false
}

type RawChannelWriter struct {
	streamID int
	channel  *channel.Channel
	eof      bool
}

func NewRawChannelWriter(streamID int, ch *channel.Channel) *RawChannelWriter {
	return &RawChannelWriter{
		streamID: streamID,
		channel:  ch,
	}
}

func (w *RawChannelWriter) Write(p []byte) (n int, err error) {
	if len(p) > MaxChunkLen {
		p = p[:MaxChunkLen]
	}

	msg := &StreamDataMessage{
		StreamID: uint16(w.streamID), // #nosec G115
		Data:     p,
		EOF:      w.eof,
	}

	if len(p) > 32 {
		for try := 1; try < CompressTries; try++ {
			chunkLen := len(p) / try
			compressed := compressData(p[:chunkLen])
			if len(compressed) < MaxDataLen && len(compressed) < chunkLen {
				msg.Data = compressed
				msg.Compressed = true
				break
			}
		}
	}

	if err := w.channel.Send(msg); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (w *RawChannelWriter) Close() error {
	w.eof = true
	_, err := w.Write(nil)
	return err
}

type Buffer struct {
	ReadWriter *bufio.ReadWriter
}

func (b *Buffer) Write(p []byte) (n int, err error) {
	return b.ReadWriter.Write(p)
}

func (b *Buffer) Read(p []byte) (n int, err error) {
	return b.ReadWriter.Read(p)
}

func (b *Buffer) Close() error {
	if err := b.ReadWriter.Writer.Flush(); err != nil {
		return err
	}
	return nil
}

func CreateReader(streamID int, ch *channel.Channel, readyCallback func(int)) *bufio.Reader {
	raw := NewRawChannelReader(streamID, ch)
	if readyCallback != nil {
		raw.AddReadyCallback(readyCallback)
	}
	return bufio.NewReader(raw)
}

func CreateWriter(streamID int, ch *channel.Channel) *bufio.Writer {
	raw := NewRawChannelWriter(streamID, ch)
	return bufio.NewWriter(raw)
}

func CreateBidirectionalBuffer(receiveStreamID, sendStreamID int, ch *channel.Channel, readyCallback func(int)) *bufio.ReadWriter {
	reader := CreateReader(receiveStreamID, ch, readyCallback)
	writer := CreateWriter(sendStreamID, ch)
	return bufio.NewReadWriter(reader, writer)
}

func compressData(data []byte) []byte {
	var compressed bytes.Buffer
	w := bytes.NewBuffer(data)
	r := bzip2.NewReader(w)
	_, err := io.Copy(&compressed, r) // #nosec G104 #nosec G110
	if err != nil {
		// Handle error, e.g., log it or return an error
		return nil
	}
	return compressed.Bytes()
}

func decompressData(data []byte) []byte {
	reader := bzip2.NewReader(bytes.NewReader(data))
	var decompressed bytes.Buffer
	// Limit the amount of data read to prevent decompression bombs
	limitedReader := io.LimitReader(reader, MaxChunkLen) // #nosec G110
	_, err := io.Copy(&decompressed, limitedReader)
	if err != nil {
		// Handle error, e.g., log it or return an error
		return nil
	}
	return decompressed.Bytes()
}
