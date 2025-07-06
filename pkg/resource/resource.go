package resource

import (
	"crypto/sha256"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	STATUS_PENDING   = 0x00
	STATUS_ACTIVE    = 0x01
	STATUS_COMPLETE  = 0x02
	STATUS_FAILED    = 0x03
	STATUS_CANCELLED = 0x04

	DEFAULT_SEGMENT_SIZE = 384 // Based on ENCRYPTED_MDU
	MAX_SEGMENTS         = 65535
	CLEANUP_INTERVAL     = 300 // 5 minutes

	// Window size constants
	WINDOW               = 4
	WINDOW_MIN           = 2
	WINDOW_MAX_SLOW      = 10
	WINDOW_MAX_VERY_SLOW = 4
	WINDOW_MAX_FAST      = 75
	WINDOW_MAX           = WINDOW_MAX_FAST

	// Rate thresholds
	FAST_RATE_THRESHOLD      = WINDOW_MAX_SLOW - WINDOW - 2
	VERY_SLOW_RATE_THRESHOLD = 2

	// Transfer rates (bytes per second)
	RATE_FAST      = (50 * 1000) / 8 // 50 Kbps
	RATE_VERY_SLOW = (2 * 1000) / 8  // 2 Kbps

	// Window flexibility
	WINDOW_FLEXIBILITY = 4

	// Hash and segment constants
	MAPHASH_LEN      = 4
	RANDOM_HASH_SIZE = 4

	// Size limits
	MAX_EFFICIENT_SIZE     = 16*1024*1024 - 1 // ~16MB
	AUTO_COMPRESS_MAX_SIZE = MAX_EFFICIENT_SIZE

	// Timeouts and retries
	PART_TIMEOUT_FACTOR           = 4
	PART_TIMEOUT_FACTOR_AFTER_RTT = 2
	PROOF_TIMEOUT_FACTOR          = 3
	MAX_RETRIES                   = 16
	MAX_ADV_RETRIES               = 4
	SENDER_GRACE_TIME             = 10.0
	PROCESSING_GRACE              = 1.0
	RETRY_GRACE_TIME              = 0.25
	PER_RETRY_DELAY               = 0.5
)

type Resource struct {
	mutex              sync.RWMutex
	data               []byte
	fileHandle         io.ReadWriteSeeker
	fileName           string
	hash               []byte
	randomHash         []byte
	originalHash       []byte
	status             byte
	compressed         bool
	autoCompress       bool
	encrypted          bool
	split              bool
	segments           uint16
	segmentIndex       uint16
	totalSegments      uint16
	completedParts     map[uint16]bool
	transferSize       int64
	dataSize           int64
	progress           float64
	window             int
	windowMax          int
	windowMin          int
	windowFlexibility  int
	rtt                float64
	fastRateRounds     int
	verySlowRateRounds int
	createdAt          time.Time
	completedAt        time.Time
	callback           func(*Resource)
	progressCallback   func(*Resource)
	readOffset         int64
}

func New(data interface{}, autoCompress bool) (*Resource, error) {
	r := &Resource{
		status:         STATUS_PENDING,
		compressed:     false,
		autoCompress:   autoCompress,
		completedParts: make(map[uint16]bool),
		createdAt:      time.Now(),
		progress:       0.0,
	}

	switch v := data.(type) {
	case []byte:
		r.data = v
		r.dataSize = int64(len(v))
	case io.ReadWriteSeeker:
		r.fileHandle = v
		size, err := v.Seek(0, io.SeekEnd)
		if err != nil {
			return nil, err
		}
		r.dataSize = size
		_, err = v.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}

		if namer, ok := v.(interface{ Name() string }); ok {
			r.fileName = namer.Name()
		}
	default:
		return nil, errors.New("unsupported data type")
	}

	// Calculate segments needed
	r.segments = uint16((r.dataSize + DEFAULT_SEGMENT_SIZE - 1) / DEFAULT_SEGMENT_SIZE) // #nosec G115
	if r.segments > MAX_SEGMENTS {
		return nil, errors.New("resource too large")
	}

	// Calculate transfer size
	r.transferSize = r.dataSize
	if r.autoCompress {
		// Estimate compressed size based on data type and content
		if r.data != nil {
			// For in-memory data, we can analyze content
			compressibility := estimateCompressibility(r.data)
			r.transferSize = int64(float64(r.dataSize) * compressibility)
		} else if r.fileHandle != nil {
			// For file handles, use extension-based estimation
			ext := strings.ToLower(filepath.Ext(r.fileName))
			r.transferSize = estimateFileCompression(r.dataSize, ext)
		}

		// Ensure minimum size and add compression overhead
		if r.transferSize < r.dataSize/10 {
			r.transferSize = r.dataSize / 10
		}
		r.transferSize += 64 // Header overhead for compression
	}

	// Calculate resource hash
	if err := r.calculateHash(); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *Resource) calculateHash() error {
	h := sha256.New()

	if r.data != nil {
		h.Write(r.data)
	} else if r.fileHandle != nil {
		if _, err := r.fileHandle.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.Copy(h, r.fileHandle); err != nil {
			return err
		}
		if _, err := r.fileHandle.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}

	r.hash = h.Sum(nil)
	return nil
}

func (r *Resource) GetHash() []byte {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return append([]byte{}, r.hash...)
}

func (r *Resource) GetStatus() byte {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.status
}

func (r *Resource) GetProgress() float64 {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.progress
}

func (r *Resource) GetTransferSize() int64 {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.transferSize
}

func (r *Resource) GetDataSize() int64 {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.dataSize
}

func (r *Resource) GetSegments() uint16 {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.segments
}

func (r *Resource) IsCompressed() bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.compressed
}

func (r *Resource) Cancel() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.status == STATUS_PENDING || r.status == STATUS_ACTIVE {
		r.status = STATUS_CANCELLED
		r.completedAt = time.Now()
		if r.callback != nil {
			r.callback(r)
		}
	}
}

func (r *Resource) SetCallback(callback func(*Resource)) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.callback = callback
}

func (r *Resource) SetProgressCallback(callback func(*Resource)) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.progressCallback = callback
}

// GetSegmentData returns the data for a specific segment
func (r *Resource) GetSegmentData(segment uint16) ([]byte, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if segment >= r.segments {
		return nil, errors.New("invalid segment number")
	}

	start := int64(segment) * DEFAULT_SEGMENT_SIZE
	size := DEFAULT_SEGMENT_SIZE
	if segment == r.segments-1 {
		size = int(r.dataSize - start)
	}

	data := make([]byte, size)
	if r.data != nil {
		copy(data, r.data[start:start+int64(size)])
		return data, nil
	}

	if r.fileHandle != nil {
		if _, err := r.fileHandle.Seek(start, io.SeekStart); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r.fileHandle, data); err != nil {
			return nil, err
		}
		return data, nil
	}

	return nil, errors.New("no data source available")
}

// MarkSegmentComplete marks a segment as completed and updates progress
func (r *Resource) MarkSegmentComplete(segment uint16) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if segment >= r.segments {
		return
	}

	r.completedParts[segment] = true
	completed := len(r.completedParts)
	r.progress = float64(completed) / float64(r.segments)

	if r.progressCallback != nil {
		r.progressCallback(r)
	}

	// Check if all segments are complete
	if completed == int(r.segments) {
		r.status = STATUS_COMPLETE
		r.completedAt = time.Now()
		if r.callback != nil {
			r.callback(r)
		}
	}
}

// IsSegmentComplete checks if a specific segment is complete
func (r *Resource) IsSegmentComplete(segment uint16) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.completedParts[segment]
}

// Activate marks the resource as active
func (r *Resource) Activate() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.status == STATUS_PENDING {
		r.status = STATUS_ACTIVE
	}
}

// SetFailed marks the resource as failed
func (r *Resource) SetFailed() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.status != STATUS_COMPLETE {
		r.status = STATUS_FAILED
		r.completedAt = time.Now()
		if r.callback != nil {
			r.callback(r)
		}
	}
}

// Helper functions for compression estimation
func estimateCompressibility(data []byte) float64 {
	// Sample the data to estimate compressibility
	sampleSize := 4096
	if len(data) < sampleSize {
		sampleSize = len(data)
	}

	// Count unique bytes in sample
	uniqueBytes := make(map[byte]struct{})
	for i := 0; i < sampleSize; i++ {
		uniqueBytes[data[i]] = struct{}{}
	}

	// Calculate entropy-based compression estimate
	uniqueRatio := float64(len(uniqueBytes)) / float64(sampleSize)
	return 0.3 + (0.7 * uniqueRatio) // Base compression ratio between 0.3 and 1.0
}

func estimateFileCompression(size int64, extension string) int64 {
	// Compression ratio estimates based on common file types
	compressionRatios := map[string]float64{
		".txt":  0.4, // Text compresses well
		".log":  0.4,
		".json": 0.4,
		".xml":  0.4,
		".html": 0.4,
		".csv":  0.5,
		".doc":  0.8, // Already compressed
		".docx": 0.95,
		".pdf":  0.95,
		".jpg":  0.99, // Already compressed
		".jpeg": 0.99,
		".png":  0.99,
		".gif":  0.99,
		".mp3":  0.99,
		".mp4":  0.99,
		".zip":  0.99,
		".gz":   0.99,
		".rar":  0.99,
	}

	ratio, exists := compressionRatios[extension]
	if !exists {
		ratio = 0.7 // Default compression ratio for unknown types
	}

	return int64(float64(size) * ratio)
}

func (r *Resource) Read(p []byte) (n int, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.data != nil {
		if r.readOffset >= int64(len(r.data)) {
			return 0, io.EOF
		}
		n = copy(p, r.data[r.readOffset:])
		r.readOffset += int64(n)
		return n, nil
	}

	if r.fileHandle != nil {
		return r.fileHandle.Read(p)
	}

	return 0, errors.New("no data source available")
}

func (r *Resource) GetName() string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.fileName
}

func (r *Resource) GetSize() int64 {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.dataSize
}
