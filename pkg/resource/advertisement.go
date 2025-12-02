package resource

import (
	"fmt"
	"math"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	OVERHEAD             = 134
	COLLISION_GUARD_SIZE = 2*WINDOW_MAX + 100
)

type ResourceAdvertisement struct {
	TransferSize  int64
	DataSize      int64
	Parts         int
	Hash          []byte
	RandomHash    []byte
	OriginalHash  []byte
	Hashmap       []byte
	Compressed    bool
	Encrypted     bool
	Split         bool
	HasMetadata   bool
	SegmentIndex  uint16
	TotalSegments uint16
	RequestID     []byte
	IsRequest     bool
	IsResponse    bool
	Flags         byte
}

func NewResourceAdvertisement(res *Resource) *ResourceAdvertisement {
	if res == nil {
		return nil
	}

	flags := byte(0x00)
	if res.HasMetadata() {
		flags |= 0x20
	}
	if res.IsResponse() {
		flags |= 0x10
	}
	if res.IsRequest() {
		flags |= 0x08
	}

	res.mutex.RLock()
	split := res.split
	compressed := res.compressed
	encrypted := res.encrypted
	randomHash := res.randomHash
	originalHash := res.originalHash
	segmentIndex := res.segmentIndex
	totalSegments := res.totalSegments
	res.mutex.RUnlock()

	if split {
		flags |= 0x04
	}
	if compressed {
		flags |= 0x02
	}
	if encrypted {
		flags |= 0x01
	}

	hashmap := res.getHashmap()

	return &ResourceAdvertisement{
		TransferSize:  res.GetTransferSize(),
		DataSize:      res.GetDataSize(),
		Parts:         int(res.GetSegments()),
		Hash:          res.GetHash(),
		RandomHash:    randomHash,
		OriginalHash:  originalHash,
		Hashmap:       hashmap,
		Compressed:    compressed,
		Encrypted:     encrypted,
		Split:         split,
		HasMetadata:   res.HasMetadata(),
		SegmentIndex:  segmentIndex,
		TotalSegments: totalSegments,
		RequestID:     res.GetRequestID(),
		IsRequest:     res.IsRequest(),
		IsResponse:    res.IsResponse(),
		Flags:         flags,
	}
}

func (ra *ResourceAdvertisement) Pack(segment int) ([]byte, error) {
	hashmapMaxLen := getHashmapMaxLen()
	hashmapStart := segment * hashmapMaxLen
	hashmapEnd := hashmapStart + hashmapMaxLen
	if hashmapEnd > len(ra.Hashmap)/MAPHASH_LEN {
		hashmapEnd = len(ra.Hashmap) / MAPHASH_LEN
	}

	hashmap := ra.Hashmap[hashmapStart*MAPHASH_LEN : hashmapEnd*MAPHASH_LEN]

	dict := map[string]interface{}{
		"t": ra.TransferSize,
		"d": ra.DataSize,
		"n": ra.Parts,
		"h": ra.Hash,
		"r": ra.RandomHash,
		"o": ra.OriginalHash,
		"i": ra.SegmentIndex,
		"l": ra.TotalSegments,
		"q": ra.RequestID,
		"f": ra.Flags,
		"m": hashmap,
	}

	return msgpack.Marshal(dict)
}

func UnpackResourceAdvertisement(data []byte) (*ResourceAdvertisement, error) {
	var dict map[string]interface{}
	if err := msgpack.Unmarshal(data, &dict); err != nil {
		return nil, fmt.Errorf("failed to unpack advertisement: %w", err)
	}

	ra := &ResourceAdvertisement{}

	if t, ok := dict["t"].(int64); ok {
		ra.TransferSize = t
	} else if t, ok := dict["t"].(uint64); ok {
		if t > uint64(math.MaxInt64) {
			return nil, fmt.Errorf("transfer size overflow")
		}
		ra.TransferSize = int64(t) // #nosec G115 - checked for overflow
	}

	if d, ok := dict["d"].(int64); ok {
		ra.DataSize = d
	} else if d, ok := dict["d"].(uint64); ok {
		if d > uint64(math.MaxInt64) {
			return nil, fmt.Errorf("data size overflow")
		}
		ra.DataSize = int64(d) // #nosec G115 - checked for overflow
	}

	if n, ok := dict["n"].(int); ok {
		ra.Parts = n
	} else if n, ok := dict["n"].(uint64); ok {
		if n > uint64(math.MaxInt32) {
			return nil, fmt.Errorf("parts count overflow")
		}
		ra.Parts = int(n) // #nosec G115 - checked for overflow
	}

	if h, ok := dict["h"].([]byte); ok {
		ra.Hash = h
	}

	if r, ok := dict["r"].([]byte); ok {
		ra.RandomHash = r
	}

	if o, ok := dict["o"].([]byte); ok {
		ra.OriginalHash = o
	}

	if m, ok := dict["m"].([]byte); ok {
		ra.Hashmap = m
	}

	if f, ok := dict["f"].(byte); ok {
		ra.Flags = f
	} else if f, ok := dict["f"].(uint64); ok {
		ra.Flags = byte(f)
	}

	ra.Encrypted = (ra.Flags & 0x01) == 0x01
	ra.Compressed = ((ra.Flags >> 1) & 0x01) == 0x01
	ra.Split = ((ra.Flags >> 2) & 0x01) == 0x01
	ra.IsRequest = ((ra.Flags >> 3) & 0x01) == 0x01
	ra.IsResponse = ((ra.Flags >> 4) & 0x01) == 0x01
	ra.HasMetadata = ((ra.Flags >> 5) & 0x01) == 0x01

	if i, ok := dict["i"].(uint16); ok {
		ra.SegmentIndex = i
	} else if i, ok := dict["i"].(uint64); ok {
		if i > uint64(math.MaxUint16) {
			return nil, fmt.Errorf("segment index overflow")
		}
		ra.SegmentIndex = uint16(i) // #nosec G115 - checked for overflow
	}

	if l, ok := dict["l"].(uint16); ok {
		ra.TotalSegments = l
	} else if l, ok := dict["l"].(uint64); ok {
		if l > uint64(math.MaxUint16) {
			return nil, fmt.Errorf("total segments overflow")
		}
		ra.TotalSegments = uint16(l) // #nosec G115 - checked for overflow
	}

	if q, ok := dict["q"].([]byte); ok {
		ra.RequestID = q
	}

	return ra, nil
}

func getHashmapMaxLen() int {
	mdu := 384
	return (mdu - OVERHEAD) / MAPHASH_LEN
}

func IsRequestAdvertisement(data []byte) bool {
	adv, err := UnpackResourceAdvertisement(data)
	if err != nil {
		return false
	}
	return adv.IsRequest && adv.RequestID != nil
}

func IsResponseAdvertisement(data []byte) bool {
	adv, err := UnpackResourceAdvertisement(data)
	if err != nil {
		return false
	}
	return adv.IsResponse && adv.RequestID != nil
}

func ReadRequestID(data []byte) []byte {
	adv, err := UnpackResourceAdvertisement(data)
	if err != nil {
		return nil
	}
	return adv.RequestID
}

func ReadTransferSize(data []byte) int64 {
	adv, err := UnpackResourceAdvertisement(data)
	if err != nil {
		return 0
	}
	return adv.TransferSize
}

func ReadSize(data []byte) int64 {
	adv, err := UnpackResourceAdvertisement(data)
	if err != nil {
		return 0
	}
	return adv.DataSize
}
