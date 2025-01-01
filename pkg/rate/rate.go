package rate

import (
	"sync"
	"time"
)

const (
	DefaultAnnounceRateTarget  = 3600.0 // Default 1 hour between announces
	DefaultAnnounceRateGrace   = 3      // Default number of grace announces
	DefaultAnnounceRatePenalty = 7200.0 // Default 2 hour penalty
	DefaultBurstFreqNew        = 3.5    // Default announces/sec for new interfaces
	DefaultBurstFreq           = 12.0   // Default announces/sec for established interfaces
	DefaultBurstHold           = 60     // Default seconds to hold after burst
	DefaultBurstPenalty        = 300    // Default seconds penalty after burst
	DefaultMaxHeldAnnounces    = 256    // Default max announces in hold queue
	DefaultHeldReleaseInterval = 30     // Default seconds between releasing held announces
)

type Limiter struct {
	rate       float64
	interval   time.Duration
	lastUpdate time.Time
	allowance  float64
	mutex      sync.Mutex
}

func NewLimiter(rate float64, interval time.Duration) *Limiter {
	return &Limiter{
		rate:       rate,
		interval:   interval,
		lastUpdate: time.Now(),
		allowance:  rate,
	}
}

func (l *Limiter) Allow() bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate)
	l.lastUpdate = now

	l.allowance += elapsed.Seconds() * l.rate
	if l.allowance > l.rate {
		l.allowance = l.rate
	}

	if l.allowance < 1.0 {
		return false
	}

	l.allowance -= 1.0
	return true
}

// AnnounceRateControl handles per-destination announce rate limiting
type AnnounceRateControl struct {
	rateTarget  float64
	rateGrace   int
	ratePenalty float64

	announceHistory map[string][]time.Time // Maps dest hash to announce times
	mutex           sync.RWMutex
}

func NewAnnounceRateControl(target float64, grace int, penalty float64) *AnnounceRateControl {
	return &AnnounceRateControl{
		rateTarget:      target,
		rateGrace:       grace,
		ratePenalty:     penalty,
		announceHistory: make(map[string][]time.Time),
	}
}

func (arc *AnnounceRateControl) AllowAnnounce(destHash string) bool {
	arc.mutex.Lock()
	defer arc.mutex.Unlock()

	history := arc.announceHistory[destHash]
	now := time.Now()

	// Cleanup old history entries
	cutoff := now.Add(-24 * time.Hour)
	newHistory := []time.Time{}
	for _, t := range history {
		if t.After(cutoff) {
			newHistory = append(newHistory, t)
		}
	}
	history = newHistory

	// Allow if within grace period
	if len(history) < arc.rateGrace {
		arc.announceHistory[destHash] = append(history, now)
		return true
	}

	// Check rate
	lastAnnounce := history[len(history)-1]
	waitTime := arc.rateTarget
	if len(history) > arc.rateGrace {
		waitTime += arc.ratePenalty
	}

	if now.Sub(lastAnnounce).Seconds() < waitTime {
		return false
	}

	arc.announceHistory[destHash] = append(history, now)
	return true
}

// IngressControl handles new destination announce rate limiting
type IngressControl struct {
	enabled             bool
	burstFreqNew        float64
	burstFreq           float64
	burstHold           time.Duration
	burstPenalty        time.Duration
	maxHeldAnnounces    int
	heldReleaseInterval time.Duration

	heldAnnounces map[string][]byte // Maps announce hash to announce data
	lastBurst     time.Time
	announceCount int
	mutex         sync.RWMutex
}

func NewIngressControl(enabled bool) *IngressControl {
	return &IngressControl{
		enabled:             enabled,
		burstFreqNew:        DefaultBurstFreqNew,
		burstFreq:           DefaultBurstFreq,
		burstHold:           time.Duration(DefaultBurstHold) * time.Second,
		burstPenalty:        time.Duration(DefaultBurstPenalty) * time.Second,
		maxHeldAnnounces:    DefaultMaxHeldAnnounces,
		heldReleaseInterval: time.Duration(DefaultHeldReleaseInterval) * time.Second,
		heldAnnounces:       make(map[string][]byte),
		lastBurst:           time.Now(),
	}
}

func (ic *IngressControl) ProcessAnnounce(announceHash string, announceData []byte, isNewDest bool) bool {
	if !ic.enabled {
		return true
	}

	ic.mutex.Lock()
	defer ic.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(ic.lastBurst)

	// Reset counter if enough time has passed
	if elapsed > ic.burstHold+ic.burstPenalty {
		ic.announceCount = 0
		ic.lastBurst = now
	}

	// Check burst frequency
	maxFreq := ic.burstFreq
	if isNewDest {
		maxFreq = ic.burstFreqNew
	}

	ic.announceCount++
	burstFreq := float64(ic.announceCount) / elapsed.Seconds()

	// Hold announce if burst frequency exceeded
	if burstFreq > maxFreq {
		if len(ic.heldAnnounces) < ic.maxHeldAnnounces {
			ic.heldAnnounces[announceHash] = announceData
		}
		return false
	}

	return true
}

func (ic *IngressControl) ReleaseHeldAnnounce() (string, []byte, bool) {
	ic.mutex.Lock()
	defer ic.mutex.Unlock()

	// Return first held announce if any exist
	for hash, data := range ic.heldAnnounces {
		delete(ic.heldAnnounces, hash)
		return hash, data, true
	}

	return "", nil, false
}
