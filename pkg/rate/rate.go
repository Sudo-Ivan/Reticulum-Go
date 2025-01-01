package rate

import (
    "sync"
    "time"
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