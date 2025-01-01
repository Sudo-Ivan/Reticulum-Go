package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"

	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
)

type Resolver struct {
	cache     map[string]*identity.Identity
	cacheLock sync.RWMutex
}

func New() *Resolver {
	return &Resolver{
		cache: make(map[string]*identity.Identity),
	}
}

func (r *Resolver) ResolveIdentity(fullName string) (*identity.Identity, error) {
	if fullName == "" {
		return nil, errors.New("empty identity name")
	}

	r.cacheLock.RLock()
	if cachedIdentity, exists := r.cache[fullName]; exists {
		r.cacheLock.RUnlock()
		return cachedIdentity, nil
	}
	r.cacheLock.RUnlock()

	// Hash the full name to create a deterministic identity
	h := sha256.New()
	h.Write([]byte(fullName))
	nameHash := h.Sum(nil)[:identity.NAME_HASH_LENGTH/8]
	hashStr := hex.EncodeToString(nameHash)

	// Check if this identity is known
	if knownData, exists := identity.GetKnownDestination(hashStr); exists {
		if id, ok := knownData[2].(*identity.Identity); ok {
			r.cacheLock.Lock()
			r.cache[fullName] = id
			r.cacheLock.Unlock()
			return id, nil
		}
	}

	// Split name into parts for hierarchical resolution
	parts := strings.Split(fullName, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid identity name format")
	}

	// Create new identity if not found
	id, err := identity.New()
	if err != nil {
		return nil, err
	}

	r.cacheLock.Lock()
	r.cache[fullName] = id
	r.cacheLock.Unlock()

	return id, nil
}

func ResolveIdentity(fullName string) (*identity.Identity, error) {
	r := New()
	return r.ResolveIdentity(fullName)
}
