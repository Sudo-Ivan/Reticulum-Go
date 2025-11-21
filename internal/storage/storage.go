package storage

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
	"github.com/vmihailenco/msgpack/v5"
)

type Manager struct {
	basePath           string
	ratchetsPath       string
	identitiesPath     string
	destinationTable   string
	knownDestinations  string
	transportIdentity  string
	mutex              sync.RWMutex
}

type RatchetData struct {
	RatchetKey []byte `msgpack:"ratchet_key"`
	Received   int64  `msgpack:"received"`
}

func NewManager() (*Manager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	basePath := filepath.Join(homeDir, ".reticulum-go", "storage")
	
	m := &Manager{
		basePath:           basePath,
		ratchetsPath:       filepath.Join(basePath, "ratchets"),
		identitiesPath:     filepath.Join(basePath, "identities"),
		destinationTable:   filepath.Join(basePath, "destination_table"),
		knownDestinations:  filepath.Join(basePath, "known_destinations"),
		transportIdentity:  filepath.Join(basePath, "transport_identity"),
	}

	if err := m.initializeDirectories(); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Manager) initializeDirectories() error {
	dirs := []string{
		m.basePath,
		m.ratchetsPath,
		m.identitiesPath,
		filepath.Join(m.basePath, "cache"),
		filepath.Join(m.basePath, "cache", "announces"),
		filepath.Join(m.basePath, "resources"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

func (m *Manager) SaveRatchet(identityHash []byte, ratchetKey []byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	hexHash := hex.EncodeToString(identityHash)
	ratchetDir := filepath.Join(m.ratchetsPath, hexHash)
	
	if err := os.MkdirAll(ratchetDir, 0700); err != nil {
		return fmt.Errorf("failed to create ratchet directory: %w", err)
	}

	ratchetData := RatchetData{
		RatchetKey: ratchetKey,
		Received:   time.Now().Unix(),
	}

	data, err := msgpack.Marshal(ratchetData)
	if err != nil {
		return fmt.Errorf("failed to marshal ratchet data: %w", err)
	}

	ratchetHash := hex.EncodeToString(ratchetKey[:16])
	outPath := filepath.Join(ratchetDir, ratchetHash+".out")
	finalPath := filepath.Join(ratchetDir, ratchetHash)

	if err := os.WriteFile(outPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write ratchet file: %w", err)
	}

	if err := os.Rename(outPath, finalPath); err != nil {
		_ = os.Remove(outPath)
		return fmt.Errorf("failed to move ratchet file: %w", err)
	}

	debug.Log(debug.DEBUG_VERBOSE, "Saved ratchet to storage", "identity", hexHash, "ratchet", ratchetHash)
	return nil
}

func (m *Manager) LoadRatchets(identityHash []byte) (map[string][]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	hexHash := hex.EncodeToString(identityHash)
	ratchetDir := filepath.Join(m.ratchetsPath, hexHash)

	ratchets := make(map[string][]byte)

	if _, err := os.Stat(ratchetDir); os.IsNotExist(err) {
		debug.Log(debug.DEBUG_VERBOSE, "No ratchet directory found", "identity", hexHash)
		return ratchets, nil
	}

	entries, err := os.ReadDir(ratchetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read ratchet directory: %w", err)
	}

	now := time.Now().Unix()
	expiry := int64(2592000) // 30 days

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(ratchetDir, entry.Name())
		data, err := os.ReadFile(filePath) // #nosec G304 - reading from controlled directory
		if err != nil {
			debug.Log(debug.DEBUG_ERROR, "Failed to read ratchet file", "file", entry.Name(), "error", err)
			continue
		}

		var ratchetData RatchetData
		if err := msgpack.Unmarshal(data, &ratchetData); err != nil {
			debug.Log(debug.DEBUG_ERROR, "Corrupted ratchet data", "file", entry.Name(), "error", err)
			_ = os.Remove(filePath)
			continue
		}

		if now > ratchetData.Received+expiry {
			debug.Log(debug.DEBUG_VERBOSE, "Removing expired ratchet", "file", entry.Name())
			_ = os.Remove(filePath)
			continue
		}

		ratchetHash := entry.Name()
		ratchets[ratchetHash] = ratchetData.RatchetKey
	}

	debug.Log(debug.DEBUG_VERBOSE, "Loaded ratchets from storage", "identity", hexHash, "count", len(ratchets))
	return ratchets, nil
}

func (m *Manager) GetBasePath() string {
	return m.basePath
}

func (m *Manager) GetRatchetsPath() string {
	return m.ratchetsPath
}

func (m *Manager) GetIdentityPath() string {
	return filepath.Join(m.basePath, "identity")
}

func (m *Manager) GetTransportIdentityPath() string {
	return m.transportIdentity
}

func (m *Manager) GetDestinationTablePath() string {
	return m.destinationTable
}

func (m *Manager) GetKnownDestinationsPath() string {
	return m.knownDestinations
}

