package config

import (
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

const (
	DefaultSharedInstancePort  = 37428
	DefaultInstanceControlPort = 37429
	DefaultLogLevel           = 4
)

func DefaultConfig() *common.ReticulumConfig {
	return &common.ReticulumConfig{
		EnableTransport:       false,
		ShareInstance:        true,
		SharedInstancePort:   DefaultSharedInstancePort,
		 InstanceControlPort:  DefaultInstanceControlPort,
		PanicOnInterfaceErr: false,
		LogLevel:            DefaultLogLevel,
		Interfaces:          make(map[string]*common.InterfaceConfig),
	}
}

func GetConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".reticulum", "config"), nil
}

func EnsureConfigDir() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(homeDir, ".reticulum")
	return os.MkdirAll(configDir, 0755)
}

// LoadConfig loads the configuration from the specified path
func LoadConfig(path string) (*common.ReticulumConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.ConfigPath = path
	return cfg, nil
}

// SaveConfig saves the configuration to the specified path
func SaveConfig(cfg *common.ReticulumConfig) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(cfg.ConfigPath, data, 0644)
}

// CreateDefaultConfig creates a default configuration file
func CreateDefaultConfig(path string) error {
	cfg := DefaultConfig()

	// Add default interface
	cfg.Interfaces["Default Interface"] = &common.InterfaceConfig{
		Type:    "AutoInterface",
		Enabled: false,
	}

	// Add default quad4net interface
	cfg.Interfaces["quad4net tcp"] = &common.InterfaceConfig{
		Type:       "TCPClientInterface",
		Enabled:    true,
		TargetHost: "rns.quad4.io",
		 TargetPort: 4242,
	}

	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// InitConfig initializes the configuration system
func InitConfig() (*common.ReticulumConfig, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config
		if err := CreateDefaultConfig(configPath); err != nil {
			return nil, err
		}
	}

	// Load config
	return LoadConfig(configPath)
} 