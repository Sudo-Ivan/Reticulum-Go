package config

import (
	"os"
	"path/filepath"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/pelletier/go-toml"
)

const (
	DefaultSharedInstancePort  = 37428
	DefaultInstanceControlPort = 37429
	DefaultLogLevel            = 4
)

func DefaultConfig() *common.ReticulumConfig {
	return &common.ReticulumConfig{
		EnableTransport:     true,
		ShareInstance:       true,
		SharedInstancePort:  DefaultSharedInstancePort,
		InstanceControlPort: DefaultInstanceControlPort,
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
	return filepath.Join(homeDir, ".reticulum-go", "config"), nil
}

func EnsureConfigDir() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(homeDir, ".reticulum-go")
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

	// Add Auto Interface
	cfg.Interfaces["Auto Discovery"] = &common.InterfaceConfig{
		Type:           "AutoInterface",
		Enabled:        true,
		GroupID:        "reticulum",
		DiscoveryScope: "link",
		DiscoveryPort:  29716,
		DataPort:       42671,
	}

	// Add RNS Amsterdam Testnet interface
	cfg.Interfaces["RNS Testnet Amsterdam"] = &common.InterfaceConfig{
		Type:       "TCPClientInterface",
		Enabled:    true,
		TargetHost: "amsterdam.connect.reticulum.network",
		TargetPort: 4965,
	}

	// Add RNS BetweenTheBorders Testnet interface
	cfg.Interfaces["RNS Testnet BetweenTheBorders"] = &common.InterfaceConfig{
		Type:       "TCPClientInterface",
		Enabled:    true,
		TargetHost: "reticulum.betweentheborders.com",
		TargetPort: 4242,
	}

	// Add local UDP interface
	cfg.Interfaces["Local UDP"] = &common.InterfaceConfig{
		Type:    "UDPInterface",
		Enabled: true,
		Address: "0.0.0.0",
		Port:    37696,
	}

	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}

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
