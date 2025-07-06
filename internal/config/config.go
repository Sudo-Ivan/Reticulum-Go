package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
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
	return os.MkdirAll(configDir, 0700) // #nosec G301
}

// parseValue parses string values into appropriate types
func parseValue(value string) interface{} {
	value = strings.TrimSpace(value)

	// Try bool
	if value == "true" {
		return true
	}
	if value == "false" {
		return false
	}

	// Try int
	if i, err := strconv.Atoi(value); err == nil {
		return i
	}

	// Return as string
	return value
}

// LoadConfig loads the configuration from the specified path
func LoadConfig(path string) (*common.ReticulumConfig, error) {
	file, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := DefaultConfig()
	cfg.ConfigPath = path

	scanner := bufio.NewScanner(file)
	var currentInterface *common.InterfaceConfig

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle interface sections
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.Trim(line, "[]")
			currentInterface = &common.InterfaceConfig{Name: name}
			cfg.Interfaces[name] = currentInterface
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if currentInterface != nil {
			// Parse interface config
			switch key {
			case "type":
				currentInterface.Type = value
			case "enabled":
				currentInterface.Enabled = value == "true"
			case "address":
				currentInterface.Address = value
			case "port":
				currentInterface.Port, _ = strconv.Atoi(value)
			case "target_host":
				currentInterface.TargetHost = value
			case "target_port":
				currentInterface.TargetPort, _ = strconv.Atoi(value)
			case "discovery_port":
				currentInterface.DiscoveryPort, _ = strconv.Atoi(value)
			case "data_port":
				currentInterface.DataPort, _ = strconv.Atoi(value)
			case "discovery_scope":
				currentInterface.DiscoveryScope = value
			case "group_id":
				currentInterface.GroupID = value
			}
		} else {
			// Parse global config
			switch key {
			case "enable_transport":
				cfg.EnableTransport = value == "true"
			case "share_instance":
				cfg.ShareInstance = value == "true"
			case "shared_instance_port":
				cfg.SharedInstancePort, _ = strconv.Atoi(value)
			case "instance_control_port":
				cfg.InstanceControlPort, _ = strconv.Atoi(value)
			case "panic_on_interface_error":
				cfg.PanicOnInterfaceErr = value == "true"
			case "loglevel":
				cfg.LogLevel, _ = strconv.Atoi(value)
			}
		}
	}

	return cfg, nil
}

// SaveConfig saves the configuration to the specified path
func SaveConfig(cfg *common.ReticulumConfig) error {
	if cfg.ConfigPath == "" {
		return fmt.Errorf("config path not set")
	}

	var builder strings.Builder

	// Write global config
	builder.WriteString("# Reticulum Configuration\n")
	builder.WriteString(fmt.Sprintf("enable_transport = %v\n", cfg.EnableTransport))
	builder.WriteString(fmt.Sprintf("share_instance = %v\n", cfg.ShareInstance))
	builder.WriteString(fmt.Sprintf("shared_instance_port = %d\n", cfg.SharedInstancePort))
	builder.WriteString(fmt.Sprintf("instance_control_port = %d\n", cfg.InstanceControlPort))
	builder.WriteString(fmt.Sprintf("panic_on_interface_error = %v\n", cfg.PanicOnInterfaceErr))
	builder.WriteString(fmt.Sprintf("loglevel = %d\n\n", cfg.LogLevel))

	// Write interface configs
	for name, iface := range cfg.Interfaces {
		builder.WriteString(fmt.Sprintf("[%s]\n", name))
		builder.WriteString(fmt.Sprintf("type = %s\n", iface.Type))
		builder.WriteString(fmt.Sprintf("enabled = %v\n", iface.Enabled))

		if iface.Address != "" {
			builder.WriteString(fmt.Sprintf("address = %s\n", iface.Address))
		}
		if iface.Port != 0 {
			builder.WriteString(fmt.Sprintf("port = %d\n", iface.Port))
		}
		if iface.TargetHost != "" {
			builder.WriteString(fmt.Sprintf("target_host = %s\n", iface.TargetHost))
		}
		if iface.TargetPort != 0 {
			builder.WriteString(fmt.Sprintf("target_port = %d\n", iface.TargetPort))
		}
		if iface.DiscoveryPort != 0 {
			builder.WriteString(fmt.Sprintf("discovery_port = %d\n", iface.DiscoveryPort))
		}
		if iface.DataPort != 0 {
			builder.WriteString(fmt.Sprintf("data_port = %d\n", iface.DataPort))
		}
		if iface.DiscoveryScope != "" {
			builder.WriteString(fmt.Sprintf("discovery_scope = %s\n", iface.DiscoveryScope))
		}
		if iface.GroupID != "" {
			builder.WriteString(fmt.Sprintf("group_id = %s\n", iface.GroupID))
		}
		builder.WriteString("\n")
	}

	return os.WriteFile(cfg.ConfigPath, []byte(builder.String()), 0600) // #nosec G306
}

// CreateDefaultConfig creates a default configuration file
func CreateDefaultConfig(path string) error {
	cfg := DefaultConfig()
	cfg.ConfigPath = path

	// Add Auto Interface
	cfg.Interfaces["Auto Discovery"] = &common.InterfaceConfig{
		Type:           "AutoInterface",
		Enabled:        true,
		GroupID:        "reticulum",
		DiscoveryScope: "link",
		DiscoveryPort:  29716,
		DataPort:       42671,
	}

	// Add default interfaces
	cfg.Interfaces["Go-RNS-Testnet"] = &common.InterfaceConfig{
		Type:       "TCPClientInterface",
		Enabled:    true,
		TargetHost: "127.0.0.1",
		TargetPort: 4242,
		Name:       "Go-RNS-Testnet",
	}

	cfg.Interfaces["Quad4 TCP"] = &common.InterfaceConfig{
		Type:       "TCPClientInterface",
		Enabled:    true,
		TargetHost: "rns.quad4.io",
		TargetPort: 4242,
		Name:       "Quad4 TCP",
	}

	cfg.Interfaces["Local UDP"] = &common.InterfaceConfig{
		Type:    "UDPInterface",
		Enabled: false,
		Address: "0.0.0.0",
		Port:    37696,
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { // #nosec G301
		return err
	}

	return SaveConfig(cfg)
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
