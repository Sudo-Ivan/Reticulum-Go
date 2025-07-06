package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Identity struct {
		Name        string
		StoragePath string
	}

	Interfaces []struct {
		Name        string
		Type        string
		Enabled     bool
		ListenPort  int
		ListenIP    string
		KissFraming bool
		I2PTunneled bool
	}

	Transport struct {
		AnnounceInterval   int
		PathRequestTimeout int
		MaxHops            int
		BitrateLimit       int64
	}

	Logging struct {
		Level string
		File  string
	}
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &Config{}
	scanner := bufio.NewScanner(file)
	var currentSection string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle sections
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")

			// If this is an interface section, append new interface
			if strings.HasPrefix(currentSection, "interface ") {
				cfg.Interfaces = append(cfg.Interfaces, struct {
					Name        string
					Type        string
					Enabled     bool
					ListenPort  int
					ListenIP    string
					KissFraming bool
					I2PTunneled bool
				}{})
			}
			continue
		}

		// Parse key-value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "identity":
			switch key {
			case "name":
				cfg.Identity.Name = value
			case "storage_path":
				cfg.Identity.StoragePath = value
			}

		case "transport":
			switch key {
			case "announce_interval":
				cfg.Transport.AnnounceInterval, _ = strconv.Atoi(value)
			case "path_request_timeout":
				cfg.Transport.PathRequestTimeout, _ = strconv.Atoi(value)
			case "max_hops":
				cfg.Transport.MaxHops, _ = strconv.Atoi(value)
			case "bitrate_limit":
				cfg.Transport.BitrateLimit, _ = strconv.ParseInt(value, 10, 64)
			}

		case "logging":
			switch key {
			case "level":
				cfg.Logging.Level = value
			case "file":
				cfg.Logging.File = value
			}

		default:
			// Handle interface sections
			if strings.HasPrefix(currentSection, "interface ") && len(cfg.Interfaces) > 0 {
				iface := &cfg.Interfaces[len(cfg.Interfaces)-1]
				switch key {
				case "name":
					iface.Name = value
				case "type":
					iface.Type = value
				case "enabled":
					iface.Enabled = value == "true"
				case "listen_port":
					iface.ListenPort, _ = strconv.Atoi(value)
				case "listen_ip":
					iface.ListenIP = value
				case "kiss_framing":
					iface.KissFraming = value == "true"
				case "i2p_tunneled":
					iface.I2PTunneled = value == "true"
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func SaveConfig(cfg *Config, path string) error {
	var builder strings.Builder

	// Write Identity section
	builder.WriteString("[identity]\n")
	builder.WriteString(fmt.Sprintf("name = %s\n", cfg.Identity.Name))
	builder.WriteString(fmt.Sprintf("storage_path = %s\n\n", cfg.Identity.StoragePath))

	// Write Transport section
	builder.WriteString("[transport]\n")
	builder.WriteString(fmt.Sprintf("announce_interval = %d\n", cfg.Transport.AnnounceInterval))
	builder.WriteString(fmt.Sprintf("path_request_timeout = %d\n", cfg.Transport.PathRequestTimeout))
	builder.WriteString(fmt.Sprintf("max_hops = %d\n", cfg.Transport.MaxHops))
	builder.WriteString(fmt.Sprintf("bitrate_limit = %d\n\n", cfg.Transport.BitrateLimit))

	// Write Logging section
	builder.WriteString("[logging]\n")
	builder.WriteString(fmt.Sprintf("level = %s\n", cfg.Logging.Level))
	builder.WriteString(fmt.Sprintf("file = %s\n\n", cfg.Logging.File))

	// Write Interface sections
	for _, iface := range cfg.Interfaces {
		builder.WriteString(fmt.Sprintf("[interface %s]\n", iface.Name))
		builder.WriteString(fmt.Sprintf("type = %s\n", iface.Type))
		builder.WriteString(fmt.Sprintf("enabled = %v\n", iface.Enabled))
		builder.WriteString(fmt.Sprintf("listen_port = %d\n", iface.ListenPort))
		builder.WriteString(fmt.Sprintf("listen_ip = %s\n", iface.ListenIP))
		builder.WriteString(fmt.Sprintf("kiss_framing = %v\n", iface.KissFraming))
		builder.WriteString(fmt.Sprintf("i2p_tunneled = %v\n\n", iface.I2PTunneled))
	}

	return os.WriteFile(path, []byte(builder.String()), 0600) // #nosec G306
}

func GetConfigDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if home directory cannot be determined
		return ".reticulum-go"
	}
	return filepath.Join(homeDir, ".reticulum-go")
}

func GetDefaultConfigPath() string {
	return filepath.Join(GetConfigDir(), "config")
}

func EnsureConfigDir() error {
	configDir := GetConfigDir()
	return os.MkdirAll(configDir, 0700) // #nosec G301
}

func InitConfig() (*Config, error) {
	// Ensure config directory exists
	if err := EnsureConfigDir(); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %v", err)
	}

	configPath := GetDefaultConfigPath()

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config
		cfg := &Config{}

		// Set default values
		cfg.Identity.Name = "reticulum-node"
		cfg.Identity.StoragePath = filepath.Join(GetConfigDir(), "storage")

		cfg.Transport.AnnounceInterval = 300
		cfg.Transport.PathRequestTimeout = 15
		cfg.Transport.MaxHops = 8
		cfg.Transport.BitrateLimit = 1000000

		cfg.Logging.Level = "info"
		cfg.Logging.File = filepath.Join(GetConfigDir(), "reticulum.log")

		// Add default interfaces
		cfg.Interfaces = append(cfg.Interfaces, struct {
			Name        string
			Type        string
			Enabled     bool
			ListenPort  int
			ListenIP    string
			KissFraming bool
			I2PTunneled bool
		}{
			Name:       "Local UDP",
			Type:       "UDPInterface",
			Enabled:    true,
			ListenPort: 37697,
			ListenIP:   "0.0.0.0",
		})

		cfg.Interfaces = append(cfg.Interfaces, struct {
			Name        string
			Type        string
			Enabled     bool
			ListenPort  int
			ListenIP    string
			KissFraming bool
			I2PTunneled bool
		}{
			Name:       "Auto Discovery",
			Type:       "AutoInterface",
			Enabled:    true,
			ListenPort: 29717,
		})

		// Save default config
		if err := SaveConfig(cfg, configPath); err != nil {
			return nil, fmt.Errorf("failed to save default config: %v", err)
		}
	}

	// Load config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	return cfg, nil
}
