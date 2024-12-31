package common

import (
    "fmt"
)

const (
    DEFAULT_SHARED_INSTANCE_PORT  = 37428
    DEFAULT_INSTANCE_CONTROL_PORT = 37429
    DEFAULT_LOG_LEVEL            = 20
)

// ConfigProvider interface for accessing configuration
type ConfigProvider interface {
    GetConfigPath() string
    GetLogLevel() int
    GetInterfaces() map[string]InterfaceConfig
}

// InterfaceConfig represents interface configuration
type InterfaceConfig struct {
    Name           string `toml:"name"`
    Type           string `toml:"type"`
    Enabled        bool   `toml:"enabled"`
    Address        string `toml:"address"`
    Port           int    `toml:"port"`
    TargetHost     string `toml:"target_host"`
    TargetPort     int    `toml:"target_port"`
    TargetAddress  string `toml:"target_address"`
    Interface      string `toml:"interface"`
    KISSFraming    bool   `toml:"kiss_framing"`
    I2PTunneled    bool   `toml:"i2p_tunneled"`
    PreferIPv6     bool   `toml:"prefer_ipv6"`
    MaxReconnTries int    `toml:"max_reconnect_tries"`
    Bitrate        int64  `toml:"bitrate"`
    MTU           int    `toml:"mtu"`
    GroupID       string
    DiscoveryScope string
	DiscoveryPort  int
	DataPort       int
}

// ReticulumConfig represents the main configuration structure
type ReticulumConfig struct {
    ConfigPath           string                     `toml:"-"`
    EnableTransport      bool                       `toml:"enable_transport"`
    ShareInstance        bool                       `toml:"share_instance"`
    SharedInstancePort   int                        `toml:"shared_instance_port"`
    InstanceControlPort  int                        `toml:"instance_control_port"`
    PanicOnInterfaceErr bool                       `toml:"panic_on_interface_error"`
    LogLevel            int                         `toml:"loglevel"`
    Interfaces          map[string]*InterfaceConfig `toml:"interfaces"`
}

// NewReticulumConfig creates a new ReticulumConfig with default values
func NewReticulumConfig() *ReticulumConfig {
    return &ReticulumConfig{
        EnableTransport:      true,
        ShareInstance:        false,
        SharedInstancePort:   DEFAULT_SHARED_INSTANCE_PORT,
        InstanceControlPort:  DEFAULT_INSTANCE_CONTROL_PORT,
        PanicOnInterfaceErr: false,
        LogLevel:            DEFAULT_LOG_LEVEL,
        Interfaces:          make(map[string]*InterfaceConfig),
    }
}

// Validate checks if the configuration is valid
func (c *ReticulumConfig) Validate() error {
    if c.SharedInstancePort < 1 || c.SharedInstancePort > 65535 {
        return fmt.Errorf("invalid shared instance port: %d", c.SharedInstancePort)
    }
    if c.InstanceControlPort < 1 || c.InstanceControlPort > 65535 {
        return fmt.Errorf("invalid instance control port: %d", c.InstanceControlPort)
    }
    return nil
} 