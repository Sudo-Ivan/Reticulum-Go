package common

import (
	"fmt"
)

const (
	DEFAULT_SHARED_INSTANCE_PORT  = 37428
	DEFAULT_INSTANCE_CONTROL_PORT = 37429
	DEFAULT_LOG_LEVEL             = 20
)

// ConfigProvider interface for accessing configuration
type ConfigProvider interface {
	GetConfigPath() string
	GetLogLevel() int
	GetInterfaces() map[string]InterfaceConfig
}

// InterfaceConfig represents interface configuration
type InterfaceConfig struct {
	Name           string
	Type           string
	Enabled        bool
	Address        string
	Port           int
	TargetHost     string
	TargetPort     int
	TargetAddress  string
	Interface      string
	KISSFraming    bool
	I2PTunneled    bool
	PreferIPv6     bool
	MaxReconnTries int
	Bitrate        int64
	MTU            int
	GroupID        string
	DiscoveryScope string
	DiscoveryPort  int
	DataPort       int
}

// ReticulumConfig represents the main configuration structure
type ReticulumConfig struct {
	ConfigPath          string
	EnableTransport     bool
	ShareInstance       bool
	SharedInstancePort  int
	InstanceControlPort int
	PanicOnInterfaceErr bool
	LogLevel            int
	Interfaces          map[string]*InterfaceConfig
	AppName             string
	AppAspect           string
}

// NewReticulumConfig creates a new ReticulumConfig with default values
func NewReticulumConfig() *ReticulumConfig {
	return &ReticulumConfig{
		EnableTransport:     true,
		ShareInstance:       false,
		SharedInstancePort:  DEFAULT_SHARED_INSTANCE_PORT,
		InstanceControlPort: DEFAULT_INSTANCE_CONTROL_PORT,
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

func DefaultConfig() *ReticulumConfig {
	return &ReticulumConfig{
		EnableTransport:     true,
		ShareInstance:       false,
		SharedInstancePort:  DEFAULT_SHARED_INSTANCE_PORT,
		InstanceControlPort: DEFAULT_INSTANCE_CONTROL_PORT,
		PanicOnInterfaceErr: false,
		LogLevel:            DEFAULT_LOG_LEVEL,
		Interfaces:          make(map[string]*InterfaceConfig),
		AppName:             "Go Client",
		AppAspect:           "node",
	}
}
