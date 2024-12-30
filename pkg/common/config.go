package common

// ConfigProvider interface for accessing configuration
type ConfigProvider interface {
    GetConfigPath() string
    GetLogLevel() int
    GetInterfaces() map[string]InterfaceConfig
}

// InterfaceConfig represents interface configuration
type InterfaceConfig struct {
    Type        string `toml:"type"`
    Name        string `toml:"name"`
    Enabled     bool   `toml:"enabled"`
    TargetHost  string `toml:"target_host,omitempty"`
    TargetPort  int    `toml:"target_port,omitempty"`
    Interface   string `toml:"interface,omitempty"`
    Address     string `toml:"address,omitempty"`
    Port        int    `toml:"port,omitempty"`
    KISSFraming bool   `toml:"kiss_framing,omitempty"`
    I2PTunneled bool   `toml:"i2p_tunneled,omitempty"`
    PreferIPv6  bool   `toml:"prefer_ipv6,omitempty"`
}

// ReticulumConfig represents the main configuration structure
type ReticulumConfig struct {
    ConfigPath            string                     `toml:"-"`
    EnableTransport       bool                       `toml:"enable_transport"`
    ShareInstance        bool                       `toml:"share_instance"`
    SharedInstancePort   int                        `toml:"shared_instance_port"`
    InstanceControlPort  int                        `toml:"instance_control_port"`
    PanicOnInterfaceErr bool                       `toml:"panic_on_interface_error"`
    LogLevel            int                        `toml:"loglevel"`
    Interfaces          map[string]*InterfaceConfig `toml:"interfaces"`
} 