package common

// ConfigProvider interface for accessing configuration
type ConfigProvider interface {
    GetConfigPath() string
    GetLogLevel() int
    GetInterfaces() map[string]InterfaceConfig
}

// InterfaceConfig represents interface configuration
type InterfaceConfig struct {
    Name         string `toml:"name"`
    Type         string `toml:"type"`
    Enabled      bool   `toml:"enabled"`
    Address      string `toml:"address"`
    Port         int    `toml:"port"`
    TargetHost   string `toml:"target_host"`
    TargetPort   int    `toml:"target_port"`
    TargetAddress string `toml:"target_address"`
    Interface    string `toml:"interface"`
    KISSFraming  bool   `toml:"kiss_framing"`
    I2PTunneled  bool   `toml:"i2p_tunneled"`
    PreferIPv6   bool   `toml:"prefer_ipv6"`
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