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
    Enabled     bool   `toml:"enabled"`
    TargetHost  string `toml:"target_host,omitempty"`
    TargetPort  int    `toml:"target_port,omitempty"`
    Interface   string `toml:"interface,omitempty"`
}

// ReticulumConfig represents the main configuration structure
type ReticulumConfig struct {
    EnableTransport      bool   `toml:"enable_transport"`
    ShareInstance        bool   `toml:"share_instance"`
    SharedInstancePort   int    `toml:"shared_instance_port"`
    InstanceControlPort  int    `toml:"instance_control_port"`
    PanicOnInterfaceErr bool   `toml:"panic_on_interface_error"`
    LogLevel            int    `toml:"loglevel"`
    ConfigPath          string `toml:"-"`
    Interfaces          map[string]InterfaceConfig
} 