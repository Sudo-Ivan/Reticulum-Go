package common

import (
	"testing"
)

func TestNewReticulumConfig(t *testing.T) {
	cfg := NewReticulumConfig()

	if !cfg.EnableTransport {
		t.Errorf("NewReticulumConfig() EnableTransport = %v; want true", cfg.EnableTransport)
	}
	if cfg.ShareInstance {
		t.Errorf("NewReticulumConfig() ShareInstance = %v; want false", cfg.ShareInstance)
	}
	if cfg.SharedInstancePort != DEFAULT_SHARED_INSTANCE_PORT {
		t.Errorf("NewReticulumConfig() SharedInstancePort = %d; want %d", cfg.SharedInstancePort, DEFAULT_SHARED_INSTANCE_PORT)
	}
	if cfg.InstanceControlPort != DEFAULT_INSTANCE_CONTROL_PORT {
		t.Errorf("NewReticulumConfig() InstanceControlPort = %d; want %d", cfg.InstanceControlPort, DEFAULT_INSTANCE_CONTROL_PORT)
	}
	if cfg.PanicOnInterfaceErr {
		t.Errorf("NewReticulumConfig() PanicOnInterfaceErr = %v; want false", cfg.PanicOnInterfaceErr)
	}
	if cfg.LogLevel != DEFAULT_LOG_LEVEL {
		t.Errorf("NewReticulumConfig() LogLevel = %d; want %d", cfg.LogLevel, DEFAULT_LOG_LEVEL)
	}
	if len(cfg.Interfaces) != 0 {
		t.Errorf("NewReticulumConfig() Interfaces length = %d; want 0", len(cfg.Interfaces))
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.EnableTransport {
		t.Errorf("DefaultConfig() EnableTransport = %v; want true", cfg.EnableTransport)
	}
	if cfg.ShareInstance {
		t.Errorf("DefaultConfig() ShareInstance = %v; want false", cfg.ShareInstance)
	}
	if cfg.SharedInstancePort != DEFAULT_SHARED_INSTANCE_PORT {
		t.Errorf("DefaultConfig() SharedInstancePort = %d; want %d", cfg.SharedInstancePort, DEFAULT_SHARED_INSTANCE_PORT)
	}
	if cfg.InstanceControlPort != DEFAULT_INSTANCE_CONTROL_PORT {
		t.Errorf("DefaultConfig() InstanceControlPort = %d; want %d", cfg.InstanceControlPort, DEFAULT_INSTANCE_CONTROL_PORT)
	}
	if cfg.PanicOnInterfaceErr {
		t.Errorf("DefaultConfig() PanicOnInterfaceErr = %v; want false", cfg.PanicOnInterfaceErr)
	}
	if cfg.LogLevel != DEFAULT_LOG_LEVEL {
		t.Errorf("DefaultConfig() LogLevel = %d; want %d", cfg.LogLevel, DEFAULT_LOG_LEVEL)
	}
	if len(cfg.Interfaces) != 0 {
		t.Errorf("DefaultConfig() Interfaces length = %d; want 0", len(cfg.Interfaces))
	}
	if cfg.AppName != "Go Client" {
		t.Errorf("DefaultConfig() AppName = %q; want %q", cfg.AppName, "Go Client")
	}
	if cfg.AppAspect != "node" {
		t.Errorf("DefaultConfig() AppAspect = %q; want %q", cfg.AppAspect, "node")
	}
}

func TestReticulumConfig_Validate(t *testing.T) {
	validConfig := DefaultConfig()
	if err := validConfig.Validate(); err != nil {
		t.Errorf("Validate() on default config failed: %v", err)
	}

	invalidPortConfig1 := DefaultConfig()
	invalidPortConfig1.SharedInstancePort = 0
	if err := invalidPortConfig1.Validate(); err == nil {
		t.Errorf("Validate() did not return error for invalid SharedInstancePort 0")
	}

	invalidPortConfig2 := DefaultConfig()
	invalidPortConfig2.SharedInstancePort = 65536
	if err := invalidPortConfig2.Validate(); err == nil {
		t.Errorf("Validate() did not return error for invalid SharedInstancePort 65536")
	}

	invalidPortConfig3 := DefaultConfig()
	invalidPortConfig3.InstanceControlPort = 0
	if err := invalidPortConfig3.Validate(); err == nil {
		t.Errorf("Validate() did not return error for invalid InstanceControlPort 0")
	}

	invalidPortConfig4 := DefaultConfig()
	invalidPortConfig4.InstanceControlPort = 65536
	if err := invalidPortConfig4.Validate(); err == nil {
		t.Errorf("Validate() did not return error for invalid InstanceControlPort 65536")
	}
}
