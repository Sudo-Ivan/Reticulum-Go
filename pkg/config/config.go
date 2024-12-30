package config

import (
    "io/ioutil"
    "gopkg.in/yaml.v3"
)

type Config struct {
    Identity struct {
        Name        string `yaml:"name"`
        StoragePath string `yaml:"storage_path"`
    } `yaml:"identity"`

    Interfaces []struct {
        Name        string `yaml:"name"`
        Type        string `yaml:"type"`
        Enabled     bool   `yaml:"enabled"`
        ListenPort  int    `yaml:"listen_port"`
        ListenIP    string `yaml:"listen_ip"`
        KissFraming bool   `yaml:"kiss_framing"`
        I2PTunneled bool   `yaml:"i2p_tunneled"`
    } `yaml:"interfaces"`

    Transport struct {
        AnnounceInterval   int   `yaml:"announce_interval"`
        PathRequestTimeout int   `yaml:"path_request_timeout"`
        MaxHops           int   `yaml:"max_hops"`
        BitrateLimit      int64 `yaml:"bitrate_limit"`
    } `yaml:"transport"`

    Logging struct {
        Level string `yaml:"level"`
        File  string `yaml:"file"`
    } `yaml:"logging"`
}

func LoadConfig(path string) (*Config, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }

    return &cfg, nil
} 