package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

type Config struct {
	AMF AMFConfig `yaml:"AMF"`
	UE  UEConfig  `yaml:"UE"`
}

type AMFConfig struct {
	IP   string `yaml:"IP"`
	Port int    `yaml:"Port"`
}

type UEConfig struct {
	SUPI string `yaml:"SUPI"`
	K    string `yaml:"K"`
	OPC  string `yaml:"OPC"`
}

func Load(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(file, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}