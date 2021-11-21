package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v2"
)

func ConfigFileName() string {
	return AppName() + ".yaml"
}

func AppName() string {
	_, filePath, _, ok := runtime.Caller(1)
	if !ok {
		return "runtime_Caller_error.yaml"
	}
	dirPath := filepath.Dir(filePath)
	dirName := filepath.Base(dirPath)
	return dirName
}

type Config struct {
	//	ExtList              string `yaml:"ExtList"`
	Log              string `yaml:"Log"`
	VirusTotalAPIKey string `yaml:"VirusTotalAPIKey"`
	TargetDir        string `yaml:"TargetDir"`

	//	DataBase             string `yaml:"DataBase"`
}

func NewConfig() *Config {
	return &Config{}
}

func (c *Config) LoadConfig() error {
	return c.LoadConfigFile(ConfigFileName())
}

func (c *Config) LoadConfigFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	err = c.ParseConfig(data)
	if err != nil {
		return err
	}
	return c.Validate()
}

func (c *Config) ParseConfig(data []byte) error {
	err := yaml.UnmarshalStrict(data, c)
	if err == nil {
		return nil
	}
	return err
}

func (c *Config) Validate() error {
	if c.TargetDir == "" {
		return errors.New("no output folder provided")
	}
	if c.VirusTotalAPIKey == "" {
		return errors.New("no Virus Total API key provided")
	}

	return nil
}

func (c *Config) LogFilePath() string {
	if c.Log != "" {
		return c.Log
	}
	return AppName() + ".log"
}
