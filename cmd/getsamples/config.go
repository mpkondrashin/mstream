package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

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
	HybridAnalysisAPIKey string        `yaml:"HybridAnalysisAPIKey"`
	ThreatLevelThreshold int           `yaml:"ThreatLevelThreshold"`
	SkipList             string        `yaml:"SkipList"`
	IncludeList          string        `yaml:"IncludeList"`
	TargetDir            string        `yaml:"TargetDir"`
	Log                  string        `yaml:"Log"`
	Interval             time.Duration `yaml:"Interval"`
	//ExtList              string `yaml:"ExtList"`
	//VirusTotalAPIKey     string `yaml:"VirusTotalAPIKey"`
	//DataBase             string `yaml:"DataBase"`
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
	if c.HybridAnalysisAPIKey == "" {
		return errors.New("no Hybrid Analysis API key provided")
	}
	if c.ThreatLevelThreshold < 0 || c.ThreatLevelThreshold > 2 {
		return fmt.Errorf("wrong threat level threshold value (%d)", c.ThreatLevelThreshold)
	}
	return nil
}

func (c *Config) LogFilePath() string {
	if c.Log != "" {
		return c.Log
	}
	return AppName() + ".log"
}
