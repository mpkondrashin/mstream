package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v2"
)

type Config struct {
	HybridAnalysisAPIKey string `yaml:"HybridAnalysisAPIKey"`
	ThreatLevelThreshold int    `yaml:"ThreatLevelThreshold"`
	SkipList             string `yaml:"SkipList"`
	IncludeList          string `yaml:"IncludeList"`
	TargetDir            string `yaml:"TargetDir"`
	ExtList              string `yaml:"ExtList"`
	Log                  string `yaml:"Log"`
	VirusTotalAPIKey     string `yaml:"VirusTotalAPIKey"`
	DataBase             string `yaml:"DataBase"`
}

func NewConfig() *Config {
	return &Config{}
}

func (c *Config) ParseAll(filePath string) error {
	err := c.LoadConfig(filePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	c.ParseArgs()
	err = c.ParseEnv()
	if err != nil {
		return err
	}
	return c.Validate()
}

func (c *Config) ParseArgs() {
	flag.StringVar(&c.VirusTotalAPIKey, "vtkey",
		c.VirusTotalAPIKey, "Virus Total API key")
	flag.StringVar(&c.HybridAnalysisAPIKey, "hakey",
		c.HybridAnalysisAPIKey, "Hybrid Analysis API key")
	flag.StringVar(&c.TargetDir, "output",
		c.TargetDir, "Target folder")
	flag.IntVar(&c.ThreatLevelThreshold, "level",
		c.ThreatLevelThreshold, "Threat level threshold")
	flag.StringVar(&c.SkipList, "skip",
		c.SkipList, "Coma separated list of platform keywords to skip")
	flag.StringVar(&c.IncludeList, "include",
		c.IncludeList, "Coma separated list of platform keywords to include")
	flag.StringVar(&c.ExtList, "ext",
		c.ExtList, "Coma separated list of extesions of files to include")
	flag.StringVar(&c.Log, "log",
		c.Log, "Log file")
	flag.StringVar(&c.DataBase, "database",
		c.DataBase, "Database file")
	flag.Parse()
}

func (c *Config) LoadConfig(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	return c.ParseConfig(data)
}

func (c *Config) ParseConfig(data []byte) error {
	err := yaml.UnmarshalStrict(data, c)
	if err == nil {
		return nil
	}
	err = json.Unmarshal(data, c)
	if err == nil {
		return nil
	}
	return err
}

func (c *Config) ParseEnv() error {
	v, ok := os.LookupEnv("MSTREAM_HYBRID_ANALYSIS_API_KEY")
	if ok {
		c.HybridAnalysisAPIKey = v
	}
	v, ok = os.LookupEnv("MSTREAM_VIRUS_TOTAL_API_KEY")
	if ok {
		c.VirusTotalAPIKey = v
	}
	mstlt := "MSTREAM_THREAT_LEVEL_THRESHOLD"
	v, ok = os.LookupEnv(mstlt)
	if ok {
		i, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%s=%s: %w", mstlt, v, err)
		}
		c.ThreatLevelThreshold = i
	}
	v, ok = os.LookupEnv("MSTREAM_SKIP_LIST")
	if ok {
		c.SkipList = v
	}
	v, ok = os.LookupEnv("MSTREAM_INCLUDE_LIST")
	if ok {
		c.IncludeList = v
	}
	v, ok = os.LookupEnv("MSTREAM_EXT_LIST")
	if ok {
		c.ExtList = v
	}
	v, ok = os.LookupEnv("MSTREAM_TARGET_DIR")
	if ok {
		c.TargetDir = v
	}
	v, ok = os.LookupEnv("MSTREAM_LOG")
	if ok {
		c.Log = v
	}
	v, ok = os.LookupEnv("MSTREAM_DATABASES")
	if ok {
		c.DataBase = v
	}
	return nil
}

func (c *Config) Validate() error {
	if c.TargetDir == "" {
		return errors.New("no output folder provided")
	}
	if c.HybridAnalysisAPIKey == "" {
		return errors.New("no Hybrid Analysis API key provided")
	}
	if c.VirusTotalAPIKey == "" {
		return errors.New("no Virus Total API key provided")
	}
	if c.DataBase == "" {
		return errors.New("no database path provided")
	}
	if c.ThreatLevelThreshold < 0 || c.ThreatLevelThreshold > 2 {
		return fmt.Errorf("wrong threat level threshold value (%d)", c.ThreatLevelThreshold)
	}
	return nil
}
