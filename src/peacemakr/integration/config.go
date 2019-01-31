package main

import (
	"github.com/spf13/viper"
	"log"
	"strings"
)

// Root level config.
type TestConfig struct {
	IntegrationTest TestClientConfig
}

// Configs to help KeyDeriver reach PeaceMakr services.
type TestClientConfig struct {
	CompanyName         string
	NumUseDomains       int
	NumKeysPerUseDomain int
	NumClients          int
	NumOfCryptoTrips    int
	Host                string
	Port                string
}

func LoadConfigs() *TestConfig {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("yml")

	// Also permit environment overrides.
	viper.SetEnvPrefix("PEACEMAKR_TEST")

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	viper.AutomaticEnv() // Bind to all configs, overriding config from env when in both file and env var.

	var configuration TestConfig

	if err := viper.MergeInConfig(); err != nil {
		log.Fatalf("Error reading config, %s", err)
	}

	err := viper.Unmarshal(&configuration)
	if err != nil {
		log.Fatalf("unable to read config, %v", err)
	}
	log.Printf("Successfully read in config")

	log.Println("Config: ", configuration)

	return &configuration
}
