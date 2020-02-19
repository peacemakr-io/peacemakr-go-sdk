package tools

import (
	"encoding"
	"github.com/google/uuid"
	peacemakr_go_sdk "github.com/peacemakr-io/peacemakr-go-sdk/pkg"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/utils"
	"github.com/spf13/viper"
	"log"
	"os"
)

type EncryptorConfig struct {
	ApiKey     string  `mapstructure:"api_key"`
	ClientName string  `mapstructure:"client_name"`
	Url        *string `mapstructure:"url"`
	Persister  utils.Persister
	Logger     peacemakr_go_sdk.SDKLogger
}

type Encryptor struct {
	Sdk peacemakr_go_sdk.PeacemakrSDK
}

type EncryptorError struct {
	msg string
}

func (e *EncryptorError) Error() string {
	return e.msg
}

var NoApiKey = &EncryptorError{msg: "no API key provided"}

func NewEncryptor(cfg *EncryptorConfig) (*Encryptor, error) {
	config := EncryptorConfig{}

	if cfg == nil {
		viper.SetEnvPrefix("PEACEMAKR_ENCRYPTOR")
		viper.AutomaticEnv()
		if err := viper.Unmarshal(&config); err != nil {
			return nil, err
		}
	} else {
		config = *cfg
	}

	if config.ClientName == "" {
		config.ClientName = uuid.New().String()
	}

	if config.Persister == nil {
		config.Persister = utils.GetInMemPersister()
	}

	if config.Logger == nil {
		config.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	sdk, err := peacemakr_go_sdk.GetPeacemakrSDK(config.ApiKey, config.ClientName, config.Url, config.Persister, config.Logger)
	if err != nil {
		return nil, err
	}

	if err := sdk.Register(); err != nil {
		return nil, err
	}

	return &Encryptor{
		Sdk: sdk,
	}, nil
}

func (e *Encryptor) Encrypt(plaintext encoding.BinaryMarshaler) ([]byte, error) {
	bytes, err := plaintext.MarshalBinary()
	if err != nil {
		return nil, err
	}

	encrypted, err := e.Sdk.Encrypt(bytes)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

func (e *Encryptor) Decrypt(encrypted []byte, plaintext encoding.BinaryUnmarshaler) error {
	decrypted, err := e.Sdk.Decrypt(encrypted)
	if err != nil {
		return err
	}

	if err := plaintext.UnmarshalBinary(decrypted); err != nil {
		return err
	}

	return nil
}
