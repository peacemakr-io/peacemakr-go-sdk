package tools

import (
	"github.com/google/uuid"
	peacemakr_go_sdk "github.com/peacemakr-io/peacemakr-go-sdk/pkg"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/utils"
	"github.com/spf13/viper"
	"log"
	"os"
	"reflect"
	"unsafe"
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

func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func StringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

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

func (e *Encryptor) Encrypt(plaintext interface{}) error {
	pType := reflect.TypeOf(plaintext).Elem()
	value := reflect.ValueOf(plaintext).Elem()
	for i := 0; i < pType.NumField(); i++ {
		valueField := value.Field(i)
		typeField := pType.Field(i)
		tag := typeField.Tag.Get("encrypt")
		if tag != "true" {
			continue
		}

		if typeField.Type.String() == "[]uint8" {
			encrypted, err := e.Sdk.Encrypt(valueField.Bytes())
			if err != nil {
				return err
			}
			valueField.SetBytes(encrypted)
			continue
		}

		if typeField.Type.String() == "string" {
			encrypted, err := e.Sdk.Encrypt(StringToBytes(valueField.String()))
			if err != nil {
				return err
			}
			valueField.SetString(BytesToString(encrypted))
			continue
		}
	}

	return nil
}

func (e *Encryptor) Decrypt(encrypted interface{}) error {
	pType := reflect.TypeOf(encrypted).Elem()
	value := reflect.ValueOf(encrypted).Elem()
	for i := 0; i < pType.NumField(); i++ {
		valueField := value.Field(i)
		typeField := pType.Field(i)
		tag := typeField.Tag.Get("encrypt")
		if tag != "true" {
			continue
		}

		if typeField.Type.String() == "[]uint8" {
			encrypted, err := e.Sdk.Decrypt(valueField.Bytes())
			if err != nil {
				return err
			}
			valueField.SetBytes(encrypted)
			continue
		}

		if typeField.Type.String() == "string" {
			encrypted, err := e.Sdk.Decrypt(StringToBytes(valueField.String()))
			if err != nil {
				return err
			}
			valueField.SetString(BytesToString(encrypted))
			continue
		}
	}

	return nil
}
