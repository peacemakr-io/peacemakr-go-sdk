package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"errors"
	"fmt"
)

var RSAKEYLENGTH = 4096
var DEBUG = true

type LocallizedKeyFetcherService struct {
	LocalPubKeys  map[string]string
	LocalPrivKeys map[string]string
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func pemString(key *rsa.PrivateKey) string {
	buf := new(bytes.Buffer)

	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err := pem.Encode(buf, privateKey)
	if err != nil {
		if DEBUG {
			log.Println("Failed to encode private key to PEM, ", err)
		}
		return ""
	}

	return buf.String()

}

func publicPemKey(key rsa.PublicKey) string {
	pub, err := x509.MarshalPKIXPublicKey(&key)
	if err != nil {
		panic(err)
	}

	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pub,
		},
	)

	return string(pubPem)
}

func getNewKey(keyType string, bitlength int) (string, string) {

	if keyType == "rsa" {
		reader := rand.Reader

		//
		// Verify the bitlength is something that this library can handle.
		// If it is not, the just fallback to a sane default.
		//
		if bitlength != 2048 || bitlength != 4096 {
			bitlength = 2048
		}

		key, err := rsa.GenerateKey(reader, bitlength)
		if err != nil {
			return fmt.Sprintf("error %v", err), fmt.Sprintf("error %v", err)
		}

		pemPriv := pemString(key)
		pemPub := publicPemKey(key.PublicKey)

		return pemPriv, pemPub
	} else {
		// Then, just default to an RSA key type of 2048 bits.
		return getNewKey("rsa", 2048)
	}


}
