package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
)

var RSAKEYLENGTH = 4096
var DEBUG = true

type LocallizedKeyFetcherService struct {
	LocalPubKeys  map[string]string
	LocalPrivKeys map[string]string
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

func getNewKey() (string, string) {
	reader := rand.Reader
	bitSize := RSAKEYLENGTH

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		if DEBUG {
			log.Println("Failed to generate keypair ", err)
		}
		return "", ""
	}

	pemPriv := pemString(key)
	pemPub := publicPemKey(key.PublicKey)

	return pemPriv, pemPub
}
