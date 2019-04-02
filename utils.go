package peacemakr_go_sdk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

var RSAKEYLENGTH = 4096
var DEBUG = true

type LocallizedKeyFetcherService struct {
	LocalPubKeys  map[string]string
	LocalPrivKeys map[string]string
}

func ECPemString(key *ecdsa.PrivateKey) string {
	buf := new(bytes.Buffer)

	marshalled, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return ""
	}

	var privateKey = &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshalled,
	}

	err = pem.Encode(buf, privateKey)
	if err != nil {
		return ""
	}

	return buf.String()
}

func PublicECPemKey(key ecdsa.PublicKey) string {
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

func getNewECKey(curve elliptic.Curve) (string, string) {
	reader := rand.Reader

	key, err := ecdsa.GenerateKey(curve, reader)
	if err != nil {
		return "", ""
	}

	pemPriv := ECPemString(key)
	pemPub := PublicECPemKey(key.PublicKey)

	return pemPriv, pemPub
}

func pemString(key *rsa.PrivateKey) string {
	buf := new(bytes.Buffer)

	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err := pem.Encode(buf, privateKey)
	if err != nil {
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
	} else if keyType == "ec" {
		switch bitlength {
		case 256:
			return getNewECKey(elliptic.P256())
		case 384:
			return getNewECKey(elliptic.P384())
		case 521:
			return getNewECKey(elliptic.P521())
		default:
			return "", ""
		}
	} else {
		// Then, just default to an RSA key type of 2048 bits.
		return getNewKey("ec", 256)
	}

}
