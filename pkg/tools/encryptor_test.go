package tools

import (
	"bytes"
	"math/rand"
	"testing"
)

type Testmsg struct {
	Secret    []byte `encrypt:"true"`
	NewSecret string `encrypt:"true"`
	Public    string
}

func TestEncryptor_Encrypt(t *testing.T) {
	e, err := NewEncryptor(&EncryptorConfig{
		ApiKey:     "",
		ClientName: "",
		Url:        nil,
		Persister:  nil,
		Logger:     nil,
	})
	if err != nil {
		t.Fatal(err)
	}

	message := make([]byte, 10)
	_, err = rand.Read(message)
	if err != nil {
		t.Fatal(err)
	}

	msg := Testmsg{Secret: message, NewSecret: "Another secret message", Public: "hello there"}
	t.Logf("Message before encryption: %+v", msg)

	if err := e.Encrypt(msg); err == nil {
		t.Fatal("Supposed to fail with non-pointer arg")
	}

	if err := e.Encrypt(&msg); err != nil {
		t.Fatal(err)
	}

	t.Logf("Message after encryption: %+v", msg)

	if err := e.Decrypt(msg); err == nil {
		t.Fatal("Supposed to fail with non-pointer arg")
	}

	if err := e.Decrypt(&msg); err != nil {
		t.Fatal(err)
	}

	t.Logf("Message after decryption: %+v", msg)

	if bytes.Compare(message, msg.Secret) != 0 {
		t.Fatal("encrypted and decrypted do not match")
	}

	if msg.NewSecret != "Another secret message" {
		t.Fatal("encrypted and decrypted do not match")
	}

	if msg.Public != "hello there" {
		t.Fatal("Modified the wrong struct field")
	}
}
