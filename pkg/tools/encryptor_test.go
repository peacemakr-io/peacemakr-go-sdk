package tools

import (
	"bytes"
	"math/rand"
	"testing"
)

type testmsg struct {
	msg []byte
}

func (m *testmsg) MarshalBinary() ([]byte, error) {
	return m.msg, nil
}

func (m *testmsg) UnmarshalBinary(data []byte) error {
	m.msg = data
	return nil
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

	message := make([]byte, 100)
	_, err = rand.Read(message)
	if err != nil {
		t.Fatal(err)
	}

	msg := testmsg{msg:message}
	encrypted, err := e.Encrypt(&msg)
	if err != nil {
		t.Fatal(err)
	}

	var newmsg testmsg
	if err := e.Decrypt(encrypted, &newmsg); err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(newmsg.msg, msg.msg) != 0 {
		t.Fatal("encrypted and decrypted do not match")
	}
}
