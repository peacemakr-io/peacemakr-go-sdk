package peacemakr_go_sdk

import (
	"crypto/rand"
	"github.com/notasecret/peacemakr-go-sdk/utils"
	"log"
	"os"
	"testing"
)

var hostname = ""

//var hostname = "localhost:8080" // Uncomment this to run against a local server (comment above)
var apiKey = "peacemaker-key-123-123-123"

//var apiKey = "Rnc+SIToovHLEWBazkGCz8Treshf3KT3RFyOwuPoFic=" // Uncomment this to run with API Key from local server (comment above)

var messageSize = 1 << 14

// Tests for the API functions

func TestRegister(t *testing.T) {
	persister := utils.GetDiskPersister(".")
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}
}

func TestCustomLogger(t *testing.T) {
	persister := utils.GetDiskPersister(".")
	logger := log.New(os.Stdout, "CustomLogger", log.LstdFlags)
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, logger)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterAndSync(t *testing.T) {
	persister := utils.GetDiskPersister(".")
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestEncrypt(t *testing.T) {
	if apiKey == "peacemaker-key-123-123-123" {
		t.Log("Not running Encrypt/Decrypt tests because we don't have a valid API Key")
		return
	}

	persister := utils.GetDiskPersister(".")
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		t.Fatal(err)
	}

	bytes := make([]byte, messageSize)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}

	encryptedBlob, err := peacemakrSDK.Encrypt(bytes)
	if err != nil {
		t.Fatal(err)
	}

	decryptedBytes, err := peacemakrSDK.Decrypt(encryptedBlob)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(bytes); i++ {
		if bytes[i] != decryptedBytes[i] {
			t.Fatalf("Decryption failed on byte %d, mismatch %v vs %v", i, bytes[i], decryptedBytes[i])
		}
	}
}

// Benchmarks for the API functions

func BenchmarkRegister(b *testing.B) {
	persister := utils.GetInMemPersister()
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &hostname, persister, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err = peacemakrSDK.Register()
	}
	b.StopTimer()

	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkSync(b *testing.B) {
	persister := utils.GetInMemPersister()
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &hostname, persister, nil)
	if err != nil {
		b.Fatal(err)
	}

	err = peacemakrSDK.Register()
	if err != nil {
		b.Fatal(err)
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err = peacemakrSDK.Sync()
	}
	b.StopTimer()

	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	if apiKey == "peacemaker-key-123-123-123" {
		b.Log("Not running Encrypt/Decrypt tests because we don't have a valid API Key")
		return
	}

	persister := utils.GetInMemPersister()
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &hostname, persister, nil)
	if err != nil {
		b.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		b.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		b.Fatal(err)
	}

	bytes := make([]byte, messageSize)
	if _, err := rand.Read(bytes); err != nil {
		b.Fatal(err)
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if _, err := peacemakrSDK.Encrypt(bytes); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkDecrypt(b *testing.B) {
	if apiKey == "peacemaker-key-123-123-123" {
		b.Log("Not running Encrypt/Decrypt tests because we don't have a valid API Key")
		return
	}

	persister := utils.GetInMemPersister()
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &hostname, persister, nil)
	if err != nil {
		b.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		b.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		b.Fatal(err)
	}

	bytes := make([]byte, messageSize)
	if _, err := rand.Read(bytes); err != nil {
		b.Fatal(err)
	}

	encryptedBlob, err := peacemakrSDK.Encrypt(bytes)
	if err != nil {
		b.Fatal(err)
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if _, err := peacemakrSDK.Decrypt(encryptedBlob); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}
