package peacemakr_go_sdk

import (
	"crypto/rand"
	"github.com/notasecret/peacemakr-go-sdk/utils"
	"log"
	"os"
	"testing"
)

func getHostname() string {
	envHostname, isSet := os.LookupEnv("PEACEMAKR_TEST_HOSTNAME")
	if !isSet {
		return ""
	}
	return envHostname
}

func getAPIKey() string {
	envApiKey, isSet := os.LookupEnv("PEACEMAKR_TEST_API_KEY")
	if !isSet {
		return "peacemaker-key-123-123-123"
	}
	return envApiKey
}

var messageSize = 1 << 14

var hostname = getHostname()
var apiKey = getAPIKey()

// Tests for the API functions

func TestRegister(t *testing.T) {
	persister := utils.GetDiskPersister(".")
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, nil, true)
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, logger, true)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterAndSync(t *testing.T) {
	persister := utils.GetDiskPersister(".")
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, nil, true)
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

// TODO: figure out why this test is failing
func TestEncrypt(t *testing.T) {
	persister := utils.GetDiskPersister(".")
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		t.Fatal(err)
	}

	if !peacemakrSDK.(*standardPeacemakrSDK).hasUseDomain() {
		t.Log("no use domain")
		if err := peacemakrSDK.(*standardPeacemakrSDK).createUseDomain(1, t.Name()); err != nil {
			t.Fatal(err)
		}

		if err := peacemakrSDK.Sync(); err != nil {
			t.Fatal(err)
		}
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &hostname, persister, nil, true)
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &hostname, persister, nil, true)
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

// TODO: figure out why these tests are failing
func BenchmarkEncrypt(b *testing.B) {
	persister := utils.GetInMemPersister()
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &hostname, persister, nil, true)
	if err != nil {
		b.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		b.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		b.Fatal(err)
	}

	if !peacemakrSDK.(*standardPeacemakrSDK).hasUseDomain() {
		if err := peacemakrSDK.(*standardPeacemakrSDK).createUseDomain(1, b.Name()); err != nil {
			b.Fatal(err)
		}

		if err := peacemakrSDK.Sync(); err != nil {
			b.Fatal(err)
		}
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
	persister := utils.GetInMemPersister()
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &hostname, persister, nil, true)
	if err != nil {
		b.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		b.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		b.Fatal(err)
	}

	if !peacemakrSDK.(*standardPeacemakrSDK).hasUseDomain() {
		if err := peacemakrSDK.(*standardPeacemakrSDK).createUseDomain(1, b.Name()); err != nil {
			b.Fatal(err)
		}

		if err := peacemakrSDK.Sync(); err != nil {
			b.Fatal(err)
		}
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
