package peacemakr_go_sdk

import (
	"crypto/rand"
	"github.com/peacemakr-io/peacemakr-go-sdk/generated/client"
	"github.com/peacemakr-io/peacemakr-go-sdk/utils"
	"log"
	"os"
	"testing"
	"time"
)

func getHostname() string {
	envHostname, isSet := os.LookupEnv("PEACEMAKR_TEST_HOSTNAME")
	if !isSet {
		// Until the prod server has a proper testing org, only a local env by default.
		return "peacemakr-services:80"
	}
	return envHostname
}

func getAPIKey() string {
	envApiKey, isSet := os.LookupEnv("PEACEMAKR_TEST_API_KEY")
	if !isSet {
		return ""
	}
	return envApiKey
}

var messageSize = 1 << 14

var hostname = getHostname()
var apiKey = getAPIKey()

func setup(m *testing.M) {
	if apiKey == "" {
		// Set up the client to get the test org and its API key
		cfg := client.TransportConfig{
			Host:     hostname,
			BasePath: client.DefaultBasePath,
			Schemes:  []string{"http"},
		}

		testClient := client.NewHTTPClientWithConfig(nil, &cfg)
		ok, err := testClient.Org.GetTestOrganizationAPIKey(nil)
		if err != nil {
			log.Fatal(err)
		}

		apiKey = *ok.Payload.Key
	}

	time.Sleep(15 * time.Second)
}

func TestMain(m *testing.M) {
	setup(m)
	code := m.Run()
	os.Exit(code)
}

// Tests for the API functions

func TestRegister(t *testing.T) {
	if err := os.MkdirAll("/tmp/test/register", os.ModePerm); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove("/tmp/test/register")
	}()

	persister := utils.GetDiskPersister("/tmp/test/register")
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}
}

func TestCustomLogger(t *testing.T) {
	if err := os.MkdirAll("/tmp/test/custom_logger", os.ModePerm); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove("/tmp/test/custom_logger")
	}()

	persister := utils.GetDiskPersister("/tmp/test/custom_logger")
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
	if err := os.MkdirAll("/tmp/test/register_and_sync", os.ModePerm); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove("/tmp/test/register_and_sync")
	}()

	persister := utils.GetDiskPersister("/tmp/test/register_and_sync")
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

func TestEncrypt(t *testing.T) {
	if err := os.MkdirAll("/tmp/test/encrypt", os.ModePerm); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove("/tmp/test/encrypt")
	}()

	persister := utils.GetDiskPersister("/tmp/test/encrypt")
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &hostname, persister, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}

	if !peacemakrSDK.(*standardPeacemakrSDK).hasUseDomain() {
		if err := peacemakrSDK.(*standardPeacemakrSDK).createUseDomain(1, t.Name()); err != nil {
			t.Fatal(err)
		}

		// Use domain and key creation, are not instantaneous.
		time.Sleep(time.Duration(5) * time.Second)

		if err := peacemakrSDK.Sync(); err != nil {
			t.Fatal(err)
		}
	}

	if err := peacemakrSDK.Sync(); err != nil {
		log.Fatal(err)
	}

	// Wait on KD to boot up
	time.Sleep(5 * time.Second)

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
