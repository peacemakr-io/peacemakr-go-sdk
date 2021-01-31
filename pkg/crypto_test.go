package peacemakr_go_sdk

import (
	"crypto/rand"
	"fmt"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/client"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/utils"
	"github.com/stretchr/testify/assert"
	"log"
	"os"
	"testing"
	"time"
)

func getURL() string {
	envHostname, isSet := os.LookupEnv("PEACEMAKR_TEST_URL")
	if !isSet {
		return ""
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

var peacemakrUrl = getURL()
var apiKey = getAPIKey()

func setup(m *testing.M) {
	if apiKey == "" && peacemakrUrl != "" {

		// Set up the client to get the test org and its API key
		cfg := client.TransportConfig{
			Host:     peacemakrUrl,
			BasePath: client.DefaultBasePath,
			Schemes:  []string{"http"},
		}

		peacemakrUrl = fmt.Sprintf("http://%s", peacemakrUrl)

		testClient := client.NewHTTPClientWithConfig(nil, &cfg)
		ok, err := testClient.Org.GetTestOrganizationAPIKey(nil)
		if err != nil {
			log.Fatal(err)
		}

		apiKey = *ok.Payload.Key
	}
	time.Sleep(100 * time.Millisecond)
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &peacemakrUrl, persister, nil)
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &peacemakrUrl, persister, logger)
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &peacemakrUrl, persister, nil)
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &peacemakrUrl, persister, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		log.Fatal(err)
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

func TestSignedOnly(t *testing.T) {
	if err := os.MkdirAll("/tmp/test/signedOnly", os.ModePerm); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove("/tmp/test/signedOnly")
	}()

	persister := utils.GetDiskPersister("/tmp/test/signedOnly")
	purl := "api.peacemakr.io"

	cfg := client.TransportConfig{
		Host:     purl,
		BasePath: client.DefaultBasePath,
		Schemes:  []string{"https"},
	}

	testClient := client.NewHTTPClientWithConfig(nil, &cfg)
	ok, err := testClient.Org.GetTestOrganizationAPIKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	purl = "https://api.peacemakr.io"
	apiKey = *ok.Payload.Key
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &purl, persister, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		log.Fatal(err)
	}

	bytes := make([]byte, messageSize)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}

	signedBlob, err := peacemakrSDK.SignOnly(bytes)
	if err != nil {
		t.Fatal(err)
	}

	verifiedBlob, err := peacemakrSDK.VerifyOnly(signedBlob)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(bytes); i++ {
		if bytes[i] != verifiedBlob[i] {
			t.Fatalf("Verification failed on byte %d, mismatch %v vs %v", i, bytes[i], verifiedBlob[i])
		}
	}
}

func TestIsPeacemakrCiphertext(t *testing.T) {
	if err := os.MkdirAll("/tmp/test/cipher", os.ModePerm); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove("/tmp/test/cipher")
	}()

	persister := utils.GetDiskPersister("/tmp/test/cipher")
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-test-client", &peacemakrUrl, persister, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Register(); err != nil {
		t.Fatal(err)
	}

	if err := peacemakrSDK.Sync(); err != nil {
		log.Fatal(err)
	}

	bytes := make([]byte, messageSize)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}

	encryptedBlob, err := peacemakrSDK.Encrypt(bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Validate the ciphertext is a Peacemakr ciphertext
	assert.True(t, peacemakrSDK.IsPeacemakrCiphertext(encryptedBlob))

	// Validate the ciphertext is not a Peacemakr ciphertext
	randomBytes := make([]byte, messageSize)
	_, _ = rand.Read(randomBytes)
	assert.False(t, peacemakrSDK.IsPeacemakrCiphertext(randomBytes))
}

// Benchmarks for the API functions

func BenchmarkRegister(b *testing.B) {
	persister := utils.GetInMemPersister()
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &peacemakrUrl, persister, nil)
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &peacemakrUrl, persister, nil)
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &peacemakrUrl, persister, nil)
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
	peacemakrSDK, err := GetPeacemakrSDK(apiKey, "go-sdk-benchmark-client", &peacemakrUrl, persister, nil)
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
