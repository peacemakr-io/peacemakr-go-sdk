package main

import (
	"bytes"
	"flag"
	"log"
	"math/rand"

	"encoding/base64"
	peacemakr_go_sdk "github.com/peacemakr-io/peacemakr-go-sdk/pkg"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/utils"
)

// Simple custom logger
type CustomLogger struct{}

func (l *CustomLogger) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func main() {
	apiKey := flag.String("apiKey", "", "apiKey")
	peacemakrUrl := flag.String("peacemakrUrl", "https://api.peacemakr.io", "URL of Peacemakr cloud services")
	verbose := flag.Bool("verbose", false, "Verbosity of the program")

	flag.Parse()
	if apiKey == nil || *apiKey == "" {
		log.Fatal("You are missing an API Key.")
	}

	if *verbose {
		log.Println("apiKey:", *apiKey)
		log.Println("peacemakrUrl:", *peacemakrUrl)
	}

	sdk, err := peacemakr_go_sdk.GetPeacemakrSDK(*apiKey, "test SignVerify client ", peacemakrUrl, utils.GetDiskPersister("/tmp/"), &CustomLogger{})
	if err != nil {
		log.Fatalf("SignVerify client getting peacemakr sdk failed %s", err)
	}

	for err = sdk.Register(); err != nil; {
		log.Println("SignVerify client failed to register, trying again...")
	}

	err = sdk.Sync()
	if err != nil {
		log.Fatalf("SignVerify clinet failed to preload all keys %s", err)
	}

	randLen := rand.Intn(4096) + 1

	plaintext, err := generateRandomBytes(randLen)
	if err != nil {
		log.Fatalf("Error in generating random bytes %s", err)
	}

	if *verbose {
		plaintextStr := base64.StdEncoding.EncodeToString(plaintext)
		log.Println("plain text:\n" + plaintextStr)
	}

	signedBlob, err := sdk.SignOnly(plaintext)

	if err != nil {
		log.Fatalf("Error in Signing Data", signedBlob)
	}

	if *verbose {
		log.Println("signed blob:\n" + string(signedBlob))
	}

	verifiedPlainText, err := sdk.VerifyOnly(signedBlob)

	if err != nil {
		log.Fatalf("Error in verifying signedBlob %s", err)
	}

	if *verbose {
		verifiedStr := base64.StdEncoding.EncodeToString(verifiedPlainText)
		log.Println("verifiedStr text:\n" + verifiedStr)
	}

	if !bytes.Equal(verifiedPlainText, plaintext) {
		log.Fatalf("Error: Verified message does not match original message")
	}

}
