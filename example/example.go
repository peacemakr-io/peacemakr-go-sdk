package main

import (
	"bytes"
	"flag"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/utils"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"
)

type TestMessage struct {
	encrypted []byte
	plaintext []byte
}

// Simple custom logger
type CustomLogger struct{}

func (l *CustomLogger) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func runEncryptingClient(clientNum int, apiKey string, hostname string, numRuns int, encrypted chan *TestMessage, wg *sync.WaitGroup, useDomainName string) {

	log.Printf("Getting Peacemakr SDK for encrypting client %d...\n", clientNum)
	sdk, err := peacemakr_go_sdk.GetPeacemakrSDK(apiKey, "test encrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"), &CustomLogger{})
	if err != nil {
		wg.Done()
		log.Fatalf("Encrypting client %d%s getting peacemakr sdk failed %s", clientNum, useDomainName, err)
	}

	log.Printf("Encrypting client %d%s: registering to host %s", clientNum, useDomainName, hostname)
	for err = sdk.Register(); err != nil; {
		log.Println("Encrypting client,", clientNum, "failed to register, trying again...")
		time.Sleep(time.Duration(1) * time.Second)
	}
	log.Printf("Encrypting client %d%s: starting %d registered.  Starting crypto round trips ...", clientNum, useDomainName, numRuns)

	err = sdk.Sync()
	if err != nil {
		wg.Done()
		log.Fatalf("Encrypting clinet %d%s: failed to preload all keys", clientNum, useDomainName)
	}

	log.Printf("Encrypting client %d%s: debug info: %s\n", clientNum, useDomainName, sdk.GetDebugInfo())

	for i := 0; i < numRuns; i++ {

		randLen := rand.Intn(4096) + 1

		plaintext, err := generateRandomBytes(randLen)
		if err != nil {
			wg.Done()
			log.Fatalf("Encrypting client %d%s: failed to get random plaintext to encrypt %s", clientNum, useDomainName, err)
		}

		var ciphertext []byte
		if len(useDomainName) == 0 {
			ciphertext, err = sdk.Encrypt(plaintext)
		} else {
			ciphertext, err = sdk.EncryptInDomain(plaintext, useDomainName)
		}
		if err != nil {
			wg.Done()
			log.Fatalf("Failed to encrypt an array (clientDebugInfo = %s, clientNum = %d) %v", sdk.GetDebugInfo(), clientNum, err)
		}
		if bytes.Equal(ciphertext, plaintext) {
			wg.Done()
			log.Fatalf("Encrypting client %d%s: encryption did nothing.", clientNum, useDomainName)
		}

		testMessage := TestMessage{
			encrypted: ciphertext,
			plaintext: plaintext,
		}
		encrypted <- &testMessage

		decrypted, err := sdk.Decrypt(ciphertext)
		if err != nil {
			wg.Done()
			log.Fatalf("Encrypting client %d%s: failed to decrypt an array of bytes %s", clientNum, useDomainName, err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			wg.Done()
			log.Fatalf("Encrypting client %d%s: failed to decrypt to original plaintext.", clientNum, useDomainName)
		}

		log.Printf("Encrypting client %d%s: encrypted %d messages\n", clientNum, useDomainName, i)

		if i == 42 {
			// Example how to release memory back to the system.  Forces keys to be re-loaded.
			sdk.ReleaseMemory()
		}
	}

	log.Printf("Encryption client %d%s: done.\n", clientNum, useDomainName)
	wg.Done()
}

func runDecryptingClient(clientNum int, apiKey string, hostname string, encrypted chan *TestMessage) {
	log.Printf("Getting Peacemakr SDK for decrypting client %d...\n", clientNum)
	sdk, err := peacemakr_go_sdk.GetPeacemakrSDK(apiKey, "test decrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"), log.New(os.Stdout, "DecryptingClient", log.LstdFlags))
	if err != nil {
		log.Fatalf("Decrypting client %d, fetching peacemakr sdk failed %s", clientNum, err)
	}

	for err = sdk.Register(); err != nil; {
		log.Println("Decryption client,", clientNum, "failed to register, trying again...")
		time.Sleep(time.Duration(1) * time.Second)
	}

	testBadDecryption(err, clientNum, sdk)

	i := 0
	for msg := range encrypted {

		// If we see this, no more ciphertexts are coming, bail.
		if msg == nil {
			break
		}

		decrypted, err := sdk.Decrypt(msg.encrypted)
		if err != nil {
			log.Fatalf("Decrypting client %d failed to decrypt in DECYRTION CLIENT string %s", clientNum, err)
		}

		if !bytes.Equal(decrypted, msg.plaintext) {
			log.Fatalf("Decrypting client %d failed to decrypt in DECYRTION CLIENT decrypted %s but expected %s", clientNum, decrypted, msg.plaintext)
		}
		log.Println("Decrypting client", clientNum, "decrypted", i, " messages")
		i++
	}

	log.Println("decryption client number", clientNum, "done.")
}
func testBadDecryption(err error, clientNum int, sdk peacemakr_go_sdk.PeacemakrSDK) {
	// Attempt a single "bad" decryption:
	randLen := rand.Intn(1<<16) + 1
	notPeaceMakrCiphertext, err := generateRandomBytes(randLen)
	if err != nil {
		log.Fatalf("Decrypting client %d: failed to get random byte array %s", clientNum, err)
	}
	decrypted, err := sdk.Decrypt(notPeaceMakrCiphertext)
	if len(decrypted) != 0 || err == nil {
		log.Fatalf("Decrypting client %d: failed to detect non-peacemkr ciphertext %s", clientNum, notPeaceMakrCiphertext)
	}

	log.Printf("Decrypting client %d: invalid ciphertext detected", clientNum)
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
	numCryptoTrips := flag.Int("numCryptoTrips", 100, "Total number of example encrypt and decrypt operations.")
	numEncryptThreads := flag.Int("numEncryptClients", 1, "Total number of encryption clients. (1)")
	numDecryptThreads := flag.Int("numDecryptClients", 10, "Total number of decryption clients. (10)")
	useDomainName := flag.String("useDomainName", "", "The specific and enforced Use Domain's name for encryption")
	flag.Parse()
	if apiKey == nil || *apiKey == "" {
		log.Fatal("You are missing an API Key.")
	}

	log.Println("apiKey:", *apiKey)
	log.Println("peacemakrUrl:", *peacemakrUrl)
	log.Println("numCryptoTrips:", *numCryptoTrips)
	log.Println("numEncryptThreads:", *numEncryptThreads)
	log.Println("numDecryptThreads:", *numDecryptThreads)
	log.Println("useDomainName:", *useDomainName)

	// Channel of encrypted things.
	encrypted := make(chan *TestMessage)
	var encryptionWork sync.WaitGroup

	// Just one decryptor

	for i := 0; i < *numDecryptThreads; i++ {
		go runDecryptingClient(i, *apiKey, *peacemakrUrl, encrypted)
	}

	// Fire up the encryption clients.
	for i := 0; i < *numEncryptThreads; i++ {

		// Do it once with indiscriminate useDomains.
		encryptionWork.Add(1)
		go runEncryptingClient(i, *apiKey, *peacemakrUrl, *numCryptoTrips, encrypted, &encryptionWork, "")

		// And, again with a specific useDomain.
		if len(*useDomainName) > 0 {
			encryptionWork.Add(1)
			go runEncryptingClient(i, *apiKey, *peacemakrUrl, *numCryptoTrips, encrypted, &encryptionWork, *useDomainName)
		}

		// Why Sleep? The number of clients can't just explode, need to give them a chance to spin up,
		// work a little, and go away.
		time.Sleep(10 * time.Microsecond)

	}

	encryptionWork.Wait()
	log.Printf("main thread signaling to decyrptors it's over...\n")
	for i := 0; i < *numDecryptThreads; i++ {
		encrypted <- nil
	}
	close(encrypted)
}
