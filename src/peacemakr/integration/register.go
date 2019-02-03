package main

import (
	"log"
	"math/rand"
	"peacemakr/sdk/client"
	"peacemakr/sdk/utils"
	"sync"
	"flag"
)

type TestMessage struct {
	encrypted string
	plaintext string
}

func runEncryptingClient(clientNum int, apiKey string, hostname string, numRuns int, encrypted chan *TestMessage, wg *sync.WaitGroup) {


	log.Printf("Getting Peacemakr SDK for encrypting client %d...\n", clientNum)
	sdk, err := client.GetPeacemakrSDK(apiKey, "test encrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"))
	if err != nil {
		log.Fatalf("Encrypting client %d getting peacemakr sdk failed %s", clientNum, err)
	}

	log.Printf("Encrypting client %d: registering to host %s", clientNum, hostname)
	err = sdk.Register()
	if err != nil {
		log.Fatalf("Encrypting cleint %d: registration failed %s", clientNum, err)
	}
	log.Printf("Encrypting client %d: starting %d registered.  Starting crypto round trips ...", clientNum, numRuns)

	log.Printf("Encrypting client %d: debug info: %s\n", clientNum, sdk.GetDebugInfo())

	for i := 0; i < numRuns; i++ {

		randLen := rand.Intn(4096) + 1

		plaintext, err := utils.GenerateRandomString(randLen)
		if err != nil {
			log.Fatalf("Encrypting client %d: failed to get random plaintext to encrypt %s", clientNum, err)
		}

		ciphertext, err := sdk.EncryptStr(plaintext)
		if err != nil {
			log.Fatalf("Failed to encrypt string (clientDebugInfo = %s, clientNum = %d) %s", sdk.GetDebugInfo(), clientNum, err)
		}
		if ciphertext == plaintext {
			log.Fatalf("Encrypting client %d: encryption did nothing.", clientNum)
		}

		testMessage := TestMessage{
			encrypted: ciphertext,
			plaintext: plaintext,
		}
		encrypted <- &testMessage

		decrypted, err := sdk.DecryptStr(ciphertext)
		if err != nil {
			log.Fatalf("Encrypting client %d: failed to decrypt string %s", clientNum, err)
		}

		if plaintext != decrypted {
			log.Fatalf("Encrypting client %d: failed to decrypt to original plaintext.", clientNum)
		}

		log.Printf("Encrypting client %d: encrypted %d messages\n", clientNum, i)
	}


	log.Printf("Encryption client %d: done.\n", clientNum)
	wg.Done()
}

func runDecryptingClient(clientNum int, apiKey string, hostname string, encrypted chan *TestMessage) {
	log.Printf("Getting Peacemakr SDK for decrypting client %d...\n", clientNum)
	sdk, err := client.GetPeacemakrSDK(apiKey, "test decrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"))
	if err != nil {
		log.Fatalf("Decrypting client %d, fetching peacemakr sdk failed %s", clientNum, err)
	}

	err = sdk.Register()
	if err != nil {
		log.Fatalf("Decrypting client %d registration failed %s", clientNum, err)
	}

	i := 0
	for msg := range encrypted {

		// If we see this, no more ciphertexts are coming, bail.
		if msg == nil {
			break
		}

		decrypted, err := sdk.DecryptStr(msg.encrypted)
		if err != nil {
			log.Fatalf("Decrypting client %d failed to decrypt in DECYRTION CLIENT string %s", clientNum, err)
		}

		if decrypted != msg.plaintext {
			log.Fatalf("%Decrypting client %d failed to decrypt in DECYRTION CLIENT decrypted %s but expected %s", clientNum, decrypted, msg.plaintext)
		}
		log.Println("Decrypting client", clientNum, "decrypted", i," messages")
		i++
	}

	log.Println("decryption client number", clientNum, "done.")
}

func main() {
	apiKey := flag.String("apiKey", "", "apiKey")
	host := flag.String("host", "api.peacemakr.io", "host of peacemakr services")
	numCryptoTrips := flag.Int("numCryptoTrips", 100, "Total number of example encrypt and decrypt operations.")
	numCryptoThreads := flag.Int("numCryptoThreads", 1, "Total number of encryption and decryption threads.")
	flag.Parse()

	log.Println("apiKey:", *apiKey)
	log.Println("host:", *host)
	log.Println("numCryptoTrips:", *numCryptoTrips)
	log.Println("numCryptoThreads:", *numCryptoThreads)

	// Channel of encrypted things.
	encrypted := make(chan *TestMessage)
	var encryptionWork sync.WaitGroup

	// Fire up the encryption clients.
	for i := 0; i < *numCryptoThreads; i++ {
		encryptionWork.Add(1)
		go runEncryptingClient(i, *apiKey, *host, *numCryptoTrips, encrypted, &encryptionWork)
	}

	// Fire up the decryption-only clients.
	for i := 0; i < *numCryptoThreads; i++ {
		go runDecryptingClient(i, *apiKey, *host, encrypted)
	}

	encryptionWork.Wait()
	log.Printf("main thread signaling to decyrptors it's over...\n")
	for i := 0; i < *numCryptoThreads; i++ {
		encrypted <- nil
	}
	close(encrypted)
}
