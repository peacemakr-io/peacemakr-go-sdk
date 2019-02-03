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

func runEncryptingClient(clientNum int, apiKey string, hostname string, numRuns int, encrypted chan TestMessage, wg *sync.WaitGroup) {


	log.Printf("Getting Peacemakr SDK...\n")
	sdk := client.GetPeacemakrSDK(apiKey, "test encrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"))

	log.Printf("Registereing a new client %d for encryption to host %s", clientNum, hostname)
	err := sdk.Register()
	if err != nil {
		log.Fatalf("%d registration failed %s", clientNum, err)
	}
	log.Println("registration successful of client", clientNum, "starting", numRuns, "crypto round trips...")

	log.Printf("Encrypting client debug info: %s\n", sdk.GetDebugInfo())

	for i := 0; i < numRuns; i++ {

		randLen := rand.Intn(4096) + 1

		plaintext, err := utils.GenerateRandomString(randLen)
		if err != nil {
			log.Fatalf("%d Failed to get random plaintext to encrypt %s", clientNum, err)
		}

		ciphertext, err := sdk.EncryptStr(plaintext)
		if err != nil {
			log.Fatalf("Failed to encrypt string (clientDebugInfo = %s, clientNum = %d) %s", sdk.GetDebugInfo(), clientNum, err)
		}
		if ciphertext == plaintext {
			log.Fatalf("%d Encryption did nothing. oops.", clientNum)
		}

		testMessage := TestMessage{
			encrypted: ciphertext,
			plaintext: plaintext,
		}
		encrypted <- testMessage

		decrypted, err := sdk.DecryptStr(ciphertext)
		if err != nil {
			log.Fatalf("%d Failed to decrypt string %s", clientNum, err)
		}

		if plaintext != decrypted {
			log.Fatalf("%d Failed to decrypt to original plaintext.", clientNum)
		}

		log.Println("Encrypting client", clientNum, "encrypted", i, " messages")
	}


	log.Println("Encryption client number", clientNum, "done.")
	close(encrypted)
	wg.Done()
}

func runDecryptingClient(clientNum int, apiKey string, hostname string, encrypted chan TestMessage, wg *sync.WaitGroup) {
	sdk := client.GetPeacemakrSDK(apiKey, "test decrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"))

	err := sdk.Register()
	if err != nil {
		log.Fatalf("%d registration failed %s", clientNum, err)
	}

	i := 0
	for msg := range encrypted {
		decrypted, err := sdk.DecryptStr(msg.encrypted)
		if err != nil {
			log.Fatalf("%d Failed to decrypt in DECYRTION CLIENT string %s", clientNum, err)
		}

		if decrypted != msg.plaintext {
			log.Fatalf("%d Failed to decrypt in DECYRTION CLIENT decrypted %s but expected %s", clientNum, decrypted, msg.plaintext)
		}
		log.Println("Decrypting client", clientNum, "decrypted", i," messages")
		i++
	}

	log.Println("decryption client number", clientNum, "done.")
	wg.Done()
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
	encrypted := make(chan TestMessage)
	var wg sync.WaitGroup

	// Fire up the encryption clients.
	for i := 0; i < *numCryptoThreads; i++ {
		wg.Add(1)
		go runEncryptingClient(i, *apiKey, *host, *numCryptoTrips, encrypted, &wg)
	}

	// Fire up the decryption-only clients.
	for i := 0; i < *numCryptoThreads; i++ {
		wg.Add(1)
		go runDecryptingClient(i, *apiKey, *host, encrypted, &wg)
	}

	wg.Wait()
}
