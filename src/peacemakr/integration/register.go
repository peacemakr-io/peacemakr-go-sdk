package main

import (
	"log"
	"math/rand"
	"peacemakr/sdk/client"
	"peacemakr/sdk/utils"
	"sync"
)

type TestMessage struct {
	encrypted string
	plaintext string
}

func runEncryptingClient(clientNum int, apiKey string, hostname string, numRuns int, encrypted chan TestMessage, wg sync.WaitGroup) {

	log.Printf("Registereing a new client %d for encryption to host %s", clientNum, hostname)
	sdk := client.GetPeacemakrSDK(apiKey, "test encrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"))
	err := sdk.Register()

	if err != nil {
		log.Fatalf("%d registration failed %s", clientNum, err)
	}
	log.Println("registration successful of client", clientNum, "starting", numRuns, "crypto round trips...")

	log.Println("Client debug info: %s\n", sdk.GetDebugInfo())

	for i := 0; i < numRuns; i++ {

		randLen := rand.Intn(4096) + 1

		plaintext, err := utils.GenerateRandomString(randLen)
		if err != nil {
			log.Fatalf("%d Failed to get random plaintext to encrypt %s", clientNum, err)
		}

		log.Println("Client", clientNum, "encrypt a msg ...")
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

		log.Println("Client", clientNum, "decrypting the same msg ...")
		decrypted, err := sdk.DecryptStr(ciphertext)
		if err != nil {
			log.Fatalf("%d Failed to decrypt string %s", clientNum, err)
		}

		if plaintext != decrypted {
			log.Fatalf("%d Failed to decrypt to original plaintext.", clientNum)
		}

		log.Println("encryption client number", clientNum, "en/decryption round trips:", i)
	}


	log.Println("client number", clientNum, "done.")
	wg.Done()
}

func runDecryptingClient(clientNum int, apiKey string, hostname string, encrypted chan TestMessage, wg sync.WaitGroup) {
	sdk := client.GetPeacemakrSDK(apiKey, "test decrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"))

	err := sdk.Register()
	if err != nil {
		log.Fatalf("%d registration failed %s", clientNum, err)
	}

	i := 0
	for msg := range encrypted {

		log.Println("Client", clientNum, "decrypting a msg ...")
		decrypted, err := sdk.DecryptStr(msg.encrypted)
		if err != nil {
			log.Fatalf("%d Failed to decrypt in DECYRTION CLIENT string %s", clientNum, err)
		}

		if decrypted != msg.plaintext {
			log.Fatalf("%d Failed to decrypt in DECYRTION CLIENT decrypted %s but expected %s", clientNum, decrypted, msg.plaintext)
		}

		log.Println("decryption client number", clientNum, "decrypted :", i)

		i++
	}

	log.Println("client number", clientNum, "done.")
	wg.Done()
}

func main() {

	log.Println("Loading configs...")
	config := LoadConfigs()

	apiKey := "peacemaker-key-123-123-123"


	// Channel of encrypted things.
	encrypted := make(chan TestMessage)
	var wg sync.WaitGroup

	// Fire up the encryption clients.
	for i := 0; i < config.IntegrationTest.NumClients; i++ {
		wg.Add(1)
		go runEncryptingClient(i, apiKey, config.IntegrationTest.Host, config.IntegrationTest.NumOfCryptoTrips, encrypted, wg)
	}

	// Fire up the decryption-only clients.
	for i := 0; i < config.IntegrationTest.NumClients; i++ {
		wg.Add(1)
		go runDecryptingClient(i, apiKey, config.IntegrationTest.Host, encrypted, wg)
	}

	wg.Wait()

	// This actually frees up the runDecryptingClient's
	close(encrypted)
}
