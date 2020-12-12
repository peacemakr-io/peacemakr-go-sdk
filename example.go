
package main

import (
	"flag"
	peacemakr_go_sdk "github.com/peacemakr-io/peacemakr-go-sdk/pkg"
	"github.com/spf13/viper"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

type PeacemakrConfig struct {
	Verbose               bool
	Host                  string
	ApiKey	              string
	PersisterFileLocation string
	ClientName            string
}

func LoadConfigs(configName string) *PeacemakrConfig {
	var configuration PeacemakrConfig

	viper.SetConfigFile(configName)

	// Also permit environment overrides.
	viper.SetEnvPrefix("PEACEMAKR")

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.BindEnv("ApiKey")
	viper.AutomaticEnv() // Bind to all configs, overriding config from env when in both file and env var.

    // If no config was found, we use default values
	if err := viper.MergeInConfig(); err != nil {
		configuration = PeacemakrConfig{
				Verbose: false,
				Host: "https://api.peacemakr.io",
				PersisterFileLocation: "/tmp/.peacemakr",
				ClientName: "peacemakr-cli",
				ApiKey: viper.GetString("ApiKey"),
		}

		if configuration.Verbose {
			log.Printf("Config:\n Verbose: %v\n Host: %v\n Persister file location: %v\n Client Name: %v\n",  configuration.Verbose, configuration.Host, configuration.PersisterFileLocation,  configuration.ClientName)
		}
		return &configuration
	}

	err := viper.Unmarshal(&configuration)
	if err != nil {
		log.Fatalf("unable to read config, %v", err)
	}

	if configuration.Verbose {
		log.Printf("Config:\n Verbose: %v\n Host: %v\n Persister file location: %v\n Client Name: %v\n",  configuration.Verbose, configuration.Host, configuration.PersisterFileLocation,  configuration.ClientName)
	}

	return &configuration
}

func encryptOrFail(sdk peacemakr_go_sdk.PeacemakrSDK, from, to *os.File) {
	if from == nil {
		log.Fatalf("missing 'from' in encryption")
	}

	if to == nil {
		log.Fatalf("missing 'to' in encryption")
	}

	if from == to {
		log.Fatalf("in-place encryption is not supproted (from and to are the same)")
	}

	data, err := ioutil.ReadAll(from)
	if err != nil {
		log.Fatalf("failed to read stdin due to error %v", err)
	}


	encryptedData, err := sdk.Encrypt(data)
	if err != nil {
		log.Fatalf("failed to encrypted due to error %v", err)
	}

	_, err = to.Write(encryptedData)
	if err != nil {
		log.Fatalf("failed to write encrypted data due to error %v", err)
	}
}

func decryptOrFail(sdk peacemakr_go_sdk.PeacemakrSDK, from, to *os.File) {
	if from == nil {
		log.Fatalf("missing 'from' in decryption")
	}

	if to == nil {
		log.Fatalf("missing 'to' in decryption")
	}

	if from == to {
		log.Fatalf("in-place decryption is not supproted (from and to are the same)")
	}

	data, err := ioutil.ReadAll(from)
	if err != nil {
		log.Fatalf("failed to read stdin due to error %v", err)
	}


	decryptedData, err := sdk.Decrypt(data)
	if err != nil {
		log.Fatalf("failed to decrypt due to error %v", err)
	}

	_, err = to.Write(decryptedData)
	if err != nil {
		log.Fatalf("failed to write decrypted data due to error %v", err)
	}
}

func registerOrFail(sdk peacemakr_go_sdk.PeacemakrSDK) {
	err := sdk.Register()
	if err != nil {
		log.Fatalf(" failed to register due to %v", err)
	}
}

func canonicalAction(action *string) string {
	if action == nil {
		log.Fatalf("failed to provide an action")
	}

	actionStr := strings.ToLower(*action)

	if actionStr != "encrypt" && actionStr != "decrypt" {
		log.Fatalf("unkonwn action: ", *action)
	}

	return actionStr
}

func loadInputFile(inputFileName string) (*os.File, error) {
	var inputFile *os.File
	var err error
	if inputFileName == "" {
		inputFile = os.Stdin 
	} else {
		inputFile, err = os.Open(inputFileName)
		if err != nil {
			log.Printf("Error opening the file %v", err)
			return nil, err
		}
	}
	return inputFile, nil
}

func loadOutputFile(outputFileName string) (*os.File, error) {
	var outputFile *os.File
	var err error
	if outputFileName == "" {
		outputFile = os.Stdout
	} else {
		outputFile, err = os.OpenFile(outputFileName, os.O_CREATE|os.O_WRONLY, os.ModePerm)
		if err != nil {
			log.Printf("Error opening the file %v", err)
			return nil, err
		}
	}
	return outputFile, nil
}

type CustomLogger struct{}
func (l *CustomLogger) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}
func main() {
	action := flag.String("action", "encrypt", "action= encrypt|decrypt")
	customConfig := flag.String("config", "peacemakr.yml", "custom config file e.g. (peacemakr.yml)")
	inputFileName := flag.String("inputFileName", "", "inputFile to encrypt/decrypt")
	outputFileName := flag.String("outputFileName", "", "outputFile to encrypt/decrypt")
	flag.Parse()

	actionStr := canonicalAction(action)

	config := LoadConfigs(*customConfig)

	if config.Verbose {
		log.Println("Finish parsing flag and config")
		log.Printf("inputfilename: %s, OutputFilename: %s", *inputFileName, *outputFileName)
	}

	if config.Verbose {
		log.Println("Setting up SDK...")
	}

	if _, err := os.Stat(config.PersisterFileLocation); os.IsNotExist(err) {
		os.MkdirAll(config.PersisterFileLocation, os.ModePerm)
	}

	sdk, err := peacemakr_go_sdk.GetPeacemakrSDK(
		config.ApiKey,
		config.ClientName,
		&config.Host,
		GetDiskPersister(config.PersisterFileLocation),
		log.New(os.Stderr, "MyProjectCrypto", log.LstdFlags))


	if err != nil {
		log.Fatalf("Failed to create peacemakr sdk due to %v", err)
	}


	inputFile, err := loadInputFile(*inputFileName)
	if err != nil {
		log.Fatalf("Error loading input file", err)
	}
	outputFile, err := loadOutputFile(*outputFileName)
	if err != nil {
		log.Fatalf("Error loading output file", err)
	}

	if config.Verbose {
		log.Printf("registering client")
		registerOrFail(sdk)
	}

	if actionStr == "encrypt" {
		if config.Verbose {
			log.Println("In encrypting")
		}
		for err = sdk.Register(); err != nil; {
			log.Println("Encrypting client, failed to register, trying again...")
			time.Sleep(time.Duration(1) * time.Second)
		}

		if config.Verbose {
			log.Println("Encrypting")
		}

		encryptOrFail(sdk, inputFile, outputFile)
	} else if actionStr == "decrypt" {
		if config.Verbose {
			log.Println("In decrypting")
		}
		for err = sdk.Register(); err != nil; {
			log.Println("Decrypting client, failed to register, trying again...")
			time.Sleep(time.Duration(1) * time.Second)
		}
		decryptOrFail(sdk, inputFile, outputFile)
	}
}
// package main

// import (
// 	"bytes"
// 	"flag"
// 	"log"
// 	"math/rand"
// 	"os"
// 	"sync"
// 	"time"

// 	peacemakr_go_sdk "github.com/peacemakr-io/peacemakr-go-sdk/pkg"
// 	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/utils"
// )

// type TestMessage struct {
// 	encrypted []byte
// 	plaintext []byte
// }

// // Simple custom logger
// type CustomLogger struct{}

// func (l *CustomLogger) Printf(format string, args ...interface{}) {
// 	log.Printf(format, args...)
// }

// func runEncryptingClient(clientNum int, apiKey string, hostname string, numRuns int, encrypted chan *TestMessage, wg *sync.WaitGroup, useDomainName string) {

// 	log.Printf("Getting Peacemakr SDK for encrypting client %d...\n", clientNum)
// 	sdk, err := peacemakr_go_sdk.GetPeacemakrSDK(apiKey, "test encrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"), &CustomLogger{})
// 	if err != nil {
// 		wg.Done()
// 		log.Fatalf("Encrypting client %d%s getting peacemakr sdk failed %s", clientNum, useDomainName, err)
// 	}

// 	log.Printf("Encrypting client %d%s: registering to host %s", clientNum, useDomainName, hostname)
// 	for err = sdk.Register(); err != nil; {
// 		log.Println("Encrypting client,", clientNum, "failed to register, trying again...")
// 	}
// 	log.Printf("Encrypting client %d%s: starting %d registered.  Starting crypto round trips ...", clientNum, useDomainName, numRuns)

// 	err = sdk.Sync()
// 	if err != nil {
// 		wg.Done()
// 		log.Fatalf("Encrypting clinet %d%s: failed to preload all keys", clientNum, useDomainName)
// 	}

// 	log.Printf("Encrypting client %d%s: debug info: %s\n", clientNum, useDomainName, sdk.GetDebugInfo())

// 	for i := 0; i < numRuns; i++ {

// 		randLen := rand.Intn(4096) + 1

// 		plaintext, err := generateRandomBytes(randLen)
// 		if err != nil {
// 			wg.Done()
// 			log.Fatalf("Encrypting client %d%s: failed to get random plaintext to encrypt %s", clientNum, useDomainName, err)
// 		}

// 		var ciphertext []byte
// 		if len(useDomainName) == 0 {
// 			ciphertext, err = sdk.Encrypt(plaintext)
// 		} else {
// 			ciphertext, err = sdk.EncryptInDomain(plaintext, useDomainName)
// 		}
// 		if err != nil {
// 			wg.Done()
// 			log.Fatalf("Failed to encrypt an array (clientDebugInfo = %s, clientNum = %d) %v", sdk.GetDebugInfo(), clientNum, err)
// 		}
// 		if bytes.Equal(ciphertext, plaintext) {
// 			wg.Done()
// 			log.Fatalf("Encrypting client %d%s: encryption did nothing.", clientNum, useDomainName)
// 		}

// 		testMessage := TestMessage{
// 			encrypted: ciphertext,
// 			plaintext: plaintext,
// 		}
// 		encrypted <- &testMessage

// 		decrypted, err := sdk.Decrypt(ciphertext)
// 		if err != nil {
// 			wg.Done()
// 			log.Fatalf("Encrypting client %d%s: failed to decrypt an array of bytes %s", clientNum, useDomainName, err)
// 		}

// 		if !bytes.Equal(plaintext, decrypted) {
// 			wg.Done()
// 			log.Fatalf("Encrypting client %d%s: failed to decrypt to original plaintext.", clientNum, useDomainName)
// 		}

// 		log.Printf("Encrypting client %d%s: encrypted message number %d \n", clientNum, useDomainName, i)

// 		if i == 42 {
// 			// Example how to release memory back to the system.  Forces keys to be re-loaded.
// 			sdk.ReleaseMemory()
// 		}
// 	}

// 	log.Printf("Encryption client %d%s: done.\n", clientNum, useDomainName)
// 	wg.Done()
// }

// func runDecryptingClient(clientNum int, apiKey string, hostname string, encrypted chan *TestMessage, wg *sync.WaitGroup) {
// 	defer wg.Done()
// 	log.Printf("Getting Peacemakr SDK for decrypting client %d...\n", clientNum)
// 	sdk, err := peacemakr_go_sdk.GetPeacemakrSDK(apiKey, "test decrypting client "+string(clientNum), &hostname, utils.GetDiskPersister("/tmp/"), log.New(os.Stdout, "DecryptingClient", log.LstdFlags))
// 	if err != nil {
// 		log.Fatalf("Decrypting client %d, fetching peacemakr sdk failed %s", clientNum, err)
// 	}

// 	for err = sdk.Register(); err != nil; {
// 		log.Println("Decryption client,", clientNum, "failed to register, trying again...")
// 		time.Sleep(time.Duration(1) * time.Second)
// 	}
// 	log.Printf("Getting decrypting client %d registered...\n", clientNum)

// 	i := 0
// 	for msg := range encrypted {

// 		// If we see this, no more ciphertexts are coming, bail.
// 		if msg == nil {
// 			break
// 		}

// 		decrypted, err := sdk.Decrypt(msg.encrypted)
// 		if err != nil {
// 			log.Fatalf("Decrypting client %d failed to decrypt in DECYRTION CLIENT string", clientNum, err)
// 		}

// 		if !bytes.Equal(decrypted, msg.plaintext) {
// 			log.Fatalf("Decrypting client %d failed to decrypt in DECYRTION CLIENT decrypted %s but expected %s", clientNum, decrypted, msg.plaintext)
// 		}
// 		log.Println("Decrypting client", clientNum, "decrypted message number", i)
// 		i++
// 	}

// 	log.Println("decryption client number", clientNum, "done.")
// }

// func generateRandomBytes(n int) ([]byte, error) {
// 	b := make([]byte, n)
// 	_, err := rand.Read(b)
// 	// Note that err == nil only if we read len(b) bytes.
// 	if err != nil {
// 		return nil, err
// 	}

// 	return b, nil
// }

// func main() {
// 	apiKey := flag.String("apiKey", "Qn2fUGTEQLvCxF8IZyffib9uiQNXdT0SDcy+iwRiPA0= ", "apiKey")
// 	peacemakrUrl := flag.String("peacemakrUrl", "https://api.peacemakr.io", "URL of Peacemakr cloud services")
// 	numCryptoTrips := flag.Int("numCryptoTrips", 1, "Total number of example encrypt and decrypt operations.")
// 	numEncryptThreads := flag.Int("numEncryptClients", 1, "Total number of encryption clients. (1)")
// 	numDecryptThreads := flag.Int("numDecryptClients", 1, "Total number of decryption clients. (10)")
// 	useDomainName := flag.String("useDomainName", "", "The specific and enforced Use Domain's name for encryption")
// 	flag.Parse()
// 	if apiKey == nil || *apiKey == "" {
// 		log.Fatal("You are missing an API Key.")
// 	}

// 	log.Println("apiKey:", *apiKey)
// 	log.Println("peacemakrUrl:", *peacemakrUrl)
// 	log.Println("numCryptoTrips:", *numCryptoTrips)
// 	log.Println("numEncryptThreads:", *numEncryptThreads)
// 	log.Println("numDecryptThreads:", *numDecryptThreads)
// 	log.Println("useDomainName:", *useDomainName)

// 	// Channel of encrypted things.
// 	encrypted := make(chan *TestMessage)
// 	var encryptionWork sync.WaitGroup
// 	var decryptorWork sync.WaitGroup

// 	// Just one decryptor

// 	for i := 0; i < *numDecryptThreads; i++ {
// 		decryptorWork.Add(1)
// 		go runDecryptingClient(i, *apiKey, *peacemakrUrl, encrypted, &decryptorWork)
// 	}

// 	// Fire up the encryption clients.
// 	for i := 0; i < *numEncryptThreads; i++ {

// 		// Do it once with indiscriminate useDomains.
// 		encryptionWork.Add(1)
// 		go runEncryptingClient(i, *apiKey, *peacemakrUrl, *numCryptoTrips, encrypted, &encryptionWork, "")

// 		// And, again with a specific useDomain.
// 		if len(*useDomainName) > 0 {
// 			encryptionWork.Add(1)
// 			go runEncryptingClient(i, *apiKey, *peacemakrUrl, *numCryptoTrips, encrypted, &encryptionWork, *useDomainName)
// 		}

// 		// Why Sleep? The number of clients can't just explode, need to give them a chance to spin up,
// 		// work a little, and go away.
// 		time.Sleep(1 * time.Microsecond)

// 	}

// 	encryptionWork.Wait()
// 	log.Printf("main thread signaling to decyrptors it's over...\n")
// 	for i := 0; i < *numDecryptThreads; i++ {
// 		encrypted <- nil
// 	}
// 	decryptorWork.Wait()
// 	close(encrypted)
// }
