package peacemakr_go_sdk

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-openapi/runtime"
	coreCrypto "github.com/notasecret/peacemakr-go-sdk/crypto"
	"github.com/notasecret/peacemakr-go-sdk/generated/client"
	clientReq "github.com/notasecret/peacemakr-go-sdk/generated/client/client"
	"github.com/notasecret/peacemakr-go-sdk/generated/client/crypto_config"
	"github.com/notasecret/peacemakr-go-sdk/generated/client/key_service"
	"github.com/notasecret/peacemakr-go-sdk/generated/client/org"
	"github.com/notasecret/peacemakr-go-sdk/generated/models"
	"github.com/notasecret/peacemakr-go-sdk/utils"
	"math/rand"
	goRt "runtime"
	goRtDebug "runtime/debug"
	"strconv"
	"time"
)

type keyStruct struct {
	privKey         string
	pubKey          string
	keyCreationTime int64
}

type standardPeacemakrSDK struct {
	clientName         string
	apiKey             string
	org                *models.Organization
	cryptoConfig       *models.CryptoConfig
	authInfo           runtime.ClientAuthInfoWriter
	version            string
	peacemakrHostname  *string
	persister          utils.Persister
	isRegisteredCache  bool
	lastUpdatedAt      int64
	secondsTillRefresh int64
	asymKeys           *keyStruct
	symKeyCache        map[string][]byte
	sysLog             SDKLogger
	printStackTrace    bool
}

// Named constants, so we can change them everywhere at the same time

var chacha20Poly1305 = "Peacemakr.CoreCrypto.Symmetric.CHACHA20_POLY1305"
var aes128gcm = "Peacemakr.CoreCrypto.Symmetric.AES_128_GCM"
var aes192gcm = "Peacemakr.CoreCrypto.Symmetric.AES_192_GCM"
var aes256gcm = "Peacemakr.CoreCrypto.Symmetric.AES_256_GCM"

var sha224 = "Peacemakr.CoreCrypto.Digest.SHA_224"
var sha256 = "Peacemakr.CoreCrypto.Digest.SHA_256"
var sha384 = "Peacemakr.CoreCrypto.Digest.SHA_384"
var sha512 = "Peacemakr.CoreCrypto.Digest.SHA_512"

func (sdk *standardPeacemakrSDK) getDebugInfo() string {
	id, err := sdk.getClientId()
	if err != nil {
		id = "(unregistered)"
	}

	orgId := "(failed to populate org)"
	if err := sdk.populateOrg(); err != nil {
		orgId = "(failed to populate org)"
	}
	if sdk.org != nil {
		orgId = *sdk.org.ID
	}

	return "ClientDebugInfo *** clientId = " + id + ", org id = " + orgId + ", version = " + sdk.version
}

func (sdk *standardPeacemakrSDK) GetDebugInfo() string {
	err := sdk.errOnNotRegistered()
	if err != nil {
		return "not registered"
	}

	debugInfo := sdk.getDebugInfo()
	sdk.logString(debugInfo)
	return debugInfo
}

func (sdk *standardPeacemakrSDK) downloadAndSaveAllKeys(keyIds []string) error {
	clientId, err := sdk.getClientId()
	if err != nil {
		sdk.logError(err)
		return err
	}

	params := key_service.NewGetAllEncryptedKeysParams()
	params.EncryptingKeyID = clientId
	params.SymmetricKeyIds = keyIds
	ret, err := sdk.getClient().KeyService.GetAllEncryptedKeys(params, sdk.authInfo)
	if err != nil {
		sdk.logError(err)
		return err
	}

	privateKey, err := sdk.persister.Load("priv")
	pubKey, err := sdk.persister.Load("pub")
	if err != nil {
		sdk.logError(err)
		return err
	}

	for _, key := range ret.Payload {

		if key == nil {
			continue
		}

		numKeys := len(key.KeyIds)

		blob, cfg, err := coreCrypto.Deserialize([]byte(*key.PackagedCiphertext))
		if err != nil {
			sdk.logError(err)
			return err
		}

		// Set the default
		if cfg.SymmetricCipher == coreCrypto.SYMMETRIC_UNSPECIFIED {
			cfg.SymmetricCipher = coreCrypto.CHACHA20_POLY1305
		}

		// This is the key to use to decrypt incoming delivered keys. When ECDH is used, this is a symmetric key. When
		// RSA is used, this is the RSA private key.
		var decryptionDeliveredKey *coreCrypto.PeacemakrKey
		if isRSA(pubKey) {

			clientPrivKey, err := coreCrypto.NewPrivateKeyFromPEM(cfg.SymmetricCipher, privateKey)
			if err != nil {
				sdk.logError(err)
			}
			decryptionDeliveredKey = clientPrivKey
			// We're in a loop, so it's destroyed after last use.

		} else if isEC(pubKey) {

			// get key Id identifying the encrypting client (of the key deriver)
			aad, err := sdk.getKeyIdFromCiphertext([]byte(*key.PackagedCiphertext))
			if err != nil {
				sdk.logError(err)
				return err
			}

			// Fetch the public EC key used to derive the shared symmetric key.
			kdPublicKey, err := sdk.getPublicKey(aad.SenderKeyID)
			if err != nil {
				sdk.logError(err)
				return err
			}

			// Construct a peacemakr key from the config and key.
			kdPeacemakrKey, err := coreCrypto.NewPublicKeyFromPEM(cfg.SymmetricCipher, kdPublicKey)
			if err != nil {
				sdk.logError(err)
				return err
			}

			kdKeyConfig, err := kdPeacemakrKey.Config()
			if err != nil {
				sdk.logError(err)
				return err
			}

			// Set the default
			if kdKeyConfig.SymmetricCipher == coreCrypto.SYMMETRIC_UNSPECIFIED {
				kdKeyConfig.SymmetricCipher = coreCrypto.CHACHA20_POLY1305
			}

			// Now that we know what config, lets construct a peacemakr key.
			// Since the pubkey is an EC key, so must the private key be EC
			// and since it's EC, we don't need a symmetric algorithm.
			clientPrivKey, err := coreCrypto.NewPrivateKeyFromPEM(kdKeyConfig.SymmetricCipher, privateKey)
			if err != nil {
				sdk.logError(err)
				return err
			}

			// Derive the shared symmetric secret between this client at the key deriver. This was used to encrypt
			// the bundle of delivered keys.
			// TODO: make this lighting wicked fast, by caching and lookup up this instead of commputing it.
			decryptionDeliveredKey = clientPrivKey.ECDHKeygen(kdKeyConfig.SymmetricCipher, kdPeacemakrKey)
			clientPrivKey.Destroy()
			kdPeacemakrKey.Destroy()

		} else {
			// TODO: should we de-register client and re-register a new key?
			err = errors.New("unkonwn key type detected, can not decrypt incoming keys")
			sdk.logError(err)
			return err
		}

		// Decrypt the binary ciphertext
		plaintext, needVerify, err := coreCrypto.Decrypt(decryptionDeliveredKey, blob)
		decryptionDeliveredKey.Destroy()
		if err != nil {
			sdk.logError(err)
			return err
		}

		if needVerify {
			aad, err := sdk.getKeyIdFromCiphertext([]byte(*key.PackagedCiphertext))
			if err != nil {
				sdk.logError(err)
				return err
			}

			err = sdk.verifyMessage(aad, *cfg, blob, plaintext)
			if err != nil {
				sdk.logError(err)
				return err
			}
		}

		// Since these are keys, convert the decrypted base64 string into binary.
		keyBytes, err := base64.StdEncoding.DecodeString(string(plaintext.Data))
		if err != nil {
			sdk.logError(err)
			return err
		}

		keyLen := int(*key.KeyLength)

		// Iterate over the byte array, saving symmetric key we extract in the clear for future use.
		for i := 0; i < numKeys; i++ {

			keyBytes := keyBytes[i*keyLen : (i+1)*keyLen]
			keyBytesId := key.KeyIds[i]

			if err := sdk.persister.Save(keyBytesId, string(keyBytes)); err != nil {
				return err
			}
		}
	}

	return nil
}

func (sdk *standardPeacemakrSDK) preloadAll(keyIds []string) error {

	return sdk.downloadAndSaveAllKeys(keyIds)
}

func (sdk *standardPeacemakrSDK) Sync() error {
	err := sdk.verifyRegistrationAndInit()
	if err != nil {
		return err
	}

	return sdk.preloadAll(nil)
}

func (sdk *standardPeacemakrSDK) EncryptStr(plaintext string) (string, error) {
	encryptedBytes, err := sdk.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return string(encryptedBytes), nil
}

func (sdk *standardPeacemakrSDK) logString(s string) {
	_, file, line, _ := goRt.Caller(1)
	debugInfo := sdk.getDebugInfo()
	sdk.sysLog.Printf("[%s: %d] %s : %s", file, line, debugInfo, s)
	if sdk.printStackTrace {
		goRtDebug.PrintStack()
	}
}

func (sdk *standardPeacemakrSDK) logError(err error) {
	_, file, line, _ := goRt.Caller(1)
	debugInfo := sdk.getDebugInfo()
	sdk.sysLog.Printf("[%s: %d] %s : %v", file, line, debugInfo, err)
	if sdk.printStackTrace {
		goRtDebug.PrintStack()
	}
}

func (sdk *standardPeacemakrSDK) isLocalStateValid() bool {
	return time.Now().Unix()-sdk.lastUpdatedAt < sdk.secondsTillRefresh
}

func (sdk *standardPeacemakrSDK) populateOrg() error {
	sdkClient := sdk.getClient()

	// Early exit if we've done this already and it's not time to refresh
	if sdk.org != nil && sdk.isLocalStateValid() {
		return nil
	}

	params := org.NewGetOrganizationFromAPIKeyParams()
	params.Apikey = sdk.apiKey

	ret, err := sdkClient.Org.GetOrganizationFromAPIKey(params, sdk.authInfo)
	if err != nil {
		sdk.logError(err)
		return err
	}

	if ret == nil {
		s := fmt.Sprintf("Failed to populate Org %v", ret.Payload)
		sdk.logString(s)
		return errors.New(s)
	}

	sdk.org = ret.Payload

	return nil
}

func (sdk *standardPeacemakrSDK) getCryptoConfigIdFromAPIToken() (string, error) {

	err := sdk.populateOrg()
	if err != nil {
		sdk.logError(err)
		return "", err
	}

	return *sdk.org.CryptoConfigID, nil
}

func (sdk *standardPeacemakrSDK) populateCryptoConfig() error {

	// Early exist if we've already done this and it's not time to refresh
	if sdk.cryptoConfig != nil && sdk.isLocalStateValid() {
		return nil
	}

	pmClient := sdk.getClient()

	var err error

	params := crypto_config.NewGetCryptoConfigParams()
	params.CryptoConfigID, err = sdk.getCryptoConfigIdFromAPIToken()
	if err != nil {
		sdk.logError(err)
		return err
	}

	ret, err := pmClient.CryptoConfig.GetCryptoConfig(params, sdk.authInfo)
	if err != nil {
		sdk.logError(err)
		return err
	}

	sdk.cryptoConfig = ret.Payload
	sdk.lastUpdatedAt = time.Now().Unix()

	if sdk.cryptoConfig.ClientKeyTTL == 0 {
		oneYear, err := time.ParseDuration("8760h")
		if err != nil {
			return err
		}

		sdk.cryptoConfig.ClientKeyTTL = oneYear.Nanoseconds() / 1e9
	}

	return nil
}

func (sdk *standardPeacemakrSDK) verifyMessage(aad *PeacemakrAAD, cfg coreCrypto.CryptoConfig, ciphertext *coreCrypto.CiphertextBlob, plaintext *coreCrypto.Plaintext) error {
	senderKeyStr, err := sdk.getPublicKey(aad.SenderKeyID)
	if err != nil {
		sdk.logError(err)
		return err
	}

	senderKey, err := coreCrypto.NewPublicKeyFromPEM(cfg.SymmetricCipher, senderKeyStr)
	if err != nil {
		sdk.logError(err)
		return err
	}

	defer senderKey.Destroy()

	err = coreCrypto.Verify(senderKey, plaintext, ciphertext)
	if err != nil {
		sdk.logError(err)
		return err
	}
	return nil
}

func (sdk *standardPeacemakrSDK) loadOneKeySymmetricKey(keyId string) ([]byte, error) {

	if val, ok := sdk.symKeyCache[keyId]; ok {
		return val, nil
	}

	// If it was already loaded, we're done.
	if sdk.persister.Exists(keyId) {
		key, err := sdk.persister.Load(keyId)
		if err != nil {
			// We failed to load the key, so just load it again from the server.
			sdk.logError(err)
		} else {
			// Hot cache.
			sdk.symKeyCache[keyId] = []byte(key)
			return []byte(key), nil
		}
	}

	// Else, we just load it from key service.
	if err := sdk.downloadAndSaveAllKeys([]string{keyId}); err != nil {
		sdk.logError(err)
		return nil, err
	}

	if !sdk.persister.Exists(keyId) {
		err := errors.New("failed to find the key, keyId = " + keyId)
		sdk.logError(err)
		return nil, err
	}

	// Return it.
	foundKey, err := sdk.persister.Load(keyId)
	if err != nil {
		err := errors.New("failed to load a found key, keyId = " + keyId)
		sdk.logError(err)
		return nil, err
	}

	// Hot cache.
	sdk.symKeyCache[keyId] = []byte(foundKey)
	return []byte(foundKey), nil
}

func isUseDomainEncryptionViable(useDomain *models.SymmetricKeyUseDomain) bool {
	return *useDomain.SymmetricKeyEncryptionAllowed
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func isRSA(pubKeyPem string) bool {
	config, err := coreCrypto.GetConfigFromPubKey(pubKeyPem)
	if err != nil {
		return false
	}
	if config == coreCrypto.RSA_2048 || config == coreCrypto.RSA_4096 {
		return true
	}
	return false
}

func isEC(pubKeyPem string) bool {
	config, err := coreCrypto.GetConfigFromPubKey(pubKeyPem)
	if err != nil {
		return false
	}
	if config == coreCrypto.ECDH_P256 ||
		config == coreCrypto.ECDH_P384 ||
		config == coreCrypto.ECDH_P521 {
		return true
	}
	return false
}

func (sdk *standardPeacemakrSDK) isKeyIdDecryptionViable(keyId string) bool {
	viableDecryptionDomains := sdk.findViableDecryptionUseDomains()
	for _, domain := range viableDecryptionDomains {
		if contains(domain.EncryptionKeyIds, keyId) {
			return true
		}
	}
	return false
}

func isUseDomainDecryptionViable(useDomain *models.SymmetricKeyUseDomain) bool {
	return *useDomain.SymmetricKeyDecryptionAllowed
}

func (sdk *standardPeacemakrSDK) findViableDecryptionUseDomains() []*models.SymmetricKeyUseDomain {
	availableDomains := []*models.SymmetricKeyUseDomain{}
	for _, useDomain := range sdk.cryptoConfig.SymmetricKeyUseDomains {
		if isUseDomainDecryptionViable(useDomain) {
			availableDomains = append(availableDomains, useDomain)
		}
	}
	return availableDomains
}

func findViableEncryptionUseDomains(useDomains []*models.SymmetricKeyUseDomain) []*models.SymmetricKeyUseDomain {
	availableDomain := []*models.SymmetricKeyUseDomain{}

	for _, useDomain := range useDomains {
		if isUseDomainEncryptionViable(useDomain) {
			availableDomain = append(availableDomain, useDomain)
		}
	}
	return availableDomain
}

func (sdk *standardPeacemakrSDK) selectUseDomain(useDomainName *string) (*models.SymmetricKeyUseDomain, error) {

	if len(sdk.cryptoConfig.SymmetricKeyUseDomains) <= 0 {
		err := errors.New("no available useDomains to select")
		sdk.logError(err)
		return nil, err
	}

	var selectedDomain *models.SymmetricKeyUseDomain = nil

	if useDomainName == nil {
		viableUseDomain := findViableEncryptionUseDomains(sdk.cryptoConfig.SymmetricKeyUseDomains)
		if len(viableUseDomain) == 0 {
			// We only have invalid domains ... but we can't just fail. Just use something.
			numSelectedUseDomains := len(sdk.cryptoConfig.SymmetricKeyUseDomains)
			selectedDomainIdx := rand.Intn(numSelectedUseDomains)
			selectedDomain = sdk.cryptoConfig.SymmetricKeyUseDomains[selectedDomainIdx]
			sdk.logString("no viable use domains for encryption")
			return selectedDomain, nil
		}
		numSelectedUseDomains := len(viableUseDomain)
		selectedDomainIdx := rand.Intn(numSelectedUseDomains)
		selectedDomain = viableUseDomain[selectedDomainIdx]
	} else {
		for _, domain := range sdk.cryptoConfig.SymmetricKeyUseDomains {
			if domain.Name == *useDomainName && isUseDomainEncryptionViable(domain) {
				return domain, nil
			}
		}

		// Else just fall back on a well known domain.
		viableUseDomain := findViableEncryptionUseDomains(sdk.cryptoConfig.SymmetricKeyUseDomains)
		if len(viableUseDomain) == 0 {
			// We only have invalid domains ... but we can't just fail. Just use something.
			numSelectedUseDomains := len(sdk.cryptoConfig.SymmetricKeyUseDomains)
			selectedDomainIdx := rand.Intn(numSelectedUseDomains)
			selectedDomain = sdk.cryptoConfig.SymmetricKeyUseDomains[selectedDomainIdx]
			sdk.logString(fmt.Sprintf("no viable use domains encryption for use domain %s", *useDomainName))
			return selectedDomain, nil
		}
		numSelectedUseDomains := len(viableUseDomain)
		selectedDomainIdx := rand.Intn(numSelectedUseDomains)
		selectedDomain = viableUseDomain[selectedDomainIdx]
	}

	return selectedDomain, nil
}

func (sdk *standardPeacemakrSDK) selectEncryptionKey(useDomainName *string) (string, *coreCrypto.CryptoConfig, error) {

	// Select a use domain.
	selectedDomain, err := sdk.selectUseDomain(useDomainName)
	if err != nil {
		return "", nil, err
	}

	// Select a key in the use domain.
	numPossibleKeys := len(selectedDomain.EncryptionKeyIds)
	selectedKeyIdx := rand.Intn(numPossibleKeys)
	keyId := selectedDomain.EncryptionKeyIds[selectedKeyIdx]

	// Setup the crypto config for the encryption.
	mode := coreCrypto.SYMMETRIC
	asymmetricCipher := coreCrypto.ASYMMETRIC_UNSPECIFIED

	if selectedDomain.DigestAlgorithm == nil {
		defaultDigest := sha256
		selectedDomain.DigestAlgorithm = &defaultDigest
	}

	var digestAlgorithm coreCrypto.MessageDigestAlgorithm
	switch *selectedDomain.DigestAlgorithm {
	case sha224:
		digestAlgorithm = coreCrypto.SHA_224
	case sha256:
		digestAlgorithm = coreCrypto.SHA_256
	case sha384:
		digestAlgorithm = coreCrypto.SHA_384
	case sha512:
		digestAlgorithm = coreCrypto.SHA_512
	default:
		digestAlgorithm = coreCrypto.SHA_256
	}

	if selectedDomain.SymmetricKeyEncryptionAlg == nil {
		defaultAlg := chacha20Poly1305
		selectedDomain.SymmetricKeyEncryptionAlg = &defaultAlg
	}

	var symmetricCipher coreCrypto.SymmetricCipher
	switch *selectedDomain.SymmetricKeyEncryptionAlg {
	case aes128gcm:
		symmetricCipher = coreCrypto.AES_128_GCM
	case aes192gcm:
		symmetricCipher = coreCrypto.AES_192_GCM
	case aes256gcm:
		symmetricCipher = coreCrypto.AES_256_GCM
	case chacha20Poly1305:
		symmetricCipher = coreCrypto.CHACHA20_POLY1305
	default:
		symmetricCipher = coreCrypto.CHACHA20_POLY1305
	}

	cfg := coreCrypto.CryptoConfig{
		Mode:             mode,
		SymmetricCipher:  symmetricCipher,
		AsymmetricCipher: asymmetricCipher,
		DigestAlgorithm:  digestAlgorithm,
	}

	return keyId, &cfg, nil
}

type PeacemakrAAD struct {
	CryptoKeyID string `json:"cryptoKeyID"`
	SenderKeyID string `json:"senderKeyID"`
}

func (sdk *standardPeacemakrSDK) savePubKey(pub string) error {
	sdk.asymKeys.pubKey = pub
	err := sdk.persister.Save("pub", pub)
	if err != nil {
		return err
	}
	return nil
}

func (sdk *standardPeacemakrSDK) getPubKey() (string, error) {
	if sdk.asymKeys != nil {
		return sdk.asymKeys.pubKey, nil
	}
	pub, err := sdk.persister.Load("pub")
	if err != nil {
		return "", err
	}

	if sdk.asymKeys == nil {
		sdk.asymKeys = &keyStruct{}
	}

	sdk.asymKeys.pubKey = pub
	return pub, nil
}

func (sdk *standardPeacemakrSDK) savePrivKey(priv string) error {
	sdk.asymKeys.privKey = priv
	err := sdk.persister.Save("priv", priv)
	if err != nil {
		return err
	}
	return nil
}

func (sdk *standardPeacemakrSDK) getPrivKey() (string, error) {
	if sdk.asymKeys != nil {
		return sdk.asymKeys.privKey, nil
	}

	priv, err := sdk.persister.Load("priv")
	if err != nil {
		return "", err
	}

	if sdk.asymKeys == nil {
		sdk.asymKeys = &keyStruct{}
	}

	sdk.asymKeys.privKey = priv
	return priv, nil
}

func (sdk *standardPeacemakrSDK) saveKeyCreationTime(time int64) error {
	sdk.asymKeys.keyCreationTime = time
	err := sdk.persister.Save("key_creation_time", strconv.FormatInt(time, 16))
	if err != nil {
		return err
	}
	return nil
}

func (sdk *standardPeacemakrSDK) getKeyCreationTime() (int64, error) {
	if sdk.asymKeys != nil {
		return sdk.asymKeys.keyCreationTime, nil
	}

	timeStr, err := sdk.persister.Load("key_creation_time")
	if err != nil {
		return 0, err
	}

	if sdk.asymKeys == nil {
		sdk.asymKeys = &keyStruct{}
	}

	sdk.asymKeys.keyCreationTime, err = strconv.ParseInt(timeStr, 16, 64)
	if err != nil {
		sdk.asymKeys.keyCreationTime = 0
		return 0, err
	}

	return sdk.asymKeys.keyCreationTime, nil
}

func (sdk *standardPeacemakrSDK) encrypt(plaintext []byte, useDomainName *string) ([]byte, error) {

	keyId, cfg, err := sdk.selectEncryptionKey(useDomainName)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	key, err := sdk.loadOneKeySymmetricKey(keyId)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	pmKey := coreCrypto.NewPeacemakrKeyFromBytes(cfg.SymmetricCipher, key)
	defer pmKey.Destroy()
	myKeyId, err := sdk.getPubKeyId()
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	aad := PeacemakrAAD{
		CryptoKeyID: keyId,
		SenderKeyID: myKeyId,
	}
	aadStr, err := json.Marshal(aad)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	pmPlaintext := coreCrypto.Plaintext{
		Data: plaintext,
		Aad:  aadStr,
	}

	randomDevice := coreCrypto.NewRandomDevice()
	ciphertext, err := coreCrypto.Encrypt(pmKey, pmPlaintext, randomDevice)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	myPrivKeyStr, err := sdk.getPrivKey()
	myKey, err := coreCrypto.NewPrivateKeyFromPEM(cfg.SymmetricCipher, myPrivKeyStr)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}
	defer myKey.Destroy()

	err = coreCrypto.Sign(myKey, pmPlaintext, cfg.DigestAlgorithm, ciphertext)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	return coreCrypto.Serialize(cfg.DigestAlgorithm, ciphertext)
}

func (sdk *standardPeacemakrSDK) Encrypt(plaintext []byte) ([]byte, error) {
	err := sdk.verifyRegistrationAndInit()
	if err != nil {
		return nil, err
	}

	return sdk.encrypt(plaintext, nil)
}

func (sdk *standardPeacemakrSDK) EncryptStrInDomain(plaintext string, useDomainName string) (string, error) {
	err := sdk.verifyRegistrationAndInit()
	if err != nil {
		return "", err
	}

	err = sdk.verifyUserSelectedUseDomain(useDomainName)
	if err != nil {
		return "", err
	}

	encryptedBytes, err := sdk.encrypt([]byte(plaintext), &useDomainName)
	if err != nil {
		return "", err
	}
	return string(encryptedBytes), nil
}

func (sdk *standardPeacemakrSDK) EncryptInDomain(plaintext []byte, useDomainName string) ([]byte, error) {
	err := sdk.verifyRegistrationAndInit()
	if err != nil {
		return nil, err
	}

	err = sdk.verifyUserSelectedUseDomain(useDomainName)
	if err != nil {
		return nil, err
	}

	return sdk.encrypt(plaintext, &useDomainName)
}

func (sdk *standardPeacemakrSDK) DecryptStr(ciphertext string) (string, error) {
	plain, err := sdk.Decrypt([]byte(ciphertext))
	if err != nil {
		// No phonehome here, it was already taken care of in Decrypt.
		return "", err
	}

	return string(plain), nil
}

func (sdk *standardPeacemakrSDK) getKeyIdFromCiphertext(ciphertext []byte) (*PeacemakrAAD, error) {

	aad, err := coreCrypto.ExtractUnverifiedAAD(ciphertext)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}
	ret := &PeacemakrAAD{}
	err = json.Unmarshal(aad, ret)

	return ret, nil
}

func (sdk *standardPeacemakrSDK) getPublicKey(keyID string) (string, error) {

	if sdk.persister.Exists(keyID) {
		key, err := sdk.persister.Load(keyID)
		if err != nil {
			sdk.logError(err)
			return "", err
		}
		return key, nil
	}

	getPubKeyParams := key_service.NewGetPublicKeyParams()
	getPubKeyParams.KeyID = keyID

	result, err := sdk.getClient().KeyService.GetPublicKey(getPubKeyParams, sdk.authInfo)
	if err != nil {
		sdk.logError(err)
		return "", err
	}

	if err := sdk.persister.Save(keyID, *result.Payload.Key); err != nil {
		sdk.logError(err)
		return "", err
	}

	return *result.Payload.Key, nil
}

func (sdk *standardPeacemakrSDK) Decrypt(ciphertext []byte) ([]byte, error) {
	err := sdk.verifyRegistrationAndInit()
	if err != nil {
		return nil, err
	}

	ciphertextblob, cfg, err := coreCrypto.Deserialize(ciphertext)
	if err != nil {
		// If we did not encrypt this blob, we can not decrypt it.
		// No need to phonehome this specific error.
		return nil, errors.New("not a peacemakr ciphertext")
	}

	aad, err := sdk.getKeyIdFromCiphertext(ciphertext)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	if !sdk.isKeyIdDecryptionViable(aad.CryptoKeyID) {
		sdk.logString("key is no longer viable for decryption")
		return nil, errors.New("ciphertext is no longer viable for decryption")
	}

	key, err := sdk.loadOneKeySymmetricKey(aad.CryptoKeyID)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	pmKey := coreCrypto.NewPeacemakrKeyFromBytes(cfg.SymmetricCipher, key)
	defer pmKey.Destroy()
	plaintext, needsVerification, err := coreCrypto.Decrypt(pmKey, ciphertextblob)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	if needsVerification {
		err = sdk.verifyMessage(aad, *cfg, ciphertextblob, plaintext)
		if err != nil {
			sdk.logError(err)
			return nil, err
		}
	}

	return plaintext.Data, nil
}

var sdkClient *client.PeacemakrClient

func (sdk *standardPeacemakrSDK) getClient() *client.PeacemakrClient {

	if sdkClient != nil {
		return sdkClient
	}

	var hostname string
	if sdk.peacemakrHostname == nil || *sdk.peacemakrHostname == "" {
		hostname = client.DefaultHost
	} else {
		hostname = *sdk.peacemakrHostname
	}

	cfg := client.TransportConfig{
		Host:     hostname,
		BasePath: client.DefaultBasePath,
		Schemes:  []string{"http"},
	}

	sdkClient = client.NewHTTPClientWithConfig(nil, &cfg)
	return sdkClient
}

func (sdk *standardPeacemakrSDK) getClientId() (string, error) {

	if !sdk.persister.Exists("clientId") {
		err := errors.New("keyID does not exist in the SDK persister, client may not be registered")
		return "", err
	}

	clientId, err := sdk.persister.Load("clientId")
	if err != nil {
		return "", err
	}

	return clientId, nil
}

func (sdk *standardPeacemakrSDK) saveClientId(clientID string) error {

	if sdk.persister.Exists("clientId") {
		err := errors.New("client ID already exists, client is already registered")
		return err
	}

	err := sdk.persister.Save("clientId", clientID)
	if err != nil {
		return err
	}

	return nil
}

func (sdk *standardPeacemakrSDK) getPubKeyId() (string, error) {

	if !sdk.persister.Exists("keyId") {
		err := errors.New("client is not registered")
		return "", err
	}

	keyId, err := sdk.persister.Load("keyId")
	if err != nil {
		return "", err
	}

	return keyId, nil
}

func (sdk *standardPeacemakrSDK) updatePubKeyId(newKeyID string) error {

	if !sdk.persister.Exists("keyId") {
		err := errors.New("public key ID doesn't exist, client may not be registered")
		return err
	}

	err := sdk.persister.Save("keyId", newKeyID)
	if err != nil {
		return err
	}

	return nil
}

func (sdk *standardPeacemakrSDK) errOnNotRegistered() error {

	if sdk.isRegisteredCache == true {
		return nil
	}

	sdk.isRegisteredCache = sdk.persister.Exists("priv") &&
		sdk.persister.Exists("pub") &&
		sdk.persister.Exists("keyId") &&
		sdk.persister.Exists("clientId")

	if sdk.isRegisteredCache == false {
		return errors.New("client not registered")
	}

	return nil
}

func (sdk *standardPeacemakrSDK) generateKeys() (string, string, string, error) {
	if sdk.asymKeys == nil {
		sdk.asymKeys = &keyStruct{}
	}

	pub, priv, keyTy := GetNewKey(sdk.cryptoConfig.ClientKeyType, int(sdk.cryptoConfig.ClientKeyBitlength))

	err := sdk.savePrivKey(priv)
	if err != nil {
		err := errors.New("unable to save private key")
		sdk.logError(err)
		return "", "", "", err
	}

	err = sdk.savePubKey(pub)
	if err != nil {
		err := errors.New("unable to save public key")
		sdk.logError(err)
		return "", "", "", err
	}

	if err := sdk.saveKeyCreationTime(time.Now().Unix()); err != nil {
		return "", "", "", err
	}

	return pub, priv, keyTy, nil
}

func (sdk *standardPeacemakrSDK) createUseDomain(numKeys int, name string) error {
	sdkClient := sdk.getClient()

	t := time.Now().Unix()

	keyIds := []string{}
	for i := 0; i < numKeys; i++ {
		keyId, err := utils.GenerateRandomString(32)
		if err != nil {
			return err
		}
		keyIds = append(keyIds, keyId)
	}
	fallbackToCloud := true
	ciphertextVersion := int64(0)
	emptyString := ""
	twentyYears := int64(60 * 60 * 24 * 365 * 20)
	zero := int64(0)
	alg := chacha20Poly1305
	digestAlg := sha256
	keyLen := int64(32)
	falseValue := false

	useDomain := models.SymmetricKeyUseDomain{
		CreationTime:                        &t,
		EncryptingPackagedCiphertextVersion: &ciphertextVersion,
		EncryptionKeyIds:                    keyIds,
		EndableKDSFallbackToCloud:           &fallbackToCloud,
		ID:                                  &emptyString,
		Name:                                name,
		OwnerOrgID:                          sdk.org.ID,
		SymmetricKeyDecryptionUseTTL:        &twentyYears,
		SymmetricKeyDecryptionAllowed:       &falseValue,
		SymmetricKeyDerivationServiceID:     &emptyString, // Empty string, means the server randomly picks.
		SymmetricKeyEncryptionAlg:           &alg,
		SymmetricKeyEncryptionUseTTL:        &twentyYears,
		SymmetricKeyEncryptionAllowed:       &falseValue,
		SymmetricKeyInceptionTTL:            &zero,
		SymmetricKeyLength:                  &keyLen,
		SymmetricKeyRetentionUseTTL:         &twentyYears,
		RequireSignedKeyDelivery:            &falseValue,
		DigestAlgorithm:                     &digestAlg,
	}

	params := crypto_config.NewAddUseDomainParams()
	params.CryptoConfigID = *sdk.cryptoConfig.ID
	params.NewUseDomain = &useDomain

	_, err := sdkClient.CryptoConfig.AddUseDomain(params, sdk.authInfo)
	if err != nil {
		return err
	}

	return nil
}

func (sdk *standardPeacemakrSDK) hasUseDomain() bool {
	return sdk.cryptoConfig.SymmetricKeyUseDomains != nil && len(sdk.cryptoConfig.SymmetricKeyUseDomains) != 0
}

//
// SDK impl
//
func (sdk *standardPeacemakrSDK) Register() error {

	if !coreCrypto.PeacemakrInit() {
		err := errors.New("unable to initialize core crypto lib")
		sdk.logError(err)
		return err
	}

	err := sdk.init()
	if err != nil {
		sdk.logError(err)
		return err
	}

	var pub, _, keyTy string

	// If either key is missing, bail.
	if !sdk.persister.Exists("priv") || !sdk.persister.Exists("pub") {
		pub, _, keyTy, err = sdk.generateKeys()
		if err != nil {
			return err
		}
	} else {
		pubLoaded, err := sdk.getPubKey()
		if err != nil {
			sdk.logError(err)
			return err
		}
		pub = pubLoaded

		_, err = sdk.getPrivKey()
		if err != nil {
			sdk.logError(err)
			return err
		}

		cfg, err := coreCrypto.GetConfigFromPubKey(pub)
		if err != nil {
			sdk.logError(err)
			return err
		}

		if cfg == coreCrypto.RSA_2048 || cfg == coreCrypto.RSA_4096 {
			keyTy = "rsa"
		} else if cfg == coreCrypto.ECDH_P256 ||
			cfg == coreCrypto.ECDH_P384 ||
			cfg == coreCrypto.ECDH_P521 {
			keyTy = "ec"
		}
	}

	sdkClient := sdk.getClient()

	keyIdExists := sdk.persister.Exists("keyId")
	clientIdExists := sdk.persister.Exists("clientId")
	//
	// Register as a new client.
	//
	if !keyIdExists || !clientIdExists {
		params := clientReq.NewAddClientParams()
		params.Client = &models.Client{}
		tempId := ""
		params.Client.ID = &tempId
		params.Client.Sdk = sdk.version
		encoding := "pem"
		params.Client.PublicKeys = []*models.PublicKey{{
			CreationTime: &sdk.asymKeys.keyCreationTime,
			Encoding:     &encoding,
			ID:           &tempId,
			Key:          &pub,
			KeyType:      &keyTy,
		}}

		ok, err := sdkClient.Client.AddClient(params, sdk.authInfo)
		if err != nil {
			sdk.logError(err)
			return err
		}

		// We only sent up one public key, but just in case the server has some other state we use the last one
		saveErr := sdk.updatePubKeyId(*ok.Payload.PublicKeys[len(ok.Payload.PublicKeys)-1].ID)
		if saveErr != nil {
			sdk.logError(err)
			return saveErr
		}
		saveErr = sdk.saveClientId(*ok.Payload.ID)
		if saveErr != nil {
			sdk.logError(err)
			return saveErr
		}

		return nil
	}

	//
	// Already loaded info from previously registered client.
	//
	if keyIdExists && clientIdExists {
		// if it exists, verify we can read it.
		_, err := sdk.getClientId()
		if err != nil {
			return err
		}

		return nil
	}

	return errors.New("unreachable hit, new unhandled case detected")
}

func (sdk *standardPeacemakrSDK) init() error {

	err := sdk.populateOrg()
	if err != nil {
		sdk.logError(err)
		return err
	}

	if sdk.org == nil {
		err := errors.New("failed to populate org from api key")
		sdk.logError(err)
		return err
	}

	err = sdk.populateCryptoConfig()
	if err != nil {
		sdk.logError(err)
		return err
	}

	return nil
}

func (sdk *standardPeacemakrSDK) getCryptoConfigCipher() coreCrypto.AsymmetricCipher {
	var cryptoConfigCipher coreCrypto.AsymmetricCipher
	switch sdk.cryptoConfig.ClientKeyType {
	case "ec":
		switch sdk.cryptoConfig.ClientKeyBitlength {
		case 256:
			cryptoConfigCipher = coreCrypto.ECDH_P256
		case 384:
			cryptoConfigCipher = coreCrypto.ECDH_P384
		case 521:
			cryptoConfigCipher = coreCrypto.ECDH_P521
		default:
			cryptoConfigCipher = coreCrypto.ASYMMETRIC_UNSPECIFIED
		}
	case "rsa":
		switch sdk.cryptoConfig.ClientKeyBitlength {
		case 2048:
			cryptoConfigCipher = coreCrypto.RSA_2048
		case 4096:
			cryptoConfigCipher = coreCrypto.RSA_4096
		default:
			cryptoConfigCipher = coreCrypto.ASYMMETRIC_UNSPECIFIED
		}
	default:
		// If they haven't specified anything for the client asymmetric keys, use ECDH_256
		sdk.cryptoConfig.ClientKeyType = "ec"
		sdk.cryptoConfig.ClientKeyBitlength = 256

		cryptoConfigCipher = coreCrypto.ECDH_P256
	}

	return cryptoConfigCipher
}

func (sdk *standardPeacemakrSDK) asymKeysAreStale() bool {
	return time.Now().Unix()-sdk.asymKeys.keyCreationTime > sdk.cryptoConfig.ClientKeyTTL
}

func (sdk *standardPeacemakrSDK) rotateClientKeyIfNeeded() error {
	pubKey, err := sdk.getPubKey()
	if err != nil {
		return err
	}

	currentCipher, err := coreCrypto.GetConfigFromPubKey(pubKey)
	if err != nil {
		return err
	}

	cryptoConfigCipher := sdk.getCryptoConfigCipher()

	// Rotate if the key has expired OR if the cipher changed
	shouldRotate := sdk.asymKeysAreStale() || (cryptoConfigCipher != currentCipher)

	if !shouldRotate {
		return nil
	}

	if sdk.asymKeysAreStale() {
		sdk.logString("Rotating expired key")
	}

	if cryptoConfigCipher != currentCipher {
		sdk.logString(fmt.Sprintf("Rotating key because asymmetric key config changed from %v to %v", currentCipher, cryptoConfigCipher))
	}

	// Save the previous stuff in case we have to roll back the change
	prevPub, err := sdk.getPubKey()
	if err != nil {
		return err
	}
	prevPriv, err := sdk.getPrivKey()
	if err != nil {
		return err
	}

	prevCreatedAt, err := sdk.getKeyCreationTime()
	if err != nil {
		return err
	}

	// Use this function to roll back in case of error
	rollback := func(outerErr error) error {
		if err := sdk.savePubKey(prevPub); err != nil {
			return errors.New(fmt.Sprintf("In recovering from %v, while saving pub key, error %v ocurred", outerErr, err))
		}
		if err := sdk.savePrivKey(prevPriv); err != nil {
			return errors.New(fmt.Sprintf("In recovering from %v, while saving priv key, error %v ocurred", outerErr, err))
		}

		if err := sdk.saveKeyCreationTime(prevCreatedAt); err != nil {
			return errors.New(fmt.Sprintf("In recovering from %v, while saving key creation time, error %v ocurred", outerErr, err))
		}
		return nil
	}

	pub, _, keyTy, err := sdk.generateKeys()
	if err != nil {
		// Roll back the changes
		return rollback(err)
	}

	networkClient := sdk.getClient()
	clientID, err := sdk.getClientId()
	if err != nil {
		return rollback(err)
	}

	pemStr := "pem"

	keyID, err := sdk.getPubKeyId()
	if err != nil {
		return rollback(err)
	}

	updateKeyParams := &clientReq.UpdateClientPublicKeyParams{
		ClientID: clientID,
		NewPublicKey: &models.PublicKey{
			CreationTime: &sdk.asymKeys.keyCreationTime,
			Encoding:     &pemStr,
			ID:           &keyID,
			Key:          &pub,
			KeyType:      &keyTy,
		},
	}

	updatedKey, err := networkClient.Client.UpdateClientPublicKey(updateKeyParams, sdk.authInfo)
	if err != nil {
		sdk.logString("Error on the network, rolling back public key changes")
		sdk.logError(err)
		return rollback(err)
	}

	// Only update the public key ID if everything was successful
	if err := sdk.updatePubKeyId(*updatedKey.Payload.ID); err != nil {
		sdk.logError(err)
		return rollback(err)
	}

	return nil
}

func (sdk *standardPeacemakrSDK) verifyRegistrationAndInit() error {

	if err := sdk.errOnNotRegistered(); err != nil {
		return err
	}

	if err := sdk.rotateClientKeyIfNeeded(); err != nil {
		return err
	}

	// This info only lasts for so long.
	if !sdk.isLocalStateValid() {
		clearAllMetadata(sdk)
	}

	return sdk.init()
}

func clearAllMetadata(sdk *standardPeacemakrSDK) {
	// Clear populateOrg
	sdk.cryptoConfig = nil
	sdk.org = nil
	// Clear populateCryptoConfig
	sdk.lastUpdatedAt = 0
}

func (sdk *standardPeacemakrSDK) verifyUserSelectedUseDomain(useDomainName string) error {

	err := sdk.populateCryptoConfig()
	if err != nil {
		e := errors.New("failed to populate use doamins from crypto config id")
		sdk.logError(e)
		return e
	}

	for _, domain := range sdk.cryptoConfig.SymmetricKeyUseDomains {
		if domain.Name == useDomainName {
			return nil
		}
	}

	err = errors.New(fmt.Sprintf("unknown use doamin: %s", useDomainName))
	sdk.logError(err)
	return err
}

func (sdk *standardPeacemakrSDK) ReleaseMemory() {
	sdk.symKeyCache = map[string][]byte{}
	clearAllMetadata(sdk)
}
