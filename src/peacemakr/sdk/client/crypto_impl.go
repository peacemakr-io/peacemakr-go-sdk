package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/go-openapi/runtime"
	"math/rand"
	coreCrypto "peacemakr/crypto"
	"peacemakr/generated/peacemakr-client/client"
	clientReq "peacemakr/generated/peacemakr-client/client/client"
	"peacemakr/generated/peacemakr-client/client/crypto_config"
	"peacemakr/generated/peacemakr-client/client/key_service"
	"peacemakr/generated/peacemakr-client/client/org"
	"peacemakr/generated/peacemakr-client/models"
	"peacemakr/sdk/utils"
	"time"
	"peacemakr/generated/peacemakr-client/client/phone_home"
	"fmt"
	"log"
)

type standardPeacemakrSDK struct {
	clientName         string
	apiKey             string
	orgId              *string
	cryptoConfigId     *string
	useDomains         []*models.SymmetricKeyUseDomain
	domainSelectorAlg  *string
	authInfo           runtime.ClientAuthInfoWriter
	version            string
	peacemakrHostname  *string
	persister          utils.Persister
	isRegisteredCache  bool
	lastUpdatedAt      int64
	secondsTillRefresh int64
	privKey		       *string
	pubKey             *string
	symKeyCache		   map[string][]byte
}

func (sdk *standardPeacemakrSDK) getDebugInfo() string {
	id, err := sdk.getClientId()
	if err != nil {
		id = "(unregistered)"
	}

	orgId := "(failed to populate org)"
	sdk.populateOrgInfo()
	if sdk.orgId != nil {
		orgId = *sdk.orgId
	}

	return "ClinetDebugInfo *** clientId = " + id + ", org id = " + orgId + ", version = " + sdk.version
}

func (sdk *standardPeacemakrSDK) GetDebugInfo() string {
	err := sdk.errOnNotRegistered()
	if err != nil {
		return "not registered"
	}

	debugInfo := sdk.getDebugInfo()
	sdk.phonehomeString(debugInfo)
	return debugInfo
}

func (sdk *standardPeacemakrSDK) preloadAll(keyIds []string) error {

	// Load all keys from key service.
	clientId, err := sdk.getClientId()
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	params := key_service.NewGetAllEncryptedKeysParams()
	params.EncryptingKeyID = clientId
	if keyIds != nil {
		params.SymmetricKeyIds = keyIds
	}
	ret, err := sdk.getClient().KeyService.GetAllEncryptedKeys(params, sdk.authInfo)
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	privateKey, err := sdk.getPrivKey()
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	for _, key := range ret.Payload {

		if key == nil {
			continue
		}

		numKeys := len(key.KeyIds)

		blob, cfg, err := coreCrypto.Deserialize([]byte(*key.PackagedCiphertext))
		if err != nil {
			sdk.phonehomeError(err)
			return err
		}
		decryptKey := coreCrypto.NewPeacemakrKeyFromPrivPem(*cfg, []byte(privateKey))

		// Decrypt the binary ciphertext
		plaintext, needVerify, err := coreCrypto.Decrypt(decryptKey, blob)
		if err != nil {
			sdk.phonehomeError(err)
			return err
		}

		if needVerify {
			aad, err := sdk.getKeyIdFromCiphertext([]byte(*key.PackagedCiphertext))
			if err != nil {
				sdk.phonehomeError(err)
				return err
			}

			err = sdk.verifyMessage(aad, blob, plaintext)
			if err != nil {
				sdk.phonehomeError(err)
				return err
			}
		}

		// Since these are keys, convert the decrypted base64 string into binary.
		keyBytes, err := base64.StdEncoding.DecodeString(string(plaintext.Data))
		if err != nil {
			sdk.phonehomeError(err)
			return err
		}

		keyLen := int(*key.KeyLength)

		// Iterate over the byte array, saving symmetric key we extract in the clear for future use.
		for i := 0; i < numKeys; i++ {

			keyBytes := keyBytes[i*keyLen : (i+1)*keyLen]
			keyBytesId := key.KeyIds[i]

			sdk.persister.Save(keyBytesId, string(keyBytes))
		}
	}

	return nil
}

func (sdk *standardPeacemakrSDK) PreLoad() error {
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

func (sdk *standardPeacemakrSDK) phonehomeString(s string) {

	params := phone_home.NewPostLogParams()
	params.Log = &models.Log{
		ClientID: nil,
		Event:    nil,
	}

	clientId, err := sdk.getClientId()
	if err != nil {
		clientId = "failed to fetch"
	}

	params.Log.ClientID = &clientId
	params.Log.Event = &s

	sdk.getClient().PhoneHome.PostLog(params, sdk.authInfo)
}

func (sdk *standardPeacemakrSDK) phonehomeError(err error) {
	debugInfo := sdk.getDebugInfo()
	errStr := debugInfo + " : " + fmt.Sprintf("%e --- %v", err, err)
	sdk.phonehomeString(errStr)
}

func (sdk *standardPeacemakrSDK) getOrgIdFromAPIToken() (string, error) {

	if sdk.orgId != nil {
		return *sdk.orgId, nil
	}

	err := sdk.populateOrgInfo()
	if err != nil {
		sdk.phonehomeError(err)
		return "", err
	}

	return *sdk.orgId, nil
}

func (sdk *standardPeacemakrSDK) populateOrgInfo() error {
	client := sdk.getClient()

	// Early exist if we've done this already
	if sdk.orgId != nil {
		return nil
	}

	params := org.NewGetOrganizationFromAPIKeyParams()
	params.Apikey = sdk.apiKey

	ret, err := client.Org.GetOrganizationFromAPIKey(params, sdk.authInfo)
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	sdk.cryptoConfigId = ret.Payload.CryptoConfigID
	sdk.orgId = ret.Payload.ID

	return nil
}

func (sdk *standardPeacemakrSDK) getCryptoConfigIdFromAPIToken() (string, error) {

	if sdk.cryptoConfigId != nil {
		return *sdk.cryptoConfigId, nil
	}

	err := sdk.populateOrgInfo()
	if err != nil {
		sdk.phonehomeError(err)
		return "", err
	}

	return *sdk.cryptoConfigId, nil
}

func (sdk *standardPeacemakrSDK) populateUseDomains(cryptoConfigId string) error {

	// Early exist if we've already done this.
	if sdk.useDomains != nil {
		return nil
	}

	client := sdk.getClient()

	var err error

	params := crypto_config.NewGetCryptoConfigParams()
	params.CryptoConfigID, err = sdk.getCryptoConfigIdFromAPIToken()
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	ret, err := client.CryptoConfig.GetCryptoConfig(params, sdk.authInfo)
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	sdk.domainSelectorAlg = ret.Payload.SymmetricKeyUseDomainSelectorScheme

	var useDomains []*models.SymmetricKeyUseDomain
	for _, d := range ret.Payload.SymmetricKeyUseDomains {

		if d == nil {
			continue
		}

		newDomain := models.SymmetricKeyUseDomain{
			CreationTime:                        d.CreationTime,
			EncryptingPackagedCiphertextVersion: d.EncryptingPackagedCiphertextVersion,
			EncryptionKeyIds:                    d.EncryptionKeyIds,
			EndableKDSFallbackToCloud:           d.EndableKDSFallbackToCloud,
			ID:                                  d.ID,
			Name:                                d.Name,
			OwnerOrgID:                          d.OwnerOrgID,
			SymmetricKeyDecryptionUseTTL:        d.SymmetricKeyDecryptionUseTTL,
			SymmetricKeyDerivationServiceID:     d.SymmetricKeyDerivationServiceID,
			SymmetricKeyEncryptionAlg:           d.SymmetricKeyEncryptionAlg,
			SymmetricKeyEncryptionUseTTL:        d.SymmetricKeyEncryptionUseTTL,
			SymmetricKeyInceptionTTL:            d.SymmetricKeyInceptionTTL,
			SymmetricKeyLength:                  d.SymmetricKeyLength,
			SymmetricKeyRetentionUseTTL:         d.SymmetricKeyRetentionUseTTL,
		}

		useDomains = append(useDomains, &newDomain)
	}

	sdk.useDomains = useDomains
	sdk.lastUpdatedAt = time.Now().Unix()

	return nil
}

func getBitLenFromRsaPubPemStr(pubRSA string) (int, error) {
	rsaKey, err := ParseRsaPublicKeyFromPemStr(pubRSA)
	if err != nil {
		return 0, err
	}
	return rsaKey.N.BitLen(), nil
}

func getBitLenFromRsaPrivPemStr(privRSA string) (int, error) {
	rsaKey, err := ParseRsaPrivateKeyFromPemStr(privRSA)
	if err != nil {
		return 0, err
	}
	return rsaKey.N.BitLen(), nil
}

func (sdk *standardPeacemakrSDK) verifyMessage(aad *PeacemakrAAD, ciphertext *coreCrypto.CiphertextBlob, plaintext *coreCrypto.Plaintext) error {
	senderPubKey, err := sdk.getPublicKey(aad.SenderKeyID)
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	pubKeyLen, err := getBitLenFromRsaPubPemStr(senderPubKey)
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	var senderKeyCfg coreCrypto.CryptoConfig
	if pubKeyLen == 4096 {
		senderKeyCfg = coreCrypto.CryptoConfig{
			Mode:             coreCrypto.ASYMMETRIC,
			SymmetricCipher:  coreCrypto.AES_256_GCM,
			AsymmetricCipher: coreCrypto.RSA_4096,
			DigestAlgorithm:  coreCrypto.SHA3_512,
		}
	} else if pubKeyLen == 2048 {
		senderKeyCfg = coreCrypto.CryptoConfig{
			Mode:             coreCrypto.ASYMMETRIC,
			SymmetricCipher:  coreCrypto.AES_256_GCM,
			AsymmetricCipher: coreCrypto.RSA_2048,
			DigestAlgorithm:  coreCrypto.SHA3_512,
		}
	} else {
		err := errors.New(fmt.Sprintf("Unknown number of bits in private key %d", pubKeyLen))
		sdk.phonehomeError(err)
		return err
	}

	senderKey := coreCrypto.NewPeacemakrKeyFromPubPem(senderKeyCfg, []byte(senderPubKey))

	err = coreCrypto.Verify(senderKey, plaintext, ciphertext)
	if err != nil {
		sdk.phonehomeError(err)
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
			sdk.phonehomeError(err)
		} else {
			// Hot cache.
			sdk.symKeyCache[keyId] = []byte(key)
			return []byte(key), nil
		}
	}

	// Else, we just load it from key service.
	err := sdk.preloadAll([]string{keyId})
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	// Verify we got it.
	if !sdk.persister.Exists(keyId) {
		err :=  errors.New("failed to find the key, keyId = " + keyId)
		sdk.phonehomeError(err)
		return nil, err
	}

	// Return it.
	foundKey, err := sdk.persister.Load(keyId)
	if err != nil {
		err := errors.New("failed to load a found key, keyId = " + keyId)
		sdk.phonehomeError(err)
		return nil, err
	}

	// Hot cache.
	sdk.symKeyCache[keyId] = []byte(foundKey)
	return []byte(foundKey), nil
}

func isUseDomainEncryptionViable(useDomain *models.SymmetricKeyUseDomain) bool {
	currentTime := time.Now().Unix()
	if (*useDomain.SymmetricKeyInceptionTTL     <= 0 || currentTime > *useDomain.CreationTime + *useDomain.SymmetricKeyInceptionTTL) ||
	   (*useDomain.SymmetricKeyEncryptionUseTTL <= 0 || currentTime < *useDomain.CreationTime + *useDomain.SymmetricKeyEncryptionUseTTL) {
		return true
	}
	return false
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
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
	currentTime := time.Now().Unix()
	if (*useDomain.SymmetricKeyInceptionTTL     <= 0 || currentTime > *useDomain.CreationTime + *useDomain.SymmetricKeyInceptionTTL) ||
	   (*useDomain.SymmetricKeyDecryptionUseTTL <= 0 || currentTime < *useDomain.CreationTime + *useDomain.SymmetricKeyDecryptionUseTTL) {
		return true
	}
	return false
}

func (sdk *standardPeacemakrSDK) findViableDecryptionUseDomains() []*models.SymmetricKeyUseDomain {
	availableDomains := []*models.SymmetricKeyUseDomain{}
	for _, useDomain := range sdk.useDomains {
		if isUseDomainDecryptionViable(useDomain) {
			availableDomains = append(availableDomains, useDomain)
		}
	}
	return availableDomains
}

func findViableEncryptionUseDomains(useDomains []*models.SymmetricKeyUseDomain)  []*models.SymmetricKeyUseDomain {
	availableDomain := []*models.SymmetricKeyUseDomain{}

	for _, useDomain := range useDomains {
		if isUseDomainEncryptionViable(useDomain) {
			availableDomain = append(availableDomain, useDomain)
		}
	}
	return availableDomain
}

func (sdk *standardPeacemakrSDK) selectUseDomain(useDomainName *string) (*models.SymmetricKeyUseDomain, error) {

	if len(sdk.useDomains) <= 0 {
		err := errors.New("no available useDomains to select")
		sdk.phonehomeError(err)
		return nil, err
	}

	var selectedDomain *models.SymmetricKeyUseDomain = nil

	if useDomainName == nil {
		viableUseDomain := findViableEncryptionUseDomains(sdk.useDomains)
		if len(viableUseDomain) == 0 {
			// We only have invalid domains ... but we can't just fail. Just use something.
			numSelectedUseDomains := len(sdk.useDomains)
			selectedDomainIdx := rand.Intn(numSelectedUseDomains)
			selectedDomain = sdk.useDomains[selectedDomainIdx]
			sdk.phonehomeString("no viable use domains for encryption")
			return selectedDomain, nil
		}
		numSelectedUseDomains := len(viableUseDomain)
		selectedDomainIdx := rand.Intn(numSelectedUseDomains)
		selectedDomain = viableUseDomain[selectedDomainIdx]
	} else {
		for _, domain := range sdk.useDomains {
			if domain.Name == *useDomainName && isUseDomainEncryptionViable(domain) {
				return domain, nil
			}
		}

		// Else just fall back on a well known domain.
		viableUseDomain := findViableEncryptionUseDomains(sdk.useDomains)
		if len(viableUseDomain) == 0 {
			// We only have invalid domains ... but we can't just fail. Just use something.
			numSelectedUseDomains := len(sdk.useDomains)
			selectedDomainIdx := rand.Intn(numSelectedUseDomains)
			selectedDomain = sdk.useDomains[selectedDomainIdx]
			sdk.phonehomeString(fmt.Sprintf("no viable use domains encryption for use domain %s", useDomainName))
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
	asymmetricCipher := coreCrypto.NONE
	symmetricCipher := coreCrypto.AES_256_GCM
	digestAlgorithm := coreCrypto.SHA_256

	if *selectedDomain.SymmetricKeyEncryptionAlg == "AES_256_GCM" {
		symmetricCipher = coreCrypto.AES_256_GCM
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
	sdk.pubKey = &pub
	err := sdk.persister.Save("pub", pub)
	if err != nil {
		log.Println("Failed to save pub")
		return err
	}
	return nil
}

func (sdk *standardPeacemakrSDK) getPubKey() (string, error) {
	if sdk.pubKey != nil {
		return *sdk.pubKey, nil
	}
	pub, err := sdk.persister.Load("pub")
	if err != nil {
		log.Println("Failed to load pub")
		return "", err
	}

	sdk.pubKey = &pub
	return pub, nil
}

func (sdk *standardPeacemakrSDK) savePrivKey(priv string) error {
	sdk.privKey = &priv
	err := sdk.persister.Save("priv", priv)
	if err != nil {
		log.Println("Failed to save priv")
		return err
	}
	return nil
}

func (sdk *standardPeacemakrSDK) getPrivKey() (string, error) {
	if sdk.privKey != nil {
		return *sdk.privKey, nil
	}
	priv, err := sdk.persister.Load("priv")
	if err != nil {
		log.Println("Failed to load priv")
		return "", err
	}

	sdk.privKey = &priv
	return priv, nil
}

func (sdk *standardPeacemakrSDK) encrypt(plaintext []byte, useDomainName *string) ([]byte, error) {

	keyId, cfg, err := sdk.selectEncryptionKey(useDomainName)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	key, err := sdk.loadOneKeySymmetricKey(keyId)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	pmKey := coreCrypto.NewPeacemakrKeyFromBytes(*cfg, key)
	myKeyId, err := sdk.persister.Load("keyId")
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	aad := PeacemakrAAD{
		CryptoKeyID: keyId,
		SenderKeyID: myKeyId,
	}
	aadStr, err := json.Marshal(aad)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	pmPlaintext := coreCrypto.Plaintext{
		Data: plaintext,
		Aad:  aadStr,
	}

	randomDevice := coreCrypto.NewRandomDevice()
	ciphertext, err := coreCrypto.Encrypt(pmKey, pmPlaintext, randomDevice)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	myKeyPemStr, err := sdk.getPrivKey()
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	numBits, err := getBitLenFromRsaPrivPemStr(myKeyPemStr)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	var myKeyCfg coreCrypto.CryptoConfig
	if numBits == 4096 {
		myKeyCfg = coreCrypto.CryptoConfig{
			Mode:             coreCrypto.ASYMMETRIC,
			SymmetricCipher:  coreCrypto.AES_256_GCM,
			AsymmetricCipher: coreCrypto.RSA_4096,
			DigestAlgorithm:  coreCrypto.SHA3_512,
		}
	} else if numBits == 2048 {
		myKeyCfg = coreCrypto.CryptoConfig{
			Mode:             coreCrypto.ASYMMETRIC,
			SymmetricCipher:  coreCrypto.AES_256_GCM,
			AsymmetricCipher: coreCrypto.RSA_2048,
			DigestAlgorithm:  coreCrypto.SHA3_512,
		}
	} else {
		err := errors.New(fmt.Sprintf("Unknown number of bits in private key %d", numBits))
		sdk.phonehomeError(err)
		return nil, err
	}

	myKey := coreCrypto.NewPeacemakrKeyFromPrivPem(myKeyCfg, []byte(myKeyPemStr))

	err = coreCrypto.Sign(myKey, pmPlaintext, ciphertext)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	return coreCrypto.Serialize(ciphertext)
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
		sdk.phonehomeError(err)
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
			sdk.phonehomeError(err)
			return "", err
		}
		return key, nil
	}

	getPubKeyParams := key_service.NewGetPublicKeyParams()
	getPubKeyParams.KeyID = keyID

	result, err := sdk.getClient().KeyService.GetPublicKey(getPubKeyParams, sdk.authInfo)
	if err != nil {
		sdk.phonehomeError(err)
		return "", err
	}

	sdk.persister.Save(keyID, *result.Payload.Key)

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
		sdk.phonehomeError(err)
		return nil, err
	}

	if !sdk.isKeyIdDecryptionViable(aad.CryptoKeyID) {
		sdk.phonehomeString("key is no longer viable for decryption")
		return nil, errors.New("ciphertext is no longer viable for decryption")
	}

	key, err := sdk.loadOneKeySymmetricKey(aad.CryptoKeyID)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	pmKey := coreCrypto.NewPeacemakrKeyFromBytes(*cfg, key)
	plaintext, needsVerification, err := coreCrypto.Decrypt(pmKey, ciphertextblob)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	if needsVerification {
		err = sdk.verifyMessage(aad, ciphertextblob, plaintext)
		if err != nil {
			sdk.phonehomeError(err)
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
	if sdk.peacemakrHostname == nil {
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

	// Do not phone home these errors, inf loop.

	if !sdk.persister.Exists("clientId") {
		err := errors.New("client is not registered")
		return "", err
	}

	clientId, err := sdk.persister.Load("clientId")
	if err != nil {
		return "", err
	}

	return clientId, nil
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

//
// SDK impl
//
func (sdk *standardPeacemakrSDK) Register() error {

	if !coreCrypto.PeacemakrInit() {
		err := errors.New("unable to initialize core crypto lib")
		sdk.phonehomeError(err)
		return err
	}

	var pub, priv string

	// If either key is missing, bail.
	if !sdk.persister.Exists("priv") || !sdk.persister.Exists("pub") {

		priv, pub = getNewKey()

		err := sdk.savePrivKey(priv)
		if err != nil {
			err := errors.New("unable to save private key")
			sdk.phonehomeError(err)
			return err
		}

		err = sdk.savePubKey(pub)
		if err != nil {
			err := errors.New("unable to save public key")
			sdk.phonehomeError(err)
			return err
		}
	} else {
		pubLoaded, err := sdk.getPubKey()
		if err != nil {
			return err
		}
		pub = pubLoaded

		privLoaded, err := sdk.getPrivKey()
		if err != nil {
			return err
		}
		priv = privLoaded
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
		keyType := "rsa"
		now := time.Now().Unix()
		params.Client.PublicKey = &models.PublicKey{
			CreationTime: &now,
			Encoding:     &encoding,
			ID:           &tempId,
			Key:          &pub,
			KeyType:      &keyType,
		}

		ok, err := sdkClient.Client.AddClient(params, sdk.authInfo)
		if err != nil {
			sdk.phonehomeError(err)
			return err
		}

		saveErr := sdk.persister.Save("keyId", *ok.Payload.PublicKey.ID)
		if saveErr != nil {
			sdk.phonehomeError(err)
			return saveErr
		}
		saveErr = sdk.persister.Save("clientId", *ok.Payload.ID)
		if saveErr != nil {
			sdk.phonehomeError(err)
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

	return errors.New("Unreachable hit, new unhandled case detected.")
}

func (sdk *standardPeacemakrSDK)  verifyRegistrationAndInit() error {

	err := sdk.errOnNotRegistered()
	if err != nil {
		return err
	}

	// This info only lasts for so long.
	if time.Now().Unix() - sdk.lastUpdatedAt > sdk.secondsTillRefresh {
		clearAllMetadata(sdk)
	}

	err = sdk.populateOrgInfo()
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	if sdk.cryptoConfigId == nil {
		err := errors.New("failed to populate cryptoConfigId for use domain verification")
		sdk.phonehomeError(err)
		return err
	}

	err = sdk.populateUseDomains(*sdk.cryptoConfigId)
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	return nil
}

func clearAllMetadata(sdk *standardPeacemakrSDK) {
	// Clear populateOrgInfo
	sdk.cryptoConfigId = nil
	sdk.orgId = nil
	// Clear populateUseDomains
	sdk.domainSelectorAlg = nil
	sdk.useDomains = nil
	sdk.lastUpdatedAt = 0
}

func (sdk *standardPeacemakrSDK) verifyUserSelectedUseDomain(useDomainName string) error {

	cryptoConfigId, err := sdk.getCryptoConfigIdFromAPIToken()
	if err != nil {
		e := errors.New("failed to get crypt config id from api token")
		sdk.phonehomeError(e)
		return e
	}

	err = sdk.populateUseDomains(cryptoConfigId)
	if err != nil {
		e := errors.New("failed to populate use doamins from crypto config id")
		sdk.phonehomeError(e)
		return e
	}

	for _, domain := range sdk.useDomains {
		if domain.Name == useDomainName {
			return nil
		}
	}

	err = errors.New(fmt.Sprintf("unknown use doamin: %s", useDomainName))
	sdk.phonehomeError(err)
	return err
}

func (sdk *standardPeacemakrSDK) ReleaseMemory() {
	sdk.symKeyCache = map[string][]byte{}
	clearAllMetadata(sdk)
}
