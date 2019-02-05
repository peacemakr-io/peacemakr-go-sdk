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

func (sdk *standardPeacemakrSDK) PreLoad() error {
	err := sdk.verifyRegistrationAndInit()
	if err != nil {
		return err
	}

	// TODO: yea, load all the things.
	panic("no implemented yet")
}

func (sdk *standardPeacemakrSDK) EncryptStr(plaintext string) (string, error) {
	err := sdk.verifyRegistrationAndInit()
	if err != nil {
		return "", err
	}

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
	errStr := debugInfo + " : " + fmt.Sprintf("%e", err)
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

func getBitLenFromRsaPemStr(pubRSA string) (int, error) {
	rsaKey, err := ParseRsaPublicKeyFromPemStr(pubRSA)
	if err != nil {
		return 0, err
	}
	return rsaKey.N.BitLen(), nil
}

func (sdk *standardPeacemakrSDK) verifyMessage(aad *PeacemakrAAD, ciphertext *coreCrypto.CiphertextBlob, plaintext *coreCrypto.Plaintext) error {
	senderRsaPubKey, err := sdk.getPublicKey(aad.SenderKeyID)
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	rsaKeyLen, err := getBitLenFromRsaPemStr(senderRsaPubKey)
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}

	var senderKeyCfg coreCrypto.CryptoConfig
	if rsaKeyLen == 4096 {
		senderKeyCfg = coreCrypto.CryptoConfig{
			Mode:             coreCrypto.ASYMMETRIC,
			SymmetricCipher:  coreCrypto.AES_256_GCM,
			AsymmetricCipher: coreCrypto.RSA_4096,
			DigestAlgorithm:  coreCrypto.SHA3_512,
		}
	} else if rsaKeyLen == 2048 {
		senderKeyCfg = coreCrypto.CryptoConfig{
			Mode:             coreCrypto.ASYMMETRIC,
			SymmetricCipher:  coreCrypto.AES_256_GCM,
			AsymmetricCipher: coreCrypto.RSA_2048,
			DigestAlgorithm:  coreCrypto.SHA3_512,
		}
	}

	senderKey := coreCrypto.NewPeacemakrKeyFromPubPem(senderKeyCfg, []byte(senderRsaPubKey))

	err = coreCrypto.Verify(senderKey, plaintext, ciphertext)
	if err != nil {
		sdk.phonehomeError(err)
		return err
	}
	return nil
}

func (sdk *standardPeacemakrSDK) pickOneKeySymmetricKey(keyId string) ([]byte, error) {
	// If it was already loaded, we're done.
	if sdk.persister.Exists(keyId) {
		key, err := sdk.persister.Load(keyId)
		if err != nil {
			// We failed to load the key, so just load it again from the server.
			sdk.phonehomeError(err)
		} else {
			return []byte(key), nil
		}
	}

	// Else, we just load it from key service.
	clientId, err := sdk.getClientId()
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	params := key_service.NewGetAllEncryptedKeysParams()
	params.EncryptingKeyID = clientId
	params.SymmetricKeyIds = []string{keyId}
	ret, err := sdk.getClient().KeyService.GetAllEncryptedKeys(params, sdk.authInfo)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	privateKey, err := sdk.persister.Load("priv")
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	for _, key := range ret.Payload {

		if key == nil {
			continue
		}

		numKeys := len(key.KeyIds)

		blob, cfg, err := coreCrypto.Deserialize([]byte(*key.PackagedCiphertext))
		if err != nil {
			sdk.phonehomeError(err)
			return nil, err
		}
		decryptKey := coreCrypto.NewPeacemakrKeyFromPrivPem(*cfg, []byte(privateKey))

		// Decrypt the binary ciphertext
		plaintext, needVerify, err := coreCrypto.Decrypt(decryptKey, blob)
		if err != nil {
			sdk.phonehomeError(err)
			return nil, err
		}

		if needVerify {
			aad, err := sdk.getKeyIdFromCiphertext([]byte(*key.PackagedCiphertext))
			if err != nil {
				sdk.phonehomeError(err)
				return nil, err
			}

			err = sdk.verifyMessage(aad, blob, plaintext)
			if err != nil {
				sdk.phonehomeError(err)
				return nil, err
			}
		}

		// Since these are keys, convert the decrypted base64 string into binary.
		keyBytes, err := base64.StdEncoding.DecodeString(string(plaintext.Data))
		if err != nil {
			sdk.phonehomeError(err)
			return nil, err
		}

		keyLen := int(*key.KeyLength)

		// Iterate over the byte array, saving symmetric key we extract in the clear for future use.
		for i := 0; i < numKeys; i++ {

			keyBytes := keyBytes[i*keyLen : (i+1)*keyLen]
			keyBytesId := key.KeyIds[i]

			sdk.persister.Save(keyBytesId, string(keyBytes))
		}
	}

	if !sdk.persister.Exists(keyId) {
		err :=  errors.New("failed to find the key, keyId = " + keyId)
		sdk.phonehomeError(err)
		return nil, err
	}

	foundKey, err := sdk.persister.Load(keyId)
	if err != nil {
		err := errors.New("failed to load a found key, keyId = " + keyId)
		sdk.phonehomeError(err)
		return nil, err
	}

	return []byte(foundKey), nil
}

func (sdk *standardPeacemakrSDK) selectUseDomain(useDomainName *string) (*models.SymmetricKeyUseDomain, error) {
	err := sdk.populateOrgInfo()
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}
	err = sdk.populateUseDomains(*sdk.cryptoConfigId)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	if len(sdk.useDomains) <= 0 {
		err := errors.New("no available useDomains to select")
		sdk.phonehomeError(err)
		return nil, err
	}

	var selectedDomain *models.SymmetricKeyUseDomain

	if useDomainName == nil {
		numSelectedUseDomains := len(sdk.useDomains)
		selectedDomainIdx := rand.Intn(numSelectedUseDomains)
		selectedDomain = sdk.useDomains[selectedDomainIdx]
	} else {

		for _, domain := range sdk.useDomains {

			// Is right? is this really want we want?
			if domain.Name == *useDomainName {
				return domain, nil
			}

		}

		// Else just fall back on a well known domain.

		numSelectedUseDomains := len(sdk.useDomains)
		selectedDomainIdx := rand.Intn(numSelectedUseDomains)
		selectedDomain = sdk.useDomains[selectedDomainIdx]
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

	if *selectedDomain.SymmetricKeyEncryptionAlg == "AESGCM" {
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

func (sdk *standardPeacemakrSDK) encrypt(plaintext []byte, useDomainName *string) ([]byte, error) {

	keyId, cfg, err := sdk.selectEncryptionKey(useDomainName)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	key, err := sdk.pickOneKeySymmetricKey(keyId)
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

	myKeyStr, err := sdk.persister.Load("priv")
	// TODO: this is wrong, fix it.
	var myKeyCfg coreCrypto.CryptoConfig
	if RSAKEYLENGTH == 4096 {
		myKeyCfg = coreCrypto.CryptoConfig{
			Mode:             coreCrypto.ASYMMETRIC,
			SymmetricCipher:  coreCrypto.AES_256_GCM,
			AsymmetricCipher: coreCrypto.RSA_4096,
			DigestAlgorithm:  coreCrypto.SHA3_512,
		}
	} else if RSAKEYLENGTH == 2048 {
		myKeyCfg = coreCrypto.CryptoConfig{
			Mode:             coreCrypto.ASYMMETRIC,
			SymmetricCipher:  coreCrypto.AES_256_GCM,
			AsymmetricCipher: coreCrypto.RSA_2048,
			DigestAlgorithm:  coreCrypto.SHA3_512,
		}
	}

	myKey := coreCrypto.NewPeacemakrKeyFromPrivPem(myKeyCfg, []byte(myKeyStr))

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
	err := sdk.verifyRegistrationAndInit()
	if err != nil {
		return "", err
	}

	plain, err := sdk.Decrypt([]byte(ciphertext))
	if err != nil {
		sdk.phonehomeError(err)
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

	aad, err := sdk.getKeyIdFromCiphertext(ciphertext)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	key, err := sdk.pickOneKeySymmetricKey(aad.CryptoKeyID)
	if err != nil {
		sdk.phonehomeError(err)
		return nil, err
	}

	ciphertextblob, cfg, err := coreCrypto.Deserialize(ciphertext)
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

		err := sdk.persister.Save("priv", priv)
		if err != nil {
			err := errors.New("unable to save private key")
			sdk.phonehomeError(err)
			return err
		}

		err = sdk.persister.Save("pub", pub)
		if err != nil {
			err := errors.New("unable to save public key")
			sdk.phonehomeError(err)
			return err
		}
	} else {
		pubLoaded, err := sdk.persister.Load("pub")
		if err != nil {
			return err
		}
		pub = pubLoaded

		privLoaded, err := sdk.persister.Load("priv")
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
		// Clear populateOrgInfo
		sdk.cryptoConfigId = nil
		sdk.orgId = nil

		// Clear populateUseDomains
		sdk.domainSelectorAlg = nil
		sdk.useDomains = nil
		sdk.lastUpdatedAt = 0
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
