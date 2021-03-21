package peacemakr_go_sdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-openapi/runtime"
	auth2 "github.com/peacemakr-io/peacemakr-go-sdk/pkg/auth"
	coreCrypto "github.com/peacemakr-io/peacemakr-go-sdk/pkg/crypto"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/client"
	clientReq "github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/client/client"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/client/crypto_config"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/client/key_service"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/client/org"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/client/server_management"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/generated/models"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/utils"
	"math/rand"
	goRt "runtime"
	"strconv"
	"time"
)

type sdkPersister struct {
	prefix    string
	persister utils.Persister
}

func (p *sdkPersister) valid() bool {
	return p.persister != nil
}

func (p *sdkPersister) getPublicKey() (string, error) {
	return p.persister.Load(p.prefix + "io.peacemakr.pub")
}

func (p *sdkPersister) setPublicKey(pem string) error {
	return p.persister.Save(p.prefix+"io.peacemakr.pub", pem)
}

func (p *sdkPersister) getPrivateKey() (string, error) {
	return p.persister.Load(p.prefix + "io.peacemakr.priv")
}

func (p *sdkPersister) setPrivateKey(pem string) error {
	return p.persister.Save(p.prefix+"io.peacemakr.priv", pem)
}

func (p *sdkPersister) getKeyCreationTime() (time.Time, error) {
	t, err := p.persister.Load(p.prefix + "io.peacemakr.key_creation_time")
	if err != nil {
		return time.Now(), err
	}

	parsed, err := strconv.ParseInt(t, 16, 64)
	if err != nil {
		return time.Now(), err
	}

	return time.Unix(parsed, 0), nil
}

func (p *sdkPersister) setKeyCreationTime(time time.Time) error {
	return p.persister.Save(p.prefix+"io.peacemakr.key_creation_time", strconv.FormatInt(time.Unix(), 16))
}

func (p *sdkPersister) getPublicKeyID() (string, error) {
	return p.persister.Load(p.prefix + "io.peacemakr.keyId")
}

func (p *sdkPersister) setPublicKeyID(id string) error {
	return p.persister.Save(p.prefix+"io.peacemakr.keyId", id)
}

func (p *sdkPersister) getClientID() (string, error) {
	return p.persister.Load(p.prefix + "io.peacemakr.clientId")
}

func (p *sdkPersister) setClientID(id string) error {
	return p.persister.Save(p.prefix+"io.peacemakr.clientId", id)
}

func (p *sdkPersister) getOrg() (*models.Organization, error) {
	str, err := p.persister.Load(p.prefix + "io.peacemakr.org")
	if err != nil {
		return nil, err
	}

	buffer := bytes.NewBufferString(str)
	decoder := json.NewDecoder(buffer)
	var o models.Organization
	err = decoder.Decode(&o)
	if err != nil {
		return nil, err
	}

	return &o, nil
}

func (p *sdkPersister) setOrg(org *models.Organization) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	err := encoder.Encode(*org)
	if err != nil {
		return err
	}

	return p.persister.Save(p.prefix+"io.peacemakr.org", buffer.String())
}

func (p *sdkPersister) clearOrg() error {
	return p.persister.Save(p.prefix+"io.peacemakr.org", "")
}

func (p *sdkPersister) getCryptoConfig() (*models.CryptoConfig, error) {
	str, err := p.persister.Load(p.prefix + "io.peacemakr.crypto_config")
	if err != nil {
		return nil, err
	}

	buffer := bytes.NewBufferString(str)
	decoder := json.NewDecoder(buffer)
	var cc models.CryptoConfig
	err = decoder.Decode(&cc)
	if err != nil {
		return nil, err
	}

	return &cc, nil
}

func (p *sdkPersister) setCryptoConfig(cc *models.CryptoConfig) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	err := encoder.Encode(*cc)
	if err != nil {
		return err
	}

	return p.persister.Save(p.prefix+"io.peacemakr.crypto_config", buffer.String())
}

func (p *sdkPersister) clearCryptoConfig() error {
	return p.persister.Save(p.prefix+"io.peacemakr.crypto_config", "")
}

func (p *sdkPersister) hasRegistrationObjects() bool {
	return p.persister.Exists(p.prefix+"io.peacemakr.priv") &&
		p.persister.Exists(p.prefix+"io.peacemakr.pub") &&
		p.persister.Exists(p.prefix+"io.peacemakr.keyId") &&
		p.persister.Exists(p.prefix+"io.peacemakr.clientId") &&
		p.persister.Exists(p.prefix+"io.peacemakr.last_updated") &&
		p.persister.Exists(p.prefix+"io.peacemakr.org") &&
		p.persister.Exists(p.prefix+"io.peacemakr.crypto_config")
}

func (p *sdkPersister) hasAsymmetricKeys() bool {
	return p.persister.Exists(p.prefix+"io.peacemakr.priv") &&
		p.persister.Exists(p.prefix+"io.peacemakr.pub")
}

func (p *sdkPersister) hasKey(id string) bool {
	return p.persister.Exists(fmt.Sprintf("%sio.peacemakr.symmetric.%s", p.prefix, id))
}

func (p *sdkPersister) getKey(id string) (string, error) {
	return p.persister.Load(fmt.Sprintf("%sio.peacemakr.symmetric.%s", p.prefix, id))
}

func (p *sdkPersister) setKey(id string, key string) error {
	return p.persister.Save(fmt.Sprintf("%sio.peacemakr.symmetric.%s", p.prefix, id), key)
}

func (p *sdkPersister) hasAsymmetricKey(id string) bool {
	return p.persister.Exists(fmt.Sprintf("%sio.peacemakr.asymmetric.%s", p.prefix, id))
}

func (p *sdkPersister) getAsymmetricKey(id string) (string, error) {
	return p.persister.Load(fmt.Sprintf("%sio.peacemakr.asymmetric.%s", p.prefix, id))
}

func (p *sdkPersister) setAsymmetricKey(id string, key string) error {
	return p.persister.Save(fmt.Sprintf("%sio.peacemakr.asymmetric.%s", p.prefix, id), key)
}

func (p *sdkPersister) getLastUpdated() (time.Time, error) {
	t, err := p.persister.Load(p.prefix + "io.peacemakr.last_updated")
	if err != nil {
		return time.Now(), err
	}

	parsed, err := strconv.ParseInt(t, 16, 64)
	if err != nil {
		return time.Now(), err
	}

	return time.Unix(parsed, 0), nil
}

func (p *sdkPersister) setLastUpdated(time time.Time) error {
	return p.persister.Save(p.prefix+"io.peacemakr.last_updated", strconv.FormatInt(time.Unix(), 16))
}

func (p *sdkPersister) clearLastUpdated() error {
	return p.persister.Save(p.prefix+"io.peacemakr.last_updated", "")
}

type standardPeacemakrSDK struct {
	clientName        string
	auth              auth2.Authenticator
	org               *models.Organization
	cryptoConfig      *models.CryptoConfig
	authInfo          runtime.ClientAuthInfoWriter
	version           string
	peacemakrHostname string
	peacemakrScheme   string
	persister         sdkPersister
	isRegisteredCache bool
	lastUpdatedAt     time.Time
	timeTillRefresh   time.Duration
	symKeyCache       map[string][]byte
	sysLog            SDKLogger
}

// Named constants, so we can change them everywhere at the same time

const (
	Chacha20Poly1305 = "Peacemakr.Symmetric.CHACHA20_POLY1305"
	Aes128gcm        = "Peacemakr.Symmetric.AES_128_GCM"
	Aes192gcm        = "Peacemakr.Symmetric.AES_192_GCM"
	Aes256gcm        = "Peacemakr.Symmetric.AES_256_GCM"

	Sha224 = "Peacemakr.Digest.SHA_224"
	Sha256 = "Peacemakr.Digest.SHA_256"
	Sha384 = "Peacemakr.Digest.SHA_384"
	Sha512 = "Peacemakr.Digest.SHA_512"
)

func (sdk *standardPeacemakrSDK) getDebugInfo() string {

	//
	// DO NOT USE GET'S HERE (inf recursive loop)
	//
	clientId := "(unknown clientId)"
	if sdk.persister.valid() {
		id, err := sdk.persister.getClientID()
		if err != nil {
			clientId = "(unknown clientId, persister read failed)"
		} else {
			clientId = id
		}
	}

	//
	// DO NOT USE GET'S HERE (inf recursive loop)
	//
	orgId := "(unknown org)"
	if sdk.org != nil && sdk.org.ID != nil {
		orgId = *sdk.org.ID
	}

	return "ClientDebugInfo *** clientId = " + clientId + ", clientName = " + sdk.clientName + ", org id = " + orgId + ", version = " + sdk.version
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
	preferredPublicKeyId, err := sdk.persister.getPublicKeyID()
	if err != nil {
		sdk.logError(err)
		return err
	}

	params := key_service.NewGetAllEncryptedKeysParams()
	params.EncryptingKeyID = preferredPublicKeyId
	params.SymmetricKeyIds = keyIds
	ret, err := sdk.getClient().KeyService.GetAllEncryptedKeys(params, sdk.authInfo)
	if err != nil {
		sdk.logError(err)
		return err
	}

	privateKeyStr, err := sdk.persister.getPrivateKey()
	pubKeyStr, err := sdk.persister.getPublicKey()
	if err != nil {
		sdk.logError(err)
		return err
	}

	// Construct the key objects
	privateKey, err := coreCrypto.NewPrivateKeyFromPEM(coreCrypto.CHACHA20_POLY1305, privateKeyStr)
	if err != nil {
		sdk.logError(err)
		return err
	}

	if len(ret.Payload) == 0 && len(keyIds) != 0 {
		return errors.New("unable to get any of the requested keys from the server")
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
		if isRSA(pubKeyStr) {
			decryptionDeliveredKey = privateKey
			// We're in a loop, so it's destroyed after last use.
		} else if isEC(pubKeyStr) {
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

			// Derive the shared symmetric secret between this client at the key deriver. This was used to encrypt
			// the bundle of delivered keys.
			// TODO: make this lighting wicked fast, by caching and lookup up this instead of computing it.
			decryptionDeliveredKey = privateKey.ECDHKeygen(kdKeyConfig.SymmetricCipher, kdPeacemakrKey)
			kdPeacemakrKey.Destroy()
		} else {
			// TODO: should we de-register client and re-register a new key?
			err = errors.New("unknown key type detected, can not decrypt incoming keys")
			sdk.logError(err)
			return err
		}

		// Decrypt the binary ciphertext
		plaintext, needVerify, err := coreCrypto.Decrypt(decryptionDeliveredKey, blob)
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

			if err := sdk.persister.setKey(keyBytesId, string(keyBytes)); err != nil {
				return err
			}

		}
	}

	privateKey.Destroy()

	return nil
}

func (sdk *standardPeacemakrSDK) preloadAll(keyIds []string) error {
	return sdk.downloadAndSaveAllKeys(keyIds)
}

func (sdk *standardPeacemakrSDK) Sync() error {
	if sdk.auth == nil {
		sdk.logString("No sync occurred because there is no API key")
		return nil
	}

	err := sdk.verifyRegistrationAndInit()
	if err != nil {
		return err
	}

	return sdk.preloadAll(nil)
}

func (sdk *standardPeacemakrSDK) logString(s string) {
	_, file, line, _ := goRt.Caller(1)
	debugInfo := sdk.getDebugInfo()
	sdk.sysLog.Printf("[%s: %d] %s : %s", file, line, debugInfo, s)
}

func (sdk *standardPeacemakrSDK) logError(err error) {
	_, file, line, _ := goRt.Caller(1)
	debugInfo := sdk.getDebugInfo()
	sdk.sysLog.Printf("[%s: %d] %s : %v", file, line, debugInfo, err)
}

func (sdk *standardPeacemakrSDK) canReachCloud() bool {
	_, err := sdk.getClient().ServerManagement.GetHealth(server_management.NewGetHealthParams())
	if err != nil {
		sdk.logError(err)
		return false
	}

	return true
}

func (sdk *standardPeacemakrSDK) isLocalStateValid() bool {
	// Pull in the last updated time
	var err error
	sdk.lastUpdatedAt, err = sdk.persister.getLastUpdated()
	if err != nil {
		sdk.logError(err)
		return false
	}

	// If we can't reach the cloud, assume the local state is valid
	if !sdk.canReachCloud() {
		return true
	}

	return time.Now().Sub(sdk.lastUpdatedAt) < sdk.timeTillRefresh
}

func (sdk *standardPeacemakrSDK) populateOrg() error {
	sdkClient := sdk.getClient()

	// Early exit if we've done this already and it's not time to refresh
	if sdk.org != nil && sdk.isLocalStateValid() {
		return nil
	}

	if sdk.persister.hasRegistrationObjects() && sdk.isLocalStateValid() {
		// Get the org from the persister
		var err error
		sdk.org, err = sdk.persister.getOrg()
		if err != nil {
			return err
		}
		return nil
	}

	params := org.NewGetOrganizationFromAPIKeyParams()
	token, err := sdk.auth.GetAuthToken()
	if err != nil {
		return err
	}

	params.Apikey = token

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
	err = sdk.persister.setOrg(sdk.org)
	if err != nil {
		sdk.logError(err)
		return err
	}

	return nil
}

func (sdk *standardPeacemakrSDK) getCryptoConfigIdFromOrgInfo() (string, error) {

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

	if sdk.persister.hasRegistrationObjects() && sdk.isLocalStateValid() {
		// Get the crypto config from the persister
		var err error
		sdk.cryptoConfig, err = sdk.persister.getCryptoConfig()
		if err != nil {
			return err
		}
		return nil
	}

	pmClient := sdk.getClient()

	var err error

	params := crypto_config.NewGetCryptoConfigParams()
	params.CryptoConfigID, err = sdk.getCryptoConfigIdFromOrgInfo()
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
	sdk.lastUpdatedAt = time.Now()
	// If there was an issue writing the time, just log it and move on, it's not a critical failure.
	if err := sdk.persister.setLastUpdated(sdk.lastUpdatedAt); err != nil {
		sdk.logError(err)
	}

	if *sdk.cryptoConfig.ClientKeyTTL == 0 {
		oneYear, err := time.ParseDuration("8760h")
		if err != nil {
			return err
		}

		oneYearInSec := int64(oneYear.Seconds())
		sdk.cryptoConfig.ClientKeyTTL = &oneYearInSec
	}

	err = sdk.persister.setCryptoConfig(sdk.cryptoConfig)
	if err != nil {
		sdk.logError(err)
		return err
	}

	return nil
}

func (sdk *standardPeacemakrSDK) verifyMessage(aad *PeacemakrAAD, cfg coreCrypto.CryptoConfig, ciphertext *coreCrypto.CiphertextBlob, plaintext *coreCrypto.Plaintext) error {
	if sdk.auth == nil {
		sdk.logString("No verification occurred because there is no API key")
		return nil
	}

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
	if keyId == "local-only-test-key" {
		keyToReturn := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
		sdk.logString(fmt.Sprintf("The key being returned is: %v DO NOT USE IN PRODUCTION", keyToReturn))
		return keyToReturn, nil
	}

	if val, ok := sdk.symKeyCache[keyId]; ok {
		return val, nil
	}

	// If it was already loaded, we're done.
	if sdk.persister.hasKey(keyId) {
		key, err := sdk.persister.getKey(keyId)
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

	if !sdk.persister.hasKey(keyId) {
		err := errors.New("failed to find the key, keyId = " + keyId)
		sdk.logError(err)
		return nil, err
	}

	// Return it.
	foundKey, err := sdk.persister.getKey(keyId)
	if err != nil {
		err := errors.New("failed to load a found key, keyId = " + keyId)
		sdk.logError(err)
		return nil, err
	}

	// Hot cache.
	sdk.symKeyCache[keyId] = []byte(foundKey)
	return []byte(foundKey), nil
}

func isUseDomainEncryptionViable(useDomain *models.SymmetricKeyUseDomain, myOrg string) bool {
	// If myOrg is specified, then it has to match the useDomain's owner ID. Otherwise, it doesn't have to match
	return useDomain.SymmetricKeyEncryptionAllowed && (*useDomain.OwnerOrgID == myOrg || myOrg == "")
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
	if keyId == "local-only-test-key" {
		return true
	}

	viableDecryptionDomains := sdk.findViableDecryptionUseDomains()
	for _, domain := range viableDecryptionDomains {
		if contains(domain.EncryptionKeyIds, keyId) {
			return true
		}
	}
	return false
}

func isUseDomainDecryptionViable(useDomain *models.SymmetricKeyUseDomain) bool {
	return useDomain.SymmetricKeyDecryptionAllowed
}

func (sdk *standardPeacemakrSDK) findViableDecryptionUseDomains() []*models.SymmetricKeyUseDomain {
	var availableDomains []*models.SymmetricKeyUseDomain
	for _, useDomain := range sdk.cryptoConfig.SymmetricKeyUseDomains {
		if isUseDomainDecryptionViable(useDomain) {
			availableDomains = append(availableDomains, useDomain)
		}
	}
	return availableDomains
}

func findViableEncryptionUseDomains(useDomains []*models.SymmetricKeyUseDomain, myOrg string) []*models.SymmetricKeyUseDomain {
	var availableDomain []*models.SymmetricKeyUseDomain

	for _, useDomain := range useDomains {
		if isUseDomainEncryptionViable(useDomain, myOrg) {
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
		// Only select a use domain that belongs to the client's encompassing org
		viableUseDomain := findViableEncryptionUseDomains(sdk.cryptoConfig.SymmetricKeyUseDomains, *sdk.cryptoConfig.OwnerOrgID)
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
			if domain.Name == *useDomainName && isUseDomainEncryptionViable(domain, "") {
				return domain, nil
			}
		}

		return nil, errors.New(fmt.Sprintf("useDomainName %s is not viable for encryption", *useDomainName))
	}

	return selectedDomain, nil
}

func (sdk *standardPeacemakrSDK) selectEncryptionKey(useDomainName *string) (string, *coreCrypto.CryptoConfig, error) {

	if sdk.auth == nil {
		sdk.logString("Returning local-only test key because there is no API key")
		return "local-only-test-key", &coreCrypto.CryptoConfig{
			Mode:             coreCrypto.SYMMETRIC,
			SymmetricCipher:  coreCrypto.CHACHA20_POLY1305,
			AsymmetricCipher: coreCrypto.ASYMMETRIC_UNSPECIFIED,
			DigestAlgorithm:  coreCrypto.SHA_256,
		}, nil
	}

	// Select a use domain.
	selectedDomain, err := sdk.selectUseDomain(useDomainName)
	if err != nil {
		return "", nil, err
	}

	// Select a key in the use domain.
	numPossibleKeys := len(selectedDomain.EncryptionKeyIds)
	selectedKeyIdx := rand.Intn(numPossibleKeys)
	keyId := selectedDomain.EncryptionKeyIds[selectedKeyIdx]

	if !sdk.persister.hasKey(keyId) {
		if err := sdk.downloadAndSaveAllKeys([]string{keyId}); err != nil {
			return "", nil, err
		}
	}

	// Setup the crypto config for the encryption.
	mode := coreCrypto.SYMMETRIC
	asymmetricCipher := coreCrypto.ASYMMETRIC_UNSPECIFIED

	if selectedDomain.DigestAlgorithm == nil {
		defaultDigest := Sha256
		selectedDomain.DigestAlgorithm = &defaultDigest
	}

	var digestAlgorithm coreCrypto.MessageDigestAlgorithm
	switch *selectedDomain.DigestAlgorithm {
	case Sha224:
		digestAlgorithm = coreCrypto.SHA_224
	case Sha256:
		digestAlgorithm = coreCrypto.SHA_256
	case Sha384:
		digestAlgorithm = coreCrypto.SHA_384
	case Sha512:
		digestAlgorithm = coreCrypto.SHA_512
	default:
		digestAlgorithm = coreCrypto.SHA_256
	}

	if selectedDomain.SymmetricKeyEncryptionAlg == nil {
		defaultAlg := Chacha20Poly1305
		selectedDomain.SymmetricKeyEncryptionAlg = &defaultAlg
	}

	var symmetricCipher coreCrypto.SymmetricCipher
	switch *selectedDomain.SymmetricKeyEncryptionAlg {
	case Aes128gcm:
		symmetricCipher = coreCrypto.AES_128_GCM
	case Aes192gcm:
		symmetricCipher = coreCrypto.AES_192_GCM
	case Aes256gcm:
		symmetricCipher = coreCrypto.AES_256_GCM
	case Chacha20Poly1305:
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

	// The encryption of nothing is nothing.
	if len(plaintext) == 0 {
		return plaintext, nil
	}

	pmKey := coreCrypto.NewPeacemakrKeyFromBytes(cfg.SymmetricCipher, key)
	defer pmKey.Destroy()
	myKeyId, err := sdk.persister.getPublicKeyID()
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

	myPrivKeyStr, err := sdk.persister.getPrivateKey()
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
	if sdk.auth != nil {
		err := sdk.verifyRegistrationAndInit()
		if err != nil {
			return nil, err
		}
	}

	return sdk.encrypt(plaintext, nil)
}

func (sdk *standardPeacemakrSDK) EncryptInDomain(plaintext []byte, useDomainName string) ([]byte, error) {
	if sdk.auth != nil {
		err := sdk.verifyRegistrationAndInit()
		if err != nil {
			return nil, err
		}

		err = sdk.verifyUserSelectedUseDomain(useDomainName)
		if err != nil {
			return nil, err
		}
	}

	return sdk.encrypt(plaintext, &useDomainName)
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

	if sdk.persister.hasAsymmetricKey(keyID) {
		key, err := sdk.persister.getAsymmetricKey(keyID)
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

	if err := sdk.persister.setAsymmetricKey(keyID, *result.Payload.Key); err != nil {
		sdk.logError(err)
		return "", err
	}

	return *result.Payload.Key, nil
}

func (sdk *standardPeacemakrSDK) Decrypt(ciphertext []byte) ([]byte, error) {
	if sdk.auth != nil {
		err := sdk.verifyRegistrationAndInit()
		if err != nil {
			return nil, err
		}
	}

	// Decryption of nothing is nothing.
	if len(ciphertext) == 0 {
		return ciphertext, nil
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

func (sdk *standardPeacemakrSDK) SignOnly(message []byte) ([]byte, error) {

	if sdk.auth != nil {
		err := sdk.verifyRegistrationAndInit()
		if err != nil {
			return nil, err
		}
	}

	if len(message) == 0 {
		err := errors.New("expect non-empty input message")
		sdk.logError(err)
		return nil, err
	}

	// obtain pubKeyId used for verifying
	pubKeyId, err := sdk.persister.getPublicKeyID()
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	// Construct aad
	aad := PeacemakrAAD{
		CryptoKeyID: "",
		SenderKeyID: pubKeyId,
	}

	aadStr, err := json.Marshal(aad)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	plaintext := coreCrypto.Plaintext{
		Data: message,
		Aad:  aadStr,
	}

	blob, err := coreCrypto.GetPlaintextBlob(plaintext)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	myPrivKeyStr, err := sdk.persister.getPrivateKey()

	key, err := coreCrypto.NewPrivateKeyFromPEM(coreCrypto.CHACHA20_POLY1305, myPrivKeyStr)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	defer key.Destroy()

	// Sign the plaintext using key with SHA_256. Store the result in blob
	err = coreCrypto.Sign(key, plaintext, coreCrypto.SHA_256, blob)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	return coreCrypto.Serialize(coreCrypto.SHA_256, blob)
}

func (sdk *standardPeacemakrSDK) VerifyOnly(signedBlob []byte) ([]byte, error) {

	if sdk.auth != nil {
		err := sdk.verifyRegistrationAndInit()
		if err != nil {
			return nil, err
		}
	}

	if len(signedBlob) == 0 {
		err := errors.New("expect non-empty input blob")
		sdk.logError(err)
		return nil, err
	}

	// obtain aad from signedBlob
	aad, err := sdk.getKeyIdFromCiphertext(signedBlob)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	// obtain cipherTextBlob, cipherTextConfig(ignored)
	blob, _, err := coreCrypto.Deserialize(signedBlob)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	// Verify
	plaintext, err := coreCrypto.ExtractPlaintextFromBlob(blob)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	senderKeyStr, err := sdk.getPublicKey(aad.SenderKeyID)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	senderKey, err := coreCrypto.NewPublicKeyFromPEM(coreCrypto.CHACHA20_POLY1305, senderKeyStr)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	defer senderKey.Destroy()

	err = coreCrypto.Verify(senderKey, &plaintext, blob)
	if err != nil {
		sdk.logError(err)
		return nil, err
	}

	return plaintext.Data, nil
}

func (sdk *standardPeacemakrSDK) IsPeacemakrCiphertext(ciphertext []byte) bool {
	_, _, err := coreCrypto.Deserialize(ciphertext)
	return err == nil
}

var sdkClient *client.PeacemakrClient

func (sdk *standardPeacemakrSDK) getClient() *client.PeacemakrClient {

	if sdkClient != nil {
		return sdkClient
	}

	hostname := sdk.peacemakrHostname
	scheme := sdk.peacemakrScheme

	cfg := client.TransportConfig{
		Host:     hostname,
		BasePath: client.DefaultBasePath,
		Schemes:  []string{scheme},
	}

	sdkClient = client.NewHTTPClientWithConfig(nil, &cfg)
	return sdkClient
}

func (sdk *standardPeacemakrSDK) updatePreferredPubKeyId(newKeyID string) error {
	err := sdk.persister.setPublicKeyID(newKeyID)
	if err != nil {
		return err
	}
	return nil
}

func (sdk *standardPeacemakrSDK) errOnNotRegistered() error {

	if sdk.isRegisteredCache == true {
		return nil
	}

	sdk.isRegisteredCache = sdk.persister.hasRegistrationObjects()

	if sdk.isRegisteredCache == false {
		return errors.New("client not registered")
	}

	return nil
}

func (sdk *standardPeacemakrSDK) generateKeys() (string, string, string, error) {
	pub, priv, keyTy := GetNewKey(*sdk.cryptoConfig.ClientKeyType, int(*sdk.cryptoConfig.ClientKeyBitlength))

	err := sdk.persister.setPrivateKey(priv)
	if err != nil {
		err := errors.New("unable to save private key")
		sdk.logError(err)
		return "", "", "", err
	}

	err = sdk.persister.setPublicKey(pub)
	if err != nil {
		err := errors.New("unable to save public key")
		sdk.logError(err)
		return "", "", "", err
	}

	if err := sdk.persister.setKeyCreationTime(time.Now()); err != nil {
		return "", "", "", err
	}

	return pub, priv, keyTy, nil
}

func (sdk *standardPeacemakrSDK) createUseDomain(numKeys int, name string) error {
	sdkClient := sdk.getClient()

	t := time.Now().Unix()

	var keyIds []string
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
	alg := Chacha20Poly1305
	digestAlg := Sha256
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
		SymmetricKeyDecryptionAllowed:       true,
		SymmetricKeyDerivationServiceID:     &emptyString, // Empty string, means the server randomly picks.
		SymmetricKeyEncryptionAlg:           &alg,
		SymmetricKeyEncryptionUseTTL:        &twentyYears,
		SymmetricKeyEncryptionAllowed:       true,
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

	if sdk.auth == nil {
		sdk.logString("Using local-only test settings for client because there is no API key")
		sdk.persister.prefix = "local-only."
		if err := sdk.persister.setPublicKeyID("my-public-key-id"); err != nil {
			return err
		}

		if err := sdk.persister.setClientID("my-client-id"); err != nil {
			return err
		}

		bitLen := int64(256)
		oneYear, err := time.ParseDuration("8760h")
		if err != nil {
			return err
		}

		oneYearInSec := oneYear.Nanoseconds() / 1e9
		keyType := "ec"
		id := "my-crypto-config-id"
		orgId := "my-org-id"

		sdk.cryptoConfig = &models.CryptoConfig{
			ClientKeyBitlength:                  &bitLen,
			ClientKeyTTL:                        &oneYearInSec,
			ClientKeyType:                       &keyType,
			ID:                                  &id,
			OwnerOrgID:                          &orgId,
			SymmetricKeyUseDomainSelectorScheme: nil,
			SymmetricKeyUseDomains:              nil,
		}

		_, _, _, err = sdk.generateKeys()
		if err != nil {
			return err
		}

		return nil
	}

	err := sdk.init()
	if err != nil {
		sdk.logError(err)
		return err
	}

	var pub, keyTy string

	// If either key is missing, bail.
	if !sdk.persister.hasAsymmetricKeys() {
		pub, _, keyTy, err = sdk.generateKeys()
		if err != nil {
			return err
		}
	} else {
		pubLoaded, err := sdk.persister.getPublicKey()
		if err != nil {
			sdk.logError(err)
			return err
		}
		pub = pubLoaded

		_, err = sdk.persister.getPrivateKey()
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

	//
	// Register as a new client.
	//
	if !sdk.persister.hasRegistrationObjects() {
		params := clientReq.NewAddClientParams()
		params.Client = &models.Client{}
		tempId := ""
		params.Client.ID = &tempId
		params.Client.Sdk = sdk.version
		encoding := "pem"
		keyCreationTime, err := sdk.persister.getKeyCreationTime()
		if err != nil {
			sdk.logError(err)
			return err
		}

		keyCreationUnix := keyCreationTime.Unix()

		params.Client.PublicKeys = []*models.PublicKey{{
			CreationTime: &keyCreationUnix,
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

		idxOfPreferredPublicKey := 0
		for idx, pubKey := range ok.Payload.PublicKeys {
			if *pubKey.ID == ok.Payload.PreferredPublicKeyID {
				idxOfPreferredPublicKey = idx
			}
		}

		// We only sent up one public key, but just in case the server has some other state we use the last one
		saveErr := sdk.updatePreferredPubKeyId(*ok.Payload.PublicKeys[idxOfPreferredPublicKey].ID)
		if saveErr != nil {
			sdk.logError(err)
			return saveErr
		}
		saveErr = sdk.persister.setClientID(*ok.Payload.ID)
		if saveErr != nil {
			sdk.logError(err)
			return saveErr
		}

		return nil
	}

	//
	// Already loaded info from previously registered client.
	//
	if sdk.persister.hasRegistrationObjects() {
		// if it exists, verify we can read it.
		_, err := sdk.persister.getClientID()
		if err != nil {
			return err
		}

		_, err = sdk.persister.getPublicKeyID()
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

	sdk.lastUpdatedAt = time.Now()
	err = sdk.persister.setLastUpdated(sdk.lastUpdatedAt)
	if err != nil {
		sdk.logError(err)
		return err
	}

	return nil
}

func (sdk *standardPeacemakrSDK) getCryptoConfigCipher() (coreCrypto.AsymmetricCipher, error) {
	var cryptoConfigCipher coreCrypto.AsymmetricCipher

	if sdk.cryptoConfig == nil {
		err := sdk.populateCryptoConfig()
		if err != nil {
			sdk.logError(err)
			return coreCrypto.ASYMMETRIC_UNSPECIFIED, err
		}
	}

	if sdk.cryptoConfig.ClientKeyType == nil {
		return coreCrypto.ASYMMETRIC_UNSPECIFIED, errors.New("missing clientKeyType")
	}

	switch *sdk.cryptoConfig.ClientKeyType {
	case "ec":
		switch *sdk.cryptoConfig.ClientKeyBitlength {
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
		switch *sdk.cryptoConfig.ClientKeyBitlength {
		case 2048:
			cryptoConfigCipher = coreCrypto.RSA_2048
		case 4096:
			cryptoConfigCipher = coreCrypto.RSA_4096
		default:
			cryptoConfigCipher = coreCrypto.ASYMMETRIC_UNSPECIFIED
		}
	default:
		// If they haven't specified anything for the client asymmetric keys, use ECDH_256
		defaultKeyType := "ec"
		defaultBitLength := int64(521)
		sdk.cryptoConfig.ClientKeyType = &defaultKeyType
		sdk.cryptoConfig.ClientKeyBitlength = &defaultBitLength

		cryptoConfigCipher = coreCrypto.ECDH_P256
	}

	return cryptoConfigCipher, nil
}

func (sdk *standardPeacemakrSDK) asymKeysAreStale() bool {
	keyCreationTime, err := sdk.persister.getKeyCreationTime()
	if err != nil {
		sdk.logError(err)
		// Default to the keys not being stale
		return false
	}

	return time.Now().Sub(keyCreationTime) > time.Second*time.Duration(*sdk.cryptoConfig.ClientKeyTTL)
}

func (sdk *standardPeacemakrSDK) rotateClientKeyIfNeeded() error {
	pubKey, err := sdk.persister.getPublicKey()
	if err != nil {
		return err
	}

	currentCipher, err := coreCrypto.GetConfigFromPubKey(pubKey)
	if err != nil {
		return err
	}

	cryptoConfigCipher, err := sdk.getCryptoConfigCipher()
	if err != nil {
		sdk.logError(err)
		return err
	}

	// Rotate if the key has expired OR if the cipher changed
	shouldRotate := sdk.asymKeysAreStale() || (cryptoConfigCipher != currentCipher)

	if !shouldRotate {
		return nil
	}

	if sdk.asymKeysAreStale() {
		sdk.logString("Rotating expired client keypair")
	}

	if cryptoConfigCipher != currentCipher {
		sdk.logString(fmt.Sprintf("Rotating key because asymmetric key config changed from %v to %v", currentCipher, cryptoConfigCipher))
	}

	// Save the previous stuff in case we have to roll back the change
	prevPub := pubKey
	prevPriv, err := sdk.persister.getPrivateKey()
	if err != nil {
		return err
	}

	prevCreatedAt, err := sdk.persister.getKeyCreationTime()
	if err != nil {
		return err
	}

	// Use this function to roll back in case of error
	rollback := func(outerErr error) error {
		if err := sdk.persister.setPublicKey(prevPub); err != nil {
			return errors.New(fmt.Sprintf("In recovering from %v, while saving pub key, error %v ocurred", outerErr, err))
		}
		if err := sdk.persister.setPrivateKey(prevPriv); err != nil {
			return errors.New(fmt.Sprintf("In recovering from %v, while saving priv key, error %v ocurred", outerErr, err))
		}

		if err := sdk.persister.setKeyCreationTime(prevCreatedAt); err != nil {
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
	clientID, err := sdk.persister.getClientID()
	if err != nil {
		return rollback(err)
	}

	pemStr := "pem"

	keyID, err := sdk.persister.getPublicKeyID()
	if err != nil {
		return rollback(err)
	}

	keyCreationTime, err := sdk.persister.getKeyCreationTime()
	if err != nil {
		return rollback(err)
	}

	newKeyTime := keyCreationTime.Unix()

	updateKeyParams := clientReq.NewAddClientPublicKeyParams()
	updateKeyParams.ClientID = clientID
	updateKeyParams.NewPublicKey = &models.PublicKey{
		CreationTime: &newKeyTime,
		Encoding:     &pemStr,
		ID:           &keyID,
		Key:          &pub,
		KeyType:      &keyTy,
	}

	updatedKey, err := networkClient.Client.AddClientPublicKey(updateKeyParams, sdk.authInfo)
	if err != nil {
		sdk.logString("Error on the network, rolling back public key changes")
		sdk.logError(err)
		return rollback(err)
	}

	// Only update the public key ID if everything was successful
	if err := sdk.updatePreferredPubKeyId(*updatedKey.Payload.ID); err != nil {
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
	// Clear the metadata from the persister and from the SDK's local mem
	sdk.cryptoConfig = nil
	_ = sdk.persister.clearCryptoConfig()
	sdk.org = nil
	_ = sdk.persister.clearOrg()
	sdk.lastUpdatedAt = time.Unix(0, 0)
	_ = sdk.persister.clearLastUpdated()
}

func (sdk *standardPeacemakrSDK) verifyUserSelectedUseDomain(useDomainName string) error {

	err := sdk.populateCryptoConfig()
	if err != nil {
		e := errors.New("failed to populate use domains from crypto config id")
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
