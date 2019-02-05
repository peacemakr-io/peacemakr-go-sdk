package client

import (
	"peacemakr/sdk/utils"
	"errors"
	"time"
)

type PeacemakrSDK interface {

	//
	// Registers to PeaceMaker as a client. The persister is used to detect prior registrations on this client, so safe
	// to call multiple times. Once a successful invocation of Register is executed once, subsequent calls become a
	// noop. One successful call is required before any
	// cryptographic use of this SDK. Successful registration returns a nil error.
	//
	// Registration may fail with invalid apiKey, missing network connectivity, or an invalid persister. On failure,
	// take corrections action and invoke again.
	//
	Register() error

	//
	// Pre-Load all available keys for this client. This invocation will help performance of subsequent encryption
	// and decryption calls
	//
	// Pre-Loading may fail, if registration was not invoked, if there's network connectivity issues, or
	// unexpected authorization issues.
	PreLoad() error

	//
	// Encrypt the plaintexts. Returns ciphertexts on success, else returns a non-nil error.
	//
	EncryptStr(plaintext string) (string, error)

	Encrypt(plaintext []byte) ([]byte, error)

	//
	// Encrypt the plaintext, but restrict which keys may be used to a Use Domain of this specific name. Names of Use
	// Domains are not unique, and this non-unique property of your Organization's Use Domains allows for graceful
	// rotation of encryption keys off of old (retiring, stale, or compromised) Use Domains, simply by creating a new
	// Use Domain with the same name. The transitional purity, both Use Domains may be selected for encryption use by
	// clients restricted to one particular name. Then, retiring of one of the two Use Domains is possible without
	// disrupting your deployed application.
	//
	// Returns a ciphertext blob on success, else returns a non-nil error.
	//
	EncryptStrInDomain(plaintext string, useDomainName string) (string, error)

	EncryptInDomain(plaintext []byte, useDomainName string) ([]byte, error)


	//
	// Decrypt the ciphertexts. Returns original plaintext on success, else returns a non-nil error.
	//
	DecryptStr(ciphertext string) (string, error)

	Decrypt(ciphertext []byte) ([]byte, error)

	//
	// For visibility or debugging purposes, identify which client and configuration this client is running.
	// Also forwards debug info to peacemakr if phonehome enabled.
	//
	GetDebugInfo() string
}

// Get a PeaceMakr SDK instance, given an apiKey, clientName, customerKeyManagerId, and persister.
//
// The apiKey must be a valid apiKey associated with your organization.  Please see management console
// to produce a valid apiKey for your organization.
//
// The optional customerKeyManagerId identifies a specific customer's preferred key manager for key derivation.
// custeromKeyManagerId may be nil, in which case, your default crypto configurations are used.
//
// The optional peacemakrServiceHost is the hostname for peacemakr hostname. Available for testing or customerized
// deployments, but by default, it points to public production peacemakr host.
//
// ClientName may be any string, and may be helpful in identifying this specific client PeaceMakr management
// dashboards.
//
// The provided persister, will be used to save local cryptographic material, used for key deliver, encryption,
// decyrption, signing, and verification.
func GetPeacemakrSDK(apiKey, clientName string, peacemakrHostname *string, persister utils.Persister) (PeacemakrSDK, error) {

	if persister == nil {
		return nil, errors.New("persister is required")
	}

	sdk := &standardPeacemakrSDK{
		clientName,
		apiKey,
		nil,
		nil,
		nil,
		nil,
		utils.GetAuthWriter(apiKey),
		"0.0.1",
		peacemakrHostname,
		persister,
		false,
		0,
		int64(time.Duration(time.Hour * 24)),
	}
	return PeacemakrSDK(sdk), nil
}
