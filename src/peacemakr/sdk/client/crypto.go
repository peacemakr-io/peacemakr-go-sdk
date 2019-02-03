package client

import "peacemakr/sdk/utils"

type PeacemakrSDK interface {

	//
	// Registers to PeaceMaker as a client with the provided apiKey. Once successful invocation is required before any
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
	// Encrypt the plaintext, but restrict which key will be used to one specific Use Domain. Returns ciphertexts on
	// success, else returns a non-nil error.
	//
	EncryptInDomainStr(plaintext string, useDomain string) (string, error)

	EncryptInDomain(plaintext []byte, useDomain string) ([]byte, error)


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
func GetPeacemakrSDK(apiKey, clientName string, peacemakrHostname *string, persister utils.Persister) PeacemakrSDK {
	sdk := &standardPeacemakrSDK{
		clientName:        clientName,
		apiKey:            apiKey,
		orgId:             nil,
		cryptoConfigId:    nil,
		authInfo:          utils.GetAuthWriter(apiKey),
		version:           "0.0.1",
		peacemakrHostname: peacemakrHostname,
		persister:         persister,
	}
	return PeacemakrSDK(sdk)
}
