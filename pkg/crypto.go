package peacemakr_go_sdk

import (
	"errors"
	"github.com/peacemakr-io/peacemakr-go-sdk/pkg/utils"
	"log"
	"net/url"
	"os"
	"time"
)

type SDKLogger interface {
	Printf(format string, args ...interface{})
}

type PeacemakrSDK interface {

	//
	// Registers to PeaceMakr as a client. The persister is used to detect prior registrations on this client, so safe
	// to call multiple times. Once a successful invocation of Register is executed once, subsequent calls become a
	// noop. One successful call is required before any
	// cryptographic use of this SDK. Successful registration returns a nil error.
	//
	// Registration may fail with invalid apiKey, missing network connectivity, or an invalid persister. On failure,
	// take corrections action and invoke again.
	//
	Register() error

	//
	// Sync this client's state with the server. This invocation will help performance of subsequent encryption
	// and decryption calls - it is completely optional but calling it will ensure that your SDK is up to date
	// at a convenient time.
	//
	// Sync may fail, if registration was not invoked, if there's network connectivity issues, or
	// unexpected authorization issues.
	//
	Sync() error

	//
	// Encrypt a byte array. Returns a ciphertext blob on success, else returns a non-nil error.
	//
	Encrypt(plaintext []byte) ([]byte, error)

	//
	// Encrypt a byte array, but restrict which keys may be used to a Use Domain of this specific name. Names of Use
	// Domains are not unique, and this non-unique property of your Organization's Use Domains allows for graceful
	// rotation of encryption keys off of old (retiring, stale, or compromised) Use Domains, simply by creating a new
	// Use Domain with the same name. The transitional purity, both Use Domains may be selected for encryption use by
	// clients restricted to one particular name. Then, retiring of one of the two Use Domains is possible without
	// disrupting your deployed application.
	//
	// Returns a ciphertext blob on success, else returns a non-nil error.
	//
	EncryptInDomain(plaintext []byte, useDomainName string) ([]byte, error)

	//
	// Decrypt the ciphertexts. Returns original byte array on success, else returns a non-nil error.
	//
	Decrypt(ciphertext []byte) ([]byte, error)

	//
	// For visibility or debugging purposes, identify which client and configuration this client is running.
	// Also forwards debug info to peacemakr if phonehome enabled.
	//
	GetDebugInfo() string

	//
	// Under certain conditions, it may be necessary to release back to the system memory space consumed by this
	// SDK instance. This method releases internally managed hot cache of keys and metadata used for cryptographic
	// operations. Note: Invoking this method my result in increased network traffic and latency during subsequent
	// cryptographic operations, as these keys must be retrieved and decrypted before they're cached and available
	// for use again.
	//
	ReleaseMemory()
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
//
// The logger may be left nil, in which case it defaults to the go standard library log.Logger with no prefix
// and standard flags. If that is not desired, you may pass in a logger that conforms to the appropriate interface,
// or even a log.Logger with your chosen configuration. See the example for 2 different options.
//
// printStackTrace changes the behavior of the SDK's logging; if true then each log message will print a stack trace. Good for debugging
// when something goes sideways, but can usually be left off.
func GetPeacemakrSDK(apiKey, clientName string, peacemakrURL *string, persister utils.Persister, optionalLogger SDKLogger) (PeacemakrSDK, error) {

	if persister == nil {
		return nil, errors.New("persister is required")
	}

	loggerToUse := optionalLogger
	if optionalLogger == nil {
		loggerToUse = log.New(os.Stderr, "", log.LstdFlags)
	}

	peacemakrHost := "api.peacemakr.io"
	peacemakrScheme := "https"
	if peacemakrURL != nil {
		url, err := url.Parse(*peacemakrURL)
		if err != nil {
			return nil, err
		}
		peacemakrHost = url.Host
		peacemakrScheme = url.Scheme
	}

	sdk := &standardPeacemakrSDK{
		clientName,
		apiKey,
		nil,
		nil,
		utils.GetAuthWriter(apiKey),
		"0.0.1",
		peacemakrHost,
		peacemakrScheme,
		persister,
		false,
		0,
		int64(time.Duration(time.Hour * 24)),
		nil,
		map[string][]byte{},
		loggerToUse,
	}
	return PeacemakrSDK(sdk), nil
}
