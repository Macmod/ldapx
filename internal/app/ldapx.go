package app

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Macmod/ldapx/decrypt"
	"github.com/Macmod/ldapx/log"
	attrentriesmid "github.com/Macmod/ldapx/middlewares/attrentries"
	attrlistmid "github.com/Macmod/ldapx/middlewares/attrlist"
	basednmid "github.com/Macmod/ldapx/middlewares/basedn"
	filtermid "github.com/Macmod/ldapx/middlewares/filter"
	"github.com/fatih/color"
	"github.com/spf13/pflag"
)

type Stats struct {
	sync.Mutex
	Forward struct {
		PacketsReceived uint64
		PacketsSent     uint64
		BytesReceived   uint64
		BytesSent       uint64
		CountsByType    map[int]uint64
	}
	Reverse struct {
		PacketsReceived uint64
		PacketsSent     uint64
		BytesReceived   uint64
		BytesSent       uint64
		CountsByType    map[int]uint64
	}
}

var version = "v1.3.3"

var green = color.New(color.FgGreen)
var red = color.New(color.FgRed)
var yellow = color.New(color.FgYellow)
var blue = color.New(color.FgBlue)

// cyan/magenta distinguish which leg of the proxy a message belongs to:
// cyan for forward/target-bound traffic (C->T), magenta for reverse/
// client-bound traffic (C<-T) - both mid-brightness, legible on light and
// dark terminal backgrounds alike, and distinct from the semantic
// red/yellow/green above (error/warning/changed) so direction and outcome
// are never visually conflated.
var cyan = color.New(color.FgCyan)
var magenta = color.New(color.FgMagenta)

var insecureTlsConfig = &tls.Config{
	InsecureSkipVerify: true,
}

// upstreamTlsConfig is used for outbound LDAPS connections to the target.
// Defaults to insecureTlsConfig (no client cert). When --key is provided,
// upstreamClientKey is set and handleLDAPConnection builds a per-connection
// tls.Config using the peer certificate from the inbound client's TLS
// handshake + this private key.
var upstreamTlsConfig = insecureTlsConfig

// upstreamClientKey is loaded from --key at startup. When non-nil,
// handleLDAPConnection pairs it with the TLS peer certificate from the
// connecting client to authenticate as a TLS client to the upstream server.
var upstreamClientKey crypto.PrivateKey

var globalStats Stats

// RuntimeConfig holds thread-safe runtime configuration
type RuntimeConfig struct {
	sync.RWMutex
	targetAddr        string
	verbFwd           uint
	verbRev           uint
	ldaps             bool
	socksServer       string
	interceptSearch   bool
	interceptModify   bool
	interceptAdd      bool
	interceptDelete   bool
	interceptModifyDN bool

	decryptCfg decrypt.Config

	spoofMechs []string
	spoofGiven bool

	splitWrapped string // "in", "out", "both", or "" (default = bundled)

	tracking bool

	tlsCertFile     string
	tlsKeyFile      string
	listenerTls     bool
	upstreamKeyFile string
}

// InterceptFlags bundles all interception settings
type InterceptFlags struct {
	Search   bool
	Modify   bool
	Add      bool
	Delete   bool
	ModifyDN bool
}

// GetInterceptFlags returns all interception flags in a single lock
func (rc *RuntimeConfig) GetInterceptFlags() InterceptFlags {
	rc.RLock()
	defer rc.RUnlock()
	return InterceptFlags{
		Search:   rc.interceptSearch,
		Modify:   rc.interceptModify,
		Add:      rc.interceptAdd,
		Delete:   rc.interceptDelete,
		ModifyDN: rc.interceptModifyDN,
	}
}

// GetVerbosity returns forward and reverse verbosity levels in a single lock
func (rc *RuntimeConfig) GetVerbosity() (fwd, rev uint) {
	rc.RLock()
	defer rc.RUnlock()
	return rc.verbFwd, rc.verbRev
}

// GetConnectionConfig returns connection settings in a single lock
func (rc *RuntimeConfig) GetConnectionConfig() (targetAddr, socksServer string, ldaps bool) {
	rc.RLock()
	defer rc.RUnlock()
	return rc.targetAddr, rc.socksServer, rc.ldaps
}

// GetDecryptionConfig returns the configured --decrypt-* credential
// source(s) (immutable after startup - decryption credentials aren't
// exposed through the interactive shell).
func (rc *RuntimeConfig) GetDecryptionConfig() decrypt.Config {
	rc.RLock()
	defer rc.RUnlock()
	return rc.decryptCfg
}

// GetSplitWrapped returns the --split-wrapped policy: "in", "out", "both",
// or "" for the default bundling behavior.
func (rc *RuntimeConfig) GetSplitWrapped() string {
	rc.RLock()
	defer rc.RUnlock()
	return rc.splitWrapped
}

// GetSpoofMechConfig returns --spoof-mechs's resolved value list and
// whether the flag was given at all - these are different states, since
// "not given" leaves supportedSASLMechanisms untouched.
func (rc *RuntimeConfig) GetSpoofMechConfig() (mechs []string, given bool) {
	rc.RLock()
	defer rc.RUnlock()
	return rc.spoofMechs, rc.spoofGiven
}

// GetTracking returns whether the tracking algorithm for paged search
// cookie management is enabled.
func (rc *RuntimeConfig) GetTracking() bool {
	rc.RLock()
	defer rc.RUnlock()
	return rc.tracking
}

var runtimeConfig RuntimeConfig

// Middleware chain pointers - accessed atomically for thread safety
var (
	filterChainPtr      atomic.Value // *filtermid.FilterMiddlewareChain
	attrListChainPtr    atomic.Value // *attrlistmid.AttrListMiddlewareChain
	baseDNChainPtr      atomic.Value // *basednmid.BaseDNMiddlewareChain
	attrEntriesChainPtr atomic.Value // *attrentriesmid.AttrEntriesMiddlewareChain
)

var (
	shutdownChan = make(chan struct{})

	proxyLDAPAddr string
	noShell       bool
	noColors      bool
	filterChain   string
	attrChain     string
	baseChain     string
	entriesChain  string
	options       MapFlag
	outputFile    string
	listener      net.Listener
)

func shutdownProgram() {
	fmt.Println("Bye!")
	close(shutdownChan)
	os.Exit(0)
}

type MapFlag struct {
	sync.RWMutex
	m map[string]string
}

func (mf *MapFlag) Type() string {
	return "map[string]string"
}

func (mf *MapFlag) String() string {
	mf.RLock()
	defer mf.RUnlock()
	return fmt.Sprintf("%v", mf.m)
}

func (mf *MapFlag) Set(value string) error {
	mf.Lock()
	defer mf.Unlock()
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid option format: %s", value)
	}
	if mf.m == nil {
		mf.m = make(map[string]string)
	}
	mf.m[parts[0]] = parts[1]
	return nil
}

func (mf *MapFlag) Get(key string) (string, bool) {
	mf.RLock()
	defer mf.RUnlock()
	value, ok := mf.m[key]
	return value, ok
}

func prettyList(list []string) string {
	str, _ := json.Marshal(list)
	return string(str)
}

func init() {
	// Temporary variables for flag parsing
	var (
		targetLDAPAddr    string
		verbFwd           uint
		verbRev           uint
		ldaps             bool
		socksServer       string
		interceptSearch   bool
		interceptModify   bool
		interceptAdd      bool
		interceptDelete   bool
		interceptModifyDN bool

		decryptHash        string
		decryptPassword    string
		decryptSvcPassword string
		decryptSvcKeytab   string
		decryptCCache      string
		decryptSvcKeySpec  string
		decryptSalt        string
		spoofMechRaw       []string
		splitWrapped       string
		tracking           bool

		listenerCert string
		listenerKey  string
		listenerTls  bool
		upstreamKey  string
	)

	pflag.StringVarP(&proxyLDAPAddr, "listen", "l", ":389", "Address & port to listen on for incoming LDAP connections")
	pflag.StringVarP(&targetLDAPAddr, "target", "t", "", "Target LDAP server address")
	pflag.UintVarP(&verbFwd, "vf", "F", 1, "Set the verbosity level for forward LDAP traffic (requests) - 0 (silent), 1 (summary), or 2 (summary + packet dumps)")
	pflag.UintVarP(&verbRev, "vr", "R", 0, "Set the verbosity level for reverse LDAP traffic (responses) - 0 (silent), 1 (summary), or 2 (summary + packet dumps)")
	pflag.BoolVarP(&ldaps, "ldaps", "s", false, "Connect to target over LDAPS (ignoring cert. validation)")
	pflag.StringVarP(&socksServer, "socks", "x", "", "SOCKS proxy address")
	pflag.BoolVarP(&noShell, "no-shell", "N", false, "Don't show the ldapx shell")
	pflag.BoolVarP(&noColors, "no-colors", "Z", false, "Disable colored output")
	pflag.StringVarP(&filterChain, "filter", "f", "", "Chain of search filter middlewares")
	pflag.StringVarP(&attrChain, "attrlist", "a", "", "Chain of attribute list middlewares")
	pflag.StringVarP(&baseChain, "basedn", "b", "", "Chain of baseDN middlewares")
	pflag.StringVarP(&entriesChain, "attrentries", "e", "", "Chain of attribute entries middlewares")
	pflag.BoolVarP(&tracking, "tracking", "T", true, "Applies a tracking algorithm to avoid issues where complex middlewares + paged searches break LDAP cookies (may be memory intensive)")
	pflag.BoolP("version", "v", false, "Show version information")
	pflag.VarP(&options, "option", "o", "Configuration options (key=value)")
	pflag.StringVarP(&outputFile, "output", "O", "", "Output file to write log messages")
	pflag.BoolVarP(&interceptSearch, "search", "S", true, "Intercept LDAP Search operations")
	pflag.BoolVarP(&interceptModify, "modify", "M", false, "Intercept LDAP Modify operations")
	pflag.BoolVarP(&interceptAdd, "add", "A", false, "Intercept LDAP Add operations")
	pflag.BoolVarP(&interceptDelete, "delete", "D", false, "Intercept LDAP Delete operations")
	pflag.BoolVarP(&interceptModifyDN, "modifydn", "L", false, "Intercept LDAP ModifyDN operations")
	pflag.StringVarP(&splitWrapped, "split-wrapped", "", "", "Split bundled wrapped messages into individual seal frames. \"in\" splits C->T direction, \"out\" splits T->C direction, \"both\" splits both (default: keep original bundling) - this flag is experimental and should not be used in general")

	pflag.StringVarP(&decryptHash, "decrypt-hash", "", "", "NT hash of the account being proxied for NTLM decryption (Sicily, SASL/GSSAPI, or SASL/GSS-SPNEGO)")
	pflag.StringVarP(&decryptPassword, "decrypt-password", "", "", "Password of the account being proxied for decryption (Sicily (NTLM), SASL/GSSAPI (NTLM), SASL/GSS-SPNEGO (NTLM), or SASL/DIGEST-MD5)")
	pflag.StringVarP(&decryptCCache, "decrypt-ccache", "", "", "Path to a ccache file containing the service ticket (ST) used in the connection for Kerberos decryption (SASL/GSSAPI or SASL/GSS-SPNEGO)")
	pflag.StringVarP(&decryptSvcPassword, "decrypt-svc-password", "", "", "Password of the target LDAP service's own account for Kerberos decryption")
	pflag.StringVarP(&decryptSvcKeySpec, "decrypt-svc-key", "", "", "Hex-encoded Kerberos key of the target LDAP service's own account for Kerberos decryption (32 bytes=AES256, 16=AES128 or RC4-HMAC; the actual type is taken from the observed ticket)")
	pflag.StringVarP(&decryptSvcKeytab, "decrypt-svc-keytab", "", "", "Path to a keytab holding the target LDAP service's own account key for Kerberos decryption")
	pflag.StringVarP(&decryptSalt, "decrypt-salt", "", "", "Overrides the salt used to derive an AES Kerberos key from --decrypt-svc-password (default: REALM + the ticket's own SPN)")
	pflag.StringSliceVarP(&spoofMechRaw, "spoof-mechs", "", nil, "Comma-separated list of SASL mechanisms to report in the rootDSE's supportedSASLMechanisms (aliases: gssapi, spnego, external, digest-md5 - or an exact string to pass through verbatim; use 'none' - or an empty value, --spoof-mechs='' - to remove the attribute entirely)")

	pflag.StringVarP(&listenerCert, "listener-cert", "", "", "Path to TLS server certificate PEM (enables TLS on the listener)")
	pflag.StringVarP(&listenerKey, "listener-key", "", "", "Path to TLS server private key PEM")
	pflag.BoolVarP(&listenerTls, "listener-tls", "", false, "Enable TLS on the listener with an in-memory self-signed certificate (alternative to --listener-cert/--listener-key)")
	pflag.StringVarP(&upstreamKey, "key", "", "", "Path to the private key PEM for TLS client authentication to the upstream server (the matching certificate is taken from the connecting client's TLS handshake)")

	// Initialize runtime config after parsing
	pflag.Parse()

	if noColors {
		color.NoColor = true
	}

	runtimeConfig.targetAddr = targetLDAPAddr
	runtimeConfig.verbFwd = verbFwd
	runtimeConfig.verbRev = verbRev
	runtimeConfig.ldaps = ldaps
	runtimeConfig.socksServer = socksServer
	runtimeConfig.interceptSearch = interceptSearch
	runtimeConfig.interceptModify = interceptModify
	runtimeConfig.interceptAdd = interceptAdd
	runtimeConfig.interceptDelete = interceptDelete
	runtimeConfig.interceptModifyDN = interceptModifyDN

	decryptCfg, err := decrypt.ResolveConfig(decryptHash, decryptPassword, decryptSvcPassword, decryptSvcKeytab, decryptCCache, decryptSvcKeySpec, decryptSalt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	runtimeConfig.decryptCfg = decryptCfg

	runtimeConfig.spoofGiven = pflag.Lookup("spoof-mechs").Changed
	runtimeConfig.spoofMechs = spoofMechRaw
	runtimeConfig.splitWrapped = splitWrapped
	runtimeConfig.tracking = tracking

	runtimeConfig.tlsCertFile = listenerCert
	runtimeConfig.tlsKeyFile = listenerKey
	runtimeConfig.listenerTls = listenerTls
	runtimeConfig.upstreamKeyFile = upstreamKey

	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		pflag.PrintDefaults()
	}

	globalStats.Forward.CountsByType = make(map[int]uint64)
	globalStats.Reverse.CountsByType = make(map[int]uint64)

}
func updateFilterChain(chain string) error {
	if err := validateFilterChain(chain); err != nil {
		return err
	}

	filterChain = chain
	newChain := &filtermid.FilterMiddlewareChain{}
	for _, c := range filterChain {
		if middlewareName, exists := filterMidFlags[rune(c)]; exists {
			newChain.Add(filtermid.FilterMiddlewareDefinition{
				Name: middlewareName,
				Func: func() filtermid.FilterMiddleware { return filterMidMap[middlewareName] },
			})
		}
	}
	filterChainPtr.Store(newChain)
	return nil
}

func getFilterChain() *filtermid.FilterMiddlewareChain {
	if chain := filterChainPtr.Load(); chain != nil {
		return chain.(*filtermid.FilterMiddlewareChain)
	}
	return &filtermid.FilterMiddlewareChain{}
}

func updateBaseDNChain(chain string) error {
	if err := validateBaseDNChain(chain); err != nil {
		return err
	}

	baseChain = chain
	newChain := &basednmid.BaseDNMiddlewareChain{}
	for _, c := range baseChain {
		if middlewareName, exists := baseDNMidFlags[rune(c)]; exists {
			newChain.Add(basednmid.BaseDNMiddlewareDefinition{
				Name: middlewareName,
				Func: func() basednmid.BaseDNMiddleware { return baseDNMidMap[middlewareName] },
			})
		}
	}
	baseDNChainPtr.Store(newChain)
	return nil
}

func getBaseDNChain() *basednmid.BaseDNMiddlewareChain {
	if chain := baseDNChainPtr.Load(); chain != nil {
		return chain.(*basednmid.BaseDNMiddlewareChain)
	}
	return &basednmid.BaseDNMiddlewareChain{}
}

func updateAttrListChain(chain string) error {
	if err := validateChainRunes(chain, attrListMidFlags); err != nil {
		return err
	}

	attrChain = chain
	newChain := &attrlistmid.AttrListMiddlewareChain{}
	for _, c := range attrChain {
		if middlewareName, exists := attrListMidFlags[rune(c)]; exists {
			newChain.Add(attrlistmid.AttrListMiddlewareDefinition{
				Name: middlewareName,
				Func: func() attrlistmid.AttrListMiddleware { return attrListMidMap[middlewareName] },
			})
		}
	}
	attrListChainPtr.Store(newChain)
	return nil
}

func getAttrListChain() *attrlistmid.AttrListMiddlewareChain {
	if chain := attrListChainPtr.Load(); chain != nil {
		return chain.(*attrlistmid.AttrListMiddlewareChain)
	}
	return &attrlistmid.AttrListMiddlewareChain{}
}

func updateAttrEntriesChain(chain string) error {
	if err := validateChainRunes(chain, attrEntriesMidFlags); err != nil {
		return err
	}

	entriesChain = chain
	newChain := &attrentriesmid.AttrEntriesMiddlewareChain{}
	for _, c := range entriesChain {
		if middlewareName, exists := attrEntriesMidFlags[rune(c)]; exists {
			newChain.Add(attrentriesmid.AttrEntriesMiddlewareDefinition{
				Name: middlewareName,
				Func: func() attrentriesmid.AttrEntriesMiddleware { return attrEntriesMidMap[middlewareName] },
			})
		}
	}
	attrEntriesChainPtr.Store(newChain)
	return nil
}

func getAttrEntriesChain() *attrentriesmid.AttrEntriesMiddlewareChain {
	if chain := attrEntriesChainPtr.Load(); chain != nil {
		return chain.(*attrentriesmid.AttrEntriesMiddlewareChain)
	}
	return &attrentriesmid.AttrEntriesMiddlewareChain{}
}

// generateSelfSignedCert creates an in-memory ECDSA P256 self-signed
// certificate valid for one year, suitable for TLS listener testing.
func generateSelfSignedCert() (tls.Certificate, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "ldapx-self-signed",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}, nil
}

// Run parses CLI flags, wires up middleware chains, and starts the proxy
// loop and interactive shell - the whole of ldapx's runtime entry point.
func Run() {
	pflag.Parse()

	if pflag.Lookup("version").Changed {
		fmt.Printf("ldapx %s\n", version)
		os.Exit(0)
	}

	log.InitLog(outputFile)

	SetupMiddlewaresMap()

	// Validate and register middleware chains.
	var startupErrors []string
	if err := updateFilterChain(filterChain); err != nil {
		startupErrors = append(startupErrors, fmt.Sprintf("filter: %v", err))
	}
	if err := updateBaseDNChain(baseChain); err != nil {
		startupErrors = append(startupErrors, fmt.Sprintf("basedn: %v", err))
	}
	if err := updateAttrListChain(attrChain); err != nil {
		startupErrors = append(startupErrors, fmt.Sprintf("attrlist: %v", err))
	}
	if err := updateAttrEntriesChain(entriesChain); err != nil {
		startupErrors = append(startupErrors, fmt.Sprintf("attrentries: %v", err))
	}
	if len(startupErrors) > 0 {
		for _, e := range startupErrors {
			fmt.Fprintf(os.Stderr, "[-] %s\n", e)
		}
		os.Exit(1)
	}

	// BaseDN middlewares
	appliedBaseDNMiddlewares := []string{}
	for _, c := range baseChain {
		if middlewareName, exists := baseDNMidFlags[rune(c)]; exists {
			appliedBaseDNMiddlewares = append(appliedBaseDNMiddlewares, middlewareName)
		}
	}

	// Filter middlewares
	appliedFilterMiddlewares := []string{}
	for _, c := range filterChain {
		if middlewareName, exists := filterMidFlags[rune(c)]; exists {
			appliedFilterMiddlewares = append(appliedFilterMiddlewares, middlewareName)
		}
	}

	// AttrList middlewares
	appliedAttrListMiddlewares := []string{}
	for _, c := range attrChain {
		if middlewareName, exists := attrListMidFlags[rune(c)]; exists {
			appliedAttrListMiddlewares = append(appliedAttrListMiddlewares, middlewareName)
		}
	}

	// AttrList middlewares
	appliedAttrEntriesMiddlewares := []string{}
	for _, c := range entriesChain {
		if middlewareName, exists := attrEntriesMidFlags[rune(c)]; exists {
			appliedAttrEntriesMiddlewares = append(appliedAttrEntriesMiddlewares, middlewareName)
		}
	}

	// Fix addresses if the port is missing
	runtimeConfig.Lock()
	if !strings.Contains(runtimeConfig.targetAddr, ":") {
		if runtimeConfig.ldaps {
			runtimeConfig.targetAddr = fmt.Sprintf("%s:%d", runtimeConfig.targetAddr, 636)
		} else {
			runtimeConfig.targetAddr = fmt.Sprintf("%s:%d", runtimeConfig.targetAddr, 389)
		}
	}
	targetAddr := runtimeConfig.targetAddr
	socks := runtimeConfig.socksServer
	ldaps := runtimeConfig.ldaps
	runtimeConfig.Unlock()

	var err error

	runtimeConfig.RLock()
	tlsCertFile := runtimeConfig.tlsCertFile
	tlsKeyFile := runtimeConfig.tlsKeyFile
	listenerTls := runtimeConfig.listenerTls
	clientKeyFile := runtimeConfig.upstreamKeyFile
	runtimeConfig.RUnlock()

	// Default listen port: 636 if TLS is configured, otherwise 389.
	// Only applies when the user didn't explicitly set --listen
	if !pflag.Lookup("listen").Changed {
		if tlsCertFile != "" || listenerTls {
			proxyLDAPAddr = ":636"
		}
	}
	// If the address has no colon at all, append whichever port is
	// appropriate.
	if !strings.Contains(proxyLDAPAddr, ":") {
		listenDefaultPort := 389
		if tlsCertFile != "" || listenerTls {
			listenDefaultPort = 636
		}
		proxyLDAPAddr = fmt.Sprintf("%s:%d", proxyLDAPAddr, listenDefaultPort)
	}

	targetIndicator := ""
	if ldaps {
		targetIndicator = " (TLS)"
	}

	var baseListener net.Listener
	baseListener, err = net.Listen("tcp", proxyLDAPAddr)
	if err != nil {
		log.Log.Printf("[-] Failed to listen on port %s: %s", proxyLDAPAddr, err)
		shutdownProgram()
	}

	listenerIndicator := ""
	if tlsCertFile != "" || tlsKeyFile != "" || listenerTls {
		var cert tls.Certificate

		if tlsCertFile != "" || tlsKeyFile != "" {
			if tlsCertFile == "" || tlsKeyFile == "" {
				log.Log.Printf("[-] Both --listener-cert and --listener-key must be specified together")
				shutdownProgram()
			}

			cert, err = tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
			if err != nil {
				log.Log.Printf("[-] Failed to load TLS certificate/key pair: %s", err)
				shutdownProgram()
			}
		} else {
			cert, err = generateSelfSignedCert()
			if err != nil {
				log.Log.Printf("[-] Failed to generate self-signed certificate: %s", err)
				shutdownProgram()
			}
		}

		clientAuth := tls.NoClientCert
		if clientKeyFile != "" {
			clientAuth = tls.RequireAnyClientCert
		}

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			ClientAuth:   clientAuth,
		}

		listenerIndicator = " (TLS)"
		listener = tls.NewListener(baseListener, tlsCfg)
	} else {
		listener = baseListener
	}

	// Build upstream TLS config for outbound LDAPS connections
	runtimeConfig.RLock()
	upstreamKey := runtimeConfig.upstreamKeyFile
	runtimeConfig.RUnlock()

	if socks != "" {
		log.Log.Printf("[+] LDAP Proxy listening on '%s'%s, forwarding to '%s'%s via '%s'", proxyLDAPAddr, listenerIndicator, targetAddr, targetIndicator, socks)
	} else {
		log.Log.Printf("[+] LDAP Proxy listening on '%s'%s, forwarding to '%s'%s", proxyLDAPAddr, listenerIndicator, targetAddr, targetIndicator)
	}

	if upstreamKey != "" {
		key, err := loadPrivateKeyFromFile(upstreamKey)
		if err != nil {
			log.Log.Printf("[-] Failed to load --key '%s': %s", upstreamKey, err)
			shutdownProgram()
		}
		upstreamClientKey = key
		log.Log.Printf("[+] Upstream TLS client key loaded from '%s'", upstreamKey)
	}

	log.Log.Printf("[+] BaseDNMiddlewares: [%s]", strings.Join(appliedBaseDNMiddlewares, ","))
	log.Log.Printf("[+] FilterMiddlewares: [%s]", strings.Join(appliedFilterMiddlewares, ","))
	log.Log.Printf("[+] AttrListMiddlewares: [%s]", strings.Join(appliedAttrListMiddlewares, ","))
	log.Log.Printf("[+] AttrEntriesMiddlewares: [%s]", strings.Join(appliedAttrEntriesMiddlewares, ","))

	if outputFile != "" {
		log.Log.Printf("[+] Logging File: '%s'", outputFile)
	}

	// Main proxy loop
	go startProxyLoop(listener)

	// Start interactive shell in the main goroutine
	if !noShell {
		RunShell()
	} else {
		<-shutdownChan
	}
}
