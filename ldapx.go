package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

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

var version = "v1.2.1"

var green = color.New(color.FgGreen)
var red = color.New(color.FgRed)
var yellow = color.New(color.FgYellow)
var blue = color.New(color.FgBlue)

var insecureTlsConfig = &tls.Config{
	InsecureSkipVerify: true,
}

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
	filterChain   string
	attrChain     string
	baseChain     string
	entriesChain  string
	tracking      bool
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
	)

	pflag.StringVarP(&proxyLDAPAddr, "listen", "l", ":389", "Address & port to listen on for incoming LDAP connections")
	pflag.StringVarP(&targetLDAPAddr, "target", "t", "", "Target LDAP server address")
	pflag.UintVarP(&verbFwd, "vf", "F", 1, "Set the verbosity level for forward LDAP traffic (requests)")
	pflag.UintVarP(&verbRev, "vr", "R", 0, "Set the verbosity level for reverse LDAP traffic (responses)")
	pflag.BoolVarP(&ldaps, "ldaps", "s", false, "Connect to target over LDAPS (ignoring cert. validation)")
	pflag.StringVarP(&socksServer, "socks", "x", "", "SOCKS proxy address")
	pflag.BoolVarP(&noShell, "no-shell", "N", false, "Don't show the ldapx shell")
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

	// Initialize runtime config after parsing
	pflag.Parse()
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

	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		pflag.PrintDefaults()
	}

	globalStats.Forward.CountsByType = make(map[int]uint64)
	globalStats.Reverse.CountsByType = make(map[int]uint64)

}
func updateFilterChain(chain string) {
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
}

func getFilterChain() *filtermid.FilterMiddlewareChain {
	if chain := filterChainPtr.Load(); chain != nil {
		return chain.(*filtermid.FilterMiddlewareChain)
	}
	return &filtermid.FilterMiddlewareChain{}
}

func updateBaseDNChain(chain string) {
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
}

func getBaseDNChain() *basednmid.BaseDNMiddlewareChain {
	if chain := baseDNChainPtr.Load(); chain != nil {
		return chain.(*basednmid.BaseDNMiddlewareChain)
	}
	return &basednmid.BaseDNMiddlewareChain{}
}

func updateAttrListChain(chain string) {
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
}

func getAttrListChain() *attrlistmid.AttrListMiddlewareChain {
	if chain := attrListChainPtr.Load(); chain != nil {
		return chain.(*attrlistmid.AttrListMiddlewareChain)
	}
	return &attrlistmid.AttrListMiddlewareChain{}
}

func updateAttrEntriesChain(chain string) {
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
}

func getAttrEntriesChain() *attrentriesmid.AttrEntriesMiddlewareChain {
	if chain := attrEntriesChainPtr.Load(); chain != nil {
		return chain.(*attrentriesmid.AttrEntriesMiddlewareChain)
	}
	return &attrentriesmid.AttrEntriesMiddlewareChain{}
}

func main() {
	pflag.Parse()

	if pflag.Lookup("version").Changed {
		fmt.Printf("ldapx %s\n", version)
		os.Exit(0)
	}

	log.InitLog(outputFile)

	SetupMiddlewaresMap()

	// Registering middlewares
	updateFilterChain(filterChain)
	updateBaseDNChain(baseChain)
	updateAttrListChain(attrChain)
	updateAttrEntriesChain(entriesChain)

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
	if !strings.Contains(proxyLDAPAddr, ":") {
		proxyLDAPAddr = fmt.Sprintf("%s:%d", proxyLDAPAddr, 389)
	}

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
	runtimeConfig.Unlock()

	var err error
	listener, err = net.Listen("tcp", proxyLDAPAddr)
	if err != nil {
		log.Log.Printf("[-] Failed to listen on port %s: %s\n", proxyLDAPAddr, err)
		shutdownProgram()
	}

	if socks != "" {
		log.Log.Printf("[+] LDAP Proxy listening on '%s', forwarding to '%s' (T) via '%s'\n", proxyLDAPAddr, targetAddr, socks)
	} else {
		log.Log.Printf("[+] LDAP Proxy listening on '%s', forwarding to '%s' (T)\n", proxyLDAPAddr, targetAddr)
	}
	log.Log.Printf("[+] BaseDNMiddlewares: [%s]", strings.Join(appliedBaseDNMiddlewares, ","))
	log.Log.Printf("[+] FilterMiddlewares: [%s]", strings.Join(appliedFilterMiddlewares, ","))
	log.Log.Printf("[+] AttrListMiddlewares: [%s]", strings.Join(appliedAttrListMiddlewares, ","))
	log.Log.Printf("[+] AttrEntriesMiddlewares: [%s]", strings.Join(appliedAttrEntriesMiddlewares, ","))

	if outputFile != "" {
		log.Log.Printf("[+] Logging File: '%s'\n", outputFile)
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
