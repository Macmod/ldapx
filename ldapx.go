package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	attrlistmid "github.com/Macmod/ldapx/middlewares/attrlist"
	basednmid "github.com/Macmod/ldapx/middlewares/basedn"
	filtermid "github.com/Macmod/ldapx/middlewares/filter"
	"github.com/fatih/color"
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

var version = "v1.0.0"

var logger = log.New(os.Stderr, "", log.LstdFlags)

var green = color.New(color.FgGreen)
var red = color.New(color.FgRed)
var yellow = color.New(color.FgYellow)
var blue = color.New(color.FgBlue)

var insecureTlsConfig = &tls.Config{
	InsecureSkipVerify: true,
}

var targetConn net.Conn

var globalStats Stats

var (
	shutdownChan = make(chan struct{})
	verbFwd      uint
	verbRev      uint
	ldaps        bool
	noShell      bool

	fc *filtermid.FilterMiddlewareChain
	ac *attrlistmid.AttrListMiddlewareChain
	bc *basednmid.BaseDNMiddlewareChain

	proxyLDAPAddr  string
	targetLDAPAddr string
	filterChain    string
	attrChain      string
	baseChain      string
	tracking       bool

	// Middleware-specific options
	options MapFlag
)

type MapFlag struct {
	sync.RWMutex
	m map[string]string
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
	flag.StringVar(&proxyLDAPAddr, "listen", ":389", "Address & port to listen on for incoming LDAP connections")
	flag.StringVar(&targetLDAPAddr, "target", "", "Target LDAP server address")
	flag.UintVar(&verbFwd, "vf", 1, "Set the verbosity level for forward LDAP traffic (requests)")
	flag.UintVar(&verbRev, "vr", 0, "Set the verbosity level for reverse LDAP traffic (responses)")
	flag.BoolVar(&ldaps, "ldaps", false, "Connect to target over LDAPS (ignoring cert. validation)")
	flag.BoolVar(&noShell, "no-shell", false, "Don't show the ldapx shell")
	flag.StringVar(&filterChain, "f", "", "Chain of search filter middlewares")
	flag.StringVar(&attrChain, "a", "", "Chain of attribute list middlewares")
	flag.StringVar(&baseChain, "b", "", "Chain of baseDN middlewares")
	flag.BoolVar(&tracking, "T", true, "Applies a tracking algorithm to avoid issues where complex middlewares + paged searches break LDAP cookies (may be memory intensive)")

	flag.Bool("version", false, "Show version information")
	flag.Var((*MapFlag)(&options), "o", "Configuration options (key=value)")

	globalStats.Forward.CountsByType = make(map[int]uint64)
	globalStats.Reverse.CountsByType = make(map[int]uint64)
}

func updateFilterChain(chain string) {
	filterChain = chain
	fc = &filtermid.FilterMiddlewareChain{}
	for _, c := range filterChain {
		if middlewareName, exists := filterMidFlags[rune(c)]; exists {
			fc.Add(filtermid.FilterMiddlewareDefinition{
				Name: middlewareName,
				Func: filterMidMap[middlewareName],
			})
		}
	}
}

func updateBaseDNChain(chain string) {
	baseChain = chain
	bc = &basednmid.BaseDNMiddlewareChain{}
	for _, c := range baseChain {
		if middlewareName, exists := baseDNMidFlags[rune(c)]; exists {
			bc.Add(basednmid.BaseDNMiddlewareDefinition{
				Name: middlewareName,
				Func: baseDNMidMap[middlewareName],
			})
		}
	}
}

func updateAttrListChain(chain string) {
	attrChain = chain
	ac = &attrlistmid.AttrListMiddlewareChain{}
	for _, c := range attrChain {
		if middlewareName, exists := attrListMidFlags[rune(c)]; exists {
			ac.Add(attrlistmid.AttrListMiddlewareDefinition{
				Name: middlewareName,
				Func: attrListMidMap[middlewareName],
			})
		}
	}
}

func main() {
	flag.Parse()

	if flag.Lookup("version").Value.(flag.Getter).Get().(bool) {
		fmt.Printf("ldapx %s\n", version)
		os.Exit(0)
	}

	SetupMiddlewaresMap()

	// Registering middlewares
	updateFilterChain(filterChain)
	updateBaseDNChain(baseChain)
	updateAttrListChain(attrChain)

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

	// BaseDN middlewares
	appliedBaseDNMiddlewares := []string{}
	for _, c := range baseChain {
		if middlewareName, exists := baseDNMidFlags[rune(c)]; exists {
			appliedBaseDNMiddlewares = append(appliedBaseDNMiddlewares, middlewareName)
		}
	}

	// Start interactive shell in background
	if !noShell {
		go RunShell()
	}

	logger.Printf("[+] LDAP Proxy listening on '%s', forwarding to '%s' (T)\n", proxyLDAPAddr, targetLDAPAddr)
	logger.Printf("[+] FilterMiddlewares: [%s]", strings.Join(appliedFilterMiddlewares, ","))
	logger.Printf("[+] AttrListMiddlewares: [%s]", strings.Join(appliedAttrListMiddlewares, ","))
	logger.Printf("[+] BaseDNMiddlewares: [%s]", strings.Join(appliedBaseDNMiddlewares, ","))

	// Main proxy loop
	startProxyLoop()
}
