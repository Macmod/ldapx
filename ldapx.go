package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

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

var version = "v1.0.0"

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
	fc           *filtermid.FilterMiddlewareChain
	ac           *attrlistmid.AttrListMiddlewareChain
	bc           *basednmid.BaseDNMiddlewareChain
	ec           *attrentriesmid.AttrEntriesMiddlewareChain

	proxyLDAPAddr  string
	targetLDAPAddr string
	verbFwd        uint
	verbRev        uint
	ldaps          bool
	noShell        bool
	filterChain    string
	attrChain      string
	baseChain      string
	entriesChain   string
	tracking       bool
	options        MapFlag
	outputFile     string

	interceptSearch   bool
	interceptModify   bool
	interceptAdd      bool
	interceptDelete   bool
	interceptModifyDN bool
	listener          net.Listener
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
	pflag.StringVarP(&proxyLDAPAddr, "listen", "l", ":389", "Address & port to listen on for incoming LDAP connections")
	pflag.StringVarP(&targetLDAPAddr, "target", "t", "", "Target LDAP server address")
	pflag.UintVarP(&verbFwd, "vf", "F", 1, "Set the verbosity level for forward LDAP traffic (requests)")
	pflag.UintVarP(&verbRev, "vr", "R", 0, "Set the verbosity level for reverse LDAP traffic (responses)")
	pflag.BoolVarP(&ldaps, "ldaps", "s", false, "Connect to target over LDAPS (ignoring cert. validation)")
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
	fc = &filtermid.FilterMiddlewareChain{}
	for _, c := range filterChain {
		if middlewareName, exists := filterMidFlags[rune(c)]; exists {
			fc.Add(filtermid.FilterMiddlewareDefinition{
				Name: middlewareName,
				Func: func() filtermid.FilterMiddleware { return filterMidMap[middlewareName] },
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
				Func: func() basednmid.BaseDNMiddleware { return baseDNMidMap[middlewareName] },
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
				Func: func() attrlistmid.AttrListMiddleware { return attrListMidMap[middlewareName] },
			})
		}
	}
}

func updateAttrEntriesChain(chain string) {
	entriesChain = chain
	ec = &attrentriesmid.AttrEntriesMiddlewareChain{}
	for _, c := range entriesChain {
		if middlewareName, exists := attrEntriesMidFlags[rune(c)]; exists {
			ec.Add(attrentriesmid.AttrEntriesMiddlewareDefinition{
				Name: middlewareName,
				Func: func() attrentriesmid.AttrEntriesMiddleware { return attrEntriesMidMap[middlewareName] },
			})
		}
	}
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

	var err error
	listener, err = net.Listen("tcp", proxyLDAPAddr)
	if err != nil {
		log.Log.Printf("[-] Failed to listen on port %s: %s\n", proxyLDAPAddr, err)
		shutdownProgram()
	}

	log.Log.Printf("[+] LDAP Proxy listening on '%s', forwarding to '%s' (T)\n", proxyLDAPAddr, targetLDAPAddr)
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
