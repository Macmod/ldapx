package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Macmod/ldapx/log"
	"github.com/Macmod/ldapx/middlewares"
	"github.com/Macmod/ldapx/parser"
	"github.com/c-bata/go-prompt"
)

var suggestions = []prompt.Suggest{
	{Text: "set", Description: "Set a configuration parameter"},
	{Text: "show", Description: "Show current configuration"},
	{Text: "help", Description: "Show help message"},
	{Text: "exit", Description: "Exit the program"},
	{Text: "clear", Description: "Clear a configuration parameter"},
	{Text: "test", Description: "Test an LDAP query through the middlewares"},
	{Text: "version", Description: "Show version information"},
}

var setParamSuggestions = []prompt.Suggest{
	{Text: "basedn", Description: "Set basedn middleware chain"},
	{Text: "filter", Description: "Set filter middleware chain"},
	{Text: "attrlist", Description: "Set attributes list middleware chain"},
	{Text: "attrentries", Description: "Set attributes entries middleware chain"},
	{Text: "target", Description: "Set target LDAP server address"},
	{Text: "ldaps", Description: "Set LDAPS connection mode (true/false)"},
	{Text: "option", Description: "Set a middleware option"},
	{Text: "verbfwd", Description: "Set forward verbosity level"},
	{Text: "verbrev", Description: "Set reverse verbosity level"},
	{Text: "isearch", Description: "Set search operation interception (true/false)"},
	{Text: "imodify", Description: "Set modify operation interception (true/false)"},
	{Text: "iadd", Description: "Set add operation interception (true/false)"},
	{Text: "idelete", Description: "Set delete operation interception (true/false)"},
	{Text: "imodifydn", Description: "Set modifydn operation interception (true/false)"},
	{Text: "socks", Description: "Set the SOCKS server to use for the target connection"},
}

var clearParamSuggestions = []prompt.Suggest{
	{Text: "basedn", Description: "Clear basedn middleware chain"},
	{Text: "filter", Description: "Clear filter middleware chain"},
	{Text: "attrlist", Description: "Clear attribute list middleware chain"},
	{Text: "attrentries", Description: "Clear attributes entries middleware chain"},
	{Text: "stats", Description: "Clear statistics"},
	{Text: "isearch", Description: "Clear search operation interception"},
	{Text: "imodify", Description: "Clear modify operation interception"},
	{Text: "iadd", Description: "Clear add operation interception"},
	{Text: "idelete", Description: "Clear delete operation interception"},
	{Text: "imodifydn", Description: "Clear modifydn operation interception"},
	{Text: "socks", Description: "Clear configured SOCKS server"},
}

var showParamSuggestions = []prompt.Suggest{
	{Text: "basedn", Description: "Show basedn middleware chain"},
	{Text: "filter", Description: "Show filter middleware chain"},
	{Text: "attrlist", Description: "Show attributes list middleware chain"},
	{Text: "attrentries", Description: "Show attributes entries middleware chain"},
	{Text: "testbasedn", Description: "Show BaseDN to use for the `test` command"},
	{Text: "testattrlist", Description: "Show attributes list to use for the `test` command"},
	{Text: "target", Description: "Show target address to connect upon receiving a connection"},
	{Text: "ldaps", Description: "Show LDAPS connection mode"},
	{Text: "option", Description: "Show current middleware options"},
	{Text: "stats", Description: "Show packet statistics"},
	{Text: "verbfwd", Description: "Show forward verbosity level"},
	{Text: "verbrev", Description: "Show reverse verbosity level"},
	{Text: "isearch", Description: "Show search operation interception status"},
	{Text: "imodify", Description: "Show modify operation interception status"},
	{Text: "iadd", Description: "Show add operation interception status"},
	{Text: "idelete", Description: "Show delete operation interception status"},
	{Text: "imodifydn", Description: "Show modifydn operation interception status"},
	{Text: "socks", Description: "Show configured SOCKS server"},
}

var helpParamSuggestions = []prompt.Suggest{
	{Text: "basedn", Description: "Show available basedn middlewares"},
	{Text: "filter", Description: "Show available filter middlewares"},
	{Text: "attrlist", Description: "Show available attributes list middlewares"},
	{Text: "attrentries", Description: "Show available attributes entries middlewares"},
	{Text: "testbasedn", Description: "Show testbasedn parameter info"},
	{Text: "testattrlist", Description: "Show testattrlist parameter info"},
	{Text: "target", Description: "Show target parameter info"},
	{Text: "ldaps", Description: "Show LDAPS parameter info"},
	{Text: "option", Description: "Show option parameter info"},
	{Text: "stats", Description: "Show stats parameter info"},
	{Text: "verbfwd", Description: "Show forward verbosity parameter info"},
	{Text: "verbrev", Description: "Show reverse verbosity parameter info"},
	{Text: "socks", Description: "Show socks parameter info"},
}

var testBaseDN = "DC=test,DC=local"
var testAttrList = []string{"cn", "objectClass", "sAMAccountName"}

func completer(in prompt.Document) []prompt.Suggest {
	w := in.GetWordBeforeCursor()

	args := strings.Split(in.TextBeforeCursor(), " ")
	if len(args) == 1 && len(args[0]) > 0 {
		return prompt.FilterHasPrefix(suggestions, w, true)
	}

	if len(args) > 2 {
		return []prompt.Suggest{}
	}

	switch args[0] {
	case "set":
		return prompt.FilterHasPrefix(setParamSuggestions, w, true)
	case "clear":
		return prompt.FilterHasPrefix(clearParamSuggestions, w, true)
	case "show":
		return prompt.FilterHasPrefix(showParamSuggestions, w, true)
	case "help":
		return prompt.FilterHasPrefix(helpParamSuggestions, w, true)
	default:
		return []prompt.Suggest{}
	}
}

func executor(in string) {
	in = strings.TrimSpace(in)
	blocks := strings.Split(in, " ")

	if len(blocks) == 0 || blocks[0] == "" {
		fmt.Println("No command provided. Type 'help' to see available commands.")
		return
	}

	switch blocks[0] {
	case "exit":
		shutdownProgram()
	case "clear":
		if len(blocks) < 2 {
			updateFilterChain("")
			updateBaseDNChain("")
			updateAttrListChain("")
			updateAttrEntriesChain("")
			clearStatistics()
			fmt.Printf("Middleware chains and statistics cleared.\n")
			return
		}
		handleClearCommand(blocks[1])
	case "set":
		if len(blocks) < 3 {
			fmt.Println("Usage: set <parameter> <value>")
			return
		}
		handleSetCommand(blocks[1], blocks[2:])
	case "show":
		if len(blocks) > 1 {
			handleShowCommand(blocks[1])
		} else {
			handleShowCommand("")
		}
	case "help":
		if len(blocks) > 1 {
			showHelp(blocks[1])
		} else {
			showHelp()
		}
	case "test":
		if len(blocks) < 2 {
			fmt.Println("Usage: test <ldap_query>")
			return
		}
		handleTestCommand(strings.Join(blocks[1:], " "))
	case "version":
		fmt.Printf("ldapx %s\n", version)
	default:
		fmt.Printf("Unknown command: '%s'\n", blocks[0])
	}
}

func RunShell() {
	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("ldapx> "),
		prompt.OptionTitle("ldapx"),
	)

	p.Run()
}

func handleClearCommand(param string) {
	switch param {
	case "filter":
		updateFilterChain("")
		fmt.Printf("Middleware chain Filter cleared.\n")
	case "basedn":
		updateBaseDNChain("")
		fmt.Printf("Middleware chain BaseDN cleared.\n")
	case "attrlist":
		updateAttrListChain("")
		fmt.Printf("Middleware chain AttrList cleared.\n")
	case "attrentries":
		updateAttrEntriesChain("")
		fmt.Printf("Middleware chain AttrEntries cleared.\n")
	case "stats":
		clearStatistics()
		fmt.Println("Statistics cleared.")
	case "isearch":
		interceptSearch = false
		fmt.Printf("Search interception cleared.\n")
	case "imodify":
		interceptModify = false
		fmt.Printf("Modify interception cleared.\n")
	case "iadd":
		interceptAdd = false
		fmt.Printf("Add interception cleared.\n")
	case "idelete":
		interceptDelete = false
		fmt.Printf("Delete interception cleared.\n")
	case "imodifydn":
		interceptModifyDN = false
		fmt.Printf("ModifyDN interception cleared.\n")
	case "socks":
		socksServer = ""
		fmt.Printf("SOCKS server cleared.\n")
	default:
		fmt.Printf("Unknown parameter: %s\n", param)
	}
}

func handleSetCommand(param string, values []string) {
	value := strings.Join(values, " ")
	switch param {
	case "filter":
		updateFilterChain(value)
		fmt.Printf("Middleware chain Filter updated:\n")
		showChainConfig("Filter", filterChain, filterMidFlags)
	case "basedn":
		updateBaseDNChain(value)
		fmt.Printf("Middleware chain BaseDN updated:\n")
		showChainConfig("BaseDN", baseChain, baseDNMidFlags)
	case "attrlist":
		updateAttrListChain(value)
		fmt.Printf("Middleware chain AttrList updated:\n")
		showChainConfig("AttrList", attrChain, attrListMidFlags)
	case "attrentries":
		updateAttrEntriesChain(value)
		fmt.Printf("Middleware chain AttrEntries updated:\n")
		showChainConfig("AttrEntries", entriesChain, attrEntriesMidFlags)
	case "testbasedn":
		testBaseDN = value
		fmt.Printf("Test BaseDN set to: %s\n", testBaseDN)
	case "testattrlist":
		testAttrList = strings.Split(value, ",")
		for i := range testAttrList {
			testAttrList[i] = strings.TrimSpace(testAttrList[i])
		}
		fmt.Printf("Test attributes list set to: %v\n", testAttrList)
	case "target":
		targetLDAPAddr = value
		fmt.Printf("Target LDAP server address set to: %s\n", targetLDAPAddr)
		/*
			fmt.Println("Connecting to the new target...")
			err := reconnectTarget()
			if err != nil {
				fmt.Printf("Failed to connect to the new target: %v\n", err)
			} else {
				fmt.Println("Successfully connected to the new target.")
			}
		*/
	case "option":
		if len(values) != 1 {
			fmt.Println("Usage: set option <key>=<value>")
			return
		}
		options.Set(values[0])

		SetupMiddlewaresMap()

		fmt.Printf("Option set: %s\n", values[0])
	case "verbfwd":
		if len(values) != 1 {
			fmt.Println("Usage: set verbfwd <level>")
			return
		}
		level, err := strconv.ParseUint(values[0], 10, 64)
		if err != nil {
			fmt.Printf("Invalid verbosity level: %s\n", values[0])
			return
		}
		verbFwd = uint(level)
		fmt.Printf("Forward verbosity level set to: %d\n", verbFwd)
	case "verbrev":
		if len(values) != 1 {
			fmt.Println("Usage: set verbrev <level>")
			return
		}
		level, err := strconv.ParseUint(values[0], 10, 64)
		if err != nil {
			fmt.Printf("Invalid verbosity level: %s\n", values[0])
			return
		}
		verbRev = uint(level)
		fmt.Printf("Reverse verbosity level set to: %d\n", verbRev)
	case "ldaps":
		if len(values) != 1 {
			fmt.Println("Usage: set ldaps <true/false>")
			return
		}
		ldapsValue, err := strconv.ParseBool(values[0])
		if err != nil {
			fmt.Printf("Invalid boolean value: %s\n", values[0])
			return
		}
		ldaps = ldapsValue
		fmt.Printf("LDAPS mode set to: %v\n", ldaps)
	case "isearch":
		if len(values) != 1 {
			fmt.Println("Usage: set isearch <true/false>")
			return
		}
		val, err := strconv.ParseBool(values[0])
		if err != nil {
			fmt.Printf("Invalid boolean value: %s\n", values[0])
			return
		}
		interceptSearch = val
		fmt.Printf("Search interception set to: %v\n", interceptSearch)
	case "imodify":
		if len(values) != 1 {
			fmt.Println("Usage: set imodify <true/false>")
			return
		}
		val, err := strconv.ParseBool(values[0])
		if err != nil {
			fmt.Printf("Invalid boolean value: %s\n", values[0])
			return
		}
		interceptModify = val
		fmt.Printf("Modify interception set to: %v\n", interceptModify)
	case "iadd":
		if len(values) != 1 {
			fmt.Println("Usage: set iadd <true/false>")
			return
		}
		val, err := strconv.ParseBool(values[0])
		if err != nil {
			fmt.Printf("Invalid boolean value: %s\n", values[0])
			return
		}
		interceptAdd = val
		fmt.Printf("Add interception set to: %v\n", interceptAdd)
	case "idelete":
		if len(values) != 1 {
			fmt.Println("Usage: set idelete <true/false>")
			return
		}
		val, err := strconv.ParseBool(values[0])
		if err != nil {
			fmt.Printf("Invalid boolean value: %s\n", values[0])
			return
		}
		interceptDelete = val
		fmt.Printf("Delete interception set to: %v\n", interceptDelete)
	case "imodifydn":
		if len(values) != 1 {
			fmt.Println("Usage: set imodifydn <true/false>")
			return
		}
		val, err := strconv.ParseBool(values[0])
		if err != nil {
			fmt.Printf("Invalid boolean value: %s\n", values[0])
			return
		}
		interceptModifyDN = val
		fmt.Printf("ModifyDN interception set to: %v\n", interceptModifyDN)
	case "socks":
		if len(values) != 1 {
			fmt.Println("Usage: set socks <true/false>")
			return
		}
		socksServer = values[0]
	default:
		fmt.Printf("Unknown parameter for 'set': %s\n", param)
	}
}

func handleShowCommand(param string) {
	if param == "" {
		showGlobalConfig()
		showChainConfig("Filter", filterChain, filterMidFlags)
		showChainConfig("BaseDN", baseChain, baseDNMidFlags)
		showChainConfig("AttrList", attrChain, attrListMidFlags)
		showChainConfig("AttrEntries", entriesChain, attrEntriesMidFlags)
		return
	}

	switch param {
	case "global":
		showGlobalConfig()
	case "filter":
		showChainConfig("Filter", filterChain, filterMidFlags)
	case "basedn":
		showChainConfig("BaseDN", baseChain, baseDNMidFlags)
	case "attrlist":
		showChainConfig("AttrList", attrChain, attrListMidFlags)
	case "attrentries":
		showChainConfig("AttrEntries", entriesChain, attrEntriesMidFlags)
	case "testbasedn":
		fmt.Println(testBaseDN)
	case "testattrlist":
		fmt.Println(testAttrList)
	case "target":
		fmt.Println(targetLDAPAddr)
	case "ldaps":
		fmt.Printf("LDAPS mode: %v\n", ldaps)
	case "options", "option":
		showOptions()
	case "stats":
		showStatistics()
	case "verbfwd":
		fmt.Printf("Forward verbosity level: %d\n", verbFwd)
	case "verbrev":
		fmt.Printf("Reverse verbosity level: %d\n", verbRev)
	case "socks":
		fmt.Printf("SOCKS proxy: %s\n", socksServer)
	default:
		fmt.Printf("Unknown parameter for 'show': '%s'\n", param)
	}
}
func showOptions() {
	fmt.Println("[Middleware Options]")
	for _, key := range middlewares.DefaultOptionsKeys {
		defaultValue := middlewares.DefaultOptions[key]
		if value, ok := options.Get(key); ok {
			fmt.Printf("  %s = %s (default = %s)\n", key, value, defaultValue)
		} else {
			fmt.Printf("  %s = %s\n", key, defaultValue)
		}
	}
	fmt.Println("")
}

func showChainConfig(name string, chain string, flags map[rune]string) {
	fmt.Printf("[%s chain]\n", name)
	if chain == "" {
		fmt.Println("  (empty)")
		fmt.Println("")
		return
	}

	fmt.Printf("  Chain: '%s'\n", chain)
	for i, c := range chain {
		if middlewareName, exists := flags[c]; exists {
			indent := strings.Repeat("  ", i)
			fmt.Printf("  %s|> %s (%c)\n", indent, middlewareName, c)
		}
	}

	fmt.Println("")
}

func printMiddlewareFlags(midFlags map[rune]string) {
	var flags []rune
	for flag := range midFlags {
		flags = append(flags, flag)
	}
	sort.Slice(flags, func(i, j int) bool {
		return flags[i] < flags[j]
	})
	for _, flag := range flags {
		fmt.Printf("  %c - %s\n", flag, midFlags[flag])
	}
}

func showHelp(args ...string) {
	if len(args) == 0 {
		fmt.Println("Available commands:")
		fmt.Println("  set <parameter> <value>    Set a configuration parameter")
		fmt.Println("  clear [<parameter>]        Clear a configuration parameter or all")
		fmt.Println("  show [<parameter>]         Show a configuration parameter or all")
		fmt.Println("  help [<parameter>]         Show this help message or parameter-specific help")
		fmt.Println("  exit                       Exit the program")
		fmt.Println("  test <query>               Simulate an LDAP query through the middlewares without sending it")
		fmt.Println("\nParameters:")
		fmt.Println("  basedn       - BaseDN middleware chain")
		fmt.Println("  filter       - Filter middleware chain")
		fmt.Println("  attrlist     - Attributes list middleware chain")
		fmt.Println("  attrentries  - AttrEntries middleware chain")
		fmt.Println("  testbasedn   - BaseDN to use for the `test` command")
		fmt.Println("  testattrlist - Attributes list to use for the `test` command (separated by commas)")
		fmt.Println("  target       - Target address to connect upon receiving a connection")
		fmt.Println("  ldaps        - Enable/disable LDAPS connection mode (true/false)")
		fmt.Println("  stats        - Packet statistics")
		fmt.Println("  option       - Middleware options")
		fmt.Println("  verbfwd      - Forward verbosity level")
		fmt.Println("  verbrev      - Reverse verbosity level")
		fmt.Println("  isearch      - Search operation interception mode (true/false)")
		fmt.Println("  imodify      - Modify operation interception mode (true/false)")
		fmt.Println("  iadd         - Add operation interception mode (true/false)")
		fmt.Println("  idelete      - Delete operation interception mode (true/false)")
		fmt.Println("  imodifydn    - ModifyDN operation interception (true/false)")
		fmt.Println("  socks        - SOCKS proxy address to use for the target connection")
		fmt.Println("\nUse 'help <parameter>' for detailed information about specific parameters")
		fmt.Println("")
		return
	}

	switch args[0] {
	case "filter":
		fmt.Println("Possible Filter middlewares:")
		printMiddlewareFlags(filterMidFlags)
	case "basedn":
		fmt.Println("Possible BaseDN middlewares:")
		printMiddlewareFlags(baseDNMidFlags)
	case "attrlist":
		fmt.Println("Possible AttrList middlewares:")
		printMiddlewareFlags(attrListMidFlags)
	case "attrentries":
		fmt.Println("Possible AttrEntries middlewares:")
		printMiddlewareFlags(attrEntriesMidFlags)
	case "testbasedn":
		fmt.Println("testbasedn - BaseDN to use for the `test` command")
	case "testattrlist":
		fmt.Println("testattrlist - Attributes list to use for the `test` command (separated by commas)")
	case "target":
		fmt.Println("target - Target address to connect upon receiving a connection (can only be set or shown)")
	case "ldaps":
		fmt.Println("ldaps - Enable/disable LDAPS connection mode (true/false)")
	case "stats":
		fmt.Println("stats - Packet statistics (cannot be set, only shown or cleared)")
	case "option":
		fmt.Println("option - Middleware options that can be set / shown / cleared (KEY=VALUE)")
	case "verbfwd":
		fmt.Println("verbfwd - Forward verbosity level (0-3)")
		fmt.Println("  0: No verbosity")
		fmt.Println("  1: Show metadata for all requests")
		fmt.Println("  2: Show packet dumps for all requests")
	case "verbrev":
		fmt.Println("verbrev - Reverse verbosity level (0-3)")
		fmt.Println("  0: No verbosity")
		fmt.Println("  1: Show metadata for all responses")
		fmt.Println("  2: Show packet dump for all responses")
	case "socks":
		fmt.Println("socks - SOCKS proxy address in the schema://host:port format")
	default:
		fmt.Printf("Unknown parameter: %s\n", args[0])
	}
	fmt.Println("")
}
func showGlobalConfig() {
	fmt.Printf("[Global settings]\n")
	fmt.Printf("  Forward Verbosity: %d\n", verbFwd)
	fmt.Printf("  Reverse Verbosity: %d\n", verbRev)
	fmt.Printf("  Listen address: %s\n", proxyLDAPAddr)
	fmt.Printf("  Target address: %s\n", targetLDAPAddr)
	fmt.Printf("  Target LDAPS: %t\n", ldaps)
	fmt.Printf("\n[Interceptions]\n")
	fmt.Printf("  Search: %t\n", interceptSearch)
	fmt.Printf("  Modify: %t\n", interceptModify)
	fmt.Printf("  Add: %t\n", interceptAdd)
	fmt.Printf("  Delete: %t\n", interceptDelete)
	fmt.Printf("  ModifyDN: %t\n", interceptModifyDN)
	fmt.Printf("\n[Test settings]\n")
	fmt.Printf("  Test BaseDN: '%s'\n", testBaseDN)
	testAttrs, _ := json.Marshal(testAttrList)
	fmt.Printf("  Test Attributes: %s\n", testAttrs)
	fmt.Println("")
}

func handleTestCommand(query string) {
	fmt.Printf("%s\n", strings.Repeat("─", 55))
	log.Log.Printf("[+] Simulated LDAP Search\n")
	log.Log.Printf("[+] Input: %s\n", query)

	filter, err := parser.QueryToFilter(query)
	if err != nil {
		red.Printf("Error compiling query: %v\n", err)
		return
	}

	parsed, err := parser.FilterToQuery(filter)
	if err != nil {
		red.Printf("Unknown error: %v\n", err)
		return
	}

	blue.Printf("Input Request:\n")
	blue.Printf("  BaseDN: %s\n", testBaseDN)
	blue.Printf("  Attributes: %v\n", testAttrList)
	blue.Printf("  Filter: %s\n", parsed)

	// Transform using current middleware chains
	newFilter, newBaseDN, newAttrs := TransformSearchRequest(
		filter,
		testBaseDN,
		testAttrList,
	)

	newParsed, err := parser.FilterToQuery(newFilter)
	if err != nil {
		red.Printf("Unknown error: '%v'", err)
	}

	green.Printf("Output Request:\n")
	green.Printf("  BaseDN: %s\n", newBaseDN)
	green.Printf("  Attributes: %v\n", newAttrs)
	green.Printf("  Filter: %v\n", newParsed)
}

func showStatistics() {
	fmt.Println("[Client -> Target]")
	fmt.Printf("  Packets Received: %d\n", globalStats.Forward.PacketsReceived)
	fmt.Printf("  Packets Sent: %d\n", globalStats.Forward.PacketsSent)
	fmt.Printf("  Bytes Received: %d\n", globalStats.Forward.BytesReceived)
	fmt.Printf("  Bytes Sent: %d\n", globalStats.Forward.BytesSent)
	fmt.Println("  Counts by Type:")
	for appType, count := range globalStats.Forward.CountsByType {
		appName, ok := parser.ApplicationMap[uint8(appType)]
		if !ok {
			appName = fmt.Sprintf("Unknown (%d)", appType)
		}
		fmt.Printf("    %s: %d\n", appName, count)
	}

	fmt.Println("\n[Client <- Target]")
	fmt.Printf("  Packets Received: %d\n", globalStats.Reverse.PacketsReceived)
	fmt.Printf("  Packets Sent: %d\n", globalStats.Reverse.PacketsSent)
	fmt.Printf("  Bytes Received: %d\n", globalStats.Reverse.BytesReceived)
	fmt.Printf("  Bytes Sent: %d\n", globalStats.Reverse.BytesSent)
	fmt.Println("  Counts by Type:")
	for appType, count := range globalStats.Reverse.CountsByType {
		appName, ok := parser.ApplicationMap[uint8(appType)]
		if !ok {
			appName = fmt.Sprintf("Unknown (%d)", appType)
		}
		fmt.Printf("    %s: %d\n", appName, count)
	}
}

func clearStatistics() {
	globalStats = Stats{
		Forward: struct {
			PacketsReceived uint64
			PacketsSent     uint64
			BytesReceived   uint64
			BytesSent       uint64
			CountsByType    map[int]uint64
		}{
			CountsByType: make(map[int]uint64),
		},
		Reverse: struct {
			PacketsReceived uint64
			PacketsSent     uint64
			BytesReceived   uint64
			BytesSent       uint64
			CountsByType    map[int]uint64
		}{
			CountsByType: make(map[int]uint64),
		},
	}
}
