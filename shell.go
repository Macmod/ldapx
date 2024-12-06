package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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
	{Text: "filter", Description: "Set filter middleware chain"},
	{Text: "basedn", Description: "Set basedn middleware chain"},
	{Text: "attrlist", Description: "Set attribute list middleware chain"},
	{Text: "target", Description: "Set target LDAP server address and reconnect"},
	{Text: "option", Description: "Set a middleware option"},
	{Text: "verbfwd", Description: "Set forward verbosity level"},
	{Text: "verbrev", Description: "Set reverse verbosity level"},
}

var clearParamSuggestions = []prompt.Suggest{
	{Text: "filter", Description: "Clear filter middleware chain"},
	{Text: "basedn", Description: "Clear basedn middleware chain"},
	{Text: "attrlist", Description: "Clear attribute list middleware chain"},
	{Text: "stats", Description: "Clear statistics"},
}

var showParamSuggestions = []prompt.Suggest{
	{Text: "filter", Description: "Show filter middleware chain"},
	{Text: "basedn", Description: "Show basedn middleware chain"},
	{Text: "attrlist", Description: "Show attribute list middleware chain"},
	{Text: "testbasedn", Description: "BaseDN to use for the `test` command"},
	{Text: "testattrlist", Description: "Attributes list to use for the `test` command"},
	{Text: "target", Description: "Target address to connect upon receiving a connection"},
	{Text: "option", Description: "Show current middleware options"},
	{Text: "stats", Description: "Show packet statistics"},
	{Text: "verbfwd", Description: "Show forward verbosity level"},
	{Text: "verbrev", Description: "Show reverse verbosity level"},
}

var helpParamSuggestions = []prompt.Suggest{
	{Text: "filter", Description: "Show available filter middlewares"},
	{Text: "basedn", Description: "Show available basedn middlewares"},
	{Text: "attrlist", Description: "Show available attribute list middlewares"},
	{Text: "testbasedn", Description: "Show testbasedn parameter info"},
	{Text: "testattrlist", Description: "Show testattrlist parameter info"},
	{Text: "target", Description: "Show target parameter info"},
	{Text: "option", Description: "Show option parameter info"},
	{Text: "stats", Description: "Show stats parameter info"},
	{Text: "verbfwd", Description: "Show forward verbosity parameter info"},
	{Text: "verbrev", Description: "Show reverse verbosity parameter info"},
}

var testBaseDN = "DC=test,DC=local"
var testAttrList = []string{"cn", "objectClass", "sAMAccountName"}

func completer(in prompt.Document) []prompt.Suggest {
	w := in.GetWordBeforeCursor()
	if w == "" {
		return []prompt.Suggest{}
	}

	args := strings.Split(in.TextBeforeCursor(), " ")
	if len(args) <= 1 {
		return prompt.FilterHasPrefix(suggestions, w, true)
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

func shutdownProgram() {
	fmt.Println("Bye!")
	close(shutdownChan)
	os.Exit(0)
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
			clearStatistics()
			fmt.Printf("All parameters cleared.\n")
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

	shutdownProgram()
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
	case "stats":
		clearStatistics()
		fmt.Println("Statistics cleared.")
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
	case "testbasedn":
		testBaseDN = value
		fmt.Printf("Test BaseDN set to: %s\n", testBaseDN)
	case "testattrlist":
		testAttrList = strings.Split(value, ",")
		for i := range testAttrList {
			testAttrList[i] = strings.TrimSpace(testAttrList[i])
		}
		fmt.Printf("Test attribute list set to: %v\n", testAttrList)
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
	default:
		fmt.Printf("Unknown parameter: %s\n", param)
	}
}

func handleShowCommand(param string) {
	if param == "" {
		showGlobalConfig()
		showChainConfig("Filter", filterChain, filterMidFlags)
		showChainConfig("BaseDN", baseChain, baseDNMidFlags)
		showChainConfig("AttrList", attrChain, attrListMidFlags)
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
	case "testbasedn":
		fmt.Println(testBaseDN)
	case "testattrlist":
		fmt.Println(testAttrList)
	case "target":
		fmt.Println(targetLDAPAddr)
	case "options", "option":
		showOptions()
	case "stats":
		showStatistics()
	case "verbfwd":
		fmt.Printf("Forward verbosity level: %d\n", verbFwd)
	case "verbrev":
		fmt.Printf("Reverse verbosity level: %d\n", verbRev)
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
		fmt.Println("  filter       - Filter middleware chain")
		fmt.Println("  basedn       - BaseDN middleware chain")
		fmt.Println("  attrlist     - Attributes list middleware chain")
		fmt.Println("  testbasedn   - BaseDN to use for the `test` command")
		fmt.Println("  testattrlist - Attributes list to use for the `test` command (separated by commas)")
		fmt.Println("  target       - Target address to connect upon receiving a connection")
		fmt.Println("  stats        - Packet statistics")
		fmt.Println("  option       - Middleware options")
		fmt.Println("  verbfwd      - Forward verbosity level")
		fmt.Println("  verbrev      - Reverse verbosity level")
		fmt.Println("\nUse 'help <parameter>' for detailed information about specific parameters")
		fmt.Println("")
		return
	}

	switch args[0] {
	case "filter":
		fmt.Println("Filter middleware chain:")
		for flag, name := range filterMidFlags {
			fmt.Printf("  %c - %s\n", flag, name)
		}
	case "basedn":
		fmt.Println("BaseDN middleware chain:")
		for flag, name := range baseDNMidFlags {
			fmt.Printf("  %c - %s\n", flag, name)
		}
	case "attrlist":
		fmt.Println("Attributes list middleware chain:")
		for flag, name := range attrListMidFlags {
			fmt.Printf("  %c - %s\n", flag, name)
		}
	case "testbasedn":
		fmt.Println("testbasedn - BaseDN to use for the `test` command")
	case "testattrlist":
		fmt.Println("testattrlist - Attributes list to use for the `test` command (separated by commas)")
	case "target":
		fmt.Println("target - Target address to connect upon receiving a connection (can only be set or shown)")
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
	fmt.Printf("  Target LDAPS: %v\n", ldaps)
	fmt.Printf("\n[Test settings]\n")
	fmt.Printf("  Test BaseDN: %s\n", testBaseDN)
	fmt.Printf("  Test Attributes: %v\n", testAttrList)
	fmt.Println("")
}

func handleTestCommand(query string) {
	fmt.Printf("%s\n", strings.Repeat("─", 55))
	logger.Printf("[+] Simulated LDAP Search\n")
	logger.Printf("[+] Input: %s\n", query)

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
		fc,
		ac,
		bc,
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
