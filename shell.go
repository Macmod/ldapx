package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Macmod/ldapx/ldaplib"
	"github.com/Macmod/ldapx/parser"
	"github.com/c-bata/go-prompt"
)

var suggestions = []prompt.Suggest{
	{Text: "set", Description: "Set a configuration parameter"},
	{Text: "show", Description: "Show current configuration"},
	{Text: "help", Description: "Show help message"},
	{Text: "exit", Description: "Exit the program"},
	{Text: "clear", Description: "Clear a middleware chain"},
	{Text: "test", Description: "Test an LDAP query through the middlewares"},
}

var setParamSuggestions = []prompt.Suggest{
	{Text: "filter", Description: "Set filter middleware chain"},
	{Text: "basedn", Description: "Set basedn middleware chain"},
	{Text: "attrlist", Description: "Set attribute list middleware chain"},
}

var clearParamSuggestions = []prompt.Suggest{
	{Text: "filter", Description: "Clear filter middleware chain"},
	{Text: "basedn", Description: "Clear basedn middleware chain"},
	{Text: "attrlist", Description: "Clear attribute list middleware chain"},
}

var showParamSuggestions = []prompt.Suggest{
	{Text: "filter", Description: "Show filter middleware chain"},
	{Text: "basedn", Description: "Show basedn middleware chain"},
	{Text: "attrlist", Description: "Show attribute list middleware chain"},
	{Text: "testbasedn", Description: "BaseDN to use for the `test` command"},
	{Text: "testattrlist", Description: "Attribute list to use for the `test` command"},
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
	default:
		return []prompt.Suggest{}
	}
}

func executor(in string) {
	in = strings.TrimSpace(in)
	blocks := strings.Split(in, " ")

	if len(blocks) == 0 {
		return
	}

	switch blocks[0] {
	case "exit":
		fmt.Println("Bye!")
		close(shutdownChan)
		os.Exit(0)
	case "clear":
		if len(blocks) < 2 {
			updateFilterChain("")
			updateBaseDNChain("")
			updateAttrListChain("")
			fmt.Printf("All middleware chains cleared.\n")
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
			showCurrentConfig(blocks[1])
		} else {
			showCurrentConfig("")
		}
	case "help":
		showHelp()
	case "test":
		if len(blocks) < 2 {
			fmt.Println("Usage: test <ldap_query>")
			return
		}
		handleTestCommand(strings.Join(blocks[1:], " "))
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
		prompt.OptionAddKeyBind(prompt.KeyBind{
			Key: prompt.ControlD,
			Fn: func(b *prompt.Buffer) {
				fmt.Println("Bye!")
				close(shutdownChan)
				os.Exit(0)
			},
		}),
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
	default:
		fmt.Printf("Unknown parameter: %s\n", param)
	}
}

func showCurrentConfig(param string) {
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
	}
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

func showHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  set <parameter> <value>    Set a configuration parameter")
	fmt.Println("  clear [<middlewarechain>]  Clear a middleware chain")
	fmt.Println("  show [<parameter>]         Show a configuration parameter or all")
	fmt.Println("  help                       Show this help message")
	fmt.Println("  exit                       Exit the program")
	fmt.Println("  test <query>               Simulate an LDAP query through the middlewares without sending it")
	fmt.Println("\nParameters:")
	fmt.Println("  filter       - Filter middleware chain")
	fmt.Println("  basedn       - BaseDN middleware chain")
	fmt.Println("  attrlist     - Attribute list middleware chain")
	fmt.Println("  testbasedn   - BaseDN to use for the `test` command")
	fmt.Println("  testattrlist - Attribute list to use for the `test` command (separated by commas)")
	fmt.Println("")
}

func showGlobalConfig() {
	fmt.Printf("[Global settings]\n")
	fmt.Printf("  Debug: %v\n", debug)
	fmt.Printf("  Listen address: %s\n", proxyLDAPAddr)
	fmt.Printf("  Target address: %s\n", targetLDAPAddr)
	fmt.Printf("  Target LDAPS: %v\n", ldaps)
	fmt.Printf("\n[Test settings]\n")
	fmt.Printf("  Test BaseDN: %s\n", testBaseDN)
	fmt.Printf("  Test Attributes: %v\n", testAttrList)
	fmt.Println("")
}

func QueryToFilter(query string) (parser.Filter, error) {
	packet, err := ldaplib.CompileFilter(query)
	if err != nil {
		return nil, err
	}
	return parser.PacketToFilter(packet)
}

func FilterToQuery(filter parser.Filter) (string, error) {
	packet := parser.FilterToPacket(filter)
	query, err := ldaplib.DecompileFilter(packet)
	return query, err
}

func handleTestCommand(query string) {
	fmt.Printf("%s\n", strings.Repeat("─", 55))
	logger.Printf("[+] Simulated LDAP Search\n")
	logger.Printf("[+] Input: %s\n", query)

	filter, err := QueryToFilter(query)
	if err != nil {
		red.Printf("Error compiling query: %v\n", err)
		return
	}

	parsed, err := FilterToQuery(filter)
	if err != nil {
		red.Printf("Unknown error: %v\n", err)
		return
	}

	blue.Printf("Parsed Request:\n")
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

	newParsed, err := FilterToQuery(newFilter)
	if err != nil {
		red.Printf("Unknown error: '%v'", err)
	}

	green.Printf("Changed Request:\n")
	green.Printf("  BaseDN: %s\n", newBaseDN)
	green.Printf("  Attributes: %v\n", newAttrs)
	green.Printf("  Filter: %v\n", newParsed)
}
