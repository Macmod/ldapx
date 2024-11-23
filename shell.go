package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/c-bata/go-prompt"
)

var suggestions = []prompt.Suggest{
	{Text: "set", Description: "Set a configuration parameter"},
	{Text: "show", Description: "Show current configuration"},
	{Text: "help", Description: "Show help message"},
	{Text: "exit", Description: "Exit the program"},
	{Text: "clear", Description: "Clear a middleware chain"},
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
}

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
	default:
		fmt.Printf("Unknown command: '%s'\n", blocks[0])
	}
}
func RunShell() {
	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("ldapx> "),
		prompt.OptionTitle("ldapx interactive shell"),
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
	fmt.Println("[Available commands]")
	fmt.Println("  set <parameter> <value>    Set a configuration parameter")
	fmt.Println("  clear [<middlewarechain>]  Clear a middleware chain")
	fmt.Println("  show [<parameter>]         Show a configuration parameter or all")
	fmt.Println("  help                       Show this help message")
	fmt.Println("  exit                       Exit the program")
	fmt.Println("\n[Parameters]")
	fmt.Println("  filter    - Filter middleware chain")
	fmt.Println("  basedn    - BaseDN middleware chain")
	fmt.Println("  attrlist  - Attribute list middleware chain")
	fmt.Println("")
}

func showGlobalConfig() {
	fmt.Printf("[Global settings]\n")
	fmt.Printf("  Debug: %v\n", debug)
	fmt.Printf("  Listen address: %s\n", proxyLDAPAddr)
	fmt.Printf("  Target address: %s\n", targetLDAPAddr)
	fmt.Printf("  Target LDAPS: %v\n", ldaps)
	fmt.Println("")
}
