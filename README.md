# ldapx

![GitHub Release](https://img.shields.io/github/v/release/Macmod/ldapx) ![](https://img.shields.io/github/go-mod/go-version/Macmod/ldapx) ![](https://img.shields.io/github/languages/code-size/Macmod/ldapx) ![](https://img.shields.io/github/license/Macmod/ldapx) ![](https://img.shields.io/github/actions/workflow/status/Macmod/ldapx/release.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/Macmod/ldapx)](https://goreportcard.com/report/github.com/Macmod/ldapx) ![GitHub Downloads](https://img.shields.io/github/downloads/Macmod/ldapx/total) [<img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/MacmodSec?style=for-the-badge&logo=X&color=blue">](https://twitter.com/MacmodSec)

![Logo](https://raw.githubusercontent.com/Macmod/ldapx/main/images/ldapx-ai-logo.jpg)

Flexible LDAP proxy that can be used to inspect & transform all LDAP packets generated by other tools on the fly.

## Installation

```bash
$ git clone github.com/Macmod/ldapx
$ cd ldapx
$ go install .
```

Or just download one of the [Releases](https://github.com/Macmod/ldapx/releases) provided.

## Usage

```bash
$ ldapx -t LDAPSERVER:389 [-f MIDDLEWARECHAIN] [-a MIDDLEWARECHAIN] [-b MIDDLEWARECHAIN] [-l LOCALADDR:LOCALPORT] [-o MIDDLEWAREOPTION=VALUE] [...]
```

Where:
* `-f` will apply Filter middlewares to all applicable requests
* `-a` will apply AttrList middlewares to all applicable requests
* `-b` will apply BaseDN middlewares to all applicable requests
* `-e` will apply AttrEntries middlewares to all applicable requests
* `-o` can be specified multiple times and is used to specify options for the middlewares
* `-F` specifies the verbosity level for forward packets (requests)
* `-R` specifies the verbosity level for reverse packets (responses)

If `--ldaps` / `-s` is specified, then the connection to the target will use LDAPS. This can come in handy if you must use a tool that doesn't support LDAPS. Use `--no-shell` / `-N` if you don't want to interact with the shell to modify the settings while the program is running.

Each middleware is specified by a single-letter key (detailed below), and can be specified multiple times.
For each type of middleware, the middlewares in the chain will be applied *in the order that they are specified* in the command.

For more options check the `--help`.

## Examples

### Applying multiple middlewares in filters, attributes list and baseDN

```bash
$ ldapx -t 192.168.117.2:389 -f OGDR -a Owp -b OX
```

![Demo1](https://github.com/Macmod/ldapx/blob/main/images/demo1.png)

### Using the shell

You can also use the builting shell to change your middlewares on the fly (`set` command) or simulate LDAP queries (`test` command):

![Demo2](https://github.com/Macmod/ldapx/blob/main/images/demo2.png)

To see packet statistics including how many packets of each LDAP operation passed through the proxy, use the `show stats` command.

```
ldapx> show stats
[Client -> Target]
  Packets Received: 14
  Packets Sent: 14
  Bytes Received: 1464
  Bytes Sent: 1464
  Counts by Type:
    Bind Request: 1
    Search Request: 12
    Modify Request: 1

[Client <- Target]
  Packets Received: 149
  Packets Sent: 149
  Bytes Received: 177045
  Bytes Sent: 177045
  Counts by Type:
    Bind Response: 1
    Search Result Entry: 129
    Search Result Done: 12
    Search Result Reference: 6
    Modify Response: 1
```

You can also show/set other parameters through the shell, such as the target address and verbosity levels. To check all available commands, use the `help` command.

## Middlewares

The tool provides several middlewares "ready for use" for inline LDAP filter transformation. These middlewares were designed for use in Active Directory environments, but theoretically some of them could work in other LDAP environments.

### BaseDN

| Key    | Name | Purpose | Description | Input  | Output | Details |
|--------|------|---------|-------------|--------|--------|---------|
| `O` | OIDAttribute | Obfuscation | Converts DN attrs to OIDs | `cn=Admin` | `2.5.4.3=Admin` | Uses standard LDAP OIDs, can be customized with options |
| `C` | Case | Obfuscation | Randomizes DN case | `CN=lol,DC=draco,DC=local` | `cN=lOl,dC=dRaCo,Dc=loCaL` | Probability based |
| `X` | HexValue | Obfuscation | Hex encodes characters in the values | `cn=john` | `cn=\6a\6fmin` | Probability based | 
| `S` | Spacing | Obfuscation | Adds random spaces in the BaseDN (in the beginning and/or end) | `DC=draco` | `DC=draco     ` | Probability based |
| `Q` | DoubleQuotes | Obfuscation | Adds quotes to values | `cn=Admin` | `cn="Admin"` | Incompatible with `HexValue` / `Spacing` |

### Filter

| Key | Name | Purpose | Description | Input  | Output | Details |
|-----|------|---------|-------------|--------|--------|---------|
| `O` | OIDAttribute | Obfuscation | Converts attrs to OIDs | `(cn=john)` | `(2.5.4.3=john)` | Uses standard LDAP OIDs; can be customized with options |
| `C` | Case | Obfuscation | Randomizes character case | `(cn=John)` | `(cN=jOhN)` | Doesn't apply to binary SID values |
| `X` | HexValue | Obfuscation | Hex encodes characters | `(memberOf=CN=Domain Admins,CN=Users)` | `(memberOf=CN=Do\6dai\6e Admins,CN=U\73ers)` | Only applies to DN string attributes |
| `S` | Spacing | Obfuscation | Adds random spaces between characters | `(memberOf=CN=lol,DC=draco)` | `(memberOf=  CN  =lol, DC =   draco)` | Only applies to DN string attributes, aNR attributes' prefix/suffix & SID attributes |
| `T` | ReplaceTautologies | Obfuscation | Replaces basic tautologies into random tautologies | `(objectClass=*)` | `(\|(packageflags:1.2.840.113556.1.4.803:=0)(!(packageflags=*)))` | |
| `t` | TimestampGarbage | Obfuscation | Adds random chars to timestamp values | `(time=20230812.123Z)` | `(time=20230812.123aBcZdeF)` | |
| `B` | AddBool | Obfuscation | Adds random boolean conditions | `(cn=john)` | `(&(cn=john)(\|(a=1)(a=2)))` | Max depth configurable |
| `D` | DblNegBool | Obfuscation | Adds double negations | `(cn=john)` | `(!(!(cn=john)))` | Max depth configurable |
| `M` | DeMorganBool | Obfuscation | Applies De Morgan's laws | `(&(a=*)(b=*))` | `(!(\|(!(a=\*))(!(b=\*))))` | |
| `R` | ReorderBool | Obfuscation | Reorders boolean conditions | `(&(a=1)(b=2))` | `(&(b=2)(a=1))` | Random reordering |
| `b` | ExactBitwiseBreakout | Obfuscation | Breaks out exact matches into bitwise operations | `(attr=7)` | `(&(attr:1.2.840.113556.1.4.803:=7)(!(attr:1.2.840.113556.1.4.804:=4294967288)))` | For numeric attributes |
| `d` | BitwiseDecomposition | Obfuscation | Decomposes bitwise operations into multiple components | `(attr:1.2.840.113556.1.4.803:=7)` | `(&(attr:1.2.840.113556.1.4.803:=1)(attr:1.2.840.113556.1.4.803:=2)(attr:1.2.840.113556.1.4.803:=4))` | For numeric attributes |
| `I` | EqInclusion | Obfuscation | Converts equality to inclusion | `(cn=krbtgt)` | `(&(cn>=krbtgs)(cn<=krbtgu)(!(cn=krbtgs))(!(cn=krbtgu)))` | Works for numeric, string and SID attributes |
| `E` | EqExclusion | Obfuscation | Converts equality to presence+exclusion | `(cn=krbtgt)` | `(&(cn=*)(!(cn<=krbtgs))(!(cn>=krbtgu)))` | Works for numeric, string and SID attributes |
| `G` | Garbage | Obfuscation | Adds random garbage conditions | `(cn=john)` | `(\|(cn=john)(eqwoi31=21oi32j))` | Configurable count |
| `A` | EqApproxMatch | Obfuscation | Converts equality to approximate match | `(cn=john)` | `(cn~=john)` | Uses LDAP's `~=` operator, which in AD is equivalent to `=` |
| `x` | EqExtensible | Obfuscation | Converts equality to extensible match | `(cn=john)` | `(cn::=john)` | Uses an extensible match with an empty matching rule |
| `Z` | PrependZeros | Obfuscation | Prepends random zeros to numeric values | `(flags=123)` | `(flags=00123)` | Only for numeric attributes and SIDs |
| `s` | SubstringSplit | Obfuscation | Splits values into substrings | `(cn=john)` | `(cn=jo*hn)` | Only for string attrs. & can break the filter if it's not specific enough |
| `N` | NamesToANR | Obfuscation | Changes attributes in the aNR set to `aNR` | `(name=john)` | `(aNR==john)` | |
| `n` | ANRGarbageSubstring | Obfuscation | Appends garbage to the end of `aNR` equalities | `(aNR==john)` | `(aNR==john*siaASJU)` | |

### Attributes List

| Key | Name | Purpose | Description | Input  | Output | Details |
|-----|------|---------|-------------|--------|--------|---------|
| `O` | OIDAttribute | Obfuscation | Converts to OID form | `cn,sn` | `2.5.4.3,2.5.4.4` | Uses standard LDAP OIDs; can be customized with options  |
| `C` | Case | Obfuscation | Randomizes character case | `cn,sn` | `cN,sN` | |
| `D` | Duplicate | Obfuscation | Duplicates attributes | `cn` | `cn,cn,cn` | |
| `G` | GarbageNonExisting | Obfuscation | Adds fake attributes | `cn,sn` | `cn,sn,x-123` | Garbage is chosen randomly from an alphabet |
| `g` | GarbageExisting | Obfuscation | Adds real attributes | `cn` | `cn,sn,mail` | Garbage is chosen from real attributes |
| `w` | AddWildcard | Obfuscation | Adds a wildcard attribute to the list | `cn,name` | `cn,name,*` |  |
| `p` | AddPlus | Obfuscation | Adds a plus sign attribute to the list | `cn,name` | `cn,name,+` | If the list is empty, it also adds a `*` to preserve the semantics |
| `W` | ReplaceWithWildcard | Obfuscation | Replaces the list with a wildcard | `cn,sn` | `*` | Replaces all attributes except operational attributes and "+" |
| `E` | ReplaceWithEmpty | Obfuscation | Empties the attributes list | `cn,sn` | | Removes all attributes except operational attributes and "+" (in which case it includes a `*`) |
| `R` | ReorderList | Obfuscation | Randomly reorders attrs | `cn,sn,uid` | `uid,cn,sn` | Random permutation |

### Attributes Entries

These middlewares are mostly related to the `Add` and `Modify` operations described in the section below.

| Key | Name | Purpose | Description | Input  | Output | Details |
|-----|------|---------|-------------|--------|--------|---------|
| `O` | OIDAttribute | Obfuscation | Converts to OID form | `cn` | `2.5.4.3` | Uses standard LDAP OIDs; can be customized with options |
| `C` | Case | Obfuscation | Randomizes character case | `cn` | `cN` | |
| `R` | ReorderList | Obfuscation | Randomly reorders attrs | `cn,sn` | `sn,cn` | Random permutation |

## Middleware Options

Some middlewares have options that can be used to change the way the middleware works internally. Middleware options can be set via either the command-line by appending `-o KEY=VALUE` switches or by using `set option KEY=VALUE` in the shell.

You can check the available options by using the `show options` / `show option` commands in the shell. If not specified explicitly, the middleware will use default values defined in `middlewares/options.go`.

## Operations

Although Search is the most common use case for this tool, `ldapx` supports other [LDAP operations](https://ldap.com/ldap-operation-types/) as well, such as Modify, Add, Delete and ModifyDN.

Please note that transforming packets involving change operations may lead to undesirable outcomes and *should be done with caution*. Transformations other than `Search` need to be enabled explicitly by specifying `--modify`, `--add`, `--delete` and/or `--modifydn` (`--search` is `true` by default). The code that transforms packets for each operation is implemented in `interceptors.go`, but the overall logic is described below:

### Search

Applies the specified `BaseDN`, `Filter` and `AttrList` middleware chains to the respective fields. 

### Modify

Applies:

* The specified `BaseDN` middleware chain to the DN of the entry being modified

* The specified `AttrEntries` middleware chain to the attribute entries specified as modifications

### Add

Applies:

* The specified `BaseDN` middleware chain to the DN of the entry being added

* The specified `AttrEntries` middleware chain to the attribute entries of the entry being added

### Delete

Applies the specified `BaseDN` middleware chain to the DN of the entry being deleted.

### ModifyDN

Applies the specified `BaseDN` middleware chain to:

* The DN of the entry being modified

* The new RDN field

* The new parent DN field

## Library Usage 

To use `ldapx` as a library, you can import the `parser` package and the individual middleware packages that you wish to use.

To apply the middlewares to a readable LDAP query, you must parse it into a `parser.Filter` using `parser.QueryToFilter()`. Then you can either apply the middlewares, convert it back to a query using `parser.FilterToQuery()`, or convert it to a network packet using `parser.FilterToPacket()`. You can also convert network packets to `parser.Filter` structures using `parser.PacketToFilter()`.

There are no docs on individual middlewares yet, but you can check the source code (`config.go` / `middlewares/*/*.go`) for method signatures and usage.

### Example

```go
package main

import (
    "fmt"

    filtermid "github.com/Macmod/ldapx/middlewares/filter"
    "github.com/Macmod/ldapx/parser"
)

func main() {
    query := "(&(cn=john)(sn=doe))"
    fmt.Printf("Original Query: %s\n", query)

    myFilter, err := parser.QueryToFilter(query)

    if err != nil {
            fmt.Errorf("error parsing query")
    }

    // FilterToString can be used to show
    // the internal representation of the parsed filter
    fmt.Println(parser.FilterToString(myFilter, 0))

    // Applying the OID middleware
    obfuscator := filtermid.OIDAttributeFilterObf(3, false)
    newFilter := obfuscator(myFilter)

    newQuery, err := parser.FilterToQuery(newFilter)
    if err != nil {
            fmt.Errorf("error converting filter to query")
    }

    fmt.Printf("Changed Query: %s\n", newQuery)
}
```

Output:
```
Original Query: (&(cn=john)(sn=doe))
Filter Type: 0
AND Filter with 2 sub-filters:
  Filter Type: 3
  Equality Match - Attribute: cn, Value: john
  Filter Type: 3
  Equality Match - Attribute: sn, Value: doe

Changed Query: (&(2.005.4.03=john)(2.005.04.004=doe))
```

## Developing Middlewares

To develop a new middleware, you can create a new function inside the appropriate package (`filter`/`basedn`/`attrlist`/`attrentries`) with the following structures, respectively:

### Filter
```go
  func YourFilterMiddleware(args) func(parser.Filter) parser.Filter
```

### BaseDN
```go
  func YourBaseDNMiddleware(args) func(string) string
```

### Attributes List
```go
  func YourAttrListMiddleware(args) func([]string) []string
```

### Attributes Entries
```go
  func YourAttrEntriesMiddleware(args) func(parser.AttrEntries) parser.AttrEntries 
```

Then to actually have ldapx use your middleware:

(1) Associate it with a letter and a name in `config.go` in either the `filterMidFlags`, `attrListMidFlags`, or `baseDNMidFlags` maps.

(2) Change SetupMiddlewaresMap in `config.go` to include the call to your middleware

A helper function named `LeafApplierFilterMiddleware` is provided to make it easier to write filter middlewares that only apply to leaf nodes of the filter. The relevant types and functions you might need are defined in the `parser` package.

For example, the code below is the code for the `EqExtensible` middleware in `obfuscation.go`. This middleware changes EqualityMatches into ExtensibleMatches with an empty MatchingRule - for example, `(cn=John)` becomes either `(cn::=John)` or `(cn:dn:=John)`:

```go
func EqExtensibleFilterObf(dn bool) func(parser.Filter) parser.Filter {
  // For every leaf in the filter...
  return LeafApplierFilterMiddleware(func(filter parser.Filter) parser.Filter {
    switch f := filter.(type) {
    // If the leaf is an EqualityMatch
    case *parser.FilterEqualityMatch:
      // Replace it with an ExtensibleMatch with an empty MatchingRule
      // optionally adding a DNAttributes (Active Directory ignores DNAttributes)
      return &parser.FilterExtensibleMatch{
        MatchingRule:  "",
        AttributeDesc: f.AttributeDesc,
        MatchValue:    f.AssertionValue,
        DNAttributes:  dn,
      }
    }

    return filter
  })
}
```

Then it's registered as follows in `config.go`:
```go
var filterMidFlags map[rune]string = map[rune]string{
  ...
  'x': "EqExtensible",
  ...
}

// In SetupMiddlewaresMap:
filterMidMap = map[string]filtermid.FilterMiddleware{
  ...
  "EqExtensible": filtermid.EqualityToExtensibleFilterObf(false),
  ...
}
```

To have your middleware use middleware options for the arguments of the function call, use the `optInt` / `optStr` / `optFloat` / `optBool` functions from `config.go`.

## Contributing

Contributions are welcome by [opening an issue](https://github.com/Macmod/ldapx/issues/new) or by [submitting a pull request](https://github.com/Macmod/ldapx/pulls).

## Acknowledgements

* Almost all obfuscation middlewares are basically implementations of the ideas presented in the [MaLDAPtive](https://www.youtube.com/watch?v=mKRS5Iyy7Qo) research by [Daniel Bohannon](https://x.com/danielhbohannon) & [Sabajete Elezaj](https://x.com/sabi_elezi), which inspired the development of this tool and helped me with countless questions. Kudos to them :)

* Some code was adapted from [go-ldap/ldap](https://github.com/go-ldap/ldap) to convert LDAP filters to human-readable queries and to parse packet fields.

* [ldap.com](https://ldap.com/), [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a), [RFC4510](https://docs.ldap.com/specs/rfc4510.txt), [RFC4515](https://docs.ldap.com/specs/rfc4515.txt), [RFC4512](https://docs.ldap.com/specs/rfc4512.txt), [RFC2696](https://www.ietf.org/rfc/rfc2696.txt) and many other online resources were of great help.

## Disclaimers 

* This tool is meant to be used for authorized security testing, troubleshooting and research purposes only. The author is not responsible for any misuse of this tool.

* Some middlewares may break queries, either because of the specific environment where they are ran, combined effects due to the presence of other middlewares in the chain, or implementation bugs. If you found a bug, please open an issue to report it.

## Known Issues

* This tool does not work currently with clients that require encryption via `SASL` mechanisms or `NTLMSSP Negotiate` (such as ADExplorer) - Check [Issue #1](https://github.com/Macmod/ldapx/issues/1) for more information.

## License
MIT License

Copyright (c) 2024 Artur Henrique Marzano Gonzaga

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
