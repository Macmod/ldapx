# ldapx

![GitHub Release](https://img.shields.io/github/v/release/Macmod/ldapx) ![](https://img.shields.io/github/go-mod/go-version/Macmod/ldapx) ![](https://img.shields.io/github/languages/code-size/Macmod/ldapx) ![](https://img.shields.io/github/license/Macmod/ldapx) ![](https://img.shields.io/github/actions/workflow/status/Macmod/ldapx/release.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/Macmod/ldapx)](https://goreportcard.com/report/github.com/Macmod/ldapx) ![GitHub Downloads](https://img.shields.io/github/downloads/Macmod/ldapx/total) [<img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/MacmodSec?style=for-the-badge&logo=X&color=blue">](https://twitter.com/MacmodSec)

Flexible LDAP proxy that can be used to inspect, transform or encrypt to LDAPS all LDAP packets generated by other tools on the fly.

## Installation

```bash
$ git clone github.com/Macmod/ldapx
$ cd ldapx
$ go install .
```

Or just download one of the [Releases](https://github.com/Macmod/ldapx/releases) provided.

## Usage

```bash
$ ldapx -target LDAPSERVER:389 [-f MIDDLEWARECHAIN] [-a MIDDLEWARECHAIN] [-b MIDDLEWARECHAIN] [-listen LOCALADDR:PORT]
```

Where:
* `-f` will apply Filter middlewares to all search requests
* `-a` will apply AttrList middlewares to all search requests
* `-b` will apply BaseDN middlewares to all search requests

`-debug` can also be provided to make it show verbose logs.

Each middleware is specified by a single-letter key (detailed below), and can be specified multiple times.
For each type of middleware, the middlewares in the chain will be applied *in the order that they are specified* in the command.

If `-ldaps` is specified, then the connection to the target will use LDAPS. This can come in handy if you must use a tool that doesn't support LDAPS.

## Examples

### Applying multiple middlewares in filters, attributes list and baseDN

```bash
$ ldapx -target 192.168.117.2:389 -f OGRD -a OW -b OZ
```

![Demo1](https://github.com/Macmod/ldapx/blob/main/images/demo1.png)

## Library Usage 
(TODO)

## Middlewares

The tool provides several middlewares "ready for use" for inline LDAP filter transformation:

| Type | Key | Name | Purpose | Description | Input | Output | Details |
|------|-----|------|---------|-------------|--------|--------|---------|
| Filter | `S` | Spacing | Obfuscation | Adds random spaces between characters | `(memberOf=CN=lol,DC=draco)` | `(memberOf=  CN  =lol, DC =   draco)` | Only applies to DN string attributes & aNR attributes' prefix/suffix |
| Filter | `T` | Timestamp | Obfuscation | Adds random chars to timestamp values | `(time=20230812.123Z)` | `(time=20230812.123aBcZdeF)` | |
| Filter | `B` | AddBool | Obfuscation | Adds random boolean conditions | `(cn=john)` | `(&(cn=john)(\|(a=1)(a=2)))` | Max depth configurable |
| Filter | `D` | DblNegBool | Obfuscation | Adds double negations | `(cn=john)` | `(!(!(cn=john)))` | Max depth configurable |
| Filter | `M` | DeMorganBool | Obfuscation | Applies De Morgan's laws | `(!(\|(a=1)(b=2)))` | `(&(!(a=1))(!(b=2)))` | Probability based |
| Filter | `O` | OIDAttribute | Obfuscation | Converts attrs to OIDs | `(cn=john)` | `(2.5.4.3=john)` | Uses standard LDAP OIDs |
| Filter | `C` | Case | Obfuscation | Randomizes character case | `(cn=John)` | `(cN=jOhN)` | Probability based |
| Filter | `X` | HexValue | Obfuscation | Hex encodes characters | `(cn=john)` | `(cn=\6a\6f\68\6e)` | Probability based |
| Filter | `R` | ReorderBool | Obfuscation | Reorders boolean conditions | `(&(a=1)(b=2))` | `(&(b=2)(a=1))` | Random reordering |
| Filter | `b` | ExactBitwiseBreakout | Obfuscation | Breaks out exact matches into bitwise operations | `(flags=7)` | `TODO` | For numeric attributes |
| Filter | `I` | EqInclusion | Obfuscation | Converts equality to inclusion | `(cn=krbtgt)` | `(&(cn>=krbtgs)(cn<=krbtgu)(!(cn=krbtgs))(!(cn=krbtgu)))` | Alternative equality |
| Filter | `E` | EqExclusion | Obfuscation | Converts equality to presence+exclusion | `(cn=krbtgt)` | `(&(cn=*)(!(cn<=krbtgs))(!(cn>=krbtgu)))` | Alternative equality |
| Filter | `d` | BitwiseDecomposition | Obfuscation | Decomposes bitwise operations into multiple components | `(attr:1.2.840.113556.1.4.803:=7)` | `(&(attr:1.2.840.113556.1.4.803:=1)(attr:1.2.840.113556.1.4.803:=2)(attr:1.2.840.113556.1.4.803:=4))` | For numeric attributes || AttrList | `C` | Case | Obfuscation | Randomizes attribute case | `cn,sn` | `cN,Sn` | Probability based |
| Filter | `G` | Garbage | Obfuscation | Adds random garbage conditions | `(cn=john)` | `(\|(cn=john)(eqwoi31=21oi32j))` | Configurable count |
| Filter | `A` | EqApproxMatch | Obfuscation | Converts equality to approximate match | `(cn=john)` | `(cn~=john)` | Uses LDAP's `~=` operator, which in AD is equivalent to `=` |
| Filter | `Z` | PrependZeros | Obfuscation | Prepends random zeros to numeric values | `(flags=123)` | `(flags=00123)` | Only for numeric attributes |
| Filter | `W` | AddWildcard | Obfuscation | Adds wildcards by splitting values into substrings | `(cn=john)` | `(cn=jo*hn)` | Only for string attrs. & can break the filter if it's not specific enough |
| Filter | `N` | NamesToANR | Obfuscation | Changes attributes in the aNR set to `aNR` | `(name=john)` | `(aNR==john)` | |
| Filter | `n` | ANRGarbageSubstring | Obfuscation | Appends garbage to the end of `aNR` equalities | `(aNR==john)` | `(aNR==john*siaASJU)` | |
| AttrList | `O` | OIDAttribute | Obfuscation | Converts to OID form | `cn,sn` | `2.5.4.3,2.5.4.4` | Uses standard LDAP OIDs |
| AttrList | `G` | GarbageNonExisting | Obfuscation | Adds fake attributes | `cn,sn` | `cn,sn,x-123` | Garbage is chosen randomly from an alphabet |
| AttrList | `g` | GarbageExisting | Obfuscation | Adds real attributes | `cn` | `cn,sn,mail` | Garbage is chosen from real attributes |
| AttrList | `S` | OIDSpacing | Obfuscation | Adds random spaces in the attributes if they are in OID syntax | `2.5.4.3,sn` | `2.5.4.3   ,sn` | |
| AttrList | `D` | Duplicate | Obfuscation | Duplicates attributes | `cn` | `cn,cn,cn` | Max duplicates configurable |
| AttrList | `W` | AddWildcard | Obfuscation | Adds a wildcard attribute to the list | `cn,name` | `cn,name,*` |  |
| AttrList | `w` | ReplaceWithWildcard | Obfuscation | Replaces the list with a wildcard | `cn,sn` | `*` | Replaces all attributes |
| AttrList | `E` | ReplaceWithEmpty | Obfuscation | Empties the attributes list | `cn,sn` | | |
| AttrList | `R` | ReorderList | Obfuscation | Randomly reorders attrs | `cn,sn,uid` | `uid,cn,sn` | Random permutation |
| BaseDN | `C` | Case | Obfuscation | Randomizes DN case | `CN=lol,DC=draco,DC=local` | `cN=lOl,dC=dRaCo,Dc=loCaL` | Probability based |
| BaseDN | `O` | OIDAttribute | Obfuscation | Converts DN attrs to OIDs | `cn=Admin` | `2.5.4.3=Admin` | Uses standard LDAP OIDs |
| BaseDN | `Z` | OIDPrependZeros | Obfuscation | Prepends zeros to OID components | `2.5.4.3=admin` | `002.0005.04.03=admin` | Only applies if there are OID components (for instance, by applying O before) |
| BaseDN | `S` | Spacing | Obfuscation | Adds random spaces in the BaseDN | `DC=draco` | `DC=draco     ` | Min/max spaces/probEnd configurable |
| BaseDN | `Q` | DoubleQuotes | Obfuscation | Adds quotes to values | `cn=Admin` | `cn="Admin"` |  |
| BaseDN | `X` | HexValue | Obfuscation | Hex encodes characters in the values | `cn=john` | `cn=\6a\6fmin` | Probability based | 

### Implementation status
* Filter - `HexValue` not working properly yet, `Garbage`, `ExactBitwiseBreakout`, `EqInclusion`, `EqExclusion` need improvements
* AttrList - `Case` not working properly
* BaseDN - Six methods working (spaces only work in beginning and end / hex only works in the values)

## Acknowledgements

* Almost all obfuscation middlewares are basically implementations of the ideas presented in the [MaLDAPtive](https://www.youtube.com/watch?v=mKRS5Iyy7Qo) research by [Daniel Bohannon](https://x.com/danielhbohannon) & [Sabajete Elezaj](https://x.com/sabi_elezi), which inspired the development of this tool. Kudos to them :)

* Some code was copied from [go-ldap/ldap](https://github.com/go-ldap/ldap) to convert LDAP filters to human-readable queries.

## Contributing

Contributions are also welcome by [opening an issue](https://github.com/Macmod/ldapx/issues/new) or by [submitting a pull request](https://github.com/Macmod/ldapx/pulls).

## License
MIT License

Copyright (c) 2023 Artur Henrique Marzano Gonzaga

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.