## TODO

## Next Releases

* Improve test coverage
* Inject queries (or other ops) into the active connection from ldapx? (possible but we would have to work around issues with messageIDs and wrapped layers)
* Is it possible to replace a query interactively? (this would depend on client timeouts, but if they are generous in general it should be possible)

## Future Research

* Special handling for StartTLS or a StartTLS command in the shell
* Intercept TGT/ST exchange and grab session key from there (to allow passing only --decrypt-password)?
* Possibilities related to obfuscating Timestamps with timezones
* More middlewares for AttributeEntries
* ExtensibleMatchFilter's with negative values, TokenSID ordering, Range Retrieval, Selection Filters, LDAP\_MATCHING\_RULE\_DN\_WITH\_DATA...