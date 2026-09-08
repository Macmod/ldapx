## TODO

* Is it possible to replace a query interactively? (this would depend on client timeouts, but if they are generous in general it should be possible)
* Intercept TGT/ST exchange and grab session key from there (to allow passing only --decrypt-password)?
* Possibilities related to obfuscating Timestamps with timezones
* ExtensibleMatchFilter's with negative values, TokenSID ordering...
* Inject queries (or other ops) into the active connection from ldapx? (possible but we would have to work around issues with messageIDs and wrapped layers)
* Improve test coverage