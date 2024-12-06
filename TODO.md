# In progress

* [Fix] Guarantee that all obfuscation methods are "stable" / document the ones that aren't

# Considering

* [Feature] Issue queries directly from ldapx
* [Fix] Try to connect only and always when the conn is needed
* [Study] Possibilities related to obfuscating Timestamps with comma/timezones, ExtensibleMatchFilter's with negative values, TokenSID ordering, Range Retrieval, Selection Filters, `LDAP_MATCHING_RULE_DN_WITH_DATA`...
* [Study] Is it possible to replace a query interactively or does it timeout?
* [Feature] Support applying middlewares to LDAP operations other than search (Add, Modify, Delete)
