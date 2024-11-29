# In progress

* [Fix] Guarantee that all obfuscation methods are "stable" / document the ones that aren't
* [Feature] Issue queries directly from ldapx
* [Review] Check if the logic behind the settings of each obfuscator is correct

# Considering

* [Feature] Add config file for fine-tuning all middlewares
* [Fix] Try to connect only and always when the conn is needed
* [Fix] Cleanly exit the program and all goroutines and make sure it doesn't have any races
* [Study] Possibilities related to obfuscating Timestamps with comma/timezones, ExtensibleMatchFilter's with negative values, TokenSID ordering, Range Retrieval, Selection Filters, LDAP_MATCHING_RULE_DN_WITH_DATA...
* [Study] Is it possible to replace a query interactively or does it timeout?
* [Feature] Support applying middlewares to LDAP operations other than search (Add, Modify, Delete)