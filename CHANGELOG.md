0.2
=====
NEW FEATURES
------------
 - Make use of the @extschema@ macro so that the extension can be installed in any desired schema (Github PR #2).
 - Show the full parameter list for functions instead of the oid list of parameter types (Github PR #4).
 - Allow usage of this extension on platforms that may restrict access to pg_authid (Github PR #5).
 - Add check_grants() and all_grants() functions to show grants that roles have been given, not just object access (Github PR #7)
 - Add precommit hooks to git repo
