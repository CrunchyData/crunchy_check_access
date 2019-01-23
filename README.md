# crunchy_check_access
Functions and views to facilitate PostgreSQL object access inspection

## Overview
Typically install this script as the database superuser.

Once installed, to find all user privileges in the database while ignoring the system catalog and information schema, do:
```
SELECT * FROM all_access() WHERE base_role != CURRENT_USER;
```

To find all user privileges in the database including the system catalog and information schema, do:
```
SELECT * FROM all_access(true) WHERE base_role != CURRENT_USER;
```

By default, execute has been revoked from PUBLIC on the installed functions except ```my_privs()``` and ```my_privs_sys()``` and their corresponding convenience views ```my_privs``` and ```my_privs_sys```. These functions/views allow users to discover their own privileges.

Note that the privileges are discovered by recursing through all roles accessable via a ```GRANT```, including non-inherited ones (need to specifically use ```SET ROLE``` to escalate and gain said privilege). The source path to a given privilege shown in the output is available in the ```role_path``` column; ```base_role``` was the entry point (initially logged in user), while ```as_role``` shows the role with the actual privilege.
