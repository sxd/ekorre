# Ekorre

Git foreign data wrapper

# About

This is unreleased software made to scratch a very specific itch. The intention
is to polish this into production grade code with support for qual pushdown
support.

The name "ekorre" is Swedish for squirrel, since squirrels like Git are good
at jumping between branches.

# Usage

```sql
CREATE EXTENSION ekorre;

CREATE SERVER git_server FOREIGN DATA WRAPPER ekorre;

IMPORT FOREIGN SCHEMA git
FROM SERVER git_server
INTO public
OPTIONS (
	repopath '/path/to/gitrepo',
    branch 'branch_name',
    root_branch 'branch_name',
);
```
