#!/bin/bash
# Profile: OpenLDAP ldapsearch client.
[ "$1" = "--check" ] && { command -v ldapsearch >/dev/null; exit; }
ldapsearch -x -H ldap://localhost:1 -b dc=example,dc=com 2>&1 || true
