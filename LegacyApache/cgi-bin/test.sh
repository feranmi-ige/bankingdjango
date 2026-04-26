#!/bin/sh
# Sample CGI script — presence of executable CGI scripts combined with
# CVE-2021-41773 enables remote code execution via path traversal.
echo "Content-Type: text/plain"
echo ""
echo "Mullein Bank CGI endpoint"
echo "Server: $(uname -a)"
