#!/bin/sh
head -1000 /home/lhmisme/sample-urls.txt | while read h; do curl -s -m 6 "$h/.well-known/oauth-authorization-server" | grep -m1 issuer | cut -d'"' -f4 | cut -d'/' -f3; done | sort | uniq -c | sort -rn | head -25
