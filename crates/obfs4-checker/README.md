# Obfs4 Connection Checker

This small tool attempts to check obfs4 bridge status.

Note: I used `curl https://onionoo.torproject.org/details?search=flag:guard` to
get the entry nodes, then did some `jq`ing to finally get the raw descriptors to
directly add into the program:

`cat list | jq -r '.relays[] | "\(.or_addresses[0]) \(.fingerprint)"' > list_of_entry_nodes`
