# Obfs4 Connection Checker

This small tool attempts to check obfs4 bridge status.

Note: I used `curl https://onionoo.torproject.org/details?search=flag:guard` to
get the entry nodes, then did some `jq`ing to finally get the raw descriptors to
directly add into the program:

`cat list | jq -r '.relays[] | "\(.or_addresses[0]) \(.fingerprint)"' > list_of_entry_nodes`

## Usage

Launch the program by running `cargo run`

Then, to pass bridges into the program for an initial scan, make the following HTTP POST request.

Here is the `curl` command:

```
  curl -X POST localhost:5000/bridge-state -H "Content-Type: application/json" -d '{"bridge_lines": ["BRIDGE_LINE"]}'
```

where you should replace `BRIDGE_LINE` by all the bridges that you wish to test

For getting updates, right now we have a `/updates` GET endpoint that you can poll for updates.

For that you can run

```
  curl localhost:5000/updates
```