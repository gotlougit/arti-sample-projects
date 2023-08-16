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

The output would look something like this:

```
{
  "bridge_results": {
    "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0": {
      "functional": false,
      "last_tested": "2023-08-16T05:44:06.906005329Z",
      "error": "Channel for [scrubbed] timed out"
    },
    "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0": {
      "functional": false,
      "last_tested": "2023-08-16T05:44:06.905914678Z",
      "error": "Network IO error, or TLS error, in TLS negotiation, talking to Some([scrubbed]): unexpected EOF"
    },
    "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1": {
      "functional": true,
      "last_tested": "2023-08-16T05:44:06.905823776Z"
    }
  },
  "time": 21
}
```

For getting updates, right now we have a `/updates` GET endpoint that you can poll for updates.

For that you can run

```
  curl localhost:5000/updates
```

This has the same output structure as the `/bridge-state` endpoint.