# pt-proxy

This is a project that provides an interface to run the obfs4 pluggable transport
in a standalone manner, ie, instead of using obfs4 to connect to the Tor network,
we can use it to connect to the Internet directly.

Just like Tor, pt-proxy exposes a SOCKS5 proxy that other programs can be configured
to utilize, at which point their communications go through the Internet in an obfuscated
manner, reach the obfs4 server that has been configured ahead of time, and then connect
to the final destination from there on.

## Usage

First make sure you have [lyrebird](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/) installed.

Then, clone this repo and compile this project using `cargo`

### Server side

To run this program in server mode (that is, the program will listen on a specified address and route connections
wherever they need to go), we run

`cargo r -- server <path-to-lyrebird> <public-address-to-listen-to>`

Eg. `cargo r -- server /usr/bin/lyrebird 0.0.0.0:5555` will use the binary at `/usr/bin/lyrebird`
and listen on all interfaces on port 5555 for incoming connections to route.

From here, you should navigate to the state directory we have (hardcoded right now) at `/tmp/arti-pt`
and note down the last line in `obfs4_bridgeline.txt`, it will look something like this:

```
Bridge obfs4 <IP ADDRESS>:<PORT> <FINGERPRINT> cert=pAAsEKxisM4YDO0Qn1UqoN1hv+jA/7uTp2ZfAB152loVTGQy9oaGAqTTO+GtkRqKeL0bVg iat-mode=0
```

You simply need to note down `cert=pAAsEKxisM4YDO0Qn1UqoN1hv+jA/7uTp2ZfAB152loVTGQy9oaGAqTTO+GtkRqKeL0bVg iat-mode=0`, and place a semicolon (;) in place of the space, so it now becomes

```
cert=pAAsEKxisM4YDO0Qn1UqoN1hv+jA/7uTp2ZfAB152loVTGQy9oaGAqTTO+GtkRqKeL0bVg;iat-mode=0
```

Without this long string, we can't authenticate to the obfs4 server and we won't be able
to use the server!

### Client side

On the client side, we also need to run a local server, this local server
will be what your programs will connect to in order to be obfuscated using obfs4.

To do this, we run

`cargo r -- client <path-to-lyrebird> <remote-obfs4-server-ip> <remote-obfs4-server-port> <authentication-info>`

The authentication info is the long string that we created in the previous section and has to be enclosed in quotation marks.

Eg. an example usage of this program could be:

`cargo r -- client lyrebird 12.34.56.78 5555 "cert=pAAsEKxisM4YDO0Qn1UqoN1hv+jA/7uTp2ZfAB152loVTGQy9oaGAqTTO+GtkRqKeL0bVg;iat-mode=0"``

in order to connect to the server we initialized previously.

By default, to use this proxy, route all connections through `socks5://127.0.0.1:9050`.
If you wish to use a different port for the lcoal SOCKS5 server, pass an additional argument to the above command, like this:

`cargo r -- client lyrebird <custom-socks5-proxy-port> 12.34.56.78 5555 "cert=pAAsEKxisM4YDO0Qn1UqoN1hv+jA/7uTp2ZfAB152loVTGQy9oaGAqTTO+GtkRqKeL0bVg;iat-mode=0"``
