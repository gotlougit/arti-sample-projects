# pt-proxy

This is a project that provides an interface to run the obfs4 pluggable transport
in a standalone manner, ie, instead of using obfs4 to connect to the Tor network,
we can use it to connect to the Internet directly.

Just like Tor, pt-proxy exposes a SOCKS5 proxy that other programs can be configured
to utilize, at which point their communications go through the Internet in an obfuscated
manner, reach the obfs4 server that has been configured ahead of time, and then connect
to the final destination from there on.