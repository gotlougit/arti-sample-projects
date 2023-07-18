# Arti Sample Projects

This is a collection of small projects created to help find bugs and documentation gaps in Arti's APIs as a part of Google Summer of Code 2023.

They include:

- A simple download manager utility which downloads a Linux variant of the Tor Browser Bundle
over Tor using `arti-client` and `arti-hyper` (for the HTTPS request). It makes six connections to
concurrently download parts of the Tor Browser Bundle over each connection to speed up transfer rates
considerably.

- A DNS resolver a-la `dig`, which will make a DNS over TCP request to a DNS server over Tor.
It helps show how arbitrary bytestreams can be routed over Tor effectively, and includes a
toy DNS implementation for this purpose.

- An obfs4 connection checker, which takes in a list of all obfs4 bridges and checks their health,
ie, whether they are online or not.

- A connection checker, which runs on a user's machine to help report whether different
ways to connect to the Tor Network work (ie, normal Tor connections, Snowflake Tor connections,
obfs4 Tor connections etc.)
