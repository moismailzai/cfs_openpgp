# cfs_openpgp
Mostly, this crate is just an excuse to familiarize myself with Rust.

Imagine you have a secure, real-world source of entropy that you use as a root key (for instance, 
https://dicekeys.com/). You may reasonably wish to use the same root (combined with a salt) to generate reproducible
cryptographic secret keys. This way, if your cryptographic secrets are ever compromised, you can use the secure 
physical key with a new salt to generate new ones. If your secrets are lost, however, you can just rebuild them using 
your physical key and the previous salt.

This application is a very thin wrapper around `sequoia_openpgp` that takes an input passphrase and generates a valid pgp 
certificate with a primary EdDSA Edwards-curve Digital Signature Algorithm key and 4 subordinate keys:

* authentication (EdDSA Edwards-curve Digital Signature Algorithm)
* encryption (ECDH public key algorithm)
* encryption (RSA 4096)
* signing (EdDSA Edwards-curve Digital Signature Algorithm)

# usage
Clone the codebase locally and run like so:
```
cargo run -- --username "Alice" --email "alice@example.com" --secret "a super-secure secret phrase that's been generated from real entropy"
```

This will output your ASCII-armored PGP certificate, a revocation signature, and the IDs and ASCII-armored 
representations of each key.

*NOTE: BE SURE TO USE THE EXACT SAME VERSION OF THIS LIBRARY (AND THUS THE SAME NETTLE AND SEQUOIA-OPENPGP LIBRARIES) 
OR YOU MAY NOT GENERATE THE SAME KEY.*

# acknowledgements
Many thanks to [Neal Walfield](https://github.com/nwalfield) of the [sequoia_openpgp](https://www.sequoia-pgp.org/) project for 
all the help on freenode #sequoia.