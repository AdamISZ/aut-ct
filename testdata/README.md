TEST DATA
=======

This is a holding area for various keysets for testing. More will be added, probably building out a set of test vectors for the proofs.

There is a large set of 48000 (approx) public keys derived from signet, taproot outputs, generated from the range of blocks indicated.

The two other keysets are generated from private keys corresponding to integers 1,2,3... with the maximum being one less than the digit shown. So for example the private key of the first public key is 010101..01 (32 single bytes of '1') - but see below about whether proofs can actually be constructed!

TODO
====

An issue arises around permissible points. We currently insist that the provided public key, which will be a leaf in the Curve Tree, is a permissible point for the given parameters (see details on "patch" in the main project README). This is only true by chance around 1 time out of 4 (because we require the positive y value to be a square, and the negative y value to not be a square, both of which are roughly 1/2 chances). This means that currently, the program `autct` can only create a proof for about a quarter of the private keys (e.g. 030303... works but 010101.. and 020202... don't).

 To investigate: can we drop this requirement? Should we deterministically increment the key in some way to ensure permissibility?
