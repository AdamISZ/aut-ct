Anonymous usage tokens from curve trees
=====

### Table of Contents
* [Introduction](#introduction)
* [Caveat](#caveat)
* [Installing](#installing)
* [Worked Example](#worked-example)
* [Running](#running)
* [Testing](#testing)

# Introduction

(Caveat: read the [caveat](#caveat), please.)

If you are time constrained and just want to see it run, or check the environment is set up correctly, then: go to [Installation](#installing) and then [Worked Example](#worked Example).

Goal: Be able to use a privacy-preserving proof of ownership of *a* public key in a set of public keys, as a kind of token with scarcity. In particular, it should be possible to create such a token from a very large anonmity sets (10s of thousands up to millions) with a verification time which is very short (sub second at least) so that it can be used practically in real systems.

More specifically, we imagine these public keys to be those of Bitcoin utxos (or perhaps just txos).

The basis of this is [Curve Trees](https://eprint.iacr.org/2022/756), implemented [here](https://github.com/simonkamp/curve-trees/tree/main). That construction allows one to prove set membership in zero knowledge, with pretty good computation and verification complexity, by essentially using an algebraic version of a Merkle tree, and using bulletproofs to get a ZKP of the validity of the "Merkle" proof.

Specifically, it can be made to work for Bitcoin public keys because of the existence of the 2-cycle of curves secp256k1 and secq256k1; we need such a 2-cycle to implement a Curve Tree construct (technically it works with a bigger cycle but the 2-cycle is optimal, since multiple bulletproofs over the same base curve can be aggregated).

That construction is not quite enough for usage of ownership of public keys as tokens; for that, there needs to be a mechanism to ensure no "double spend" of tokens. This line of thinking tends to lead to a "zerocoin" type of construction, and indeed the above paper introduces "Vcash" as doing exactly that. But this requires a globally synchronised accumulator to record (in a ZK way) the spending of each coin/commitment. Without such a "virtual ledger", the other way you could record "usage" of a key in the set is with a key image, a la Cryptonote/Monero ring signatures. This allows more localized and "loosely-coupled" verification of no-double-spend, depending on thie use case.

This "key image" approach can be implemented as described here in this repo, in [this document](./aut-ct.pdf). It's a simple additional ZK proof of knowledge of the opening of a Pedersen commitment, tied to a key image, using completely standard Sigma protocol techniques.

# Caveat

**Everything here is completely experimental and not safe in any way** (not helped by the fact I am a neophyte in Rust!). Importantly, even the underlying Curve Trees code was *only* written as a benchmarking tool, and therefore even that is not safe to use in anything remotely resembling a production environment.

If you choose to play around with this stuff for Bitcoin projects I suggest using signet for now.

# Installing

Set up Rust, if you haven't, using [rustup](https://rustup.rs/).

Install this project:

```
git clone https://github.com/AdamISZ/aut-ct
```

Check if it's working with

```
cargo test
```

from inside the repository.

# Running

Build the project with `cargo build --release` (without release flag, the debug version is very slow), then the binaries are in `aut-ct/target/release`. There are three binaries, `autct`, `rpcclient`, `rpcserver`. Taking each in turn:

`autct`:

```
./autct 37......cf somepubkeys.txt
```

The prover provides a hex-encoded 32 byte string, as private key, as first argument, then a plaintext file with a list of pubkeys, compressed, hex encoded, separated by whitespace, all on one line. The output is, for now, hardcoded to output to a file in the current directory called `proof.txt`, which should usually be around 2-3kB. The program will look for the pubkey corresponding to the given private key, in the list of pubkeys in the pubkey file, in order to identify the correct index to use in the proof.

`rpcserver`:

```
./rpcserver somepubkeys.txt
```

As probably obvious, the idea here is that we run a service (somewhere) for a client to be able to throw serialized proofs at, and ask it to verify (preferably quickly!) if the proof and the corresponding key image actually validate against the curve tree. If so, the user can credit whoever provided this proof, with some kind of token, service access, whatever, and also keep track of what key images have already been used (this code currently doesn't do that but it's the trivial part: just keep a list of used key images, and check). Here "quickly" should be in the 100ms or less range, for even up to 100K + pubkeys. The RPC server takes a few seconds to start (loading precomputation tables and constructing the Curve Tree), and then serves on port 23333.

`rpcclient`:

```
./rpcclient somepubkeys.txt proof.txt
```

This client connects to the above server (port 23333 locally currently) and calls the `verify()` function with a binary string taken directly from the second argument (here `proof.txt`), and should return with `1` in sub 100ms. Errors will give negative integers instead.

In the directory `testdata` there is an example pubkey file containing approximately 48000 pubkeys taken from all taproot outputs on signet between blocks 85000 and 155000, which you can use to test if you like. The private key `373d30b06bb88d276828ac60fa4f7bc6a2d035615a1fb17342638ad2203cafcf` is for one of those pubkeys (signet!), so if you use it, the proof should verify, and the key image you get as output from the verifier should be: `a496230673e00ed72abe37b9acd01763620f918e5618df4d0db1377d0d8ba72d80`. 

Additionally the depth and branching factors of the Curve Tree are still hard coded (2, 256 respectively); obviously this can (and will, in future) be mode configurable.

# Worked Example

Compute the proof:

```
target/release/autct \
     373d30b06bb88d276828ac60fa4f7bc6a2d035615a1fb17342638ad2203cafcf \
     aut-ct/testdata/signet-pubkeys-85000-155000.txt
```

Start the RPC server (port number currently hardcoded to 23333):

```
target/release/rpcserver \
aut-ct/testdata/signet-pubkeys-85000-155000.txt
```

Make a request from the rpc client, to verify the proof:

```
target/release/rpcclient aut-ct/testdata/signet-pubkeys-85000-155000.txt \
proof.txt
```

Ouput log in rpcserver terminal should contain:

```
Verifying curve tree passed and it matched the key image.
```

Output of rpcclient should be just `1` for successful verification. Any negative number means the proof is not valid for the given Curve Tree.

# Testing

See more info [here](./testdata/README.md).
# TODO

Inclusion of domain-specific strings (customisable) to the challenge hash. User choice of tree parameters (depth, height), and/or choice of parameters depending on data set. Ability to enter secret key in a safer way than on the command line(!), as well as many other security considerations. Proper command line arguments, help messages etc. Standard format for inputting keys, perhaps a bolt-on tool to take data from Bitcoin blocks and convert to a more compact format for public keys (binary instead of current hex).
