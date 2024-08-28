Anonymous usage tokens from curve trees
=====

### Table of Contents
* [Introduction](#introduction)
* [Caveat](#caveat)
* [Installing](#installing)
* [Worked Example](#worked-example)
* [Running](#running)
* [Testing](#testing)
* [Making an RPC client](#making-an-rpc-client)
* [Keysets](#keysets)
* [Security](#security)

# Introduction

(Caveat: read the [caveat](#caveat), please.)

* If you are interested in **proof of assets** not anonymous usage tokens, please go to [this page](./auditor-docs/).

* If you are time constrained and just want to see it run, or check the environment is set up correctly, then: go to [Installation](#installing) and then [Worked Example](#worked-example).

Goal: Be able to use a privacy-preserving proof of ownership of *a* public key in a set of public keys, as a kind of token with scarcity. In particular, it should be possible to create such a token from a very large anonmity sets (10s of thousands up to millions) with a verification time which is very short so that it can be used practically in real systems. In practice this code already allows such verifications **in about 40-60ms on commodity hardware for up to 2.5M pubkeys (at least)**.

More specifically, we imagine these public keys to be those of Bitcoin utxos (or perhaps just txos).

The basis of this is [Curve Trees](https://eprint.iacr.org/2022/756), implemented [here](https://github.com/simonkamp/curve-trees/tree/main). That construction allows one to prove set membership in zero knowledge, with pretty good computation and verification complexity, by essentially using an algebraic version of a Merkle tree, and using bulletproofs to get a ZKP of the validity of the "Merkle" proof.

Specifically, it can be made to work for Bitcoin public keys because of the existence of the 2-cycle of curves secp256k1 and secq256k1; we need such a 2-cycle to implement a Curve Tree construct (technically it works with a bigger cycle but the 2-cycle is optimal, since multiple bulletproofs over the same base curve can be aggregated).

That construction is not quite enough for usage of ownership of public keys as tokens; for that, there needs to be a mechanism to ensure no "double spend" of tokens. This line of thinking tends to lead to a "zerocoin" type of construction, and indeed the above paper introduces "Vcash" as doing exactly that. But this requires a globally synchronised accumulator to record (in a ZK way) the spending of each coin/commitment. Without such a "virtual ledger", the other way you could record "usage" of a key in the set is with a key image, a la Cryptonote/Monero ring signatures. This allows more localized and "loosely-coupled" verification of no-double-spend, depending on thie use case.

This "key image" approach can be implemented as described here in this repo, in [this document](./aut-ct.pdf). It's a simple additional ZK proof of knowledge of the opening of a Pedersen commitment, tied to a key image, using completely standard Sigma protocol techniques.

An initial draft of a workable protocol for "receive tokens in exchange for proven utxo ownership" is in [this document](./docs/protocol-utxo.md).

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

from inside the repository. If there are no errors, you are good to go.

If you see an error like:

```
linker `cc` not found
```

... e.g., on Debian, your Rust installation is not functioning because it doesn't have the C compiler toolchain. This should fix it:

```
sudo apt install build-essential
```

# Running

Build the project with `cargo build --release` (without release flag, the debug version is very slow), then the executable is at `target/release/autct`.

Start with `target/release/autct --help` for the summary of the syntax. Note that two flags are required (TODO: they should be arguments), namely `-M` for the mode/method and `-k` for the keyset.

Taking each of the four `mode`s in turn:

"serve":

```
target/release/autct -M serve --keysets \
my-context:testdata/autct-203015-500000-0-2-1024.aks,my-other-context:some-other-filepath -n signet
```

The application's architecture is based around the idea of a (potentially always-on) daemon acting as an RPC server, for clients to request actions from. This allows easier usage by external applications written in different environments/languages etc., and means that such clients do **not** need to have implemented any of the custom cryptographic operations.

Currently the application supports three specific distinct RPC requests, represented by the modes `prove`, `verify` and `newkeys`.

The RPC server will often takes some considerable time to start up (1-2 minutes e.g.) (loading precomputation tables and constructing the Curve Tree), and then serves on port as specified with `-p` at host specified with `-H` (default 127.0.0.1:23333).

Additionally, a server can serve the proving and verification function for multiple different contexts simultaneously, by extending the comma-separated list as shown above. Each item in the list must have a different context label, and the keyset files for each can be the same or different, as desired.

"newkeys":

```
./autct -M newkeys --keysets none -n mainnet -i privkey-file
```

If you need a new taproot address and its corresponding private key, this convenience method allows that. The private key is written in WIF format to the file specified with the `-i` flag, and can be imported into other taproot-supporting wallets; the address is the 'standard' p2tr type. The network (`-n`) should be one of `mainnet`, `signet` or `regtest`.

"prove":

```
target/release/autct -M prove --keysets \
my-context:testdata/autct-203015-500000-0-2-1024.aks \
-i privkeyfile
```

As per `newkeys` above, the private key is read in as WIF format from the file specified with `-i` (the default is a local directory file called `privkey`).

Note that the `keysets` (or `-k`) option takes a particular format: `contextlabel:filename`, and that this can be a comma-separated list for the `serve` operation, but for proving and veryifying, you must just use one. The idea of `context-label` is that usage tokens' scarcity depends on context; you can use the same utxo twice in *different* contexts (like, different applications) but only once in the same context.

The file `autct-203015-500000-0-2-1024.aks`, or whatever else is specified (see [here](./docs/protocol-utxo.md) Appendix 1 for filename structure), should contain public keys in format: compressed, hex encoded, separated by whitespace, all on one line.

The output of the proving algorithm is sent to the file specified by `-P`, which should usually be around 2-3kB. The program will look for the pubkey corresponding to the given private key, in the list of pubkeys in the pubkey file, in order to identify the correct index to use in the proof.

Note that in contrast to verification as specified below, proving can take a non trivial time (15 seconds for large keysets is not untypical).

"verify":

```
target/release/autct -M request --keysets \
my-context:testdata/autct-203015-500000-0-2-1024.aks -P proof1
```

This client connects to the above server and calls the `verify()` function with a binary string taken directly from the file specified with `-P`, and should return with the success or failure of verification status in the field `accepted`. If something is wrong, for example the key image is reused, you will see an error message describing the condition.

In the directory `testdata` there is an example pubkey file containing approximately 330K pubkeys taken from all taproot utxos on signet at block 203015, which you can use to test if you like. For this pubkey set, the private key `cRczLRUHjDTEM92wagj3mMRvP69Jz3SEHQc8pFKiszFBPpJo8dVD` is for one of those pubkeys (signet!), so if you use it, the proof should verify, and the key image you get as output from the verifier should be: `2e7b894455872f3039fb734b42534be410a2a2237a08212b4c9a5bd039c6b4d080` (with the default test labels as per the worked example below).

## Configuring

Use `target/release/autct --help` for documentation of the options available; these are the same settings you can set in the config file:

The config file is auto-generated in `~/.config/autct/default-config.toml` (or similar).

Precedence operation is as you would expect: command line options take precedence over config file values, and be aware updates (i.e. just choosing a different option in a command line call) will be persisted to that config file. Third in order of precedence is the default value. As noted, two "options" (`-M` and `-k`) are required to be specified always.

The depth and branching factor are the parameters of the curve tree. The `generators_length_log_2` may be removed in future but it should be the smallest power of 2 that's bigger than `D(912+L-1)` where `D` is the depth and `L` is the branching factor (see Issue #19 for detailed discussion). If it helps, for keysets up to 500K in size, the defaults should be fine. The rpc port can also be configured here.

Finally, one *may* need to set the `user_string` with `-u` to a hex serialized BIP340 pubkey or alternate user string (see [here](./docs/protocol-utxo.md) Appendix 2). This defines "who" can use the resources accessed by "consuming" the utxo in that context.

# Worked Example

Paths here assume you are in the root of the repository.

Put a WIF encoded private key into a file in the current directory called `privkey` (by default; change with `-i`):

```
echo cRczLRUHjDTEM92wagj3mMRvP69Jz3SEHQc8pFKiszFBPpJo8dVD > privkey
```

Then encrypt it:

```
target/release/autct -M encryptkey --keysets none -i privkey -n signet
```

You'll be prompted for a password. Delete the file `privkey` afterwards; the encrypted password will be in `privkey.enc`.

This particular private key corresponds to an existing signet utxo with more than 500k sats in it. Please don't spend it!

Next, start the RPC server:

```
target/release/autct -M serve --keysets \
my-context:testdata/autct-203015-500000-0-2-1024.aks -n signet
```

.. as noted above, it may take a minute to start up. Once you see `Starting server at 127.0.0.1:23333`, it is ready.

Then switch to a new terminal. Request computation of the proof:

```
target/release/autct -M prove --keysets my-context:testdata/autct-203015-500000-0-2-1024.aks \
-n signet -i privkey.enc -P default-proof-file
```

This will likely take around 15 seconds, at the end you should see `Proof generated successfully` and the file `default-proof-file` will contain it.

If you check the other terminal you will see some debug output as the proof was created.

Next make a request to verify the proof and deliver a resource:

```
target/release/autct -M verify -P default-proof-file -k \
my-context:testdata/autct-203015-500000-0-2-1024.aks
```

Ouput log in servers terminal should look similar to this:

```
Elapsed time for selrerand paramater generation: 58.00ns
Elapsed time for verifier gadget call: 2.15ms
Elapsed time for verifier calls: 46.28ms
Root is odd? false
Elapsed time for verify_curve_tree_proof: 49.00ms
Verifying curve tree passed and it matched the key image. Here is the key image: "2e7b894455872f3039fb734b42534be410a2a2237a08212b4c9a5bd039c6b4d080"
```

Output of rpcclient should look like:

```
Configuration file: '/home/user/.config/autct/default-config.toml'
	mode = "request"
	... other config settings
	
Request was accepted by the Autct verifier! The proof is valid and the (unknown) pubkey is unused.
```

Note that if you repeat this test, you will get instead:

```
Request rejected, proofs are valid but key image is reused.
```

which is correct; key image was stored in the file `autct-v1.0my-contextkeyimages.aki` and reuse will not be allowed unless that file is deleted.

(Process currently verified working on Ubuntu 22.04, Debian 12 and Windows 10)

# Testing

See more info [here](./testdata/README.md).

# Making an RPC client

As an example for the case of Python, see [here](https://github.com/AdamISZ/autct-api).

Conceptually, developers should be able to run *this* application in server mode, locally, and then their own app can make proof and verification calls quickly and without any custom and non-standard crypto code, to the RPC API provided here, consisting of the three methods `prove`, `verify` and `createkeys`. The calls are done over websockets. See the `example.py` in the src directory in that repo, for concrete examples.

As long as websockets are supported, the same should be very easy to do foor other programming languages/environments.

Read [here](./docs/RPC-API.md) for the definitions of the methods/objects used in the RPC-API.

# Keysets

Apart from small test key sets as in the [testing document](./testdata/README.md), you might want to use real world key sets from the mainnet taproot keys. [This document](./docs/utxo-keysets.md) explains how that can be done, but be aware that these data sets are large (e.g. it could easily take 30 minutes to do this, even after you figure out the process!).

# Security

See more [here](./docs/security-analysis.md).
