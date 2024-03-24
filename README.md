Anonymous usage tokens from curve trees
=====

### Table of Contents
* [Introduction](#introduction)
* [Caveat](#caveat)
* [Installing](#installing)
* [Worked Example](#worked-example)
* [Running](#running)
* [Testing](#testing)
* [Security](#security)

# Introduction

(Caveat: read the [caveat](#caveat), please.)

If you are time constrained and just want to see it run, or check the environment is set up correctly, then: go to [Installation](#installing) and then [Worked Example](#worked-example).

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

Build the project with `cargo build --release` (without release flag, the debug version is very slow), then the binaries are in `aut-ct/target/release`. There are three binaries, `autct`, `rpcclient`, `rpcserver`.

Each binary can be run as `./autct --help` to see the set of options that can be used:

```
./autct --help
Usage: autct [OPTIONS] --keyset <KEYSET>

Options:
  -V, --version <VERSION>
          
  -k, --keyset <KEYSET>
          
  -c, --context-label <CONTEXT_LABEL>
          
  -u, --user-string <USER_STRING>
          
  -d, --depth <DEPTH>
          
  -b, --branching-factor <BRANCHING_FACTOR>
          
  -g, --generators-length-log-2 <GENERATORS_LENGTH_LOG_2>
          
  -h, --rpc-host <RPC_HOST>
          
  -p, --rpc-port <RPC_PORT>
          
  -v, --verbose <VERBOSE>
          Print additional information in the terminal [possible values: true, false]
  -P, --proof-file-str <PROOF_FILE_STR>
          
  -i, --privkey-file-str <PRIVKEY_FILE_STR>
          
  -h, --help
          Print help
  -V, --version
          Print version
```

Note that while `--keyset` is indeed required and not optional for *all* of the binaries, certain other options are required depending on each, as per below:


Taking each in turn:

`autct`:

```
./autct --keyset autct-830000-500000-0-2-1024.aks -i privkeyfile
```

Note that the private key is read in as hex from the file specified with `-p`, which by default is a local directory file called `privkey`.

The file `autct-830000-500000-0-2-1024.aks`, or whatever else is specified (see [here](./docs/protocol-utxo.md) Appendix 1 for filename structure), should contain public keys in formaat: compressed, hex encoded, separated by whitespace, all on one line. The output is sent to the file specified by `-P` (by default `./proof.txt`), which should usually be around 2-3kB. The program will look for the pubkey corresponding to the given private key, in the list of pubkeys in the pubkey file, in order to identify the correct index to use in the proof.

`rpcserver`:

```
./rpcserver --keyset autct-830000-500000-0-2-1024.aks
```

As probably obvious, the idea here is that we run a service (somewhere) for a client to be able to throw serialized proofs at, and ask it to verify (quickly!) if the proof and the corresponding key image actually validate against the curve tree. If so, the user can credit whoever provided this proof, with some kind of token, service access, whatever, and also keep track of what key images have already been used (this code currently doesn't do that but it's the trivial part: just keep a list of used key images, and check). Here "quickly" should be in the 50-100ms range, for even up to millions of pubkeys. The RPC server takes a few seconds to start (loading precomputation tables and constructing the Curve Tree), and then serves on port as specified with `-p` at host specified with `-h` (default 127.0.0.1:23333).

`rpcclient`:

```
./rpcclient --keyset autct-830000-500000-0-2-1024.aks -P proof.txt
```

This client connects to the above server and calls the `verify()` function with a binary string taken directly from the file specified with `-P` (`./proof.txt` by default), and should return with `1`. Errors will give negative integers instead.

In the directory `testdata` there are example pubkey files containing approximately 50K and 100K pubkeys (approx) taken from all taproot outputs on signet between blocks 85000 and 155000, which you can use to test if you like. The private key `373d30b06bb88d276828ac60fa4f7bc6a2d035615a1fb17342638ad2203cafcf` is for one of those pubkeys (signet!), so if you use it, the proof should verify, and the key image you get as output from the verifier should be: `068a2b638740814678a2274f537084c0d1ef3ec46a6466b3ca0c2550ac0ebc1f80`. 

## Configuring

There is a config file auto-generated in `~/.config/autct/default-config.toml` (or similar).
Precedence operation is as you would expect: command line options take precedence over config file values, and updates will be persisted to that config file. Third in order of precedence is the default value.

Note that a current TODO is that the branching_factor field is not currently being used, but the others are. If you need to change it, edit it at the top of `utils.rs` and then recompile, until this is fixed.

The depth is the depth of the curve tree. The `generators_length_log_2` may be removed in future but it should be the smallest power of 2 that's bigger than `D(912+L-1)` where `D` is the depth and `L` is the branching factor. If it helps, for key sets less than 64000 in size, the defaults should be fine. The rpc port can also be configured here.

Finally, to actually *use* this as a tool, one should (in most cases) set the `context_label` field, using `-c` to something agreed by the verifier as defining usage in a particular domain, and the `user_string` with `-u` to a hex serialized BIP340 pubkey or alternate user string (see [here](./docs/protocol-utxo.md) Appendix 2). This defines the scope of usage of the resources represented by the (u)txo.

# Worked Example

Paths here assume you are in the root of the repository.

Put a hex serialized private key into a file in the current directory called `privkey`:

```
echo 373d30b06bb88d276828ac60fa4f7bc6a2d035615a1fb17342638ad2203cafcf > privkey
```

(you could change the permissions of this file but this is only a test).

Then compute the proof:

```
target/release/autct -k testdata/signet-pubkeys-85000-155000.txt
```

In a different terminal, but still in repository root, start the RPC server:

```
target/release/rpcserver -k \
testdata/signet-pubkeys-85000-155000.txt
```

Go back to the original terminal, and make a request from the rpc client,
to verify the proof:

```
target/release/rpcclient -P proof.txt -k \
testdata/signet-pubkeys-85000-155000.txt
```

Ouput log in rpcserver terminal should look similar to this:

```
Elapsed time for selrerand paramater generation: 58.00ns
Elapsed time for verifier gadget call: 2.15ms
Elapsed time for verifier calls: 46.28ms
Root is odd? false
Elapsed time for verify_curve_tree_proof: 49.00ms
Verifying curve tree passed and it matched the key image. Here is the key image: "068a2b638740814678a2274f537084c0d1ef3ec46a6466b3ca0c2550ac0ebc1f80"
```

Output of rpcclient should be just `1` for successful verification. Any negative number means the proof is not valid for the given Curve Tree.

(Process currently verified working on Ubuntu 22.04 and Debian 12)

# Testing

See more info [here](./testdata/README.md). 

# Security

See more [here](./docs/security-analysis.md).
