Anonymous usage tokens from curve trees (WIP)
=====

(Caveat: read the section "Caveat", please. Also, this is not quite finished, hence "WIP", see details at the end.)

Goal: Be able to use a privacy-preserving proof of ownership of *a* public key in a set of public keys, as a kind of token with scarcity. In particular, it should be possible to create such a token from a very large anonmity sets (10s of thousands up to millions) with a verification time which is very short (sub second at least) so that it can be used practically in real systems.

More specifically, we imagine these public keys to be those of Bitcoin utxos (or perhaps just txos).

The basis of this is [Curve Trees](https://eprint.iacr.org/2022/756), implemented [here](https://github.com/simonkamp/curve-trees/tree/main). That construction allows one to prove set membership in zero knowledge, with pretty good computation and verification complexity, by essentially using an algebraic version of a Merkle tree, and using bulletproofs to get a ZKP of the validity of the "Merkle" proof.

Specifically, it can be made to work for Bitcoin public keys because of the existence of the 2-cycle of curves secp256k1 and secq256k1; we need such a 2-cycle to implement a Curve Tree construct (technically it works with a bigger cycle but the 2-cycle is optimal, since multiple bulletproofs over the same base curve can be aggregated).

That construction is not quite enough for usage of ownership of public keys as tokens; for that, there needs to be a mechanism to ensure no "double spend" of tokens. This line of thinking tends to lead to a "zerocoin" type of construction, and indeed the above paper introduces "Vcash" as doing exactly that. But this requires a globally synchronised accumulator to record (in a ZK way) the spending of each coin/commitment. Without such a "virtual ledger", the other way you could record "usage" of a key in the set is with a key image, a la Cryptonote/Monero ring signatures. This allows more localized and "loosely-coupled" verification of no-double-spend, depending on thie use case.

This "key image" approach can be implemented as described here in this repo, in [this document](./aut-ct.pdf). It's a simple additional ZK proof of knowledge of the opening of a Pedersen commitment, tied to a key image, using completely standard Sigma protocol techniques.

Caveat
==

**Everything here is completely experimental and not safe in any way** (not helped by the fact I am a neophyte in Rust!). Importantly, even the underlying Curve Trees code was *only* written as a benchmarking tool, and therefore even that is not safe to use in anything remotely resembling a production environment.

If you choose to play around with this stuff for Bitcoin projects I suggest using signet for now.

Installation
==

Install curve trees, then install this project inside it:

```
git clone https://github.com/simonkamp/curve-trees
cd curve-trees
git clone https://github.com/AdamISZ/aut-ct
```

Temporary:
For now I need to patch the universal hash construction so it can be recreated by more than one participant (the idea is that the base tree is transparently constructible by all parties, from the same set of bitcoin/utxo pubkeys; but the ZK proof construction requires that the tiebreaker for the y-coord of a compressed EC point take a certain algebraic form (this is called in the paper, and code, "permissible points"), and *this* requires passing through a "universal hash function" which in the code is just constructed from random inputs; the following patch forces those vars to be a fixed value, so they're the same between both parties. I'm not 100% sure what the right solution is, but this is just a "for now, to make it work":

```
diff --git a/relations/src/permissible.rs b/relations/src/permissible.rs
index 032d0ad..e1d0eb5 100644
--- a/relations/src/permissible.rs
+++ b/relations/src/permissible.rs
@@ -18,8 +18,14 @@ pub struct UniversalHash<F: Field> {
 impl<F: Field> UniversalHash<F> {
     pub fn new<R: Rng>(rng: &mut R, a: F, b: F) -> Self {
         Self {
-            alpha: F::rand(rng),
-            beta: F::rand(rng),
+            // Doctoring this to just use a fixed value for now,
+            // instead of the rng; TODO we want deterministic
+            // random values for both prover and verifier
+            // to come up with the same SRParams values:
+            alpha: F::try_from(42u64).unwrap(),
+            beta: F::try_from(690u64).unwrap(),
+            //alpha: F::rand(rng),
+            //beta: F::rand(rng),
             a,
             b,
         }
```

Running
===

You need to edit the Cargo.toml of the `curve-trees` repo (so `cd ..` to go up one level from `autct`). Add `autct` to the list of `members`, and add a section for `workspace.package`, as below:

```
[workspace]
members = [
    "bulletproofs",
    "relations",
    "autct"
]

[workspace.package]
name = "curve_trees"
version = "0.1.0"
```

Then, build the project with `cargo build --release` (without release flag, the debug version is very slow), then the binaries are in `curve-trees/target/release`. They are called `autct` for the prover and `autct-verifier` for the verifier. Examples:

```
./autct 37......cf somepubkeys.txt
```

The prover provides a hex-encoded 32 byte string, as private key, as first argument, then a plaintext file with a list of pubkeys, compressed, hex encoded, separated by whitespace, all on one line. The output is `proof.txt`, which should usually be around 2-3kB. The program will look for the pubkey corresponding to the given private key, in the list of pubkeys in the pubkey file, in order to identify the correct index to use in the proof.

```
./autctverify somepubkeys.txt
```

The verifier must also be provided the same pubkey text file, and checks the content of `proof.txt` and outputs the key image if it verifies (actually, it just panics and crashes if it doesn't :laughing: ). The idea is that if a person tries to reuse their key, it will "verify" but you can reject it if it has the same key image as a previous run.

In the directory `testdata` there is an example pubkey file containing approximately 48000 pubkeys taken from all taproot outputs on signet between blocks 85000 and 155000, which you can use to test if you like. The private key `373d30b06bb88d276828ac60fa4f7bc6a2d035615a1fb17342638ad2203cafcf` is for one of those pubkeys (signet!), so if you use it, the proof should verify, and the key image you get as output from the verifier should be: `a496230673e00ed72abe37b9acd01763620f918e5618df4d0db1377d0d8ba72d80`. 

Additionally the depth and branching factors of the Curve Tree are still hard coded (2, 256 respectively); obviously this can be mode configurable.

Yes, this is all laughably primitive for now.

TODO
===

Needs several basic things to flesh it out. Tests of the PedDLEQ primitive. More sample test data ( a set of test vectors). User choice of tree parameters (depth, height), and/or choice of parameters depending on data set. Ability to enter secret key in a safer way than on the command line(!), as well as many other security considerations. An API/interface. Proper command line arguments, help messages etc. Standard format for inputting keys, perhaps a bolt on tool to take data from Bitcoin blocks and convert to a more compact format for public keys. Need to solve the question of how to make the universal hashing for permissible points be deterministic (see patch above).

