## Documentation of auditor function in aut-ct

The auditor function allows a variant of **privacy-preserving proof of assets**.

The protocol for proving possession of assets within a BTC (satoshi) range, without revealing which, out of the set of taproot utxos in the keyset file, are referred to, is detailed in [this pdf](./privacy-preserving-proof-of-assets.pdf) with substantial explanation of the reasoning.

In short, we prove statements like:

* I own the private keys to a set of 10 taproot Bitcoin utxos out of all taproot utxos that are more than 0.05 BTC in size, whose total value is in the range 5.0 BTC to 7.0 BTC, but I am not revealing anything else about the individual utxos.

The utxos must be of taproot type, and the anonymity set is a corresponding key file, as is used in the aut-ct function detailed on the main page of this repo. The individual utxos used for proving must all have different addresses, otherwise the proof will be rejected.

The additional supporting document on [multirepresentation](./multirepresentation.pdf) details a sub-component of this proof, that can prove that a number of Pedersen commitments have the same ``representation'' (secret witness multipliers) with respect to different vectors of base points (or generators).

Example usage
======

Run the server exactly as for `aut-ct` functions detailed on the main page:

```
target/release/autct -M serve -k mycontext:something.aks -n signet
```

But use the `auditprove` method from the client:

```
target/release/autct -M auditprove -k mycontext:something.aks -n signet -H 127.0.0.1 -i some-privkeys.txt --audit-range-min 5000 --audit-range-exponent 12
```

First note the two new option flags ``--audit-range-min`` which corresponds to \(k\) in the description, and ``-audit-range-exponent`` which corresponds to \(n\). Second, the format of `some-privkeys.txt` is like this:

```
cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87Lc8ycuM4,5000
cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87M73ZA41f,2000
```

that is, it is pairs (raw WIF private key, value-in-sats) one per line, remembering that these proofs are over the values of multiple utxos, not just one.

To verify an existing proof file, you need to know what ``audit-range-min`` and ``audit-range-exponent`` are being claimed (for now; this is actually in the proof serialization so it can be extracted), and run the `auditverify` method:

```
target/release/autct -M auditverify -k mycontext:something.aks -n signet -H 127.0.0.1 -P some-proof.txt --audit-range-min 5000 --audit-range-exponent 12
```

If successful, the following will be printed:

```
Audit is valid! The utxos' total value is
between 5000 and 9096 satoshis.
```

For more details on how to generate correct "keyset" (really, commitment-set) files \*.aks, from signet or mainnet utxo dumps, see the `audit` flag in `filter-utxos.py` in the subsidiary [repo](https://github.com/AdamISZ/aut-ct-test-cases) and information about generating keysets [here](https://github.com/AdamISZ/aut-ct/blob/auditing/docs/utxo-keysets.md).

