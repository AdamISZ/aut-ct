# How to derive a keyset for AutCt by scanning the whole utxo set

You need:
* Bitcoin Core (can be pruned for this, but ofc fully synced)
* [This](https://github.com/theStack/utxo_dump_tools) repo cloned on your machine
* [This](https://github.com/AdamISZ/aut-ct-test-cases) repo cloned on your machine
* Installation of Python3
* Installation of Golang

1. Query the bitcoind RPC:

```
bitcoin-cli dumptxoutset "yourabsolutepathfilename"
```

(which can take a long while; it's a full utxo snapshot, which currently contains approx 165M keys; I have seen 10-15 minutes on a good-laptop-equivalent VPS).

2. Run this Golang program:

https://github.com/theStack/utxo_dump_tools/blob/master/utxo_to_sqlite/utxo_to_sqlite.go

.. with appropriate input (the above "yourabsolutepathfilename") and output file names. The output file can then be used as input for step 3. As you can probably tell, this is a sqlite3 database file.

This process will probably take another 10-15 minutes.

3. Run this Python script:

https://github.com/AdamISZ/aut-ct-test-cases/blob/master/src/filter_utxos.py

(See the notes on the repo; install with `pip install .` before running the script).

Example syntax:

```
python3 filter_utxos.py 500000 utxos16Mar.sqlite autct-830000-500000-0-2-1024.aks
```

... noting that here, I'm using an example of the key filename syntax defined in Appendix 1 [here](./protocol-utxo.md).

Note that the output file produced by that script is in the format taken by https://github.com/AdamISZ/aut-ct for usage tokens from a pubkey set.

Depending on your chosen filter, this can take 15-60 seconds for a query, as a rough guideline.

TODO:
There are pros and cons to allowing repeated pubkeys here, depending on the usage scenario. For now, duplicates are allowed, so a post-processing step like list(set(x)) may be needed.
