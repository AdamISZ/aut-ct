TEST DATA
=======

Test vectors

Currently there is a single json file `testcases.json` of 10 test cases for the Pedersen-DLEQ primitive. In each one is stored a transcript of all the data used to construct the proof as hex values. For more details see `run_test_cases` in `src/peddleq.rs`.

For how the test vectors in `testcases.json` were constructed, or to make new test cases, see the details in [this repo](https://github.com/AdamISz/aut-ct-test-cases). In future this repo may be extended to creating tools to create key sets as described next:

Key sets

This is a holding area for various keysets for testing. More will be added.

There is a large set of 48000 (approx) public keys derived from signet, taproot outputs, generated from the range of blocks indicated.

The two other keysets are generated from private keys corresponding to integers 1,2,3... with the maximum being one less than the digit shown. So for example the private key of the first public key is 010101..01 (32 single bytes of '1'). So an example proof invocation would be `./autct 0303...03 fakekeys-6.txt`.

