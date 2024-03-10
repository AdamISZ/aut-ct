# Security analysis

This is an initial, rough draft of some considerations that need to be taken into account. Hopefully a more formal analysis can follow up, at some point.

This project fits the template of the well-known truism in cryptography (perhaps "fallacy of composition"):

> If cryptosystem A is proven secure and cryptosystem B, separately, is proven secure, it does not follow that the cryptosystem C = (A AND B) is secure.

This would apply specifically to the weak tie-ing together of "D is proven a rerandomisation of an element of set S with produces curve tree T" and "(D, E) is a Pedersen commitment to a key x with randomness r (with (x,r) the secret witness) such that I prove knowledge of (x, r) *and* E is xJ where J is a separate NUMS generator".

The second quoted sentence of course refers to the "Pedersen-DLEQ proof" construction that is described in the pdf file in the root of this repository.

For the rest, for brevity, we'll refer to Curve Tree proof as CTP and Pedersen-DLEQ proof as PDP.

# Intended security guarantees

These are:

1. Producing a CTP that a given point C~ is a rerandomisation of one of the points P in the set S (i.e. it is xG + rH where xG=P), when it is not, should be reducible to a hardness assumption (ECDLP or family).
2. Producing a pair (CTP1, PDP1) and another pair (CTP2, PDP2) where the element S implicitly (secretly) referred to is the same, but the E=xJ value in PDP1,2 are different, should be reducible to a hardness assumption (ECDLP or family)
3. An adversary in possession of knowledge of the secret keys of *only* N elements of S, as well as in possession of K instances of valid proof pairs (CTP, PDP) for arbitrary other elements of S, producing N+1 proof pairs (CTP1..N+1, PDP1..N+1), that all validate, should be reducible to a hardness assumption (ECDLP or family).
4. An adversary possessing N-1 secret keys of the N members of the set S deriving information about the secret key of the remaining 1 member of S, given K valid proof pairs (CTP, PDP) for that member, with more than negligible probability (parameterised by K) should be reducible to a hardness assumption (ECDLP or family).

Number 1 in this list is already the topic of the security proof of the Curve Trees paper.

Number 3 and 4 are (very rough descriptions) of typical requirements of unforgeability and zero knowledgeness. In other words, a serious attempt to analyze security w.r.t forgery or key leakage has to *at least* account for an attacker's possible knowledge of a bunch of other valid proofs, and an attacker's possible ownership of multiple other (in the extreme, *all* other) elements of the set from which the proofs are derived. Number 2 should probably be beefed up similarly, but it refers specifically to the "key image" part of the Pedersen-DLEQ proof.


