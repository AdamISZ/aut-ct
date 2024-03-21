This is currently a rough draft.

# Protocol to enforce scarcity with anonymity through AUT-CT tokens on bitcoin utxos

# 1. Roles

This protocol is defined for multiple actors called **clients** to access a "resource" provided by a single actor called a **server**. The server and client may be local or physically remote; if the latter then they should communicate **only** over an authenticated-encrypted channel.

The "resource" here is nowhere specified and does not affect the protocol directly. The server may be providing more than one resource, and therefore may define more than one **context** (see next section) for running multiple different protocol executions, in series with one client, and in parallel with many clients.

# 2. Setup phase

For their first communication with the **server**, the **client** MUST send the request `setup`, an API query that is defined to have the following query fields:

```
{
    "version-range": (a, b),
    "application-label": "default-application-label",
    "context-label": "default-context-label",
    "user-label": "default-user-label",
    "keyset": "default-keyset-filename"
}
```

The server MUST reject the message if its own version (of this protocol) is not between `a` and `b` inclusive. The server MUST reject the message if the `application-label` field does not match its own (which is a constant over all of its protocol executions). The server MUST reject the message if the `default-context-label` is not a member of the set of context labels it has currently defined as active. The server MUST reject the message if `keyset` is not in a valid keyset filename format (see Appendix 1). The server MAY reject the message for any other reason.

In case the server accepts the message, it MUST send `setup-response`; if it rejects, it MAY send `setup-response`, with the following fields:

```
{
    "version": c,
    "result" : true / false,
    "keysets": ["chosen-keyset-name",]

}
```

About the `keysets`: The **client** chooses ONE keyset name (see Appendix 1) that fits the filter that is suitable for the utxo(s) it plans to use. The **server** MAY choose to respond with a list of length one: the same keyset, meaning agreement. Or it MAY choose a different `keysets` list, for example because it has not cached in advance the keyset that the client suggests, it can respond with a list of keysets that it *has* cached, thus informing the client, who can choose to continue or not.

The reason for this negotiation is that preparing keysets is an expensive operation which cannot be done in real time (the number of keys varies from 10^5 to 10^7, typically, and these must be scanned from the utxo set in a very expensive operation).

Having received result `true`, the **client** MAY now start the next phase of communication on the open channel.

# 3. The service request

The **client** must prepare an AUT-CT token as follows, to craft the service request:

To select a utxo U, it must check:
* Is `U` in the keyset S that was negotiated (or chosen by **client** after negotiation)?
* Has the private key `x` for `U` ever been used before for the same (application-label, context-label) tuple? Reject if yes.

Then create the AUT-CT token with an execution of the algorithm:
Input: (utxo U, pubkey P, private key x, keyset S, application-label lA, context-label lC, user-label lU)

Output: a single binary string. The typical size is 3kB.

The request is sent as follows from the **client** to the **server**:

```
{
    "keyset": "chosen-keyset-name",
    "user-label": "chosen-user-label",
    "context-label": "chosen-context-label",
    "application-label": chosen-application-label",
    "proof": "..."
}
```

# 4. The service response

On receiving the service request, the **server** makes these checks:

* The server MUST reject the request if `keyset` is not included in the `keysets` list it sent during setup.
* The server MUST reject the request if `context-label` is not included in its list of valid contexts.
* The server MUST reject the request if `application-label` is not its own application label.
* The server MUST reject the request if `user-label` is malformed (see Appendix 2).
* The server MUST reject the request if verification on `proof` fails.

On verification: the input to the verification algorithm is:
(keyset S, application-label lA, context-label lC, user-label lU, proof)

Output: a boolean true/false

The response is sent as follows from the **server** to the **client**:

```
{
    "keyset": "chosen-keyset-name",
    "user-label": "chosen-user-label",
    "context-label": "chosen-context-label",
    "application-label": chosen-application-label",
    "accepted": true / false,
    "resource-string": "..." or None,
    "key-image": "deadbeef.." or None,
}
```

The first four fields are present to ensure disambiguation with any other parallel queries (TODO: needed or not?).
The server MUST send the result of the verification algorithm, as the field `accepted`.

If `accepted` is `true`:
* `resource-string` is whatever the **server** has defined as the resource that the client is requesting, such as: an API key, a cookie etc. It should be non-null for this case.
* `key-image` is a point on the elliptic curve secp256k1, serialized as according to BIP340. This is exactly the point that was serialized in the `proof` that the **client** sends; this field acts as a confirmation to the client, that this value is now stored and cannot be reused for this (application-label, context-label) tuple.

If `accepted` is `false`:
* `resource-string` MUST be null
* `key-image` MUST be null

# Appendix 1

TODO

# Appendix 2

TODO
