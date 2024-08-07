## RPC API for Autct

This defines the structures of requests and responses for the three RPC calls made available by an instance of the Autct server (instantiated with `./autct -M serve -k ...`).

Note that the fields of the `...Request` objects below do not contain `Option<>` fields; all fields are required to be provided by the calling client. However the responses contain `Option<>` fields so these may not always be present.

### Method: `RPCProver.prove`

Request object:

```rust
pub struct RPCProverRequest {
                pub keyset: String,
                pub depth: i32,
                pub generators_length_log_2: u8,
                pub user_label: String,
                pub privkey_file_loc: String,
                pub bc_network: String,
                pub encryption_password: String,
            }
```

Example json serialization:

```
{"keyset":"my-context:testdata/fakekeys-6.txt","depth":2,
"generators_length_log_2":11,"user_label":"name-goes-here",
"privkey_file_loc":"privkey-four","bc_network":"signet",
"encryption_password": "hunter2"}
```

#### Definition of request fields:

* `keyset` : must be a string of format "a:b" where a is the required context label and b is the keyset file. Server will reject requests with more than one element in this comma separated value list, and will reject if this context and keyset are not part of the list that it serves.
* `depth` : must be an even number; recommend not changing from the default value of `depth` in the config.
* `generators_log_length_2` : as above, do not change from the config default (11).
* `user_label`: currently unused, so set to any string.
* `privkey_file_loc`: this is the name of the file containing the private key. Use an absolute file path, or else, use the path relative to the location the server is running from.
* `bc_network` : one of `mainnet`, `signet`, `regtest`
* `encryption_password`: the password to decrypt the private key file.

Response object:

```rust
pub struct RPCProverResponse {
        pub keyset: Option<String>,
        pub user_label: Option<String>,
        pub context_label: Option<String>,
        pub proof: Option<String>,
        pub key_image: Option<String>,
        pub accepted: i32,
}
```

Example json serialization:

```
{"keyset":"testdata/fakekeys-6.txt","user_label":"name-goes-here",
"context_label":"my-context","proof":"yLUS...BZ0YA","key_image":"2f82e66e65d4202461500eef774a6270d355d8e20d9e15a5ec1a4fc7e3a4d34280","
accepted":0}
```

#### Definition of the response fields:

* `keyset` - echo of request
* `user_label` - echo of request
* `context_label` - echo of request
* `proof` - the example above is truncated. This is a bse64 serialization of the proof. Exact length may vary but 2.7kB approximately with default settings (in binary, pre base64 encoding).
* `key_image` - the key image (which is fixed per pubkey to prevent re-use). A 33 byte value encoded as a hex string.
* `accepted` - 0 for success, a negative integer otherwise. See `src/autct.rs` for detailed error codes.

Note that all fields except `accepted` are optional and may not be provided, in case of an error.

### Method: `RPCProofVerifier.verify`

Request object:

```rust
pub struct RPCProofVerifyRequest {
        pub keyset: String,
        pub user_label: String,
        pub context_label: String,
        pub application_label: String,
        pub proof: String,
    }
```

Example json serialization:

```
{"keyset":"testdata/fakekeys-6.txt","user_label":"name-goes-here",
"context_label":"my-context","application_label":"autct-v1.0",
"proof":"yLUS...BZ0YA"}
```

#### Definition of request fields:

* `keyset` - same note as above for `RPCProverRequest`.
* `user_label` - same note as above for `RPCProverRequest`.
* `context_label` - same note as above for `RPCProverRequest`.
* `application_label` - same note as above for `RPCProverRequest`.
* `proof` - base64 serialized string, exactly as returned in `RPCProverResponse`.


Response object:

```rust
    pub struct RPCProofVerifyResponse {
            pub keyset: String,
            pub user_label: String,
            pub context_label: String,
            pub application_label: String,
            pub accepted: i32,
            pub resource_string: Option<String>,
            pub key_image: Option<String>,
    }
```

Example json serialization:

```
{"keyset":"testdata/fakekeys-6.txt","user_label":"name-goes-here",
"context_label":"my-context","application_label":"autct-v1.0",
"accepted":1,"resource_string":"soup-for-you",
"key_image":"2f82e66e65d4202461500eef774a6270d355d8e20d9e15a5ec1a4fc7e3a4d34280"}
```

#### Definition of response fields:

* `keyset` - echo of request
* `user_label` - echo of request
* `context_label` - echo of request
* `application_label` - echo of request
* `accepted` - integer value of `1` if the verification of the proof passes. A negative value indicates that some part of the verification failed/rejected; see `src/autct.rs` for detailed error messages that are parsed from this integer.
* `resource_string` - will not be included if verification fails. If it succeeds, it will be a string that the server can optionally provide in response to the 'consumption' of the utxo/key image.
* `key_image`: a 33 byte value encoded as hex which is the key image corresponding to the proof (which the server stores in its database to prevent reuse).


### Method: `RPCCreateKeys.createkeys`

Request object:

```rust
pub struct RPCCreateKeysRequest {
    pub bc_network: String,
    pub privkey_file_loc: String,
    pub encryption_password: String
}
```

#### Definition of request fields

* `bc_network` - as for `RPCProverRequest`
* `privkey_file_loc` - as in `RPCProver Request`, except note that this is a file that will be *written to*, not read from.
* `encryption_password` - the private key (WIF format) will be written to a file and then encrypted using AES-GCM-SIV and Argon2, to this password.


Response object:

```rust
pub struct RPCCreateKeysResponse {
    pub address: Option<String>,
    pub privkey_file_loc: Option<String>,
    pub accepted: i32,
}
```

#### Definition of response fields
* `address` - a string containing a bitcoin address. The address provided will be of type `p2tr`, for the current network.
* `privkey_file_loc` - echo of request (acts as confirmation that the private key, in WIF format, has been written and encrypted to that file.)
* `accepted` - an integer. if 0, it means the operation succeeded, negative integers represent an error. See `src/autct.rs` for detailed error messages.
