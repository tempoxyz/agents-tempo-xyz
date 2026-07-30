# agents.tempo.xyz

Public identity material for Tempo-operated web agents.

## Web Bot Auth directory

Requests advertise this directory origin with:

```http
Signature-Agent: webbot="https://agents.tempo.xyz"
```

A verifier resolves the public key set from:

```text
https://agents.tempo.xyz/.well-known/http-message-signatures-directory
```

The response follows
[`draft-meunier-webbotauth-httpsig-directory-00`](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-directory/).
It is intentionally public and read-only. This repository contains public
verification keys only; private signing keys must never be committed or
deployed here.

The static response is signed offline by the advertised key. Vercel publishes
the resulting `Content-Digest`, `Signature-Input`, and `Signature` fields; it
does not receive the private key.

## Key operations

The initial key is seeded ahead of the mppx TAP + Web Bot Auth demonstration.
To rotate it:

1. Generate the replacement key outside this repository.
2. Add its public JWK while retaining the previous key for an overlap window.
3. Verify each `kid` is the RFC 7638 thumbprint of `{ "crv", "kty", "x" }`.
4. Generate a response signature for every published key and update the
   response signature headers.
5. Merge and deploy, then wait at least the five-minute directory cache
   lifetime before signing requests with the replacement key.
6. Remove the previous key after the maximum request lifetime plus the
   five-minute directory cache lifetime.

Generate the response fields without exposing the private key to Vercel:

```sh
WBA_PRIVATE_JWK_PATH=/secure/path/to/private.jwk.json \
WBA_DIRECTORY_CREATED=1785446184 \
WBA_DIRECTORY_EXPIRES=1816982184 \
npm run sign
```

During an overlap rotation, set `WBA_PRIVATE_JWK_PATHS` to the
platform-delimited paths for every published key. The generator emits one
response signature per key.

Copy the generated public header values into `vercel.json`, then run
`npm test` before publishing a directory change.
