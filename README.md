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

## Key operations

The initial key is seeded ahead of the mppx TAP + Web Bot Auth demonstration.
To rotate it:

1. Generate the replacement key outside this repository.
2. Add its public JWK while retaining the previous key for an overlap window.
3. Verify each `kid` is the RFC 7638 thumbprint of `{ "crv", "kty", "x" }`.
4. Merge and deploy, then begin signing with the replacement key.
5. Remove the previous key after the maximum request lifetime plus the
   five-minute directory cache lifetime.

Run `npm test` before publishing a directory change.
