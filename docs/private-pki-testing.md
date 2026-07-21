# Private PKI TLS Testing

Sponzey Edge validates TLS server authentication without public DNS or an
external certificate authority. This test path is separate from Let's Encrypt
and does not weaken certificate verification.

## Test Chain

The test-only fixture creates this hierarchy for `app.private.test`:

```text
Sponzey Test Root (CA=true, pathLen=1)
  -> Sponzey Test Issuing CA (CA=true, pathLen=0)
       -> app.private.test (CA=false, serverAuth, DNS SAN)
```

Required inbound mTLS uses a separate client hierarchy:

```text
Sponzey Test Client Root (CA=true, pathLen=1)
  -> Sponzey Test Client Issuing CA (CA=true, pathLen=0)
       -> operator.private.test (CA=false, clientAuth)
```

The server certificate store receives only the leaf-first `leaf + Intermediate`
fullchain and the leaf private key. The client trust store receives only the
Root certificate. Root and Intermediate private keys remain inside the test
fixture while certificates are generated and are never written to the product
data directory, backup archive, logs, or evidence.

## Authentication Matrix

The `edge-proxy` tests use the production rustls server adapter and mio HTTPS
runtime over loopback. Validation is enabled for every client.

| Case | Expected result |
| --- | --- |
| Root trusted, complete chain, correct SNI | handshake and HTTPS forwarding succeed |
| Unrelated or empty trust | client rejects the server |
| Wrong SNI | client rejects the server identity |
| Missing Intermediate | chain construction fails |
| Reversed chain | server material loading fails |
| Expired or not-yet-valid leaf | client rejects the server |
| Leaf/private-key mismatch | material validation fails before runtime install |
| Required mTLS, trusted complete clientAuth chain | handshake and forwarding succeed |
| Required mTLS, no client certificate | handshake fails before HTTP parsing |
| Required mTLS, unrelated Root or missing Intermediate | handshake fails before HTTP parsing |
| Required mTLS, serverAuth-only or invalid validity | handshake fails before HTTP parsing |

The successful forwarding assertion also requires the upstream request to
contain `X-Forwarded-Proto: https`. A failed handshake must affect only that
connection; a subsequent trusted request on the same listener must succeed.

## Run

```bash
cargo test -p edge-proxy private_pki -- --test-threads=1
```

These tests prove local private-chain trust, hostname, validity, key matching,
strict upstream authentication, required inbound mTLS, and HTTPS forwarding.
They do not claim public CA issuance, revocation checking, optional or
identity-authorizing mTLS, automatic renewal, or Let's Encrypt readiness.

The fixture is also the verification foundation for planned outbound mTLS,
optional/client-identity authorization, wildcard/SNI selection, TLS passthrough,
and certificate replacement/expiry workflows. Those capabilities are not
implemented yet, but they are not excluded merely because public certificates
are unavailable.
