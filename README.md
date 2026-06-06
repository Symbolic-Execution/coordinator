# coordinator

Rust coordinator service for the symbolic execution stack.

Current slice:

- exposes the public HTTP API from `repos/spec/coordinator`
- verifies real EIP-712 signatures for reader registration and disclosure
- tracks nonce replay protection and disclosure request state in memory
- proxies reader registration and `to-reader` operations to `mpc`
- proxies handle resolution to the coprocessor
- uses an in-memory authorization backend for controller lookup in tests

Not implemented yet:

- on-chain controller and policy reads
- durable storage for readers, nonces, and disclosures
- production coprocessor integration contract validation
- background polling or retry workers

## Run

```bash
cargo run
```

Environment:

- `COORDINATOR_BIND_ADDR` default `127.0.0.1:4000`
- `COORDINATOR_MPC_URL` default `http://127.0.0.1:3000`
- `COORDINATOR_COPROCESSOR_URL` default `http://127.0.0.1:5000`
- `COORDINATOR_EIP712_NAME` default `Coordinator`
- `COORDINATOR_EIP712_VERSION` default `1`
- `COORDINATOR_EIP712_SALT` default `0x9999...99`

## Test

```bash
cargo test
```
