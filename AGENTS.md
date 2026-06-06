# Coordinator Agent Instructions

## Project Overview

This repo implements the Coordinator HTTP API: public configuration,
authorization-aware disclosure lifecycle, reader registration, and disclosure
execution through `MPC` and the coprocessor.

The sibling spec repo is the current source of truth. Before changing
behavior, read:

- `../spec/README.md`
- `../spec/coordinator/coordinator-api.md`
- `../spec/mpc/mpc-api.md`
- `../spec/coprocessor/coprocessor-api.md`

## Coding Style

Use the same Rust architecture style established in `coprocessor`:

- Prefer deep modules with stable interfaces and concentrated invariants.
- Keep `main.rs` thin: environment parsing, adapter wiring, and process startup
  only.
- Put HTTP transport in `api`, remote adapters in `backends`, and request
  lifecycle rules in `service`.
- Keep public data shapes in `types` and runtime-held config in `state`.
- Test behavior through public interfaces and HTTP flows, not private helpers.

## Structure

- Root crate exposes modules through `lib.rs`.
- Runtime/process configuration belongs in `config.rs`.
- Transport-independent request handling belongs in `service.rs`.
- Signing and authorization helpers stay in their own focused modules.

## Security And Privacy

- Do not log signatures, plaintext private values, DEKs, or decrypted payloads.
- Keep authorization failures distinct from malformed input and unavailable
  backends.
- Treat handle ids, controller resolution, and EIP-712 fields as part of the
  security contract.
