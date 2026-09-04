# multisig

[![ci](https://github.com/AvhiMaz/multisig/actions/workflows/ci.yml/badge.svg)](https://github.com/AvhiMaz/multisig/actions/workflows/ci.yml)

multisig is a multisig program for solana, written in [pinocchio](https://github.com/anza-xyz/pinocchio) with no allocator and zero-copy account layouts.
an owner proposes a transaction, owners vote on it, and once approvals reach the threshold anyone may execute it.

owner and threshold changes are ordinary proposals targeting this program, so they cost the same threshold as a spend.

## proposals

a proposal holds a compiled message in solana's wire format: deduplicated account keys, instructions referencing them by index, and address lookup tables. one approval can therefore:

- settle several cpis atomically
- use accounts loaded from lookup tables, resolved and verified on-chain rather than trusted
- sign as the vault, or as ephemeral pdas derived from the proposal, which is what lets it create accounts that sign for themselves

messages too large for one transaction upload in chunks, against a length and sha-256 committed up front.
