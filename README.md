# multisig

[![ci](https://github.com/AvhiMaz/multisig/actions/workflows/ci.yml/badge.svg)](https://github.com/AvhiMaz/multisig/actions/workflows/ci.yml)

multisig is a multisig program for solana, written in [pinocchio](https://github.com/anza-xyz/pinocchio) with no allocator and accounts read in place.
an owner proposes a transaction, owners vote on it, and once approvals reach the threshold anyone may execute it.

owner and threshold changes are ordinary proposals targeting this program, so they cost the same threshold as a spend.

## owners

up to 4096 of them. the owner set is a variable-length tail on the multisig account, so a three owner wallet pays for three owners and the account grows and shrinks as the set changes.

a vote is a bit at the owner's position, not a copy of their address, so a proposal costs a byte per eight owners. that keeps a large owner set affordable: at a thousand owners the config is 33 kB and a proposal is still under 700 bytes.

a transaction caps how many owners fit in one `init_multisig` call at roughly thirty. beyond that, create a small multisig and grow it with `add_owner`.

## proposals

a proposal holds a compiled message in solana's wire format: deduplicated account keys, instructions referencing them by index, and address lookup tables. one approval can therefore:

- settle several cpis atomically
- use accounts loaded from lookup tables, resolved and verified on-chain rather than trusted
- sign as the vault, or as ephemeral pdas derived from the proposal, which is what lets it create accounts that sign for themselves

messages too large for one transaction upload in chunks, against a length and sha-256 committed up front.

## safeguards

- approval latches at the threshold; execution never recounts
- an owner or threshold change makes older proposals stale, so votes cast under one rule cannot settle under another
- an optional time lock defers execution, and cancelling an approved proposal takes the same threshold that approved it
- owners can be limited to initiate, vote or execute

## status

every instruction, config action and refusal path is covered by integration tests against the compiled program, and the whole lifecycle runs against a devnet deployment. never audited, so do not use it with real funds.
