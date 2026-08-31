# multisig

[![ci](https://github.com/AvhiMaz/multisig/actions/workflows/ci.yml/badge.svg)](https://github.com/AvhiMaz/multisig/actions/workflows/ci.yml)

multisig is a squads-style multisig program, written in [pinocchio](https://github.com/anza-xyz/pinocchio) with no allocator and zero-copy account layouts.
an owner proposes a transaction, owners vote on it, and once approvals reach the threshold anyone may execute it.
