# AGENTS.md

This file guides AI coding agents working in this repository. Keep it concise.

## Overview

A Go library of reusable Cadence 1.0 transaction templates for the Flow blockchain,
exposed from the single package `transactions` (module
`github.com/onflow/cadence-standard-transactions`). Each template is a
`*SimpleTransaction` builder returning Cadence source as a Go string, typically wrapped
in a `while` loop scaffold for benchmarking-style workloads. The repository ships no
usage documentation beyond a minimal README; consumers import the package and read the
source directly.

## Build and Test Commands

No Makefile, CI workflow, or `*_test.go` files exist. Use standard Go tooling:

- `go build ./...` — compile all packages
- `go mod tidy` — sync the module graph (Go `1.24.0`, toolchain `go1.24.3` per `go.mod`)

Do not fabricate `go test` invocations; this repo has no tests.

## Architecture

Single Go package under `transactions/`:

- `transactions/types.go` — `Transaction` interface, `TrimAndReplaceIndentation` helper.
- `transactions/transaction.go` — `SimpleTransaction` struct (builder with
  `prepareBlock`, `executeBlock`, `fieldDeclarations`, `setupTemplate`),
  `NewSimpleTransaction`, `LoopTemplate`.
- `transactions/helpers.go` — `StringOfLen`, `StringArrayOfLen`, `StringDictOfLen`,
  `simpleTransactionWithLoop` (unexported).
- `transactions/simple.go` — 53 exported `var X = func(...) *SimpleTransaction` template
  bindings (per `grep -cE '^var [A-Z].*= func\('`) covering account, storage, crypto,
  array/dict, parsing, and BLS/ECDSA signature workloads.
- `transactions/contract.go` — templates that invoke `TestContract` (empty call,
  `emitEvent`, `mintNFT`, dict event).
- `transactions/contract.cdc` — Cadence contract `TestContract`, embedded via
  `//go:embed contract.cdc` into `TestContractCode []byte`. Defines an `NFT` resource,
  events, and a `FlowTransactionScheduler.TransactionHandler` at
  `/storage/testCallbackHandler` and `/public/testCallbackHandler`
  (`contract.cdc` lines 56-57).
- `transactions/scheduled_transactions.go` — `scheduleTemplate` wrapping
  `FlowTransactionScheduler.schedule(...)`, with payload-sizing variants
  (`ScheduledTransactionAndExecuteTransaction`, `…WithLargeDataTransaction`,
  `…WithLargeArrayTransaction`).

Only direct dependency: `github.com/onflow/crypto v0.25.3` (used in `simple.go` for
BLS signature and public-key aggregation helpers).

## Conventions and Gotchas

- Templates are exposed as package-level `var` bindings, most typed
  `func(loopLength uint64) *SimpleTransaction`. Follow this pattern when adding
  templates — see the existing examples in `simple.go`.
- Bodies that loop should use `simpleTransactionWithLoop` or `LoopTemplate` so the
  generated `while i < N` scaffold stays uniform (`transaction.go` lines 66-76).
- Cadence source is embedded as raw Go string literals. Tabs in those strings are
  normalized by `TrimAndReplaceIndentation` (`types.go` line 17); avoid hand-aligning
  indentation.
- `contract.cdc` is embedded into Go via `//go:embed` — edits to the `.cdc` file are
  picked up at the next `go build`. Do not duplicate the contract source into `.go`
  files.
- The `flow-go-sdk` dependency was intentionally removed (commit 467e9c5). Do not
  reintroduce it; `github.com/onflow/crypto` is the only non-stdlib direct dep.
- `FlowTransactionScheduler` is imported by name in `contract.cdc` with no address
  alias defined in this repo. The consumer resolves it at deployment time.
- Storage paths used as fixtures follow a short-prefix naming scheme
  (`/storage/ABrSt`, `/storage/ACpDStSv`, `/storage/DestDict`, etc.). Reuse existing
  prefixes when extending a related template rather than inventing new ones.

## Files Not to Modify

- `go.sum` — regenerate via `go mod tidy` instead of editing by hand.
