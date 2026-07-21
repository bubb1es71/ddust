# AGENTS.md

Guidance for LLM coding agents working in this repository.

## Project overview

`ddust` is an experimental Rust CLI implementing [BIP451 (Dust UTXO Disposal Protocol)](https://github.com/bitcoin/bips/blob/master/bip-0451.md). It finds dust-attack UTXOs in descriptor-based, watch-only wallets and disposes of them via low-fee transactions that spend the entire dust amount as fees to an OP_RETURN output.

Key dependencies: `bdk_wallet` 3, `bdk_bitcoind_rpc` (sync via Bitcoin Core RPC), `bdk_redb` (persistence), `clap` 4 (derive API).

## Repository layout

- `src/main.rs` (~2000 lines) — the entire binary. There is no `lib.rs` and no module tree. Do not split it into modules unless the task explicitly calls for it. Sections, top to bottom:
  - `main()` — clap parsing, tracing setup, RPC client, command dispatch
  - `cmd_*` handlers — `desc`, `add`, `list`, `spend`, `broadcast`
  - wallet persistence — `create_wallet` / `load_wallet` / `sync_wallet` / `wallet_names` (redb, one db file per network: `ddust-<network>.redb`)
  - dust detection — `is_dust`, `estimate_input_vsize`, `get_input_vsize`
  - mempool batching / RBF — `find_unconfirmed_ddust_txs`, `is_ddust_tx`, `add_foreign_utxos`, `find_batchable_txs`, `CandidateTx`
  - `mod tests` (bottom of file) — unit and integration tests
- `src/test_calc.rs` — fee/vsize calculation tests (included via `#[cfg(test)] mod` in `main.rs`)
- `src/test_env.rs` — regtest test environment (`TestEnv`, spawns bitcoind via `corepc-node`)
- `Justfile` — task runner: build/test recipes plus regtest node and wallet RPC helpers
- `data/` — local runtime state (gitignored)
- `docs/` — design/background material
- `.github/workflows/rust.yaml` — CI gates

## Commands

```bash
just fmt      # cargo fmt
just clippy   # cargo fmt, then cargo clippy --tests   (note: formats first)
just build    # clippy, then cargo build --tests
just test     # cargo test --tests
just run ...  # cargo run -- -d data -c regtest ...
```

CI gates that must pass (`.github/workflows/rust.yaml`):

```bash
cargo fmt --all --check
cargo clippy -- -D warnings
cargo build
cargo test
```

### Testing requires bitcoind

`cargo test` spawns a regtest node via `corepc-node`. Set `BITCOIND_EXE` to a bitcoind binary first, or the tests fail:

```bash
export BITCOIND_EXE=/path/to/bitcoind
```

Download instructions are in the README "Testing" section. CI uses Bitcoin Core 31.0.

## Conventions

- Rust 2024 edition, toolchain 1.97.1+ (pinned in `rust-toolchain.toml`; rustfmt config in `rustfmt.toml`)
- Commits use conventional-commit style, lowercase type prefix: `fix: ...`, `test: ...`, `refactor: ...`, `doc: ...` (see `git log`)
- **stdout is for command output only** (JSON, PSBTs, txids, descriptors). All diagnostics go to stderr via `tracing` (`debug!`, `info!`, `error!`). Never add `println!`/`eprintln!` for logging
- Clippy warnings are denied in CI (`-D warnings`); fix warnings, don't silence them

## Behavioral invariants — do not break these

- A ddust transaction is identified by exactly one OP_RETURN output and all inputs signed with sighash `ALL|ANYONECANPAY` (`is_ddust_tx`). Sighash parsing must handle both ECDSA (legacy/P2SH/P2WSH) and taproot key-path inputs
- `list` and `spend` skip dust UTXOs at any address that also holds an unspent non-dust UTXO (public-key exposure / quantum-risk guard); `--unsafe` overrides this
- Default dust threshold is 546 sats (`--amount`); default chain is regtest (`--chain`)
- Mempool batching must satisfy RBF replacement rules: the combined fee rate must exceed the highest replaced ddust tx fee rate by at least 0.1 sat/vB, and the OP_RETURN data of the first replaced tx must be preserved

## Safety rules for agents

- Never run `spend` or `broadcast` against `-c main` unless the user explicitly asks
- Justfile `rpc` group recipes (`just start`, `just create`, `just generate`, `just send`, ...) operate on a local regtest node in `data/`
- Running the tool itself (not tests) requires Bitcoin Core 31+ with RPC + cookie auth, a tor proxy, and `-privatebroadcast` — see README "Requirements"

## When changing code

1. `just build` (formats, lints, compiles including tests)
2. `just test` with `BITCOIND_EXE` set
3. Update the README if CLI commands/flags change; update this file if structure, commands, or conventions change
