# Fuzzing

Continuous fuzzing with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
(libFuzzer). The robustness test in `tests/robustness_test.rs` feeds random
bytes through the parsers once; these targets do the same for hours and keep
the inputs that crash.

| Target | What it drives |
|---|---|
| `filesystems` | every filesystem parser, via detection and a forced parse, plus a dry-run undelete |
| `carve` | the carver with every built-in signature, all length walks, all validators |
| `json` | the MCP server's JSON parser, with a serializer round-trip check |
| `custom_spec` | custom carver specs from an MCP client, then a carve with them |
| `identify` | content-based type identification |
| `manifest` | CSV and JSON manifest parsing |

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run filesystems -- -max_total_time=600
```

Crashing inputs land in `fuzz/artifacts/<target>/`. To keep one as a
regression test, copy it to `tests/fuzz_regressions/<target>/` with a name
that says what it broke; `tests/fuzz_regressions_test.rs` replays every file
there on every `cargo test`. Fix the bug, keep the file.

The nightly `Fuzz` workflow runs each target for a while and fails, with the
inputs attached as artifacts, if any crashes.
