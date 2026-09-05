Inputs that once crashed a parser, found by fuzzing (see `fuzz/README.md`).
One subdirectory per fuzz target; every file in it is replayed by
`tests/fuzz_regressions_test.rs` on every `cargo test`. Name a file after the
bug it exposed. Never delete one: the point is that the bug stays fixed.
