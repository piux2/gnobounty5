# gnolang
  * Finish passing gnolang files tests (DONE).
  * Dry the code with select refactors.
  * Implement form of channel send/recv.
  * Complete float32/float64 implementation (as struct).
  * Check parsed AST for compile-time errors.
    - unused names,
    - XXX
  * Ensure determinism regarding 32 vs 64 bit for int/uint.
  * Ensure non-realm paths cannot mutate state.

# /pkgs
  * Replace testify with gnolang/gno/pkgs/testify
  * `command`: make utility that parses flags using `BurntSushi/toml` or some vetted toml lib, but nothing else (besides amino json)
  * Move most of classic/sdk/ as packages in gno/pkgs/
  * Move tendermint consensus modules as packages in gno/pkgs/tendermint
  * Embedded AminoMarshaler fields should not cause the parent to become AminoMarshaler.

# other
  * Replace spf13 with gnolang/testify fork of jaekwon/testify
