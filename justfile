TARGET  := "--target x86_64-pc-windows-gnu"

bld: bld-lib bld-examples

# build the library
bld-lib:
  cargo build --package crumpet {{TARGET}} --release

# build example programs
bld-examples:
  cargo build --package examples_dynamic --examples {{TARGET}} --release
  cargo build --package examples_static --examples {{TARGET}} --release

# publish to crates.io
publish:
  cargo publish --package crumpet

# dry-run publish to crates.io
pub-dry:
  cargo publish --package crumpet --dry-run

# list files in crates package
pkg-list:
  cargo package --package crumpet --list

# push binaries to test server
push-test:
  scp target/x86_64-pc-windows-gnu/release/examples/*.exe win1:bin/tpm/

# pull assets from test server
pull-test:
  mkdir -p temp_run
  -scp -r win1:bin/tpm/dyn temp_run/
  -scp -r win1:bin/tpm/stat temp_run/
  -scp win1:bin/tpm/ek_*.pem temp_run/
  -scp win1:bin/tpm/ek_*.blob temp_run/
  -scp win1:bin/tpm/msg.txt temp_run/
  -scp win1:bin/tpm/sig.bin temp_run/
