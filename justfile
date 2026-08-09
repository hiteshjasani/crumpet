TARGET  := "--target x86_64-pc-windows-gnu"

bld: bld-lib bld-examples

bld-lib:
  cargo build --package crumpet {{TARGET}} --release

bld-examples:
  cargo build --package examples_dynamic --examples {{TARGET}} --release
  cargo build --package examples_static --examples {{TARGET}} --release

publish:
  cargo publish --package crumpet

pub-dry:
  cargo publish --package crumpet --dry-run

push-test:
  scp target/x86_64-pc-windows-gnu/release/examples/*.exe win1:bin/tpm/

pull-test:
  mkdir -p temp_run
  scp -r win1:bin/tpm/dyn temp_run/
  scp -r win1:bin/tpm/stat temp_run/
