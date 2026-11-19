#!/bin/sh
# Quality gate. Run from the repository root: sh scripts/check.sh
set -eu

echo "== go: format"
unformatted=$(gofmt -l cmd internal web)
if [ -n "$unformatted" ]; then
  echo "gofmt needed:"; echo "$unformatted"; exit 1
fi

echo "== go: vet"
go vet ./...

echo "== go: test"
go test ./...

echo "== go: build"
mkdir -p bin
exe=$(go env GOEXE)
for d in cmd/*/; do
  name=$(basename "$d")
  go build -o "bin/$name$exe" "./cmd/$name"
done

echo "== rust: format, lint, test, build"
(
  cd agent
  cargo fmt --check
  cargo clippy --all-targets -q -- -D warnings
  cargo test -q
  cargo build -q
)

echo "ALL CHECKS PASSED"
