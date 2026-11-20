#!/bin/sh
# Quality gate. Run from the repository root: sh scripts/check.sh
set -eu

version=$(git describe --tags --always --dirty 2>/dev/null || printf dev)
export NN_VERSION="$version"

echo "== go: format"
unformatted=$(gofmt -l cmd internal web)
if [ -n "$unformatted" ]; then
  echo "gofmt needed:"; echo "$unformatted"; exit 1
fi

echo "== go: vet"
go vet ./...

echo "== go: test"
go test ./...

echo "== go: linux updater vet"
GOOS=linux go vet ./cmd/nn-host-updater ./internal/updater

echo "== go: build (including nn-actor and nn-host-updater)"
mkdir -p bin
exe=$(go env GOEXE)
for d in cmd/*/; do
  name=$(basename "$d")
  go build -ldflags "-X github.com/JulianStremel/netnoodle/internal/version.Version=$version" -o "bin/$name$exe" "./cmd/$name"
done

echo "== rust: format, lint, test, build"
(
  cd agent
  cargo fmt --check
  cargo clippy --all-targets -q -- -D warnings
  cargo test -q
  cargo build -q
)

if [ -z "${NN_SKIP_DOCKER:-}" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "== rust (linux): clippy, test in Docker"
  docker build -q --build-arg NN_VERSION="$version" --target agent-check . >/dev/null
else
  echo "== rust (linux): SKIPPED (no Docker; set up Docker or run on Linux)"
fi

echo "ALL CHECKS PASSED"
