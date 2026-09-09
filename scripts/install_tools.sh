#!/usr/bin/env sh
# Install every tool in sbom/tools.cdx.json for $TARGETARCH, verifying each
# download against the sha256 the SBOM records for that exact artifact.
#
# Run at image build time (see Dockerfile.rw-checks). Reads the SBOM, never
# tools/tools.yaml -- so a version bumped in tools.yaml without re-running
# scripts/gen_tool_sbom.py cannot reach an image: the SBOM would still carry
# the old URL and hash.
#
# Failure is always fatal. A tool that 404s, or whose bytes do not match the
# recorded hash, aborts the build -- never a silently missing binary that
# would surface later as an empty check result rather than an error.
set -eu

SBOM="${SBOM:-/build/sbom/tools.cdx.json}"
DEST="${DEST:-/usr/local/bin}"
ARCH="${TARGETARCH:?TARGETARCH must be set (buildx sets it; pass --build-arg otherwise)}"

command -v jq >/dev/null || { echo "install_tools.sh: jq is required" >&2; exit 1; }

count=0
jq -r --arg arch "$ARCH" '
  .components[]
  | . as $c
  | ($c.properties // [] | from_entries) as $p
  | ($c.externalReferences[]? | select(.comment == "linux/\($arch)")) as $ref
  | [$c.name, $ref.url, ($ref.hashes[] | select(.alg=="SHA-256") | .content),
     $p["rw:archive-kind"], $p["rw:binary-name"]]
  | @tsv
' "$SBOM" | while IFS="$(printf '\t')" read -r name url sha kind binary; do
  echo "==> $name ($kind, linux/$ARCH)"
  tmp="$(mktemp -d)"
  curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/artifact" "$url"

  actual="$(sha256sum "$tmp/artifact" | cut -d' ' -f1)"
  if [ "$actual" != "$sha" ]; then
    echo "    INTEGRITY FAILURE for $name" >&2
    echo "      expected $sha" >&2
    echo "      actual   $actual" >&2
    echo "      url      $url" >&2
    exit 1
  fi

  case "$kind" in
    binary)  install -m 0755 "$tmp/artifact" "$DEST/$binary" ;;
    tar.gz)  tar -xzf "$tmp/artifact" -C "$tmp" ;;
    tar.xz)  tar -xJf "$tmp/artifact" -C "$tmp" ;;
    zip)     unzip -qo "$tmp/artifact" -d "$tmp" ;;
    *)       echo "    unknown archive kind: $kind" >&2; exit 1 ;;
  esac

  if [ "$kind" != "binary" ]; then
    found="$(find "$tmp" -type f -name "$binary" -perm -u+x 2>/dev/null | head -1)"
    [ -n "$found" ] || found="$(find "$tmp" -type f -name "$binary" | head -1)"
    [ -n "$found" ] || { echo "    $binary not found inside archive" >&2; exit 1; }
    install -m 0755 "$found" "$DEST/$binary"
  fi

  rm -rf "$tmp"
  count=$((count + 1))
done

# The loop above runs in a subshell (pipeline), so verify from the outside
# that every component actually landed rather than trusting its counter.
expected="$(jq -r --arg arch "$ARCH" '
  [.components[] | select(.externalReferences[]?.comment == "linux/\($arch)")] | length
' "$SBOM")"
installed=0
for b in $(jq -r --arg arch "$ARCH" '
  .components[] | select(.externalReferences[]?.comment == "linux/\($arch)")
  | (.properties | from_entries)["rw:binary-name"]
' "$SBOM"); do
  [ -x "$DEST/$b" ] && installed=$((installed + 1)) || echo "MISSING: $b" >&2
done
echo "installed $installed/$expected tools for linux/$ARCH"
[ "$installed" = "$expected" ] || exit 1
