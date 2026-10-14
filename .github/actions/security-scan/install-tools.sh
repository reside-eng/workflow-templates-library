#!/usr/bin/env bash
# Installs the pinned gitleaks and trivy binaries into $1 after verifying their sha256.
set -euo pipefail

dest="${1:?destination directory}"
mkdir -p "$dest"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
TRIVY_VERSION="${TRIVY_VERSION:-0.76.0}"

# Checksums from the upstream release files; add a line when bumping a version.
declare -A SHA=(
  ["gitleaks_8.30.1_linux_x64.tar.gz"]="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
  ["gitleaks_8.30.1_linux_arm64.tar.gz"]="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
  ["trivy_0.76.0_Linux-64bit.tar.gz"]="e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7"
  ["trivy_0.76.0_Linux-ARM64.tar.gz"]="aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c"
)

case "$(uname -m)" in
  x86_64) gl_arch=x64; tv_arch=64bit ;;
  aarch64|arm64) gl_arch=arm64; tv_arch=ARM64 ;;
  *) echo "::error::unsupported architecture $(uname -m)"; exit 1 ;;
esac

fetch() {
  local name="$1" url="$2" sum="${SHA[$1]:-}"
  if [ -z "$sum" ]; then
    echo "::error::no pinned checksum for $name (update install-tools.sh when bumping versions)"; exit 1
  fi
  curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/$name" "$url"
  echo "$sum  $tmp/$name" | sha256sum -c - >/dev/null
}

gl="gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz"
fetch "$gl" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gl}"
tar -xzf "$tmp/$gl" -C "$dest" gitleaks

tv="trivy_${TRIVY_VERSION}_Linux-${tv_arch}.tar.gz"
fetch "$tv" "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tv}"
tar -xzf "$tmp/$tv" -C "$dest" trivy

chmod +x "$dest/gitleaks" "$dest/trivy"
echo "gitleaks $("$dest/gitleaks" version) and $("$dest/trivy" --version | head -1) installed in $dest"
