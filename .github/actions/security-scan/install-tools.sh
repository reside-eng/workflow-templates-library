#!/usr/bin/env bash
# Installs the pinned gitleaks and trivy binaries into $1 after verifying their sha256.
set -euo pipefail

dest="${1:?destination directory}"
mkdir -p "$dest"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# "<version> <sha256 of that release asset>", one line per architecture. Renovate bumps version and
# checksum together (renovate.json customManagers, github-release-attachments datasource).
GITLEAKS_X64="8.30.1 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
GITLEAKS_ARM64="8.30.1 e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
TRIVY_X64="0.76.0 e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7"
TRIVY_ARM64="0.76.0 aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c"

case "$(uname -m)" in
  x86_64) gitleaks_pin="$GITLEAKS_X64"; gl_arch=x64; trivy_pin="$TRIVY_X64"; tv_arch=64bit ;;
  aarch64|arm64) gitleaks_pin="$GITLEAKS_ARM64"; gl_arch=arm64; trivy_pin="$TRIVY_ARM64"; tv_arch=ARM64 ;;
  *) echo "::error::unsupported architecture $(uname -m)"; exit 1 ;;
esac

fetch() {
  local name="$1" url="$2" sum="$3"
  curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/$name" "$url"
  echo "$sum  $tmp/$name" | sha256sum -c - >/dev/null
}

read -r gl_version gl_sha <<<"$gitleaks_pin"
gl="gitleaks_${gl_version}_linux_${gl_arch}.tar.gz"
fetch "$gl" "https://github.com/gitleaks/gitleaks/releases/download/v${gl_version}/${gl}" "$gl_sha"
tar -xzf "$tmp/$gl" -C "$dest" gitleaks

read -r tv_version tv_sha <<<"$trivy_pin"
tv="trivy_${tv_version}_Linux-${tv_arch}.tar.gz"
fetch "$tv" "https://github.com/aquasecurity/trivy/releases/download/v${tv_version}/${tv}" "$tv_sha"
tar -xzf "$tmp/$tv" -C "$dest" trivy

chmod +x "$dest/gitleaks" "$dest/trivy"
echo "gitleaks $("$dest/gitleaks" version) and $("$dest/trivy" --version | head -1) installed in $dest"
