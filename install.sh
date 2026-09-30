#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run: sudo bash install.sh" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "Mitigato requires a Linux server with systemd." >&2
  exit 1
fi

python_bin=""
for candidate in python3 python3.13 python3.12 python3.11; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import tomllib' >/dev/null 2>&1; then
    python_bin="$candidate"
    break
  fi
done
if [[ -z $python_bin ]]; then
  echo "Install Python 3.11 or newer, then run this script again." >&2
  exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
  echo "Installing nftables..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y nftables
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nftables
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm nftables
  else
    echo "Install nftables with your package manager, then run this script again." >&2
    exit 1
  fi
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$python_bin" "$script_dir/mitigato.py" install "$@"
