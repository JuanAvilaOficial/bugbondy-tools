#!/usr/bin/env bash
# install_deps.sh - Verifica/instala las herramientas externas del Bug Bounty Pipeline.
set -euo pipefail

MISSING=()

check_tool() {
  if command -v "$1" >/dev/null 2>&1; then
    echo "OK       $1"
  else
    echo "MISSING $1"
    MISSING+=("$1")
  fi
}

check_tool nuclei
check_tool subfinder
check_tool amass
check_tool ffuf
check_tool httpx
check_tool nmap

if [ ${#MISSING[@]} -eq 0 ]; then
  echo "Todas las herramientas del pipeline estan instaladas."
  exit 0
fi

echo "Faltan herramientas: ${MISSING[*]}"
echo "Instale las dependencias faltantes (ej. cargo install, apt-get, o uvx) antes de continuar."
exit 1
