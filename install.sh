#!/usr/bin/env bash
# Installs easm-recon dependencies on Kali / Debian / Ubuntu.
#   ./install.sh           install everything (apt + go tools + nuclei templates)
#   ./install.sh --check   only report what is installed
set -Eeuo pipefail

GO_TOOLS=(
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
  "alterx|github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "gau|github.com/lc/gau/v2/cmd/gau@latest"
  "assetfinder|github.com/tomnomnom/assetfinder@latest"
  "waybackurls|github.com/tomnomnom/waybackurls@latest"
)
APT_PKGS=(python3 dnsutils whois nmap jq curl libpcap-dev golang-go git ca-certificates)

have() { command -v "$1" >/dev/null 2>&1; }
check() {
  local t
  for t in python3 dig whois nmap jq curl go subfinder amass dnsx naabu httpx httpx-toolkit nuclei katana alterx gau assetfinder waybackurls findomain; do
    if have "$t"; then printf '  [+] %-14s %s\n' "$t" "$(command -v "$t")"; else printf '  [-] %-14s missing\n' "$t"; fi
  done
  if have httpx && ! httpx -h 2>&1 | grep -q -- '-status-code'; then
    echo "  [!] 'httpx' on PATH is NOT ProjectDiscovery httpx (python-httpx?). Put \$HOME/go/bin first in PATH or install httpx-toolkit."
  fi
}

if [[ "${1:-}" == "--check" ]]; then check; exit 0; fi

SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"
if have apt-get; then
  echo "[*] Installing system packages: ${APT_PKGS[*]}"
  $SUDO apt-get update -y
  $SUDO apt-get install -y "${APT_PKGS[@]}"
  # Kali ships some tools as packages; harmless if unavailable elsewhere.
  $SUDO apt-get install -y amass findomain 2>/dev/null || echo "[i] amass/findomain not in apt repos; optional."
else
  echo "[!] apt-get not found. Install manually: ${APT_PKGS[*]}"
fi

if have go; then
  export GOPATH="${GOPATH:-$HOME/go}"; export PATH="$GOPATH/bin:$PATH"
  for entry in "${GO_TOOLS[@]}"; do
    name="${entry%%|*}"; pkg="${entry#*|}"
    echo "[*] go install $name"
    go install -v "$pkg" >/dev/null 2>&1 || echo "[!] failed: $name (needs Go >= 1.21; naabu needs libpcap-dev)"
  done
  grep -q 'go/bin' "$HOME/.bashrc" 2>/dev/null || echo 'export PATH="$HOME/go/bin:$PATH"' >> "$HOME/.bashrc"
  grep -q 'go/bin' "$HOME/.zshrc" 2>/dev/null || { [[ -f "$HOME/.zshrc" ]] && echo 'export PATH="$HOME/go/bin:$PATH"' >> "$HOME/.zshrc"; }
else
  echo "[!] Go not found; ProjectDiscovery tools not installed."
fi

if have nuclei; then echo "[*] Updating nuclei templates"; nuclei -update-templates -silent || true; fi
chmod +x "$(dirname "$0")/easm-recon.sh" "$(dirname "$0")/engine/easm.py" 2>/dev/null || true

echo; echo "[*] Dependency status:"; check
cat <<'EOF'

Next steps:
  1. Open a new shell (or: export PATH="$HOME/go/bin:$PATH")
  2. Add passive-source API keys to ~/.config/subfinder/provider-config.yaml (big coverage boost)
  3. export NVD_API_KEY=<free key from https://nvd.nist.gov/developers/request-an-api-key>
  4. ./easm-recon.sh --passive-only example.com
EOF
