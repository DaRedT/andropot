#!/bin/bash
set -e
echo "[*] Installing Go and dependencies..."
sudo apt update && sudo apt install -y golang git curl
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo "[*] Installing Recon Tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest
echo "[+] Installation complete. Tools are in $GOPATH/bin"
