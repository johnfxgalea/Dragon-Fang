#!/bin/bash
set -euxo pipefail

URL_REPO="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip"
ZIP_NAME="ghidra_10.1.2_PUBLIC_20220125.zip"

wget -nc -P ./ $URL_REPO
unzip $ZIP_NAME
mv ghidra_10.1.2_PUBLIC ghidra_PUBLIC

echo "Done downloading Ghidra."
