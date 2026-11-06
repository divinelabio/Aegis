#!/bin/bash
set -e

DOWNLOAD_DIR="/var/www/downloads"
AEGIS_DIR="/var/www/downloads/aegis"
HASH="4beebb973315dfc600aba591934237e9b8ff53ca4e6dcc15cdd6a5ec1a406a7e"
EXPECTED_SIZE=1279453696

cd "$AEGIS_DIR"

if [ ! -f "Aegis-Community-Edition.ova.tmp" ]; then
    echo "Error: Aegis-Community-Edition.ova.tmp not found!"
    exit 1
fi

ACTUAL_SIZE=$(stat -c%s "Aegis-Community-Edition.ova.tmp")
if [ "$ACTUAL_SIZE" -ne "$EXPECTED_SIZE" ]; then
    echo "Error: File size mismatch! Expected $EXPECTED_SIZE, got $ACTUAL_SIZE"
    exit 1
fi

echo "Verifying SHA256 checksum..."
ACTUAL_HASH=$(sha256sum "Aegis-Community-Edition.ova.tmp" | awk '{print $1}')
if [ "$ACTUAL_HASH" != "$HASH" ]; then
    echo "Error: Hash mismatch! Expected $HASH, got $ACTUAL_HASH"
    exit 1
fi

echo "Verification succeeded. Backing up previous version..."
if [ -f "aegis-waf-appliance-1.0.ova" ] && [ ! -L "aegis-waf-appliance-1.0.ova" ]; then
    mv -f aegis-waf-appliance-1.0.ova aegis-waf-appliance-1.0.ova.v1-backup
fi

mv -f Aegis-Community-Edition.ova.tmp Aegis-Community-Edition.ova
chmod 644 Aegis-Community-Edition.ova

echo "Updating symlinks in $AEGIS_DIR..."
ln -sfn Aegis-Community-Edition.ova aegis-appliance-community.ova
ln -sfn Aegis-Community-Edition.ova aegis-community-appliance-latest.ova
ln -sfn Aegis-Community-Edition.ova aegis-community-appliance-v1.0.ova
ln -sfn Aegis-Community-Edition.ova aegis-waf-appliance-latest.ova
ln -sfn Aegis-Community-Edition.ova aegis-waf-appliance-1.0.ova

echo "Generating checksum files in $AEGIS_DIR..."
for name in Aegis-Community-Edition.ova aegis-appliance-community.ova aegis-community-appliance-latest.ova aegis-community-appliance-v1.0.ova aegis-waf-appliance-latest.ova aegis-waf-appliance-1.0.ova; do
    echo "$HASH  $name" > "$name.sha256"
    chmod 644 "$name.sha256"
done

echo "Updating symlinks in $DOWNLOAD_DIR..."
cd "$DOWNLOAD_DIR"
for name in Aegis-Community-Edition.ova aegis-appliance-community.ova aegis-community-appliance-latest.ova aegis-community-appliance-v1.0.ova aegis-waf-appliance-latest.ova aegis-waf-appliance-1.0.ova; do
    ln -sfn "aegis/$name" "$name"
    ln -sfn "aegis/$name.sha256" "$name.sha256"
done

echo "Listing directory contents:"
ls -la "$AEGIS_DIR"
echo "---"
ls -la "$DOWNLOAD_DIR"

echo "Appliance published successfully!"
