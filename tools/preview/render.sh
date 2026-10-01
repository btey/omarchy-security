#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Renders preview.html into plugins/security_hub/preview.png, the image
# omarchyplugins.com shows for the plugin. Needs chromium, the
# JetBrainsMono Nerd Font (for the icons) and network access for the
# Google Fonts it loads.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
out=${1:-$here/../../plugins/security_hub/preview.png}
profile=$(mktemp -d)
trap 'rm -rf -- "$profile"' EXIT
chromium --headless=new --disable-gpu --hide-scrollbars --user-data-dir="$profile" \
  --window-size=1600,900 --force-device-scale-factor=2 --virtual-time-budget=5000 \
  --screenshot="$out" "file://$here/preview.html" 2>/dev/null
echo "$out"
