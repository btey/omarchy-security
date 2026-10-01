#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Crops tools/preview/capture.sh's screenshots into tools/preview/shots/.

    crop.py OUT SHOTS SCALE

For each tab, the hub's layer (from the step's `hyprctl -j layers`), at the
output's scale. The prompt and the alert are full-screen layers with a card
in them, so the last step ("osd") is cut at the background instead: trimmed,
then split at the empty rows between the cards, top to bottom (osd-0 is the
threat alert, osd-1 the connection prompt below it).
"""
import json
import os
import re
import subprocess
import sys


def magick(*args):
    return subprocess.run(["magick", *args], check=True, capture_output=True, text=True).stdout


def crop(png, geometry, dest):
    magick(png, "-crop", geometry, "+repage", "-strip", dest)
    print(os.path.basename(dest), geometry)


def hub(png, layers_json, scale, dest):
    layers = [layer for monitor in json.load(open(layers_json)).values()
              for level in monitor["levels"].values() for layer in level
              if layer["namespace"] == "omarchy-security-hub"]
    if not layers:
        sys.exit(f"no hub layer in {layers_json}")
    l = layers[0]
    crop(png, f"{l['w'] * scale}x{l['h'] * scale}+{l['x'] * scale}+{l['y'] * scale}", dest)


def cards(png, shots):
    # The bounding box of everything that is not the background colour.
    w, h, x, y = map(int, re.findall(r"\d+", magick(png, "-fuzz", "3%", "-format", "%@", "info:")))
    # One column: black where a row is all background, lighter otherwise.
    background = magick(png, "-format", "%[pixel:p{0,0}]", "info:")
    rows = magick(png, "-crop", f"{w}x{h}+{x}+{y}", "+repage", "-fuzz", "3%",
                  "-fill", "black", "-opaque", background, "-fill", "white", "+opaque", "black",
                  "-scale", f"1x{h}!", "-depth", "8", "txt:-").splitlines()[1:]
    empty = [row.split("(", 1)[1].startswith("0,0,0") for row in rows]
    found, top = [], None
    for i, blank in enumerate(empty + [True]):
        if not blank and top is None:
            top = i
        elif blank and top is not None:
            found.append((top, i))
            top = None
    for i, (a, b) in enumerate(found):
        crop(png, f"{w}x{b - a}+{x}+{y + a}", os.path.join(shots, f"osd-{i}.png"))


def main():
    out, shots, scale = sys.argv[1], sys.argv[2], int(sys.argv[3])
    for name in sorted(os.listdir(out)):
        if not name.endswith(".json"):
            continue
        step = name[:-5]
        png = os.path.join(out, step + ".png")
        if step == "osd":
            cards(png, shots)
        else:
            hub(png, os.path.join(out, name), scale, os.path.join(shots, step + ".png"))


if __name__ == "__main__":
    main()
