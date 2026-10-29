#!/usr/bin/env python3
"""Writes the Pluma mark as a still Telegram sticker animation (.tgs: a
gzipped Lottie), for the places of the app that play an animation of the
logo (the QR code screens).

The mark comes from an SVG of the brand kit: stroked paths made of M, C and L
commands only, in the 512 grid of pluma-icon-square.svg. Anything else in the
SVG stops the script rather than being left out.

    tgs.py MARK.svg OUT.tgs --color FFFFFF [--disc 111111]

Standard library only.
"""

import argparse
import gzip
import json
import re
import sys

SIZE = 512
FRAMES = 60
# The circle of Telegram's animation (PlaneLogo.tgs) and the width of the
# mark inside it.
DISC = 414
MARK_WIDTH = 240

PATH = re.compile(r"<path\s([^>]*)/>")
ATTR = re.compile(r'([a-z-]+)="([^"]*)"')
VIEWBOX = re.compile(r'viewBox="([-\d. ]+)"')
TOKEN = re.compile(r"[MCL]|-?\d+(?:\.\d+)?")


def rgb(hex6):
    if not re.fullmatch(r"[0-9A-Fa-f]{6}", hex6):
        raise SystemExit(f"tgs: {hex6!r} is not a colour (RRGGBB)")
    return [round(int(hex6[i:i + 2], 16) / 255, 4) for i in (0, 2, 4)] + [1]


def static(value):
    return {"a": 0, "k": value}


def transform(**over):
    tr = {"ty": "tr", "p": static([0, 0]), "a": static([0, 0]), "s": static([100, 100]),
          "r": static(0), "o": static(100), "sk": static(0), "sa": static(0)}
    tr.update(over)
    return tr


def bezier(d):
    """An SVG path (M, then C or L segments) as a Lottie shape: vertices with
    in and out tangents relative to them. A path that ends where it starts is
    closed."""
    tokens = TOKEN.findall(d)
    if "".join(t for t in tokens if t.isalpha())[:1] != "M" or re.sub(r"[MCL\d.,\s-]", "", d):
        raise SystemExit(f"tgs: unsupported path {d!r}")
    pos, cmd, nums = 0, None, []
    points = []  # (vertex, in tangent, out tangent) in absolute coordinates

    def take(n):
        nonlocal pos
        out = [float(t) for t in tokens[pos:pos + n]]
        if len(out) != n or any(t.isalpha() for t in tokens[pos:pos + n]):
            raise SystemExit(f"tgs: truncated path {d!r}")
        pos += n
        return [(out[i], out[i + 1]) for i in range(0, n, 2)]

    while pos < len(tokens):
        if tokens[pos].isalpha():
            cmd = tokens[pos]
            pos += 1
        if cmd == "M":
            (v,) = take(2)
            points.append([v, v, v])
            cmd = "L"  # further pairs are lines
        elif cmd == "L":
            (v,) = take(2)
            points.append([v, v, v])
        elif cmd == "C":
            c1, c2, v = take(6)
            points[-1][2] = c1
            points.append([v, c2, v])
    closed = len(points) > 2 and points[-1][0] == points[0][0]
    if closed:
        points[0][1] = points[-1][1]
        points.pop()
    rel = lambda a, b: [round(a[0] - b[0], 3), round(a[1] - b[1], 3)]  # noqa: E731
    return {
        "v": [[round(p[0][0], 3), round(p[0][1], 3)] for p in points],
        "i": [rel(p[1], p[0]) for p in points],
        "o": [rel(p[2], p[0]) for p in points],
        "c": closed,
    }


def mark_layer(svg, color):
    box = VIEWBOX.search(svg)
    if not box:
        raise SystemExit("tgs: the SVG has no viewBox")
    x, y, w, h = (float(v) for v in box.group(1).split())
    shapes = []
    for m in PATH.finditer(svg):
        attrs = dict(ATTR.findall(m.group(1)))
        if attrs.get("fill") != "none" or "stroke" not in attrs:
            raise SystemExit(f"tgs: only stroked paths are supported: {m.group(0)[:80]}")
        caps = {"round": 2, "butt": 1, "square": 3}
        joins = {"round": 2, "miter": 1, "bevel": 3}
        shapes.append({"ty": "gr", "nm": f"Path {len(shapes) + 1}", "it": [
            {"ty": "sh", "ks": static(bezier(attrs["d"]))},
            {"ty": "st", "c": static(rgb(color)), "o": static(100), "w": static(float(attrs["stroke-width"])),
             "lc": caps[attrs.get("stroke-linecap", "butt")], "lj": joins[attrs.get("stroke-linejoin", "miter")],
             "ml": 4},
            transform(),
        ]})
    if not shapes:
        raise SystemExit("tgs: no paths in the SVG")
    scale = MARK_WIDTH / w * 100
    return {
        "ddd": 0, "ind": 1, "ty": 4, "nm": "Mark", "sr": 1,
        "ks": {"o": static(100), "r": static(0), "p": static([SIZE / 2, SIZE / 2, 0]),
               "a": static([x + w / 2, y + h / 2, 0]), "s": static([scale, scale, 100])},
        "ao": 0, "shapes": shapes, "ip": 0, "op": FRAMES, "st": 0, "bm": 0,
    }


def disc_layer(color):
    return {
        "ddd": 0, "ind": 2, "ty": 4, "nm": "Disc", "sr": 1,
        "ks": {"o": static(100), "r": static(0), "p": static([SIZE / 2, SIZE / 2, 0]),
               "a": static([0, 0, 0]), "s": static([100, 100, 100])},
        "ao": 0, "shapes": [{"ty": "gr", "nm": "Disc", "it": [
            {"ty": "el", "p": static([0, 0]), "s": static([DISC, DISC]), "d": 1},
            {"ty": "fl", "c": static(rgb(color)), "o": static(100), "r": 1},
            transform(),
        ]}],
        "ip": 0, "op": FRAMES, "st": 0, "bm": 0,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mark", help="the mark SVG")
    ap.add_argument("out", help="the .tgs to write")
    ap.add_argument("--color", required=True, help="the colour of the mark, RRGGBB")
    ap.add_argument("--disc", help="a circle behind the mark, RRGGBB")
    a = ap.parse_args()
    with open(a.mark, encoding="utf-8") as f:
        svg = f.read()
    layers = [mark_layer(svg, a.color)]
    if a.disc:
        layers.append(disc_layer(a.disc))
    doc = {"v": "5.5.2", "fr": FRAMES, "ip": 0, "op": FRAMES, "w": SIZE, "h": SIZE, "nm": "Pluma", "ddd": 0,
           "assets": [], "layers": layers}
    data = json.dumps(doc, separators=(",", ":")).encode()
    # No file name or time in the gzip header: a re-run writes the same bytes.
    with open(a.out, "wb") as f:
        f.write(gzip.compress(data, mtime=0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
