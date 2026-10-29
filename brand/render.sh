#!/usr/bin/env bash
# Renders the Pluma images of the iOS app from the brand kit's SVGs into
# brand/ios, each under the upstream path of the file it replaces;
# ci/patch.py copies them over the upstream checkout. Run it after an SVG
# changes and commit the result: the CI has no renderer.
#
# Needs rsvg-convert (librsvg), ImageMagick 7 (magick) and Python 3.
#
# The sources (brand kit of the server repository, task 017):
#   pluma-icon-square.svg  the app icon, full bleed (iOS masks the corners);
#   pluma-mark.svg         the mark: the ring #111111, the feathers #4A4A4A,
#                          #8A8A8A, #BDBDBD;
#   pluma-mark-mono.svg    the mark in black, for template images.
set -euo pipefail
cd "$(dirname "$0")"

out=ios
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# No creation date in the PDFs: a re-run writes the same bytes.
export SOURCE_DATE_EPOCH=0

graphite=111111
light_border=E3EAE2

# The <path> elements of an SVG of the kit, one per line, in the 512 grid of
# pluma-icon-square.svg.
paths() {
	grep -o '<path [^>]*/>' "$1"
}
mark=$(paths pluma-mark.svg)
mono=$(paths pluma-mark-mono.svg)
white=${mono//#000000/#FFFFFF}

# The mark (its viewBox 64 80 392 336, centre 260,248) scaled to a width and
# centred on a point: mark_at CX CY WIDTH PATHS.
mark_at() {
	awk -v cx="$1" -v cy="$2" -v w="$3" 'BEGIN {
		s = w / 392
		printf "<g transform=\"translate(%.4f %.4f) scale(%.6f)\">", cx - 260 * s, cy - 248 * s, s
	}'
	printf '%s</g>' "$4"
}

# An SVG document of a size in points: svg NAME WIDTH HEIGHT CONTENT.
svg() {
	printf '<svg xmlns="http://www.w3.org/2000/svg" width="%s" height="%s" viewBox="0 0 %s %s">%s</svg>\n' \
		"$2" "$3" "$2" "$3" "$4" >"$tmp/$1.svg"
}

# A PNG of an SVG: png SVG WIDTH HEIGHT OUT [opaque]. Opaque icons get a
# white background and no alpha channel.
png() {
	mkdir -p "$(dirname "$4")"
	rsvg-convert -w "$2" -h "$3" "$1" -o "$tmp/render.png"
	if [ "${5:-}" = opaque ]; then
		magick "$tmp/render.png" -background white -alpha remove -alpha off -strip "PNG24:$4"
	else
		magick "$tmp/render.png" -strip "PNG32:$4"
	fi
}

# A vector PDF of an SVG, one SVG unit per point: pdf SVG OUT.
pdf() {
	mkdir -p "$(dirname "$2")"
	rsvg-convert -f pdf -d 72 -p 72 "$1" -o "$2"
}

rm -rf "$out"

# The app icon (Icon Composer): a white background, the ring and the feathers
# as layers of their own, so that the dark and tinted appearances can recolour
# them. The layers are bitmaps: Icon Composer clips a stroked SVG path to its
# geometry and fills it as a shape.
icon=$out/Telegram/Telegram-iOS/Telegram.icon
mkdir -p "$icon/Assets"
n=0
for name in Ring Feather1 Feather2 Feather3; do
	n=$((n + 1))
	layer=$(sed -n "${n}p" <<<"$mark")
	svg "$name" 512 512 "$layer"
	png "$tmp/$name.svg" 1024 1024 "$icon/Assets/$name.png"
done
# A layer's own colours by default; in the dark and tinted appearances a
# graphite background (#131513) with a light ring (#E8ECE8) and lighter
# feathers.
layer() {
	cat <<EOF
        {
          "fill-specializations" : [
            {
              "appearance" : "dark",
              "value" : {
                "solid" : "$2"
              }
            },
            {
              "appearance" : "tinted",
              "value" : {
                "solid" : "$2"
              }
            }
          ],
          "glass" : false,
          "image-name" : "$1.png",
          "name" : "$1"
        }
EOF
}
{
	cat <<'EOF'
{
  "fill" : {
    "solid" : "srgb:1.00000,1.00000,1.00000,1.00000"
  },
  "fill-specializations" : [
    {
      "appearance" : "dark",
      "value" : {
        "solid" : "srgb:0.07451,0.08235,0.07451,1.00000"
      }
    }
  ],
  "groups" : [
    {
      "layers" : [
EOF
	layer Feather3 "srgb:0.41961,0.43529,0.41961,1.00000"
	echo ','
	layer Feather2 "srgb:0.54118,0.54118,0.54118,1.00000"
	echo ','
	layer Feather1 "srgb:0.74118,0.74118,0.74118,1.00000"
	echo ','
	layer Ring "srgb:0.90980,0.92549,0.90980,1.00000"
	cat <<'EOF'
      ],
      "lighting" : "combined",
      "shadow" : {
        "kind" : "neutral",
        "opacity" : 0.5
      },
      "specular" : true,
      "translucency" : {
        "enabled" : false,
        "value" : 0.5
      }
    }
  ],
  "supported-platforms" : {
    "circles" : [
      "watchOS"
    ],
    "squares" : "shared"
  }
}
EOF
} >"$icon/icon.json"

# The alternate icon BlueIcon, which the app counts as its default one (the
# icon picker, the theme file type), and its notification sizes.
alt=$out/Telegram/Telegram-iOS/BlueIcon.alticon
for spec in BlueIcon@2x:120 BlueIcon@3x:180 BlueIconIpad:76 BlueIconIpad@2x:152 BlueIconLargeIpad@2x:167 \
	BlueNotificationIcon:20 BlueNotificationIcon@2x:40 BlueNotificationIcon@3x:60; do
	png pluma-icon-square.svg "${spec#*:}" "${spec#*:}" "$alt/${spec%:*}.png" opaque
done

# The home screen quick action and the context menu item that open the
# app's own chats: the mark in a rounded square outline, a template.
svg outlined 24 24 "<rect x=\"2.83\" y=\"2.83\" width=\"18.34\" height=\"18.34\" rx=\"5.5\" fill=\"none\" stroke=\"#000000\" stroke-width=\"1.66\"/>$(mark_at 12 12 11.5 "$mono")"
pdf "$tmp/outlined.svg" "$out/Telegram/Telegram-iOS/Icons.xcassets/Shortcuts/AppIcon.imageset/tlogo_24.pdf"
pdf "$tmp/outlined.svg" "$out/submodules/TelegramUI/Images.xcassets/Chat/Context Menu/Telegram.imageset/tlogo_24.pdf"

# The title of the call screen, a template tinted white.
svg calltitle 20 15 "$(mark_at 10 7.5 17.4 "$mono")"
pdf "$tmp/calltitle.svg" "$out/submodules/TelegramUI/Images.xcassets/Call/CallTitleLogo.imageset/ic_calls_tlogo.pdf"

# CallKit's button of the app in the system call screen, an alpha template.
svg callkit 80 80 "$(mark_at 40 40 60 "$mono")"
png "$tmp/callkit.svg" 80 80 "$out/submodules/TelegramUI/Images.xcassets/Call/CallKitLogo.imageset/CallKitLogo@2x.png"
png "$tmp/callkit.svg" 120 120 "$out/submodules/TelegramUI/Images.xcassets/Call/CallKitLogo.imageset/CallKitLogo@3x.png"

# QR codes: the logo in the middle of a shared invite code (a graphite circle
# with the white mark), and the white mark over the code of a profile.
svg qrlogo 72 72 "<circle cx=\"36\" cy=\"36\" r=\"36\" fill=\"#$graphite\"/>$(mark_at 36 36 42 "$white")"
pdf "$tmp/qrlogo.svg" "$out/submodules/TelegramUI/Images.xcassets/Chat/Links/QrLogo.imageset/ic_qrlogo.pdf"
svg qrmark 72 72 "$(mark_at 36 36 42 "$white")"
pdf "$tmp/qrmark.svg" "$out/submodules/TelegramUI/Images.xcassets/Share/QrPlaneIcon.imageset/ic_qrlogo.pdf"
# The same as still animations, which the QR screens play in place of these.
mkdir -p "$out/Telegram/Telegram-iOS/Resources"
python3 -I tgs.py pluma-mark-mono.svg "$out/Telegram/Telegram-iOS/Resources/PlaneLogo.tgs" --color FFFFFF --disc "$graphite"
python3 -I tgs.py pluma-mark-mono.svg "$out/Telegram/Telegram-iOS/Resources/PlaneLogoPlain.tgs" --color FFFFFF

# The first page of the intro: the mark on a white disc in place of
# Telegram's blue sphere, and no paper plane flying around it (a transparent
# texture of the same size; the intro needs the file).
svg sphere 296 296 "<circle cx=\"148\" cy=\"148\" r=\"146.5\" fill=\"#FFFFFF\" stroke=\"#$light_border\" stroke-width=\"3\"/>$(mark_at 148 148 172 "$mark")"
png "$tmp/sphere.svg" 296 296 "$out/Telegram/Telegram-iOS/Resources/intro/telegram_sphere@2x.png"
svg plane 164 148 ""
png "$tmp/plane.svg" 164 148 "$out/Telegram/Telegram-iOS/Resources/intro/telegram_plane1@2x.png"

echo "render: $(find "$out" -type f | wc -l | tr -d ' ') files in brand/$out"
