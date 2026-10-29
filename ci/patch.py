#!/usr/bin/env python3
"""Turns a checkout of TelegramMessenger/Telegram-iOS into the Pluma client.

Every change is an exact edit: the text it replaces must occur the expected
number of times, or the whole run fails. An upstream update that moves any
of these places stops the build here instead of producing a client that
talks to Telegram or does not sign in. After the edits the result is checked
again (no Telegram datacenter address or server key is left in the network
code).

The app's identity (bundle ID, api_id, api_hash, Team ID) is not an edit: it
goes to the build configuration that Telegram-iOS's Make.py reads
(--configurationPath), written here as build-system/pluma-configuration.json.

The brand: Pluma's images (rendered into brand/ios by brand/render.sh)
replace Telegram's, each upstream file checked by its SHA-256 first, and the
texts the user sees say Pluma where they said Telegram (the counts of the
pinned commit are part of the patch).

Standard library only, so the CI and a developer machine run it as is.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import pathlib
import re
import sys
import textwrap

# The targets of the app, as Make.py names their provisioning profiles
# (build-system/Make/BuildConfiguration.py): bundle ID suffix, profile name,
# and the suffix of the secret that holds the profile (README, Signing).
TARGETS = (
    ("", "Telegram", "MAIN"),
    (".Share", "Share", "SHARE"),
    (".NotificationService", "NotificationService", "NOTIFICATION_SERVICE"),
    (".NotificationContent", "NotificationContent", "NOTIFICATION_CONTENT"),
    (".Widget", "Widget", "WIDGET"),
    (".SiriIntents", "Intents", "SIRI_INTENTS"),
    (".BroadcastUpload", "BroadcastUpload", "BROADCAST_UPLOAD"),
)

# Telegram's own server keys (production, test) with the fingerprints the
# server announces for them, and the key Telegram signs its backup address
# records with. None of them may survive the patch.
TELEGRAM_FINGERPRINTS = (0xD09D1D85DE64FD85, 0xB25898DF208D2603)
TELEGRAM_KEY_LINES = (
    "MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g",
    "MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR",
    "MIIBCgKCAQEAyr+18Rex2ohtVy8sroGPBwXD3DOoKCSpjDqYoXgCqB7ioln4eDCF",
)

# Telegram's address ranges (core.telegram.org/resources/cidr.txt) and the
# one seed address outside them.
TELEGRAM_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22",
    "149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24",
    "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48", "2001:b28:f23c::/48", "2a0a:f280::/32",
    "95.161.76.100/32",
))

# Where the network code lives: what verify() scans.
NETWORK_DIRS = ("submodules/MtProtoKit", "submodules/TelegramCore/Sources", "submodules/TelegramVoip/Sources")

NETWORK = "submodules/TelegramCore/Sources/Network/Network.swift"
ACCOUNT = "submodules/TelegramCore/Sources/Account/Account.swift"
SERIALIZATION = "submodules/TelegramCore/Sources/State/Serialization.swift"
AUTH_KEYS = "submodules/MtProtoKit/Sources/MTDatacenterAuthMessageService.m"
ENCRYPTION = "submodules/MtProtoKit/Sources/MTEncryption.m"
BACKUP = "submodules/MtProtoKit/Sources/MTBackupAddressSignals.m"
DNS = "submodules/MtProtoKit/Sources/MTDNS.m"
CALLS = "submodules/TelegramVoip/Sources/OngoingCallContext.swift"
APP_BUILD = "Telegram/BUILD"
APP_DELEGATE = "submodules/TelegramUI/Sources/AppDelegate.swift"
INTRO_ANIMATIONS = "submodules/RMIntro/Sources/core/animations.c"
MAKE = "build-system/Make/Make.py"
BUILD_CONFIGURATION = "build-system/Make/BuildConfiguration.py"
VERSIONS = "versions.json"
BAZELRC = ".bazelrc"

# Written by the patch.
CONFIGURATION = "build-system/pluma-configuration.json"
PLUMA_BAZELRC = "pluma.bazelrc"

# Pluma's images, rendered by brand/render.sh under the upstream paths of the
# files they replace, and the SHA-256 of each of those files in the pinned
# commit.
BRAND = pathlib.Path(__file__).resolve().parent.parent / "brand" / "ios"
APP_ICON = "Telegram/Telegram-iOS/Telegram.icon"
BRAND_REPLACED = {
    # The app icon (Icon Composer) and the alternate icon the app counts as
    # its default one.
    f"{APP_ICON}/icon.json": "cf7c84b1ceef48a16c9ea2c193428417f99b80258752d7fcc14914f6b0ca4c89",
    "Telegram/Telegram-iOS/BlueIcon.alticon/BlueIcon@2x.png": "a2f7b28961cbf6fa0a46b970a8f928f057784619d51a555a76af95d5fcf1e049",
    "Telegram/Telegram-iOS/BlueIcon.alticon/BlueIcon@3x.png": "93510b572e0aa62f2d919147abe61511121d6b22048d9123ca49951d72097eaa",
    "Telegram/Telegram-iOS/BlueIcon.alticon/BlueIconIpad.png": "0df79fe993096053534a6b8e29564d5ca45e5dfed3b08efc13b46f88498d4d30",
    "Telegram/Telegram-iOS/BlueIcon.alticon/BlueIconIpad@2x.png": "e0512a4bc616c30db3cd45f2d0f5f9cc2daa59e6629e1715b2c966e3d1cab852",
    "Telegram/Telegram-iOS/BlueIcon.alticon/BlueIconLargeIpad@2x.png": "c1ad8db762259527ff8b2d787196010bec2584ca6a5e906da2138b43f7940050",
    "Telegram/Telegram-iOS/BlueIcon.alticon/BlueNotificationIcon.png": "5efeec2428e5cb6e7c2094b23ac6b2a095610e10175436d72235862796ab64b3",
    "Telegram/Telegram-iOS/BlueIcon.alticon/BlueNotificationIcon@2x.png": "1ef3dc249a9fef7b0adfec5c9c9afbaf49d66f3f7d0520908cfb4da25aa73565",
    "Telegram/Telegram-iOS/BlueIcon.alticon/BlueNotificationIcon@3x.png": "a4997112e7808dd56e58f1e8eb05a4fdb203ce2021ca0070296a631e0534b3e1",
    # The home screen quick action and the context menu item of the app.
    "Telegram/Telegram-iOS/Icons.xcassets/Shortcuts/AppIcon.imageset/tlogo_24.pdf": "787186461237a57b6a8406d61f8e34a16e0fe852b412cb7d727823ea956fea3b",
    "submodules/TelegramUI/Images.xcassets/Chat/Context Menu/Telegram.imageset/tlogo_24.pdf": "787186461237a57b6a8406d61f8e34a16e0fe852b412cb7d727823ea956fea3b",
    # Calls: the call screen title and CallKit's button of the app.
    "submodules/TelegramUI/Images.xcassets/Call/CallTitleLogo.imageset/ic_calls_tlogo.pdf": "a2a9c3cb4b640df4dd49f76edae8ede35b2454a880756d37b7725cc06131ac2a",
    "submodules/TelegramUI/Images.xcassets/Call/CallKitLogo.imageset/CallKitLogo@2x.png": "ad30551081c7852c8d0776360fbb30fed0ca21ef96a08b84c7bc09bac342f4ff",
    "submodules/TelegramUI/Images.xcassets/Call/CallKitLogo.imageset/CallKitLogo@3x.png": "d3f5692599ba33a620ee3a576d3dce76b8587fa4ca048fb2a017ffd14766f8ee",
    # The logos of the QR codes, still and animated.
    "submodules/TelegramUI/Images.xcassets/Chat/Links/QrLogo.imageset/ic_qrlogo.pdf": "7c70dc0384fa389e83ec8258c17c72fa9440927835ae82684fece7883686e59f",
    "submodules/TelegramUI/Images.xcassets/Share/QrPlaneIcon.imageset/ic_qrlogo.pdf": "b1360bb26ad4df49470c1fd27c2238b68d390db8ad8bc4a67d0dd00b4f893b71",
    "Telegram/Telegram-iOS/Resources/PlaneLogo.tgs": "d13203f9221c5dfd0a4a34a835f7f7d5b53e90276077998b9784299c914995e4",
    "Telegram/Telegram-iOS/Resources/PlaneLogoPlain.tgs": "486cbe566d05f023f3c72ec00b55f921deb1f7aed2efb630fe717425e2d98d0a",
    # The first page of the intro: the sphere and the plane around it.
    "Telegram/Telegram-iOS/Resources/intro/telegram_sphere@2x.png": "621831c454689762c79c80083f797352aa420c488c19ba924da006ab533dd0bb",
    "Telegram/Telegram-iOS/Resources/intro/telegram_plane1@2x.png": "c28d4e5438f3a10fa1df725764b4bc897af475983070aaf08df1b631334a10a1",
}
# The layers of Pluma's app icon, and those of Telegram's that go.
BRAND_ADDED = tuple(f"{APP_ICON}/Assets/{n}.png" for n in ("Feather1", "Feather2", "Feather3", "Ring"))
BRAND_REMOVED = {
    f"{APP_ICON}/Assets/Oval.svg": "30b7245c9edef107ea7520cdd958246fcc771fa0872bb2f6cd13ab2dc11cfffd",
    f"{APP_ICON}/Assets/Plane.svg": "f4da98d58f274a9d95d491badd14afafa378f335a0bd2b496db83836e21f15e8",
}

# The built-in English strings: the interface (the generated
# PresentationStrings) and the texts of the push notifications.
STRINGS = "Telegram/Telegram-iOS/en.lproj/Localizable.strings"
# The permission prompts and, for two languages, the name under the icon:
# the name of Telegram in each language's InfoPlist.strings and how many times
# the pinned commit has it.
INFOPLIST_STRINGS = "Telegram/Telegram-iOS/{}.lproj/InfoPlist.strings"
INFOPLIST_NAMES = {
    "ar": {"\u062a\u064a\u0644\u064a\u062c\u0631\u0627\u0645": 7},  # تيليجرام, also under the icon
    "be": {"Telegram": 4},
    "ca": {"Telegram": 4},
    "de": {"Telegram": 4},
    "en": {"Telegram": 4},
    "es": {"Telegram": 4},
    "fa": {"\u062a\u0644\u06af\u0631\u0627\u0645": 4},  # تلگرام
    "fr": {"Telegram": 5},
    "id": {"Telegram": 4},
    "it": {"Telegram": 4},
    # 텔레그램, also under the icon; with the subject particle 이, which is 가
    # after a vowel.
    "ko": {"Telegram": 2, "\ud154\ub808\uadf8\ub7a8\uc774": 2, "\ud154\ub808\uadf8\ub7a8": 1},
    "ms": {"Telegram": 4},
    "nl": {"Telegram": 4},
    "pl": {"Telegram": 4},
    "pt": {"Telegram": 4},
    "ru": {"Telegram": 2},
    "tr": {"Telegram": 4},
    "uk": {"Telegram": 4},
    "uz": {"Telegram": 4},
}
KOREAN_SUBJECT = ("\ud154\ub808\uadf8\ub7a8\uc774", "\uac00")
# The name in source code: (file, text, how many times). {name} is the app's.
CODE_NAMES = (
    # The album the app saves photos and videos to.
    ("submodules/TelegramUI/Sources/StoreDownloadedMedia.swift",
     '        let albumName = "{name}"\n', 1),
    # The name in the system call screen (iOS 13; later ones show the app's).
    ("submodules/TelegramCallsUI/Sources/CallKitIntegration.swift",
     'CXProviderConfiguration(localizedName: "{name}")', 1),
    # The widget of a passcode-locked app.
    ("submodules/WidgetItems/Sources/WidgetItems.swift",
     'generalLockedText: "Open {name} and enter passcode to edit widget.",', 1),
    ("Telegram/SiriIntents/IntentHandler.swift",
     'NSLocalizedDescriptionKey: "Open {name} and enter passcode to edit widget."', 1),
    # The service account 777000 until the server's data arrives.
    ("submodules/TelegramCore/Sources/State/AccountStateManagementUtils.swift",
     'firstName: "{name} Notifications"', 1),
    # The e-mail about a login code that does not arrive.
    ("submodules/AuthorizationUI/Sources/AuthorizationSequenceController.swift",
     'emailBody.append("{name}: \\(appVersion)\\n")', 1),
    # The label of the app's entry in a contact of the address book, written
    # and read back: Telegram installed on the same phone writes its own.
    ("submodules/AccountContext/Sources/DeviceContactData.swift",
     'self.init(label: "{name}", value: "\\(phonebookUsernamePrefix)', 1),
    ("submodules/TelegramUI/Sources/DeviceContactDataManager.swift",
     'if address.label == "{name}", let peerId = parseAppSpecificContactReference(', 3),
    ("Telegram/SiriIntents/IntentContacts.swift",
     'if address.label == "{name}", let peerId = parseAppSpecificContactReference(', 1),
)

# Everything the patch reads, edits or checks: the check job fetches only
# these (ci/fetch-upstream.sh sparse).
UPSTREAM_PATHS = ((VERSIONS, BAZELRC, APP_BUILD, "build-system/Make") + NETWORK_DIRS
                  + (APP_ICON,) + tuple(sorted(r for r in BRAND_REPLACED if not r.startswith(APP_ICON + "/")))
                  + (APP_DELEGATE, INTRO_ANIMATIONS, STRINGS)
                  + tuple(INFOPLIST_STRINGS.format(lang) for lang in INFOPLIST_NAMES)
                  + tuple(sorted({rel for rel, _, _ in CODE_NAMES})))


class PatchError(Exception):
    pass


def src(indent, text):
    """A block of source: text dedented, then every line indented by indent
    (blank lines too, as Xcode leaves them), ending with a newline."""
    lines = textwrap.dedent(text).strip("\n").split("\n")
    return "".join(indent + line + "\n" for line in lines)


def lines_pattern(text):
    """A pattern for text whose blank lines may hold any indentation: Xcode
    indents them to the depth of the code around them."""
    body, end = (text[:-1], "\n") if text.endswith("\n") else (text, "")
    return "\n".join("[ \t]*" if not l.strip() else re.escape(l) for l in body.split("\n")) + end


# --- RSA key -----------------------------------------------------------------


def _der_read(data, pos, tag):
    if data[pos] != tag:
        raise PatchError(f"RSA key: DER tag {data[pos]:#x} at {pos}, expected {tag:#x}")
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return data[pos:pos + length], pos + length


def parse_pkcs1_der(der):
    """Returns (n, e) as big-endian bytes without leading zeros."""
    seq, end = _der_read(der, 0, 0x30)
    if end != len(der):
        raise PatchError("RSA key: trailing data after the key")
    n, pos = _der_read(seq, 0, 0x02)
    e, pos = _der_read(seq, pos, 0x02)
    if pos != len(seq):
        raise PatchError("RSA key: unexpected fields in the key")
    return n.lstrip(b"\0"), e.lstrip(b"\0")


def parse_pkcs1_public_key(pem):
    lines = [l.strip() for l in pem.strip().splitlines()]
    if not lines or lines[0] != "-----BEGIN RSA PUBLIC KEY-----" or lines[-1] != "-----END RSA PUBLIC KEY-----":
        raise PatchError("RSA key: expected a PKCS#1 PEM (BEGIN RSA PUBLIC KEY)")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError:
        raise PatchError("RSA key: the PEM body is not base64")
    return parse_pkcs1_der(der)


def _tl_bytes(b):
    if len(b) < 254:
        out = bytes([len(b)]) + b
    else:
        out = b"\xfe" + len(b).to_bytes(3, "little") + b
    return out + b"\0" * (-len(out) % 4)


def key_fingerprint(n, e):
    """MTProto fingerprint, as MTRsaFingerprint computes it: the low 64 bits
    of SHA1 over the TL-serialized modulus and exponent."""
    digest = hashlib.sha1(_tl_bytes(n) + _tl_bytes(e)).digest()
    return int.from_bytes(digest[-8:], "little")


def canonical_pem(n, e):
    def der_int(b):
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\x02" + _der_len(len(b)) + b

    body = der_int(n) + der_int(e)
    der = b"\x30" + _der_len(len(body)) + body
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ["-----BEGIN RSA PUBLIC KEY-----", *lines, "-----END RSA PUBLIC KEY-----"]


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def objc_key(pem, indent):
    """The key as an Objective-C string literal in MtProtoKit's layout: the
    first line after @", the others below it."""
    lines = [f'"{l}\\n"' for l in pem[:-1]] + [f'"{pem[-1]}"']
    return "@" + lines[0] + "".join(f"\n{indent}{l}" for l in lines[1:])


# --- edits -------------------------------------------------------------------


class Tree:
    def __init__(self, root):
        self.root = pathlib.Path(root)
        if not (self.root / VERSIONS).is_file() or not (self.root / APP_BUILD).is_file():
            raise PatchError(f"{root}: not a TelegramMessenger/Telegram-iOS checkout")

    def read(self, rel):
        return (self.root / rel).read_text(encoding="utf-8")

    def write(self, rel, text):
        self.write_bytes(rel, text.encode("utf-8"))

    def write_bytes(self, rel, data):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def unlink(self, rel):
        (self.root / rel).unlink()

    def sha256(self, rel):
        p = self.root / rel
        return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None

    def expect_file(self, rel, sha256):
        """The file must be the one of the pinned commit, byte for byte."""
        found = self.sha256(rel)
        if found != sha256:
            state = "missing" if found is None else f"SHA-256 {found}"
            raise PatchError(f"{rel}: {state}, expected {sha256}; upstream changed it")

    def replace_file(self, rel, sha256, data):
        self.expect_file(rel, sha256)
        self.write_bytes(rel, data)

    def add_file(self, rel, data):
        if (self.root / rel).exists():
            raise PatchError(f"{rel}: already exists; upstream changed it")
        self.write_bytes(rel, data)

    def remove_file(self, rel, sha256):
        self.expect_file(rel, sha256)
        self.unlink(rel)

    def expect(self, rel, s, count=1):
        found = self.read(rel).count(s)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {s!r}, expected {count}; upstream changed it")

    def replace(self, rel, old, new, count=1):
        text = self.read(rel)
        found = text.count(old)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {old!r}, expected {count}")
        self.write(rel, text.replace(old, new))

    def replace_lines(self, rel, old, new, count=1):
        """replace(), but blank lines of old match whatever indentation."""
        text = self.read(rel)
        out, found = re.subn(lines_pattern(old), lambda _: new, text)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {old.strip()[:80]!r}..., expected {count}")
        self.write(rel, out)

    def replace_body(self, rel, head, tail, body, must_contain=()):
        """Replaces what lies between head and the first tail after it."""
        text = self.read(rel)
        if text.count(head) != 1:
            raise PatchError(f"{rel}: {text.count(head)} occurrences of {head!r}, expected 1")
        start = text.index(head) + len(head)
        end = text.find(tail, start)
        if end < 0:
            raise PatchError(f"{rel}: no {tail!r} after {head!r}")
        for s in must_contain:
            if s not in text[start:end]:
                raise PatchError(f"{rel}: the replaced block has no {s!r}; upstream changed it")
        self.write(rel, text[:start] + body + text[end:])

    def replace_block(self, rel, head, tail, block, must_contain=()):
        """Replaces head, the first tail after it and what lies between."""
        text = self.read(rel)
        if text.count(head) != 1:
            raise PatchError(f"{rel}: {text.count(head)} occurrences of {head!r}, expected 1")
        start = text.index(head)
        end = text.find(tail, start + len(head))
        if end < 0:
            raise PatchError(f"{rel}: no {tail!r} after {head!r}")
        for s in must_contain:
            if s not in text[start:end]:
                raise PatchError(f"{rel}: the replaced block has no {s!r}; upstream changed it")
        self.write(rel, text[:start] + block + text[end + len(tail):])

    def network_sources(self):
        for d in NETWORK_DIRS:
            base = self.root / d
            if not base.is_dir():
                raise PatchError(f"{d}: missing; not a full checkout of the network code")
            for p in sorted(base.rglob("*")):
                if p.is_file() and p.suffix in (".swift", ".m", ".h", ".mm", ".c", ".cpp"):
                    yield p.relative_to(self.root).as_posix()


# --- configuration -----------------------------------------------------------


def load_env(path):
    out = {}
    for n, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise PatchError(f"{path}:{n}: expected KEY=VALUE")
        out[key.strip()] = value.strip()
    return out


class Config:
    def __init__(self, upstream, app, server_ipv4, server_port, server_ipv6, rsa_pem, team_id):
        def need(env, key):
            if not env.get(key):
                raise PatchError(f"{key} is not set")
            return env[key]

        self.layer = int(need(upstream, "UPSTREAM_LAYER"))
        self.version = need(upstream, "UPSTREAM_VERSION")
        self.xcode = need(upstream, "XCODE_VERSION")
        self.bazel = need(upstream, "BAZEL_VERSION")

        self.bundle_id = need(app, "PLUMA_BUNDLE_ID")
        if not re.fullmatch(r"[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+", self.bundle_id):
            raise PatchError(f"PLUMA_BUNDLE_ID {self.bundle_id!r} is not a reverse-DNS bundle ID")
        self.app_name = need(app, "PLUMA_APP_NAME")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .-]{0,14}", self.app_name):
            raise PatchError(f"PLUMA_APP_NAME {self.app_name!r}: up to 15 letters, digits, spaces, dots and dashes")
        self.url_scheme = need(app, "PLUMA_URL_SCHEME")
        if not re.fullmatch(r"[a-z][a-z0-9+.-]*", self.url_scheme) or self.url_scheme in ("tg", "telegram", "tonsite"):
            raise PatchError(f"PLUMA_URL_SCHEME {self.url_scheme!r}: a URL scheme of Pluma's own")
        self.api_id = int(need(app, "PLUMA_API_ID"))
        if self.api_id <= 0:
            raise PatchError("PLUMA_API_ID must be positive")
        self.api_hash = need(app, "PLUMA_API_HASH")
        if not re.fullmatch(r"[0-9a-f]{32}", self.api_hash):
            raise PatchError("PLUMA_API_HASH must be 32 lowercase hex digits")

        self.team_id = team_id
        if not re.fullmatch(r"[A-Z0-9]{10}", team_id or ""):
            raise PatchError(f"Team ID {team_id!r} is not an Apple Team ID (10 letters and digits)")

        try:
            self.ipv4 = str(ipaddress.IPv4Address(server_ipv4))
        except ValueError:
            raise PatchError(f"server IPv4 {server_ipv4!r} is not an IPv4 address (MtProtoKit needs an address, not a name)")
        self.ipv6 = None
        if server_ipv6:
            try:
                self.ipv6 = str(ipaddress.IPv6Address(server_ipv6))
            except ValueError:
                raise PatchError(f"server IPv6 {server_ipv6!r} is not an IPv6 address")
        for a in filter(None, (self.ipv4, self.ipv6)):
            if any(ipaddress.ip_address(a) in net for net in TELEGRAM_NETWORKS):
                raise PatchError(f"server address {a} is Telegram's")
        try:
            self.port = int(server_port)
        except ValueError:
            self.port = 0
        if not 0 < self.port < 65536:
            raise PatchError(f"server port {server_port!r} is not a port")

        self.n, self.e = parse_pkcs1_public_key(rsa_pem)
        # MtProtoKit turns the PKCS#1 key into a SubjectPublicKeyInfo by
        # gluing on the header of a 2048-bit key (MTRsa.m).
        if len(self.n) * 8 != 2048 or int.from_bytes(self.e, "big") != 65537:
            raise PatchError(f"RSA key: {len(self.n) * 8} bits, exponent {int.from_bytes(self.e, 'big')}; "
                             "the clients expect 2048 bits and 65537")
        self.rsa_pem = canonical_pem(self.n, self.e)
        self.fingerprint = key_fingerprint(self.n, self.e)
        if self.fingerprint in TELEGRAM_FINGERPRINTS:
            raise PatchError("RSA key: this is Telegram's key")

    def build_configuration(self):
        """The configuration of Make.py (build-system/appstore-configuration.json
        is upstream's)."""
        return {
            "bundle_id": self.bundle_id,
            "api_id": str(self.api_id),
            "api_hash": self.api_hash,
            "team_id": self.team_id,
            # No App Center crash reports, no App Store or in-app purchases.
            "app_center_id": "0",
            # A public build, as the App Store's: no internal debug features,
            # and among them the reflector benchmark against Telegram's
            # servers (TelegramUI AppDelegate).
            "is_internal_build": "false",
            "is_appstore_build": "true",
            "appstore_id": "0",
            "app_specific_url_scheme": self.url_scheme,
            "premium_iap_product_id": "",
            # Siri and iCloud need capabilities of their own; iCloud was one
            # more source of Telegram's backup addresses.
            "enable_siri": False,
            "enable_icloud": False,
        }


# --- the patch ---------------------------------------------------------------


SEED_OLD = src(" " * 12, """
    let seedAddressList: [Int: [String]]

    if testingEnvironment {
        seedAddressList = [
            1: ["149.154.175.10"],
            2: ["149.154.167.40"],
            3: ["149.154.175.117"]
        ]
    } else {
        seedAddressList = [
            1: ["149.154.175.50", "2001:b28:f23d:f001::a"],
            2: ["149.154.167.50", "95.161.76.100", "2001:67c:4e8:f002::a"],
            3: ["149.154.175.100", "2001:b28:f23d:f003::a"],
            4: ["149.154.167.91", "2001:67c:4e8:f004::a"],
            5: ["149.154.171.5", "2001:b28:f23f:f005::a"]
        ]
    }

    for (id, ips) in seedAddressList {
        context.setSeedAddressSetForDatacenterWithId(id, seedAddressSet: MTDatacenterAddressSet(addressList: ips.map { MTDatacenterAddress(ip: $0, port: 443, preferForMedia: false, restrictToTcp: false, cdn: false, preferForProxy: false, secret: nil) }))
    }
""")

CLOUD_SOURCE_OLD = src(" " * 12, """
    var wrappedAdditionalSource: MTSignal?
    #if os(iOS)
    if #available(iOS 10.0, *), !supplementary, arguments.isICloudEnabled {
        var cloudDataContextValue: CloudDataContext?
        if let value = cloudDataContext.with({ $0 }) {
            cloudDataContextValue = value
        } else {
            cloudDataContextValue = makeCloudDataContext(encryptionProvider: arguments.encryptionProvider)
            let _ = cloudDataContext.swap(cloudDataContextValue)
        }

        if let cloudDataContext = cloudDataContextValue {
            wrappedAdditionalSource = MTSignal(generator: { subscriber in
                let disposable = cloudDataContext.get(phoneNumber: .single(phoneNumber)).start(next: { value in
                    subscriber?.putNext(value)
                }, completed: {
                    subscriber?.putCompletion()
                })
                return MTBlockDisposable(block: {
                    disposable.dispose()
                })
            })
        }
    }
    #endif
""")

DISCOVER_OLD = ("                context.setDiscoverBackupAddressListSignal(MTBackupAddressSignals.fetchBackupIps(testingEnvironment, "
                "currentContext: context, additionalSource: wrappedAdditionalSource, phoneNumber: phoneNumber, "
                "mainDatacenterId: datacenterId))\n")

INITIAL_DC_OLD = src(" " * 24, """
    #if DEBUG
    let initialDatacenterId: Int = 1
    #else
    let initialDatacenterId: Int = 2
    #endif
""")

WARMUP_OLD = src(" " * 12, """
    var datacenterIds: [Int] = [1, 2]
    if testingEnvironment {
        datacenterIds = [3]
    } else {
        datacenterIds.append(contentsOf: [4])
    }
""")

CALL_REFLECTOR_OLD = src(" " * 16, """
    var unfilteredConnections: [CallSessionConnection]
    unfilteredConnections = [connections.primary] + connections.alternatives

    if version == "12.0.0" {
        for connection in unfilteredConnections {
            if case let .reflector(reflector) = connection {
                unfilteredConnections.append(.reflector(CallSessionConnection.Reflector(
                    id: 123456,
                    ip: "91.108.9.38",
                    ipv6: "",
                    isTcp: true,
                    port: 595,
                    peerTag: reflector.peerTag
                )))
            }
        }
    }
""")

DNS_OLD = ("    return [[self resolveHostname:hostname] timeout:10.0 onQueue:[MTQueue concurrentDefaultQueue] "
           "orSignal:[self resolveHostnameNative:hostname port:port]];\n")

BACKUP_HEAD = ("+ (MTSignal * _Nonnull)fetchBackupIps:(bool)isTestingEnvironment currentContext:(MTContext * _Nonnull)currentContext "
               "additionalSource:(MTSignal * _Nullable)additionalSource phoneNumber:(NSString * _Nullable)phoneNumber "
               "mainDatacenterId:(NSInteger)mainDatacenterId {\n")
BACKUP_BODY = ("    // pluma: no backup addresses. The DNS and CloudKit records they come\n"
               "    // from are Telegram's and point at Telegram.\n"
               "    return [MTSignal complete];")

EXTENSIONS = src(" " * 4, """
    extensions = select({
        ":disableExtensionsSetting": [],
        "//conditions:default": [
            ":ShareExtension",
            ":NotificationContentExtension",
            ":NotificationServiceExtension" + notificationServiceExtensionVersion,
            ":IntentsExtension",
            ":WidgetExtension",
            ":BroadcastUploadExtension",
        ],
    }),
""")


def required_configuration_keys(tree):
    text = tree.read(BUILD_CONFIGURATION)
    m = re.search(r"required_keys = \[(.*?)\]", text, re.S)
    if not m:
        raise PatchError(f"{BUILD_CONFIGURATION}: no required_keys; upstream changed it")
    return set(re.findall(r"'([a-z_]+)'", m.group(1)))


def patch(tree, c):
    # The upstream is the one upstream.env describes: the schema layer the
    # server speaks (ADR 0008 of the server repository), the version and the
    # toolchain the CI installs.
    tree.expect(SERIALIZATION, f"    public func currentLayer() -> UInt {{\n        return {c.layer}\n    }}\n")
    versions = json.loads(tree.read(VERSIONS))
    for key, want in (("app", c.version), ("xcode", c.xcode)):
        if versions.get(key) != want:
            raise PatchError(f"{VERSIONS}: {key} is {versions.get(key)!r}, upstream.env says {want!r}")
    if versions.get("bazel", "").split(":")[0] != c.bazel:
        raise PatchError(f"{VERSIONS}: bazel is {versions.get('bazel')!r}, upstream.env says {c.bazel!r}")

    # What ci/build.sh relies on in Make.py: the build configurations, the
    # code signing modes, the caches; and the targets the profiles are for.
    for s in ("elif configuration == 'debug_sim_arm64':", "elif configuration == 'release_sim_arm64':",
              "elif configuration == 'release_arm64':",
              "    codesigning_group.add_argument(\n        '--xcodeManagedCodesigning',",
              "    codesigning_group.add_argument(\n        '--codesigningInformationPath',",
              "    cacheTypeGroup.add_argument(\n        '--cacheDir',",
              "    parser.add_argument(\n        '--bazelUserRoot',",
              "    buildParser.add_argument(\n        '--continueOnError',"):
        tree.expect(MAKE, s)
    for suffix, name, _ in TARGETS:
        tree.expect(BUILD_CONFIGURATION, f"'{suffix}': '{name}'")
    tree.expect(APP_BUILD, EXTENSIONS)
    tree.expect(APP_BUILD, '    name = "disableProvisioningProfiles",\n')
    tree.expect(APP_BUILD, '        ":disableProvisioningProfilesSetting": None,\n', count=10)
    tree.expect(APP_BUILD, "        <string>group.{telegram_bundle_id}</string>\n")

    # MtProtoKit: one datacenter, the Pluma server, for the production and
    # the test backend alike.
    addresses = ", ".join(f'"{a}"' for a in (c.ipv4, c.ipv6) if a)
    seed = src(" " * 12, f"""
        // pluma: a single datacenter, the Pluma server, on both backends.
        let seedAddressList: [Int: [String]] = [
            1: [{addresses}]
        ]

        for (id, ips) in seedAddressList {{
            context.setSeedAddressSetForDatacenterWithId(id, seedAddressSet: MTDatacenterAddressSet(addressList: ips.map {{ MTDatacenterAddress(ip: $0, port: {c.port}, preferForMedia: false, restrictToTcp: false, cdn: false, preferForProxy: false, secret: nil) }}))
        }}
    """)
    tree.replace_lines(NETWORK, SEED_OLD, seed)

    # A fresh install starts on it, and the only keys it makes ahead are for it.
    tree.replace_lines(ACCOUNT, INITIAL_DC_OLD,
                 src(" " * 24, """
                     // pluma: the server is datacenter 1.
                     let initialDatacenterId: Int = 1
                 """))
    tree.replace_lines(ACCOUNT, WARMUP_OLD,
                 src(" " * 12, """
                     // pluma: the server is the only datacenter, on both backends.
                     let datacenterIds: [Int] = [1]
                 """))

    # No backup addresses: Telegram publishes them in DNS records (fetched
    # over Google's DNS-over-HTTPS) and in CloudKit, and they point at
    # Telegram. The caller, and the library as well.
    tree.replace_lines(NETWORK, CLOUD_SOURCE_OLD,
                 "            // pluma: no backup addresses from CloudKit (see below).\n")
    tree.replace(NETWORK, DISCOVER_OLD,
                 "                // pluma: no backup addresses; Telegram's DNS and CloudKit records point at Telegram.\n")
    tree.replace_body(BACKUP, BACKUP_HEAD, "\n}\n\n@end\n", BACKUP_BODY,
                      must_contain=("fetchBackupIpsResolveGoogle:", "fetchConfigFromAddress:"))
    # Proxy host names resolve through the system, not Google's DNS-over-HTTPS.
    tree.replace(DNS, DNS_OLD,
                 "    // pluma: the system resolver only, no DNS-over-HTTPS at Google.\n"
                 "    return [self resolveHostnameNative:hostname port:port];\n")

    # MtProtoKit: the server key replaces Telegram's production and test
    # keys (the key is chosen by the fingerprint the server announces).
    key = objc_key(c.rsa_pem, " " * 13)
    keys = ("    dispatch_once(&onceToken, ^{\n"
            "        // pluma: the key of the Pluma server, for both backends.\n"
            "        testingPublicKeys = @[\n"
            f"            [[MTDatacenterAuthPublicKey alloc] initWithPublicKey:{key}]\n"
            "        ];\n"
            "\n"
            "        productionPublicKeys = @[\n"
            f"            [[MTDatacenterAuthPublicKey alloc] initWithPublicKey:{key}]\n"
            "        ];\n"
            "    });\n")
    tree.replace_block(AUTH_KEYS, "    dispatch_once(&onceToken, ^{\n        testingPublicKeys = @[\n", "    });\n", keys,
                       must_contain=TELEGRAM_KEY_LINES[:2])
    # The key of Telegram's backup address records: the records are off, and
    # none of Telegram's keys stays in the client.
    tree.replace_block(ENCRYPTION, '    NSString *keyString = @"-----BEGIN RSA PUBLIC KEY-----\\n"\n',
                       '"-----END RSA PUBLIC KEY-----";\n',
                       "    // pluma: the server's key; Telegram's backup address records are off.\n"
                       f"    NSString *keyString = {objc_key(c.rsa_pem, '')};\n",
                       must_contain=(TELEGRAM_KEY_LINES[2],))

    # Calls: no extra TCP reflector of Telegram's for the 12.0.0 protocol.
    tree.replace_lines(CALLS, CALL_REFLECTOR_OLD,
                 src(" " * 16, """
                     // pluma: the reflectors are the server's; no extra one of Telegram's.
                     let unfilteredConnections: [CallSessionConnection] = [connections.primary] + connections.alternatives
                 """))

    # The name under the icon and in the share sheet, and the URL scheme of
    # the app's own links (the widget opens the app with it). The bundle ID,
    # the extensions' IDs and the App Group follow from the build
    # configuration.
    tree.replace(APP_BUILD, "    <key>CFBundleDisplayName</key>\n    <string>Telegram</string>\n",
                 f"    <key>CFBundleDisplayName</key>\n    <string>{c.app_name}</string>\n", count=2)
    tree.replace(APP_BUILD, "    <key>CFBundleName</key>\n    <string>Telegram</string>\n",
                 f"    <key>CFBundleName</key>\n    <string>{c.app_name}</string>\n", count=7)
    tree.replace(APP_BUILD, "                <string>telegram</string>\n",
                 f"                <string>{c.url_scheme}</string>\n")

    patch_brand(tree)
    patch_names(tree, c)

    # The build configuration of Make.py, with exactly the keys it reads.
    conf = c.build_configuration()
    want = required_configuration_keys(tree)
    if set(conf) != want:
        raise PatchError(f"{BUILD_CONFIGURATION}: Make.py reads {sorted(want)}, the patch writes {sorted(conf)}")
    tree.write(CONFIGURATION, json.dumps(conf, indent=2) + "\n")

    # The Bazel flags of ci/build.sh (the caches; simulator builds without
    # provisioning profiles): Make.py passes no flags of its own choosing.
    rc = tree.read(BAZELRC)
    if "try-import" in rc or PLUMA_BAZELRC in rc:
        raise PatchError(f"{BAZELRC}: already imports a file; upstream changed it")
    tree.write(BAZELRC, rc + ("" if rc.endswith("\n") else "\n")
               + "\n# pluma: the flags of ci/build.sh.\n"
               + f"try-import %workspace%/{PLUMA_BAZELRC}\n")


ALTERNATE_ICONS_OLD = """alternate_icon_folders = [
    "BlackIcon",
    "BlackClassicIcon",
    "BlackFilledIcon",
    "BlueIcon",
    "BlueClassicIcon",
    "BlueFilledIcon",
    "WhiteFilledIcon",
    "New1",
    "New2",
    "Premium",
    "PremiumBlack",
    "PremiumTurbo",
]
"""

APP_ICONS_OLD = src(" " * 16, """
    var icons = [
        PresentationAppIcon(name: "BlueIcon", imageName: "BlueIcon", isDefault: buildConfig.isAppStoreBuild),
        PresentationAppIcon(name: "New2", imageName: "New2"),
        PresentationAppIcon(name: "New1", imageName: "New1"),
        PresentationAppIcon(name: "BlackIcon", imageName: "BlackIcon"),
        PresentationAppIcon(name: "BlueClassicIcon", imageName: "BlueClassicIcon"),
        PresentationAppIcon(name: "BlackClassicIcon", imageName: "BlackClassicIcon"),
        PresentationAppIcon(name: "BlueFilledIcon", imageName: "BlueFilledIcon"),
        PresentationAppIcon(name: "BlackFilledIcon", imageName: "BlackFilledIcon")
    ]
    if buildConfig.isInternalBuild {
        icons.append(PresentationAppIcon(name: "WhiteFilledIcon", imageName: "WhiteFilledIcon"))
    }

    icons.append(PresentationAppIcon(name: "Premium", imageName: "Premium", isPremium: true))
    icons.append(PresentationAppIcon(name: "PremiumTurbo", imageName: "PremiumTurbo", isPremium: true))
    icons.append(PresentationAppIcon(name: "PremiumBlack", imageName: "PremiumBlack", isPremium: true))

    return icons
""")


def brand_files():
    """The files of brand/ios, as paths relative to it."""
    if not BRAND.is_dir():
        raise PatchError(f"{BRAND}: missing (brand/render.sh)")
    return sorted(p.relative_to(BRAND).as_posix() for p in BRAND.rglob("*")
                  if p.is_file() and not p.name.startswith("."))


def patch_brand(tree):
    """Pluma's images in place of Telegram's: the app icon and the alternate
    one, the logos of the quick action, the context menu, calls and QR codes,
    and the first page of the intro."""
    want = sorted(set(BRAND_REPLACED) | set(BRAND_ADDED))
    if brand_files() != want:
        raise PatchError(f"brand/ios holds {brand_files()}, the patch expects {want}; "
                         "re-run brand/render.sh or update BRAND_* in ci/patch.py")
    for rel, sha256 in BRAND_REPLACED.items():
        tree.replace_file(rel, sha256, (BRAND / rel).read_bytes())
    for rel, sha256 in BRAND_REMOVED.items():
        tree.remove_file(rel, sha256)
    for rel in BRAND_ADDED:
        tree.add_file(rel, (BRAND / rel).read_bytes())

    # One alternate icon, Pluma's, in the folder of the one the app counts as
    # its default (BlueIcon: the icon picker, the theme file type); the
    # others are Telegram's, so the bundle carries them no more and the
    # picker does not offer them.
    tree.replace(APP_BUILD, ALTERNATE_ICONS_OLD,
                 "# pluma: Pluma's icon only, in the folder the app counts as its default.\n"
                 "alternate_icon_folders = [\n"
                 '    "BlueIcon",\n'
                 "]\n")
    tree.replace_lines(APP_DELEGATE, APP_ICONS_OLD, src(" " * 16, """
        // pluma: Pluma's icon only; the others are Telegram's.
        return [
            PresentationAppIcon(name: "BlueIcon", imageName: "BlueIcon", isDefault: buildConfig.isAppStoreBuild)
        ]
    """))

    # The intro: sage instead of Telegram's blues behind the pages "Powerful"
    # (#4F6E52) and "Cloud-Based" (#6F8F72).
    tree.replace(INTRO_ANIMATIONS, "    vec4 powerful_bg_color = {47/255., 90/255., 131/255., 1};\n",
                 "    vec4 powerful_bg_color = {79/255., 110/255., 82/255., 1}; // pluma: #4F6E52\n")
    tree.replace(INTRO_ANIMATIONS, "    vec4 cloud_color = {42/255., 180/255., 247/255., 1};\n",
                 "    vec4 cloud_color = {111/255., 143/255., 114/255., 1}; // pluma: #6F8F72\n")


# An entry of a .strings file, "key" = "value";, where the value may span
# lines: the key with what precedes the value, the value, the end.
STRINGS_ENTRY = re.compile(r'^("(?:[^"\\]|\\.)*"\s*=\s*")((?:[^"\\]|\\.)*)(";)', re.M)
# The name as a word, also right after an escaped line break (\nTelegram).
TELEGRAM_WORD = re.compile(r"(?:(?<![0-9A-Za-z_])|(?<=\\n))(Telegram|TELEGRAM)(?![0-9A-Za-z_])")
# The entries of the English strings that name Telegram, and how many times
# they do, in the pinned commit. Keys never change (the code refers to them),
# nor do URLs, user names or link targets: they are lower case or part of
# another word (telegram.org, t.me, TelegramTips, (telegram)).
STRINGS_RENAMED = (556, 609)


def rename_strings(text, name):
    """The values of a .strings file with the word Telegram (TELEGRAM) as
    name; returns the text, the entries changed and the occurrences."""
    entries = occurrences = 0

    def entry(m):
        nonlocal entries, occurrences
        value, n = TELEGRAM_WORD.subn(lambda w: name if w.group(1) == "Telegram" else name.upper(), m.group(2))
        if n:
            entries += 1
            occurrences += n
        return m.group(1) + value + m.group(3)

    return STRINGS_ENTRY.sub(entry, text), entries, occurrences


def patch_names(tree, c):
    """Pluma, not Telegram, in what the user reads: the built-in strings, the
    permission prompts, the name in other languages and a few texts of the
    code."""
    text, entries, occurrences = rename_strings(tree.read(STRINGS), c.app_name)
    if (entries, occurrences) != STRINGS_RENAMED:
        raise PatchError(f"{STRINGS}: Telegram in {entries} entries ({occurrences} times), expected "
                         f"{STRINGS_RENAMED[0]} ({STRINGS_RENAMED[1]} times); upstream changed the strings")
    tree.write(STRINGS, text)

    for lang, names in INFOPLIST_NAMES.items():
        rel = INFOPLIST_STRINGS.format(lang)
        for old, count in names.items():
            new = c.app_name + KOREAN_SUBJECT[1] if old == KOREAN_SUBJECT[0] else c.app_name
            tree.replace(rel, old, new, count=count)

    # The main Info.plist: the permission prompts in English (the
    # InfoPlist.strings of the language override them) and the theme files.
    tree.replace(APP_BUILD, "    <string>Telegram stores your contacts heavily encrypted",
                 f"    <string>{c.app_name} stores your contacts heavily encrypted")
    tree.replace(APP_BUILD, "When you send your location to your friends, Telegram needs access to show them a map.",
                 f"When you send your location to your friends, {c.app_name} needs access to show them a map.", count=3)
    tree.replace(APP_BUILD, "<string>Telegram iOS Color Theme File</string>",
                 f"<string>{c.app_name} iOS Color Theme File</string>")

    for rel, text, count in CODE_NAMES:
        tree.replace(rel, text.format(name="Telegram"), text.format(name=c.app_name), count=count)


def verify_names(tree, c):
    for m in STRINGS_ENTRY.finditer(tree.read(STRINGS)):
        if TELEGRAM_WORD.search(m.group(2)):
            raise PatchError(f"{STRINGS}: {m.group(0)[:80]!r} still names Telegram")
    for lang, names in INFOPLIST_NAMES.items():
        rel = INFOPLIST_STRINGS.format(lang)
        text = tree.read(rel)
        for old in names:
            if old in text:
                raise PatchError(f"{rel}: still names Telegram ({old})")
        if "CFBundleDisplayName" in text and f'"CFBundleDisplayName" = "{c.app_name}";' not in text:
            raise PatchError(f"{rel}: the name under the icon is not {c.app_name}")
    for value in re.findall(r"<string>([^<]*)</string>", tree.read(APP_BUILD)):
        if " " in value and TELEGRAM_WORD.search(value):
            raise PatchError(f"{APP_BUILD}: {value[:60]!r} still names Telegram")
    for rel, text, _ in CODE_NAMES:
        if text.format(name="Telegram") in tree.read(rel):
            raise PatchError(f"{rel}: still names Telegram")


def verify_brand(tree):
    for rel in sorted(set(BRAND_REPLACED) | set(BRAND_ADDED)):
        if tree.sha256(rel) != hashlib.sha256((BRAND / rel).read_bytes()).hexdigest():
            raise PatchError(f"{rel}: not Pluma's image of brand/ios")
    for rel in BRAND_REMOVED:
        if (tree.root / rel).exists():
            raise PatchError(f"{rel}: Telegram's image is still there")
    m = re.search(r"^alternate_icon_folders = \[(.*?)\]", tree.read(APP_BUILD), re.S | re.M)
    if not m or re.findall(r'"([^"]+)"', m.group(1)) != ["BlueIcon"]:
        raise PatchError(f"{APP_BUILD}: alternate icons other than Pluma's")
    if tree.read(APP_DELEGATE).count("PresentationAppIcon(") != 1:
        raise PatchError(f"{APP_DELEGATE}: the icon picker offers Telegram's icons")


IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
PEM_BLOCK = re.compile(r"-----BEGIN RSA PUBLIC KEY-----(.*?)-----END RSA PUBLIC KEY-----", re.S)


def telegram_addresses(text):
    found = []
    for m in IPV4.finditer(text):
        try:
            a = ipaddress.IPv4Address(m.group(0))
        except ValueError:
            continue
        if any(a in net for net in TELEGRAM_NETWORKS):
            found.append(str(a))
    for m in IPV6.finditer(text):
        try:
            a = ipaddress.IPv6Address(m.group(0))
        except ValueError:
            continue
        if any(a in net for net in TELEGRAM_NETWORKS):
            found.append(str(a))
    return found


def embedded_keys(text):
    """The RSA keys in a source file: every PEM block whose body is base64
    once the string literal syntax (quotes, \\n, line breaks) is gone."""
    keys = []
    for m in PEM_BLOCK.finditer(text):
        body = re.sub(r'\\n|["\s]', "", m.group(1))
        if len(body) < 300 or not re.fullmatch(r"[A-Za-z0-9+/]+=*", body):
            continue  # code around the markers, not a key (MTRsa.m)
        try:
            keys.append(parse_pkcs1_der(base64.b64decode(body, validate=True)))
        except (ValueError, IndexError, PatchError):
            raise PatchError(f"an RSA key that does not parse: {body[:40]}...")
    return keys


def verify(tree, c):
    """Checks the result independently of how the edits were made."""
    keys = 0
    for rel in tree.network_sources():
        text = tree.read(rel)
        addresses = telegram_addresses(text)
        if addresses:
            raise PatchError(f"{rel}: Telegram's address {addresses[0]} is still there")
        for line in TELEGRAM_KEY_LINES:
            if line in text:
                raise PatchError(f"{rel}: Telegram's key {line[:24]}... is still there")
        try:
            found = embedded_keys(text)
        except PatchError as e:
            raise PatchError(f"{rel}: {e}")
        for n, e in found:
            if (n, e) != (c.n, c.e):
                raise PatchError(f"{rel}: an RSA key other than the server's ({key_fingerprint(n, e):#018x})")
        keys += len(found)
    if keys != 3:
        raise PatchError(f"the network code holds {keys} RSA keys, expected 3 (production, test, backup records)")

    net = tree.read(NETWORK)
    addresses = ", ".join(f'"{a}"' for a in (c.ipv4, c.ipv6) if a)
    if (net.count("setSeedAddressSetForDatacenterWithId(") != 1 or net.count("seedAddressList = ") != 0
            or f"                1: [{addresses}]\n            ]\n" not in net
            or net.count(f"MTDatacenterAddress(ip: $0, port: {c.port}, ") != 1):
        raise PatchError(f"{NETWORK}: the seed addresses are not the server's alone")
    if "fetchBackupIps(" in net or "setDiscoverBackupAddressListSignal(" in net:
        raise PatchError(f"{NETWORK}: still asks for backup addresses")
    for rel in tree.network_sources():
        if rel.endswith(".swift") and "fetchBackupIps(" in tree.read(rel):
            raise PatchError(f"{rel}: still asks for backup addresses")
    account = tree.read(ACCOUNT)
    if "let initialDatacenterId: Int = 1\n" not in account or "initialDatacenterId: Int = 2" in account:
        raise PatchError(f"{ACCOUNT}: a fresh install does not start on datacenter 1")
    if "[MTSignal complete];\n}\n\n@end\n" not in tree.read(BACKUP):
        raise PatchError(f"{BACKUP}: backup addresses are not off")

    verify_brand(tree)
    verify_names(tree, c)

    build = tree.read(APP_BUILD)
    if "<string>Telegram</string>" in build or "<string>telegram</string>" in build:
        raise PatchError(f"{APP_BUILD}: Telegram's name or URL scheme is still there")
    conf = json.loads(tree.read(CONFIGURATION))
    if (conf["bundle_id"], conf["api_id"], conf["team_id"]) != (c.bundle_id, str(c.api_id), c.team_id):
        raise PatchError(f"{CONFIGURATION}: not the Pluma app")


def main(argv=None):
    if (argv if argv is not None else sys.argv[1:]) == ["--paths"]:
        print("\n".join(UPSTREAM_PATHS))
        return 0
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 epilog="patch.py --paths prints the upstream paths the patch reads.")
    ap.add_argument("--source", required=True, help="the Telegram-iOS checkout")
    ap.add_argument("--upstream", required=True, help="upstream.env")
    ap.add_argument("--app", required=True, help="config/app.env")
    ap.add_argument("--server-ipv4", required=True)
    ap.add_argument("--server-port", required=True)
    ap.add_argument("--server-ipv6", default="")
    ap.add_argument("--rsa-public-key", required=True, help="PKCS#1 PEM of the server key")
    ap.add_argument("--team-id", required=True, help="the Apple Team ID that signs the app")
    a = ap.parse_args(argv)
    try:
        c = Config(load_env(a.upstream), load_env(a.app), a.server_ipv4, a.server_port, a.server_ipv6,
                   pathlib.Path(a.rsa_public_key).read_text(), a.team_id)
        tree = Tree(a.source)
        patch(tree, c)
        verify(tree, c)
    except PatchError as e:
        print(f"patch: {e}", file=sys.stderr)
        return 1
    address = c.ipv4 + (f", {c.ipv6}" if c.ipv6 else "")
    print(f"patch: {c.bundle_id} \"{c.app_name}\", api_id {c.api_id}, team {c.team_id}, layer {c.layer}, "
          f"server {address} port {c.port}, server key {c.fingerprint:#018x} ({c.fingerprint})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
