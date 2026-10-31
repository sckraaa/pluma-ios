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
pinned commit are part of the patch). The app's links use its own scheme,
plm://, not Telegram's tg://, and Settings > Devices links to Pluma's site
and web client, not to Telegram's clients. The default themes take the
palette "graphite and sage" instead of Telegram's blue. Settings no longer
lead to Telegram's support, FAQ and feature channel.

The chat list's notice about contacts' birthdays opens the chat with the
contact instead of offering a Premium gift, which Pluma does not sell.

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
DAY_THEME = "submodules/TelegramPresentationData/Sources/DefaultDayPresentationTheme.swift"
DARK_THEME = "submodules/TelegramPresentationData/Sources/DefaultDarkPresentationTheme.swift"
PRESENTATION_DATA = "submodules/TelegramPresentationData/Sources/PresentationData.swift"
THEME_SETTINGS = "submodules/TelegramUIPreferences/Sources/PresentationThemeSettings.swift"
LEGACY_COLORS = "submodules/LegacyComponents/Sources/TGColor.m"
AVATAR_NODE = "submodules/AvatarNode/Sources/AvatarNode.swift"
SETTINGS_ITEMS = "submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoSettingsItems.swift"
SETTINGS_SEARCH = "submodules/SettingsUI/Sources/Search/SettingsSearchableItems.swift"
# The birthday notice of the chat list: what a tap does, its text, its close.
CHAT_LIST = "submodules/ChatListUI/Sources/ChatListControllerNode.swift"
CHAT_LIST_NOTICE = "submodules/TelegramUI/Components/ChatList/ChatListHeaderNoticeComponent/Sources/ChatListNoticeItem.swift"
CHAT_LIST_PANELS = "submodules/TelegramUI/Components/GlobalControlPanelsContext/Sources/GlobalControlPanelsContext.swift"
# The birthday row of a contact's profile.
PROFILE_ITEMS = "submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoProfileItems.swift"
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
    # The laptop of Settings > Devices (the header of RecentSessionsController),
    # copied from brand/pluma-devices.tgs: the plane on its lid and in its QR
    # code is the mark.
    "Telegram/Telegram-iOS/Resources/Devices.tgs": "9abb2d5dbd4ac7d2a83722b4871b6be03f76605d1594bcb5b17204ec8e4285fe",
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

# The links the app makes with Telegram's scheme tg://, which Pluma's replaces:
# (file, text with {scheme}, how many times).
SCHEME_LINKS = (
    # The QR code of a sign-in on another device, and what the scanner of
    # another device accepts: only Pluma's codes sign in to Pluma.
    ("submodules/AuthorizationUI/Sources/AuthorizationSequencePhoneEntryControllerNode.swift",
     'let urlString = "{scheme}://login?token=\\(tokenString)"', 1),
    ("submodules/QrCodeUI/Sources/QrCodeScanScreen.swift",
     'filteredCodes = codes.filter { $0.message.hasPrefix("{scheme}://") }', 1),
    # The QR code of a proxy (the phone's camera opens it in the app).
    ("submodules/QrCodeUI/Sources/QrCodeScreen.swift", ': "{scheme}://proxy")?server=', 1),
    ("submodules/QrCodeUI/Sources/QrCodeScreen.swift", ': "{scheme}://socks")?server=', 1),
    # The link a settings search result copies.
    ("submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoScreen.swift",
     'let link = "{scheme}://settings/\\(item.id)"', 1),
    # Links that open the app from outside: after a chat import, and from the
    # share extension (its scheme, and the story it hands over).
    ("submodules/ChatImportUI/Sources/ChatImportActivityScreen.swift",
     'let url = URL(string: "{scheme}://localpeer?id=\\(controller.peerId.toInt64())")!', 1),
    ("submodules/TelegramUI/Components/ShareExtensionContext/Sources/ShareExtensionContext.swift",
     'appSpecificScheme: "{scheme}", openUrl:', 1),
    ("submodules/TelegramUI/Components/ShareExtensionContext/Sources/ShareExtensionContext.swift",
     'self.openUrl("{scheme}://shareStory?session=\\(sessionId)")', 1),
)
# Links the app reads: proxies, sticker sets, wallpapers and ads given as
# links take the app's own scheme as well as tg:// (OpenUrl.swift does so for
# every link already).
URL_HANDLING = "submodules/UrlHandling/Sources/UrlHandling.swift"
URL_HANDLING_TG = 'if let parsedUrl = URL(string: url), parsedUrl.scheme == "tg", let host = parsedUrl.host,'
URL_HANDLING_OWN = ('if let parsedUrl = URL(string: url), parsedUrl.scheme == "tg" || parsedUrl.scheme == '
                    'sharedContext.applicationBindings.appSpecificScheme, let host = parsedUrl.host,')

# Settings > Devices: the links of its header ("Link Pluma Desktop or Pluma
# Web by scanning a QR code", AuthSessions.HeaderInfo) open Pluma's site and
# its web client instead of Telegram's, as in the Android client (the owner's
# decision): (file, text with {url}, Telegram's URL, Pluma's, how many
# times). The screen's "Learn More" (openOtherAppsUrl, telegram.org/apps)
# stays.
SESSIONS = "submodules/SettingsUI/Sources/Privacy and Security/Recent Sessions/RecentSessionsController.swift"
# The QR scanner opened from that screen ("Link Desktop Device") names and
# opens the same two sites under its viewfinder.
QR_SCAN = "submodules/QrCodeUI/Sources/QrCodeScanScreen.swift"
CLIENT_LINKS = (
    (SESSIONS, '    }, openDesktopLink: {\n'
               '        context.sharedContext.openExternalUrl(context: context, urlContext: .generic, url: "{url}", ',
     "https://getdesktop.telegram.org", "https://pluma.chat/", 1),
    (SESSIONS, '    }, openWebLink: {\n'
               '        context.sharedContext.openExternalUrl(context: context, urlContext: .generic, url: "{url}", ',
     "https://web.telegram.org", "https://web.pluma.chat/", 1),
    (QR_SCAN, '                                    case "desktop":\n'
              '                                        self.context.sharedContext.openExternalUrl(context: self.context, urlContext: .generic, url: "{url}", ',
     "https://getdesktop.telegram.org", "https://pluma.chat/", 1),
    (QR_SCAN, '                                    case "web":\n'
              '                                        self.context.sharedContext.openExternalUrl(context: self.context, urlContext: .generic, url: "{url}", ',
     "https://web.telegram.org", "https://web.pluma.chat/", 1),
)
# The text of the scanner that names those sites, by key, in the only
# language the app bundles (en.lproj): (file, entry, Pluma's entry, how many).
CLIENT_TEXTS = (
    (STRINGS,
     '"AuthSessions.AddDevice.ScanInstallInfo" = "Go to [getdesktop.telegram.org](desktop) or '
     '[web.telegram.org](web) to get the QR code";',
     '"AuthSessions.AddDevice.ScanInstallInfo" = "Go to [pluma.chat](desktop) or '
     '[web.pluma.chat](web) to get the QR code";', 1),
)
# Telegram's client sites, which none of those files may open after the edits.
CLIENT_SITES = re.compile(r"(?:get)?desktop\.telegram\.org|web\.telegram\.org")

# Everything the patch reads, edits or checks: the check job fetches only
# these (ci/fetch-upstream.sh sparse).
UPSTREAM_PATHS = ((VERSIONS, BAZELRC, APP_BUILD, "build-system/Make") + NETWORK_DIRS
                  + (APP_ICON,) + tuple(sorted(r for r in BRAND_REPLACED if not r.startswith(APP_ICON + "/")))
                  + (APP_DELEGATE, INTRO_ANIMATIONS, STRINGS)
                  + tuple(INFOPLIST_STRINGS.format(lang) for lang in INFOPLIST_NAMES)
                  + tuple(sorted({rel for rel, _, _ in CODE_NAMES}))
                  + tuple(sorted({rel for rel, _, _ in SCHEME_LINKS})) + (URL_HANDLING,)
                  + tuple(sorted({rel for rel, _, _, _, _ in CLIENT_LINKS}))
                  + (DAY_THEME, DARK_THEME, PRESENTATION_DATA, THEME_SETTINGS, LEGACY_COLORS, AVATAR_NODE)
                  + (SETTINGS_ITEMS, SETTINGS_SEARCH)
                  + (CHAT_LIST, CHAT_LIST_NOTICE, CHAT_LIST_PANELS, PROFILE_ITEMS))


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

    def replace_in_line(self, rel, anchor, edits):
        """Edits the one line that holds anchor: each (old, new, count) must
        occur exactly count times in it."""
        lines = self.read(rel).split("\n")
        hits = [i for i, line in enumerate(lines) if anchor in line]
        if len(hits) != 1:
            raise PatchError(f"{rel}: {len(hits)} lines with {anchor.strip()[:60]!r}..., expected 1; upstream changed it")
        line = lines[hits[0]]
        for old, new, count in edits:
            if line.count(old) != count:
                raise PatchError(f"{rel}: {line.count(old)} occurrences of {old!r} in the line of "
                                 f"{anchor.strip()[:40]!r}..., expected {count}")
            line = line.replace(old, new)
        lines[hits[0]] = line
        self.write(rel, "\n".join(lines))

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
    patch_scheme(tree, c)
    patch_client_links(tree)
    patch_palette(tree)
    patch_support(tree)
    patch_birthdays(tree)

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
    the laptop of Settings > Devices and the first page of the intro."""
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


# --- birthdays ---------------------------------------------------------------
#
# The notice at the top of the chat list about contacts whose birthday is today
# (contacts.getBirthdays) offers to gift them Premium, which Pluma does not
# sell. It stays, shown whenever upstream shows it, and opens the chat instead
# (the owner's decision): the contact's chat, or with several contacts a list
# of them to choose the chat from. The list is an action sheet, as the live
# location panel above the chat list lists its chats
# (LiveLocationHeaderPanelComponent.swift), sorted by the names it shows, the
# id breaking a tie: the notice's peers come in the order of a dictionary
# (GlobalControlPanelsContext.swift), which may change from one launch of the
# app to the next, and upstream's own gift picker has no order to follow
# (ContactSelectionControllerNode.swift). The second line of the notice says "Send Message", the
# action of a contact's context menu in the contact list
# (ContactContextMenus.swift), instead of "Gift them Pluma Premium." The close
# button dismisses it as upstream (help.dismissSuggestion with
# BIRTHDAY_CONTACTS_TODAY), without the toast that sends the user to Settings
# to gift Premium: with Premium purchases blocked and no Stars, Settings offer
# no gifts (PeerInfoSettingsItems.swift).

BIRTHDAY_OPEN_OLD = src(" " * 24, """
    case let .birthdayPremiumGift(peers, birthdays):
        self.effectiveContainerNode.currentItemNode.interaction?.openPremiumGift(peers, birthdays)
""")
BIRTHDAY_OPEN = src(" " * 24, """
    case let .birthdayPremiumGift(peers, _):
        // pluma: no Premium gifts. The chat with the contact; with several, a
        // list of them to choose the chat from, as the live location panel
        // lists its chats. The list goes by name, the same on every launch:
        // peers come in the order of a dictionary.
        if peers.count == 1, let peer = peers.first {
            self.effectiveContainerNode.peerSelected?(peer, nil, true, true, nil)
        } else if !peers.isEmpty, let controller = self.controller {
            let actionSheet = ActionSheetController(presentationData: self.presentationData)
            let dismissAction: () -> Void = { [weak actionSheet] in
                actionSheet?.dismissAnimated()
            }
            var items: [ActionSheetItem] = []
            items.append(ActionSheetTextItem(title: self.presentationData.strings.ChatList_BirthdayMultipleTitle(Int32(peers.count))))
            let strings = self.presentationData.strings
            let nameDisplayOrder = self.presentationData.nameDisplayOrder
            let named = peers.map { ($0, $0.displayTitle(strings: strings, displayOrder: nameDisplayOrder)) }.sorted(by: { lhs, rhs in
                lhs.1 == rhs.1 ? lhs.0.id < rhs.0.id : lhs.1.localizedCaseInsensitiveCompare(rhs.1) == .orderedAscending
            })
            for (peer, title) in named {
                items.append(ActionSheetButtonItem(title: title, action: { [weak self] in
                    dismissAction()
                    self?.effectiveContainerNode.peerSelected?(peer, nil, true, true, nil)
                }))
            }
            actionSheet.setItemGroups([
                ActionSheetItemGroup(items: items),
                ActionSheetItemGroup(items: [ActionSheetButtonItem(title: self.presentationData.strings.Common_Cancel, action: { dismissAction() })])
            ])
            controller.present(actionSheet, in: .window(.root))
        }
""")

BIRTHDAY_TEXT_OLD = src(" " * 12, """
    case let .birthdayPremiumGift(peers, _):
        let title: String
        let text: String
        if peers.count == 1, let peer = peers.first {
            var peerName = peer.compactDisplayTitle
            if peerName.count > 20 {
                peerName = peerName.prefix(20).trimmingCharacters(in: .whitespacesAndNewlines) + "\\u{2026}"
            }
            title = item.strings.ChatList_BirthdaySingleTitle(peerName).string
            text = item.strings.ChatList_BirthdaySingleText
        } else {
            title = item.strings.ChatList_BirthdayMultipleTitle(Int32(peers.count))
            text = item.strings.ChatList_BirthdayMultipleText
        }
""")
BIRTHDAY_TEXT = (BIRTHDAY_TEXT_OLD
                 .replace("    case let .birthdayPremiumGift(peers, _):\n",
                          "    case let .birthdayPremiumGift(peers, _):\n" + src(" " * 16, """
                              // pluma: "Send Message", not the offer of a Premium gift: the
                              // notice opens the chat (ChatListControllerNode.swift).
                          """))
                 .replace("text = item.strings.ChatList_BirthdaySingleText\n", "text = item.strings.ContactList_Context_SendMessage\n")
                 .replace("text = item.strings.ChatList_BirthdayMultipleText\n", "text = item.strings.ContactList_Context_SendMessage\n"))
# The key of that line in the built-in strings, with its English text.
BIRTHDAY_TEXT_KEY = '"ContactList.Context.SendMessage" = "Send Message";\n'

BIRTHDAY_CLOSE_OLD = src(" " * 12, """
    case .birthdayPremiumGift:
        let _ = self.context.engine.notices.dismissServerProvidedSuggestion(suggestion: ServerProvidedSuggestion.todayBirthdays.id).startStandalone()
        parentController.present(UndoOverlayController(presentationData: presentationData, content: .universal(animation: "anim_gift", scale: 0.058, colors: ["__allcolors__": UIColor.white], title: nil, text: presentationData.strings.ChatList_PremiumGiftInSettingsInfo, customUndoText: nil, timeout: 5.0), elevatedLayout: false, action: { _ in
            return true
        }), in: .current)
""")
BIRTHDAY_CLOSE = src(" " * 12, """
    case .birthdayPremiumGift:
        // pluma: no toast that sends to Settings to gift Premium; they offer no gifts.
        let _ = self.context.engine.notices.dismissServerProvidedSuggestion(suggestion: ServerProvidedSuggestion.todayBirthdays.id).startStandalone()
""")

# The birthday row of a contact's profile offers a gift on the birthday, by a
# tap and by its gift icon (PeerInfoProfileItems.swift), while the chat checks
# that Premium can be bought first (premium_purchase_blocked,
# ChatControllerOpenAttachmentMenu.swift). The notice leads there in two taps:
# the row offers a gift only while Premium can be bought, as the chat does and
# as the Android and web apps do. As (the pinned upstream's text, Pluma's).
BIRTHDAY_PROFILE = (
    ("                let isBirthdayToday = hasBirthdayToday(birthday: birthday)\n",
     "                let isBirthdayToday = hasBirthdayToday(birthday: birthday)\n"
     "                // pluma: a gift on the birthday only while Premium can be bought.\n"
     "                let canGiftOnBirthday = isBirthdayToday && !PremiumConfiguration.with("
     "appConfiguration: context.currentAppConfiguration.with { $0 }).isPremiumDisabled\n"),
    ("                } else if isBirthdayToday && cachedData.disallowedGifts != TelegramDisallowedGifts.All {\n",
     "                } else if canGiftOnBirthday && cachedData.disallowedGifts != TelegramDisallowedGifts.All {\n"),
    ("icon: isBirthdayToday ? .premiumGift : nil, action: birthdayAction,",
     "icon: canGiftOnBirthday ? .premiumGift : nil, action: birthdayAction,"),
)

# The birthday case of each file, from its head to the case after it:
# (file, head, tail).
BIRTHDAY_CASES = (
    (CHAT_LIST, "                        case let .birthdayPremiumGift(", "                        case .reviewLogin:\n"),
    (CHAT_LIST_NOTICE, "            case let .birthdayPremiumGift(", "            case let .reviewLogin("),
    (CHAT_LIST_PANELS, "            case .birthdayPremiumGift:\n", "            case .premiumGrace:\n"),
)


def patch_birthdays(tree):
    """The birthday notice of the chat list opens the chat with the contact
    (with several, a list of them) and offers no Premium gift, nor does the
    birthday row of the contact's profile."""
    tree.expect(STRINGS, BIRTHDAY_TEXT_KEY)
    tree.replace(CHAT_LIST, BIRTHDAY_OPEN_OLD, BIRTHDAY_OPEN)
    tree.replace(CHAT_LIST_NOTICE, BIRTHDAY_TEXT_OLD, BIRTHDAY_TEXT)
    tree.replace(CHAT_LIST_PANELS, BIRTHDAY_CLOSE_OLD, BIRTHDAY_CLOSE)
    for old, new in BIRTHDAY_PROFILE:
        tree.replace(PROFILE_ITEMS, old, new)


def birthday_case(tree, rel, head, tail):
    text = tree.read(rel)
    if text.count(head) != 1:
        raise PatchError(f"{rel}: {text.count(head)} birthday notice cases, expected 1")
    start = text.index(head)
    end = text.find(tail, start)
    if end < 0:
        raise PatchError(f"{rel}: no {tail.strip()!r} after the birthday notice case")
    return text[start:end]


def verify_birthdays(tree):
    opened, text, closed = (birthday_case(tree, *case) for case in BIRTHDAY_CASES)
    if "openPremiumGift(" in opened or opened.count(".peerSelected?(peer, nil, true, true, nil)") != 2:
        raise PatchError(f"{CHAT_LIST}: the birthday notice does not open the chat")
    if ("ChatList_BirthdaySingleText" in text or "ChatList_BirthdayMultipleText" in text
            or text.count("text = item.strings.ContactList_Context_SendMessage\n") != 2):
        raise PatchError(f"{CHAT_LIST_NOTICE}: the birthday notice still offers a gift")
    if "ChatList_PremiumGiftInSettingsInfo" in closed or "suggestion: ServerProvidedSuggestion.todayBirthdays.id" not in closed:
        raise PatchError(f"{CHAT_LIST_PANELS}: closing the birthday notice does not dismiss it, or offers a gift")
    profile = tree.read(PROFILE_ITEMS)
    if any(old in profile for old, _ in BIRTHDAY_PROFILE[1:]) or not all(new in profile for _, new in BIRTHDAY_PROFILE):
        raise PatchError(f"{PROFILE_ITEMS}: the birthday row offers a gift without Premium for sale")


# --- palette "graphite and sage" ----------------------------------------------
#
# Task 017 of the server repository. Graphite for text, icons and headers;
# sage the single accent:
#
#   role                         light                       dark
#   accent (buttons, switches,   #5B7A5E, white text         #9DBB9F, text #131513
#     counters, selection)
#   soft accent                  #6F8F72 on #E3EAE2          #7FA082 on #2C3A2D
#   links                        #4F6E52                     #B2CEB4
#   incoming bubble              #F1F2F0                     #232623
#   outgoing bubble              #E3EAE2 -> #D5E1D4,         #2C3A2D -> #36473A,
#                                  text #1F2E20                text #E8ECE8
#   time and checks, outgoing    #5B7A5E                     #B2CEB4
#   background                   #FFFFFF                     #131513
#
# The default themes of a fresh install are Day Classic and, with the system's
# dark mode, Night; both take these colours. Text and secondary text keep
# upstream's greys, which differ from the palette's by a shade.

# The colours of the avatars that stand for Saved Messages and for reposts.
AVATAR_SAVED_MESSAGES = ("    static let savedMessagesColors: [UIColor] = [\n"
                         "        UIColor(rgb: 0x2a9ef1), UIColor(rgb: 0x72d5fd)\n")
AVATAR_REPOST = ("    static let repostColors: [UIColor] = [\n"
                 "        UIColor(rgb: 0x3DA1FD), UIColor(rgb: 0x34C76F)\n")

# (file, text, replacement, how many times).
PALETTE_EDITS = (
    # Day Classic (and Day): the accent, the source of 64 colours.
    (DAY_THEME, "public let defaultDayAccentColor = UIColor(rgb: 0x0088ff)\n",
     "public let defaultDayAccentColor = UIColor(rgb: 0x5b7a5e) // pluma: sage\n", 1),
    (DAY_THEME, "        startButtonColor: UIColor(rgb: 0x2ca5e0),\n", "        startButtonColor: defaultDayAccentColor,\n", 1),
    (DAY_THEME, "PresentationThemeGradientColors(topColor: UIColor(rgb: 0x46739e), bottomColor: UIColor(rgb: 0x2a5982))",
     "PresentationThemeGradientColors(topColor: UIColor(rgb: 0x5b7a5e), bottomColor: UIColor(rgb: 0x4f6e52))", 1),
    (DAY_THEME, "        contentColor: UIColor(rgb: 0x35c759),\n", "        contentColor: defaultDayAccentColor,\n", 1),
    (DAY_THEME, "neutral1: PresentationThemeFillForeground(fillColor: UIColor(rgb: 0x4892f2),",
     "neutral1: PresentationThemeFillForeground(fillColor: UIColor(rgb: 0x6f8f72),", 1),
    (DAY_THEME, "        itemSelectedBackgroundColor: UIColor(rgb: 0xe9f0fa),\n",
     "        itemSelectedBackgroundColor: UIColor(rgb: 0xe3eae2),\n", 1),
    (DAY_THEME, "        checkmarkColor: day ? defaultDayAccentColor : UIColor(rgb: 0x21c004),\n",
     "        checkmarkColor: defaultDayAccentColor,\n", 1),
    (DAY_THEME, "PresentationThemeGradientColors(topColor: UIColor(rgb: 0x72d5fd), bottomColor: UIColor(rgb: 0x2a9ef1))",
     "PresentationThemeGradientColors(topColor: UIColor(rgb: 0x9dbb9f), bottomColor: UIColor(rgb: 0x5b7a5e))", 1),
    (DAY_THEME, "storyUnseenColors: PresentationThemeGradientColors(topColor: UIColor(rgb: 0x34C76F), bottomColor: UIColor(rgb: 0x3DA1FD))",
     "storyUnseenColors: PresentationThemeGradientColors(topColor: UIColor(rgb: 0x9dbb9f), bottomColor: UIColor(rgb: 0x4f6e52))", 1),
    # Day Classic's messages: the incoming bubble (and its highlight)...
    (DAY_THEME, "                    fill: [UIColor(rgb: 0xffffff)],\n                    highlightedFill: UIColor(rgb: 0xd9f4ff),\n",
     "                    fill: [UIColor(rgb: 0xf1f2f0)],\n                    highlightedFill: UIColor(rgb: 0xe3eae2),\n", 2),
    (DAY_THEME, "highlightedFill: UIColor(rgb: 0xd9f4ff),", "highlightedFill: UIColor(rgb: 0xe3eae2),", 2),
    (DAY_THEME, "UIColor(rgb: 0x004bad)", "UIColor(rgb: 0x4f6e52)", 6),
    (DAY_THEME, "fileTitleColor: UIColor(rgb: 0x0b8bed),", "fileTitleColor: UIColor(rgb: 0x4f6e52),", 1),
    # ... the outgoing one, sage instead of green, with its time and checks.
    (DAY_THEME, "fill: [UIColor(rgb: 0xe1ffc7)],", "fill: [UIColor(rgb: 0xe3eae2), UIColor(rgb: 0xd5e1d4)],", 2),
    (DAY_THEME, "highlightedFill: UIColor(rgb: 0xbaff93),", "highlightedFill: UIColor(rgb: 0xc5d4c4),", 2),
    (DAY_THEME, "UIColor(rgb: 0x3fc33b)", "UIColor(rgb: 0x5b7a5e)", 12),
    (DAY_THEME, "            primaryTextColor: UIColor(rgb: 0x000000),\n"
                "            secondaryTextColor: UIColor(rgb: 0x008c09, alpha: 0.8),\n",
     "            primaryTextColor: UIColor(rgb: 0x1f2e20),\n"
     "            secondaryTextColor: UIColor(rgb: 0x5b7a5e),\n", 1),
    (DAY_THEME, "fileDurationColor: UIColor(rgb: 0x008c09, alpha: 0.8),", "fileDurationColor: UIColor(rgb: 0x5b7a5e),", 1),
    (DAY_THEME, "accentTextColor: UIColor(rgb: 0x00a700),", "accentTextColor: UIColor(rgb: 0x4f6e52),", 1),
    (DAY_THEME, "UIColor(rgb: 0x93d987)", "UIColor(rgb: 0x9dbb9f)", 3),
    (DAY_THEME, "mediaControlInnerBackgroundColor: UIColor(rgb: 0xe1ffc7),", "mediaControlInnerBackgroundColor: UIColor(rgb: 0xe3eae2),", 1),
    (DAY_THEME, "pendingActivityColor: UIColor(rgb: 0x42b649),", "pendingActivityColor: UIColor(rgb: 0x5b7a5e),", 1),
    (DAY_THEME, "fileTitleColor: UIColor(rgb: 0x3faa3c),", "fileTitleColor: UIColor(rgb: 0x4f6e52),", 1),
    (DAY_THEME, "fileDescriptionColor: UIColor(rgb: 0x6fb26a),", "fileDescriptionColor: UIColor(rgb: 0x6f8f72),", 1),
    (DAY_THEME, "mediaPlaceholderColor: UIColor(rgb: 0xd2f2b6),", "mediaPlaceholderColor: UIColor(rgb: 0xd5e1d4),", 1),
    (DAY_THEME, "UIColor(rgb: 0x00A700)", "UIColor(rgb: 0x5b7a5e)", 4),
    (DAY_THEME, "textSelectionColor: UIColor(rgb: 0xbbde9f),", "textSelectionColor: UIColor(rgb: 0x5b7a5e, alpha: 0.25),", 1),
    (DAY_THEME, "outgoingCheckColor: UIColor(rgb: 0x19c700),", "outgoingCheckColor: UIColor(rgb: 0x5b7a5e),", 1),
    # Bluish greys of buttons in chats and of sticker outlines.
    (DAY_THEME, "UIColor(rgb: 0x596e89, alpha: 0.35)", "UIColor(rgb: 0x6b6f6b, alpha: 0.35)", 2),
    (DAY_THEME, "UIColor(rgb: 0x86a9c9, alpha: 0.5)", "UIColor(rgb: 0x9aa29a, alpha: 0.5)", 2),
    # Day's outgoing gradient, which ends in the accent.
    (DAY_THEME, "fill: [UIColor(rgb: 0x57b2e0), defaultDayAccentColor],", "fill: [UIColor(rgb: 0x6f8f72), defaultDayAccentColor],", 2),
    (DAY_THEME, "highlightedFill: UIColor(rgb: 0x57b2e0).withMultipliedBrightnessBy(0.7),",
     "highlightedFill: UIColor(rgb: 0x6f8f72).withMultipliedBrightnessBy(0.7),", 2),
    (DAY_THEME, "mediaPlaceholderColor: UIColor(rgb: 0x0077d9),", "mediaPlaceholderColor: UIColor(rgb: 0x4f6e52),", 1),
    # Day Classic's chat background: plain white, not Telegram's pattern (a
    # file on Telegram's servers). The dates and service messages on it: grey
    # on #F1F2F0, as Day has them on white.
    (DAY_THEME, "    let defaultPatternWallpaper: TelegramWallpaper = defaultBuiltinWallpaper(data: .default, "
                "colors: defaultBuiltinWallpaperGradientColors.map(\\.rgb))\n",
     "    // pluma: a plain white chat background.\n"
     "    let defaultPatternWallpaper: TelegramWallpaper = .color(0xffffff)\n", 1),
    (DAY_THEME, "withDefaultWallpaper: PresentationThemeServiceMessageColorComponents(fill: UIColor(rgb: 0x939fab, alpha: 0.5), "
                "primaryText: UIColor(rgb: 0xffffff), linkHighlight: UIColor(rgb: 0x748391, alpha: 0.25), scam: UIColor(rgb: 0xffffff), "
                "dateFillStatic: UIColor(rgb: 0x000000, alpha: 0.2), dateFillFloating: UIColor(rgb: 0x939fab, alpha: 0.5))",
     "withDefaultWallpaper: PresentationThemeServiceMessageColorComponents(fill: UIColor(rgb: 0xf1f2f0), "
     "primaryText: UIColor(rgb: 0x6b6f6b), linkHighlight: UIColor(rgb: 0x748391, alpha: 0.25), scam: UIColor(rgb: 0xff3b30), "
     "dateFillStatic: UIColor(rgb: 0xf1f2f0), dateFillFloating: UIColor(rgb: 0xf1f2f0, alpha: 0.9))", 1),
    (DAY_THEME, "        dateTextColor: PresentationThemeVariableColor(color: UIColor(rgb: 0xffffff))\n",
     "        dateTextColor: PresentationThemeVariableColor(withWallpaper: UIColor(rgb: 0xffffff), "
     "withoutWallpaper: UIColor(rgb: 0x6b6f6b))\n", 1),

    # Night: sage where it is white (its accent), the palette's bubbles and
    # background, dark text on the accent.
    (DARK_THEME, "accentColor: UIColor(rgb: 0x3e88f7), backgroundColors: [], bubbleColors: [], animateBubbleColors: false,",
     "accentColor: UIColor(rgb: 0x9dbb9f), backgroundColors: [], bubbleColors: [], animateBubbleColors: false,", 1),
    (DARK_THEME, "        } else if accentColor.rgb == 0x3e88f7 {\n            bubbleColors = [\n                0x0771ff,\n"
                 "                0x9047ff,\n                0xa256bf,\n            ].reversed()\n",
     "        } else if accentColor.rgb == 0x9dbb9f {\n            // pluma: the palette's outgoing bubbles with its accent.\n"
     "            bubbleColors = [0x2c3a2d, 0x36473a]\n", 1),
    (DARK_THEME, "            if initialAccentColor.lightness > 0.735 {\n                secondaryBadgeTextColor = UIColor(rgb: 0x000000)\n",
     "            // pluma: dark text on the palette's accent too.\n"
     "            if initialAccentColor.lightness > 0.735 || initialAccentColor.rgb == 0x9dbb9f {\n"
     "                secondaryBadgeTextColor = UIColor(rgb: 0x000000)\n", 1),
    (DARK_THEME, "    let rootNavigationBar = PresentationThemeRootNavigationBar(\n        buttonColor: UIColor(rgb: 0xffffff),\n",
     "    let rootNavigationBar = PresentationThemeRootNavigationBar(\n        buttonColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        accentTextColor: UIColor(rgb: 0xffffff),\n        blurredBackgroundColor:",
     "        accentTextColor: UIColor(rgb: 0x9dbb9f),\n        blurredBackgroundColor:", 1),
    (DARK_THEME, "        badgeBackgroundColor:  UIColor(rgb: 0xffffff),\n        badgeStrokeColor: UIColor(rgb: 0x1c1c1d),\n"
                 "        badgeTextColor:  UIColor(rgb: 0x000000)",
     "        badgeBackgroundColor:  UIColor(rgb: 0x9dbb9f),\n        badgeStrokeColor: UIColor(rgb: 0x1c1c1d),\n"
     "        badgeTextColor:  UIColor(rgb: 0x131513)", 2),
    (DARK_THEME, "        selectedIconColor: UIColor(rgb: 0xffffff),\n", "        selectedIconColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        selectedTextColor: UIColor(rgb: 0xffffff),\n", "        selectedTextColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        accentColor: UIColor(rgb: 0xffffff),\n", "        accentColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        accentTextColor: UIColor(rgb: 0xffffff),\n        disabledTextColor: UIColor(rgb: 0x525252),\n"
                 "        startButtonColor: UIColor(rgb: 0xffffff),\n",
     "        accentTextColor: UIColor(rgb: 0x9dbb9f),\n        disabledTextColor: UIColor(rgb: 0x525252),\n"
     "        startButtonColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        contentColor: UIColor(rgb: 0x67ce67),\n", "        contentColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        blocksBackgroundColor: UIColor(rgb: 0x000000),\n", "        blocksBackgroundColor: UIColor(rgb: 0x131513),\n", 1),
    (DARK_THEME, "        plainBackgroundColor: UIColor(rgb: 0x000000),\n", "        plainBackgroundColor: UIColor(rgb: 0x131513),\n", 1),
    (DARK_THEME, "        itemAccentColor: UIColor(rgb: 0xffffff),\n", "        itemAccentColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "            fillColor: UIColor(rgb: 0xffffff),\n            strokeColor: UIColor(rgb: 0xffffff, alpha: 0.3),\n"
                 "            foregroundColor:  UIColor(rgb: 0x000000)\n",
     "            fillColor: UIColor(rgb: 0x9dbb9f),\n            strokeColor: UIColor(rgb: 0xffffff, alpha: 0.3),\n"
     "            foregroundColor:  UIColor(rgb: 0x131513)\n", 1),
    (DARK_THEME, "itemBarChart: PresentationThemeItemBarChart(color1: UIColor(rgb: 0xffffff),",
     "itemBarChart: PresentationThemeItemBarChart(color1: UIColor(rgb: 0x9dbb9f),", 1),
    (DARK_THEME, "        backgroundColor: UIColor(rgb: 0x000000),\n        itemSeparatorColor:",
     "        backgroundColor: UIColor(rgb: 0x131513),\n        itemSeparatorColor:", 1),
    (DARK_THEME, "        itemBackgroundColor: UIColor(rgb: 0x000000),\n        pinnedItemBackgroundColor:",
     "        itemBackgroundColor: UIColor(rgb: 0x131513),\n        pinnedItemBackgroundColor:", 1),
    (DARK_THEME, "        checkmarkColor: UIColor(rgb: 0xffffff),\n", "        checkmarkColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        unreadBadgeActiveBackgroundColor: UIColor(rgb: 0xffffff),\n        unreadBadgeActiveTextColor: UIColor(rgb: 0x000000),\n",
     "        unreadBadgeActiveBackgroundColor: UIColor(rgb: 0x9dbb9f),\n        unreadBadgeActiveTextColor: UIColor(rgb: 0x131513),\n", 1),
    (DARK_THEME, "        verifiedIconFillColor: UIColor(rgb: 0xffffff),\n        verifiedIconForegroundColor:  UIColor(rgb: 0x000000),\n",
     "        verifiedIconFillColor: UIColor(rgb: 0x9dbb9f),\n        verifiedIconForegroundColor:  UIColor(rgb: 0x131513),\n", 1),
    (DARK_THEME, "PresentationThemeGradientColors(topColor: UIColor(rgb: 0x72d5fd), bottomColor: UIColor(rgb: 0x2a9ef1))",
     "PresentationThemeGradientColors(topColor: UIColor(rgb: 0x9dbb9f), bottomColor: UIColor(rgb: 0x5b7a5e))", 1),
    (DARK_THEME, "storyUnseenColors: PresentationThemeGradientColors(topColor: UIColor(rgb: 0x34C76F), bottomColor: UIColor(rgb: 0x3DA1FD))",
     "storyUnseenColors: PresentationThemeGradientColors(topColor: UIColor(rgb: 0xb2ceb4), bottomColor: UIColor(rgb: 0x7fa082))", 1),
    (DARK_THEME, "fill: [UIColor(rgb: 0x1D1D1D, alpha: incomingBubbleAlpha)],", "fill: [UIColor(rgb: 0x232623, alpha: incomingBubbleAlpha)],", 2),
    (DARK_THEME, "fill: [UIColor(rgb: 0x61BCF9), UIColor(rgb: 0x0088ff)],\n                    highlightedFill: UIColor(rgb: 0x61BCF9),",
     "fill: [UIColor(rgb: 0x2c3a2d), UIColor(rgb: 0x36473a)],\n                    highlightedFill: UIColor(rgb: 0x36473a),", 2),
    (DARK_THEME, "        infoLinkTextColor: UIColor(rgb: 0xffffff),\n        outgoingCheckColor: UIColor(rgb: 0xffffff),\n",
     "        infoLinkTextColor: UIColor(rgb: 0xb2ceb4),\n        outgoingCheckColor: UIColor(rgb: 0xb2ceb4),\n", 1),
    (DARK_THEME, "selectionControlColors: PresentationThemeFillStrokeForeground(fillColor: UIColor(rgb: 0xffffff), "
                 "strokeColor: UIColor(rgb: 0xffffff), foregroundColor:  UIColor(rgb: 0x000000)),",
     "selectionControlColors: PresentationThemeFillStrokeForeground(fillColor: UIColor(rgb: 0x9dbb9f), "
     "strokeColor: UIColor(rgb: 0xffffff), foregroundColor:  UIColor(rgb: 0x131513)),", 1),
    (DARK_THEME, "        buttonColor: UIColor(rgb: 0xffffff),\n        micLevelColor: UIColor(rgb: 0xffffff, alpha: 0.2),\n"
                 "        activeIconColor:  UIColor(rgb: 0x000000)\n",
     "        buttonColor: UIColor(rgb: 0x9dbb9f),\n        micLevelColor: UIColor(rgb: 0x9dbb9f, alpha: 0.2),\n"
     "        activeIconColor:  UIColor(rgb: 0x131513)\n", 1),
    (DARK_THEME, "        panelBackgroundColorNoWallpaper: UIColor(rgb: 0x000000),\n",
     "        panelBackgroundColorNoWallpaper: UIColor(rgb: 0x131513),\n", 1),
    (DARK_THEME, "        panelControlAccentColor: UIColor(rgb: 0xffffff),\n", "        panelControlAccentColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        actionControlFillColor: UIColor(rgb: 0xffffff),\n        actionControlForegroundColor:  UIColor(rgb: 0x000000),\n",
     "        actionControlFillColor: UIColor(rgb: 0x9dbb9f),\n        actionControlForegroundColor:  UIColor(rgb: 0x131513),\n", 1),
    (DARK_THEME, "        badgeBackgroundColor: UIColor(rgb: 0xffffff),\n        badgeStrokeColor: UIColor(rgb: 0xffffff),\n"
                 "        badgeTextColor:  UIColor(rgb: 0x000000)\n",
     "        badgeBackgroundColor: UIColor(rgb: 0x9dbb9f),\n        badgeStrokeColor: UIColor(rgb: 0x9dbb9f),\n"
     "        badgeTextColor:  UIColor(rgb: 0x131513)\n", 1),
    (DARK_THEME, "        standardActionTextColor: UIColor(rgb: 0xffffff),\n", "        standardActionTextColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        controlAccentColor: UIColor(rgb: 0xffffff),\n", "        controlAccentColor: UIColor(rgb: 0x9dbb9f),\n", 1),
    (DARK_THEME, "        checkContentColor:  UIColor(rgb: 0x000000)\n", "        checkContentColor:  UIColor(rgb: 0x131513)\n", 1),
    (DARK_THEME, "        badgeFillColor: UIColor(rgb: 0xffffff),\n        badgeForegroundColor: UIColor(rgb: 0x000000),\n",
     "        badgeFillColor: UIColor(rgb: 0x9dbb9f),\n        badgeForegroundColor: UIColor(rgb: 0x131513),\n", 1),
    # Night's chat background: plain graphite, not Telegram's pattern.
    (DARK_THEME, "    let defaultPatternWallpaper: TelegramWallpaper = defaultBuiltinWallpaper(data: .default, "
                 "colors: defaultDarkWallpaperGradientColors.map(\\.rgb), intensity: -34)\n",
     "    // pluma: a plain graphite chat background.\n"
     "    let defaultPatternWallpaper: TelegramWallpaper = .color(0x131513)\n", 1),

    # With the system's dark mode the app gave Night the blue accent; Night
    # is in Pluma's colours itself now.
    (PRESENTATION_DATA, "                            if automaticTheme == .builtin(.night) && effectiveColors == nil {\n"
                        "                                effectiveColors = PresentationThemeAccentColor(baseColor: .blue)\n"
                        "                            }\n",
     "                            // pluma: no blue accent for Night; it has Pluma's colours itself.\n", 1),
    # The first accent the theme settings offer, the default one: sage.
    (THEME_SETTINGS, "            case .blue:\n                value = 0x0088ff\n",
     "            case .blue:\n                value = 0x5b7a5e // pluma: sage\n", 1),
    (THEME_SETTINGS, "            if baseTheme == .night && self.baseColor == .blue {\n                return UIColor(rgb: 0x3e88f7)\n",
     "            if baseTheme == .night && self.baseColor == .blue {\n                return UIColor(rgb: 0x9dbb9f) // pluma: sage\n", 1),
    # The accent of the legacy screens (camera, media editor, location).
    (LEGACY_COLORS, "        color = TGColorWithHex(0x0088ff);\n", "        color = TGColorWithHex(0x5b7a5e); // pluma: sage\n", 1),
    # The avatars drawn instead of a photo: Saved Messages (also replies and
    # notes) and reposted stories, gradients of Telegram's blue in any theme.
    (AVATAR_NODE, AVATAR_SAVED_MESSAGES, AVATAR_SAVED_MESSAGES.replace(
        "UIColor(rgb: 0x2a9ef1), UIColor(rgb: 0x72d5fd)\n",
        "UIColor(rgb: 0x5b7a5e), UIColor(rgb: 0x9dbb9f) // pluma: sage\n"), 1),
    (AVATAR_NODE, AVATAR_REPOST, AVATAR_REPOST.replace(
        "UIColor(rgb: 0x3DA1FD), UIColor(rgb: 0x34C76F)\n",
        "UIColor(rgb: 0x4f6e52), UIColor(rgb: 0x9dbb9f) // pluma: sage\n"), 1),
)

# Night's message colours, each kind on one long line: (file, a text that
# only that line has, edits within the line).
PALETTE_LINE_EDITS = (
    # Incoming: sage links and controls.
    (DARK_THEME, "            secondaryTextColor: UIColor(rgb: 0xffffff, alpha: 0.5), linkTextColor: UIColor(rgb: 0xffffff),", (
        ("linkTextColor: UIColor(rgb: 0xffffff),", "linkTextColor: UIColor(rgb: 0xb2ceb4),", 1),
        ("accentTextColor: UIColor(rgb: 0xffffff),", "accentTextColor: UIColor(rgb: 0x9dbb9f),", 1),
        ("accentControlColor: UIColor(rgb: 0xffffff),", "accentControlColor: UIColor(rgb: 0x9dbb9f),", 1),
        ("mediaActiveControlColor: UIColor(rgb: 0xffffff),", "mediaActiveControlColor: UIColor(rgb: 0x9dbb9f),", 1),
        ("radioProgress: UIColor(rgb: 0xffffff),", "radioProgress: UIColor(rgb: 0x9dbb9f),", 1),
        (" bar: UIColor(rgb: 0xffffff),", " bar: UIColor(rgb: 0x9dbb9f),", 1),
        ("textSelectionColor: UIColor(rgb: 0xffffff, alpha: 0.2),", "textSelectionColor: UIColor(rgb: 0x9dbb9f, alpha: 0.3),", 1),
        ("textSelectionKnobColor: UIColor(rgb: 0xffffff)", "textSelectionKnobColor: UIColor(rgb: 0x9dbb9f)", 1),
    )),
    # Outgoing: light text, light sage time, checks, links and controls.
    (DARK_THEME, "            ), primaryTextColor: UIColor(rgb: 0xffffff), secondaryTextColor: UIColor(rgb: 0xffffff, alpha: 0.5),", (
        ("primaryTextColor: UIColor(rgb: 0xffffff),", "primaryTextColor: UIColor(rgb: 0xe8ece8),", 1),
        ("secondaryTextColor: UIColor(rgb: 0xffffff, alpha: 0.5),", "secondaryTextColor: UIColor(rgb: 0xb2ceb4),", 1),
        ("linkTextColor: UIColor(rgb: 0xffffff),", "linkTextColor: UIColor(rgb: 0xb2ceb4),", 1),
        ("accentTextColor: UIColor(rgb: 0xffffff),", "accentTextColor: UIColor(rgb: 0xb2ceb4),", 1),
        ("accentControlColor: UIColor(rgb: 0xffffff),", "accentControlColor: UIColor(rgb: 0xb2ceb4),", 1),
        ("mediaActiveControlColor: UIColor(rgb: 0xffffff),", "mediaActiveControlColor: UIColor(rgb: 0xb2ceb4),", 1),
        ("mediaControlInnerBackgroundColor:  UIColor(rgb: 0x313131),", "mediaControlInnerBackgroundColor:  UIColor(rgb: 0x2c3a2d),", 1),
        ("radioProgress: UIColor(rgb: 0xffffff),", "radioProgress: UIColor(rgb: 0xb2ceb4),", 1),
        (" bar: UIColor(rgb: 0xffffff),", " bar: UIColor(rgb: 0xb2ceb4),", 1),
        ("textSelectionKnobColor: UIColor(rgb: 0xffffff)", "textSelectionKnobColor: UIColor(rgb: 0xb2ceb4)", 1),
    )),
)

# Telegram's blues of the default themes; none may be left.
TELEGRAM_BLUES = ("0x0088ff", "0x3e88f7", "0x2ca5e0", "0x46739e", "0x4892f2", "0xe9f0fa", "0x72d5fd", "0x2a9ef1",
                  "0x3DA1FD", "0xd9f4ff", "0x004bad", "0x0b8bed", "0x57b2e0", "0x0077d9", "0x61BCF9")


SUPPORT_ITEMS_OLD = src(" " * 4, """
    items[.support]!.append(PeerInfoScreenDisclosureItem(id: 0, text: presentationData.strings.Settings_Support, icon: PresentationResourcesSettings.support, action: {
        interaction.openSettings(.support)
    }))
    items[.support]!.append(PeerInfoScreenDisclosureItem(id: 1, text: presentationData.strings.Settings_FAQ, icon: PresentationResourcesSettings.faq, action: {
        interaction.openSettings(.faq)
    }))
    items[.support]!.append(PeerInfoScreenDisclosureItem(id: 2, text: presentationData.strings.Settings_Tips, icon: PresentationResourcesSettings.tips, action: {
        interaction.openSettings(.tips)
    }))
""")

SUPPORT_SEARCH_OLD = src(" " * 8, """
    let helpItems = helpSearchableItems(context: context)
    allItems.append(contentsOf: helpItems)
""")


def patch_support(tree):
    """The last section of Settings leads to Telegram's services only: "Ask a
    Question" asks the server for Telegram's support account (help.getSupport,
    which Pluma's server does not serve), the FAQ is telegram.org/faq and
    "Features" is the channel @TelegramTips. The section goes, and so do its
    items in the settings search."""
    tree.replace_lines(SETTINGS_ITEMS, SUPPORT_ITEMS_OLD,
                       "    // pluma: no support section; its items lead to Telegram's support, FAQ and channel.\n")
    tree.replace_lines(SETTINGS_SEARCH, SUPPORT_SEARCH_OLD,
                       "        // pluma: no support, FAQ or features items (see PeerInfoSettingsItems.swift).\n")


def verify_support(tree):
    if "items[.support]!.append(" in tree.read(SETTINGS_ITEMS):
        raise PatchError(f"{SETTINGS_ITEMS}: Settings still lead to Telegram's support")
    if "helpSearchableItems(context: context)" in tree.read(SETTINGS_SEARCH):
        raise PatchError(f"{SETTINGS_SEARCH}: the settings search still leads to Telegram's support")


def patch_palette(tree):
    for rel, old, new, count in PALETTE_EDITS:
        tree.replace(rel, old, new, count=count)
    for rel, anchor, edits in PALETTE_LINE_EDITS:
        tree.replace_in_line(rel, anchor, edits)


def verify_palette(tree):
    for rel in (DAY_THEME, DARK_THEME):
        text = tree.read(rel)
        for blue in TELEGRAM_BLUES:
            if blue in text:
                raise PatchError(f"{rel}: Telegram's blue {blue} is still there")
    if "PresentationThemeAccentColor(baseColor: .blue)" in tree.read(PRESENTATION_DATA):
        raise PatchError(f"{PRESENTATION_DATA}: Night still gets the blue accent")
    # The other avatar colours stay: they are the peer colours, one per user.
    avatars = tree.read(AVATAR_NODE)
    for name in ("savedMessagesColors", "repostColors"):
        found = re.search(r"    static let %s: \[UIColor\] = \[\n(.*)\n" % name, avatars)
        if not found or any(blue.lower() in found.group(1).lower() for blue in TELEGRAM_BLUES):
            raise PatchError(f"{AVATAR_NODE}: {name} is not sage")


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
        tree.replace(rel, text.replace("{name}", "Telegram"), text.replace("{name}", c.app_name), count=count)


def patch_scheme(tree, c):
    """plm:// instead of tg://. The app registers its own scheme, not
    Telegram's: tg:// links from other apps open Telegram, if it is installed.
    The links the app makes use its scheme, and the QR code sign-in works
    between Pluma clients only. Links of Telegram's scheme inside the app
    (in messages, from bots) still open in the app, as they always did."""
    # The scheme of the app's own links (the build configuration) already
    # replaces telegram:// (patch()); tg:// is no longer registered beside it.
    tree.replace(APP_BUILD, "                <string>tg</string>\n                <string>tonsite</string>\n",
                 "                <string>tonsite</string>\n")
    for rel, text, count in SCHEME_LINKS:
        tree.replace(rel, text.replace("{scheme}", "tg"), text.replace("{scheme}", c.url_scheme), count=count)
    tree.replace(URL_HANDLING, URL_HANDLING_TG, URL_HANDLING_OWN, count=4)


def patch_client_links(tree):
    """Pluma's site and web client, not Telegram's, behind the links of
    Settings > Devices and of its QR scanner, and named in the scanner's text."""
    for rel, text, old, new, count in CLIENT_LINKS:
        tree.replace(rel, text.replace("{url}", old), text.replace("{url}", new), count=count)
    for rel, old, new, count in CLIENT_TEXTS:
        tree.replace(rel, old, new, count=count)


def verify_client_links(tree):
    for rel in sorted({rel for rel, _, _, _, _ in CLIENT_LINKS}):
        left = CLIENT_SITES.search(tree.read(rel))
        if left:
            raise PatchError(f"{rel}: still opens {left.group(0)}")
    for rel, text, _, new, count in CLIENT_LINKS:
        if tree.read(rel).count(text.replace("{url}", new)) != count:
            raise PatchError(f"{rel}: does not open {new}")
    for rel, old, new, count in CLIENT_TEXTS:
        text = tree.read(rel)
        if old in text or text.count(new) != count:
            raise PatchError(f"{rel}: the scanner's text does not name Pluma's sites")


def verify_scheme(tree, c):
    build = tree.read(APP_BUILD)
    schemes = re.findall(r"<key>CFBundleURLSchemes</key>\s*<array>(.*?)</array>", build, re.S)
    registered = [v for block in schemes for v in re.findall(r"<string>([^<]*)</string>", block)]
    if sorted(registered) != sorted([c.url_scheme, "tonsite"]):
        raise PatchError(f"{APP_BUILD}: the app registers the URL schemes {registered}")
    for rel in sorted({rel for rel, _, _ in SCHEME_LINKS}):
        text = tree.read(rel)
        if '"tg://' in text or 'appSpecificScheme: "tg"' in text:
            raise PatchError(f"{rel}: still makes tg:// links")


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
        if text.replace("{name}", "Telegram") in tree.read(rel):
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
    verify_scheme(tree, c)
    verify_client_links(tree)
    verify_palette(tree)
    verify_support(tree)
    verify_birthdays(tree)

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
