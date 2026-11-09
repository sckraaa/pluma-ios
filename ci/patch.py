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
palette "graphite and sage" instead of Telegram's blue; of the seven colours
Telegram gives users and chats by their id, blue is sage and cyan a teal.
The first page of the intro shows the mark writing itself, and the intro's
pages are laid out around it.
Settings no longer lead to Telegram's support, FAQ and feature channel.

What App Store Connect warns about on upload is settled too: the app names
the purpose of background location, carries no Apple font, and gives Siri an
example phrase for every intent in every language.

The chat list's notice about contacts' birthdays opens the chat with the
contact instead of offering a Premium gift, which Pluma does not sell.

The context menu of an outgoing message shows when it was read without
Premium, which Pluma does not sell, and offers no Premium where it is hidden.

The tags of Saved Messages work without Premium, and a message takes as many
reactions, or tags in Saved Messages, as the server's limits allow.

Videos are encoded before sending at about twice Telegram's bitrate at every
quality the user can choose, and with better sound; so are round videos and
GIF files.

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

# The MTProto engine of a build: MtProtoKit, which the edits below are for. The
# Rust engine of third-party/mtproto-engine is in every build, for macOS and
# behind Debug Settings; it takes its addresses and keys from MtProtoKit's
# context, and the patch must stop if it becomes the default on iOS.
NETWORK_ENGINE = "submodules/TelegramCore/Sources/SyncCore/SyncCore_NetworkEngineSettings.swift"
NETWORK_ENGINE_DEFAULT = ("        #if os(macOS)\n"
                          "        return NetworkEngineSettings(engine: .rust)\n"
                          "        #else\n"
                          "        return NetworkEngineSettings(engine: .mtProtoKit)\n"
                          "        #endif\n")

# Where the network code lives: what verify() scans (without the unit tests,
# which are not in the app and carry Telegram's addresses as fixtures).
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
INTRO_CONTROLLER = "submodules/RMIntro/Sources/platform/ios/RMIntroViewController.m"
INTRO_HEADER = "submodules/RMIntro/PublicHeaders/RMIntro/RMIntroViewController.h"
# Where the intro makes the textures of its GL view from its images.
INTRO_TEXTURES = "submodules/RMIntro/Sources/platform/ios/texture_helper.m"
# The intro's screen in the sign-in flow, which hosts RMIntroViewController.
INTRO_SPLASH = "submodules/AuthorizationUI/Sources/AuthorizationSequenceSplashController.swift"
DAY_THEME = "submodules/TelegramPresentationData/Sources/DefaultDayPresentationTheme.swift"
DARK_THEME = "submodules/TelegramPresentationData/Sources/DefaultDarkPresentationTheme.swift"
PRESENTATION_DATA = "submodules/TelegramPresentationData/Sources/PresentationData.swift"
THEME_SETTINGS = "submodules/TelegramUIPreferences/Sources/PresentationThemeSettings.swift"
LEGACY_COLORS = "submodules/LegacyComponents/Sources/TGColor.m"
AVATAR_NODE = "submodules/AvatarNode/Sources/AvatarNode.swift"
# People's identity colours: the name colours, those TelegramCore takes for
# the server's colours 0-6, and the copies of the letter avatars' gradients.
PEER_NAME_COLORS = "submodules/AccountContext/Sources/PeerNameColors.swift"
PEER_COLOR_UPDATES = "submodules/TelegramCore/Sources/State/ManagedPeerColorUpdates.swift"
NOTIFICATION_AVATARS = "Telegram/NotificationService/Sources/NotificationService.swift"
WIDGET_AVATARS = "Telegram/WidgetKitWidget/PeerNode.swift"
INTENT_AVATARS = "Telegram/SiriIntents/IntentHandler.swift"
LIVE_STREAM_AVATARS = "submodules/TelegramUI/Components/Stories/StoryContainerScreen/Sources/LiveChatReactionStreamView.swift"
SETTINGS_ITEMS = "submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoSettingsItems.swift"
SETTINGS_SEARCH = "submodules/SettingsUI/Sources/Search/SettingsSearchableItems.swift"
# The birthday notice of the chat list: what a tap does, its text, its close.
CHAT_LIST = "submodules/ChatListUI/Sources/ChatListControllerNode.swift"
CHAT_LIST_NOTICE = "submodules/TelegramUI/Components/ChatList/ChatListHeaderNoticeComponent/Sources/ChatListNoticeItem.swift"
CHAT_LIST_PANELS = "submodules/TelegramUI/Components/GlobalControlPanelsContext/Sources/GlobalControlPanelsContext.swift"
# The birthday row of a contact's profile.
PROFILE_ITEMS = "submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoProfileItems.swift"
# The read date of an outgoing message in its context menu.
CONTEXT_MENUS = "submodules/TelegramUI/Sources/ChatInterfaceStateContextMenus.swift"
# The tags of Saved Messages: the flag of the chat's state, the gates that
# check Premium (a tap on a tag, its context menu, the tag bar of a message's
# context menu, the panel of tags over the chat and when it shows), and the
# number of reactions a message takes.
CHAT_STATE = "submodules/ChatPresentationInterfaceState/Sources/ChatPresentationInterfaceState.swift"
CHAT_CONTROLLER = "submodules/TelegramUI/Sources/ChatController.swift"
TAG_CONTEXT_MENU = "submodules/TelegramUI/Sources/ChatControllerOpenMessageReactionContextMenu.swift"
MESSAGE_CONTEXT_MENU = "submodules/TelegramUI/Sources/Chat/ChatControllerOpenMessageContextMenu.swift"
TAG_PANEL = "submodules/TelegramUI/Sources/ChatSearchTitleAccessoryPanelNode.swift"
TITLE_PANELS = "submodules/TelegramUI/Sources/ChatInterfaceTitlePanelNodes.swift"
MESSAGE_REACTIONS = "submodules/TelegramCore/Sources/State/MessageReactions.swift"
MEDIA_FILE = "submodules/TelegramCore/Sources/SyncCore/SyncCore_TelegramMediaFile.swift"
SEARCH_STICKERS = "submodules/TelegramCore/Sources/TelegramEngine/Stickers/SearchStickers.swift"
ENTITY_KEYBOARD_INPUT = "submodules/TelegramUI/Components/ChatEntityKeyboardInputNode/Sources/ChatEntityKeyboardInputNode.swift"
ENTITY_KEYBOARD_SIGNALS = "submodules/TelegramUI/Components/EntityKeyboard/Sources/EmojiPagerContentSignals.swift"
STICKER_PACK_SCREEN = "submodules/StickerPackPreviewUI/Sources/StickerPackScreen.swift"
# The update screen (TelegramUpdateUI); AppUpdate.swift and
# MTApiEnvironment.m are in NETWORK_DIRS.
UPDATE_INFO = "submodules/TelegramUpdateUI/Sources/UpdateInfoController.swift"
# What a video is encoded at before sending: the two preset tables, the
# recorder of round videos, GIF files.
VIDEO_PRESETS_LEGACY = "submodules/LegacyComponents/Sources/TGMediaVideoConverter.m"
VIDEO_PRESETS = "submodules/TelegramUI/Components/MediaEditor/Sources/MediaEditorValues.swift"
ROUND_VIDEO_RECORDER = "submodules/Camera/CameraLegacy/Sources/CameraOutput.swift"
ROUND_VIDEO_RECORDER_NEO = "submodules/Camera/CameraNeo/Sources/VideoRecorder.swift"
GIF_CONVERTER = "submodules/LegacyComponents/Sources/TGGifConverter.m"
# The quality an edited video is sent at when none was chosen.
VIDEO_FETCH = "submodules/TelegramUI/Components/Resources/FetchVideoMediaResource/Sources/FetchVideoMediaResource.swift"
# Sections of 13.2 that Pluma's server does not serve and that a client without
# the server's app config key does not show (wallet_available, news_feed_enabled,
# agent_bot_ids):
# (file, the upstream text that decides).
WALLET_CONFIGURATION = "submodules/WalletContext/Sources/WalletContext.swift"
NEWS_CONFIGURATION = "submodules/TelegramUI/Components/News/NewsFeedSupport/Sources/NewsFeedConfiguration.swift"
AGENT_CONFIGURATION = "submodules/AccountContext/Sources/AgentChat.swift"
OFF_BY_SERVER = (
    (WALLET_CONFIGURATION, "    public static var defaultValue: WalletConfiguration {\n        return WalletConfiguration(\n            isAvailable: false,\n"),
    (WALLET_CONFIGURATION, 'let isAvailable = appConfiguration.data?["wallet_available"] as? Bool ?? self.defaultValue.isAvailable\n'),
    (SETTINGS_ITEMS, "        if WalletConfiguration.with(appConfiguration: context.currentAppConfiguration.with { $0 }).isAvailable {\n"),
    (NEWS_CONFIGURATION, "    return isDevAccount(appConfiguration: appConfiguration) || newsFeedSwitch(appConfiguration: appConfiguration) == true\n"),
    (AGENT_CONFIGURATION, 'guard peerId.namespace == Namespaces.Peer.CloudUser, let data = appConfiguration.data, let botIds = data["agent_bot_ids"] as? [Any] else {\n'),
)
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
INTRO_RESOURCES = "Telegram/Telegram-iOS/Resources/intro"
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
    # The badge of a message or block the app cannot show.
    "submodules/TelegramUI/Images.xcassets/Chat/Message/UnsupportedIcon.imageset/logo.pdf": "3fa116c1bf4e112e72450eef0430d7d105c35424cc867406348a006fc099faa5",
    # The textures of the intro's first page, the sphere and the plane around
    # it: transparent, as the page's mark is a view of its own (brand/render.sh).
    # The intro fills the sphere's with its background colour, so the sphere
    # stays a square of that colour, which the first page needs (INTRO_SPHERE_MASK).
    f"{INTRO_RESOURCES}/telegram_sphere@2x.png": "621831c454689762c79c80083f797352aa420c488c19ba924da006ab533dd0bb",
    f"{INTRO_RESOURCES}/telegram_plane1@2x.png": "c28d4e5438f3a10fa1df725764b4bc897af475983070aaf08df1b631334a10a1",
}
# Pluma's files that upstream does not have: the layers of the app icon, the
# title of the intro's first page, the wordmark, and the page's mark writing
# itself (a Lottie animation, brand/mark_write.py). Then the layers of
# Telegram's icon that go.
INTRO_MARK = f"{INTRO_RESOURCES}/pluma_mark_write.json"
BRAND_ADDED = (tuple(f"{APP_ICON}/Assets/{n}.png" for n in ("Feather1", "Feather2", "Feather3", "Ring"))
               + tuple(f"{INTRO_RESOURCES}/pluma_wordmark@{s}x.png" for s in (2, 3)) + (INTRO_MARK,))
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
    # The widget of a passcode-locked app.
    ("submodules/WidgetItems/Sources/WidgetItems.swift",
     'generalLockedText: "Open {name} and enter passcode to edit widget.",', 1),
    ("Telegram/SiriIntents/IntentHandler.swift",
     'NSLocalizedDescriptionKey: "Open {name} and enter passcode to edit widget."', 1),
    # The service account 777000 until the server's data arrives.
    ("submodules/TelegramCore/Sources/State/Sync/UpdateInterpreter+Messages.swift",
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
SCHEME_TEXT = '"SocksProxySetup.QrCode.TgLink" = "{scheme}:// link";'
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
# tg:// literals and Telegram's hosts that stay in the app's code: (file, how many
# times). The tg:// ones are not links the app makes for people (those are in
# SCHEME_LINKS) but what it reads: prefixes of messages, the fallback markers
# of custom emoji, mentions and dates; the hosts are the lists of link parsers,
# the terms, the privacy policy and the FAQ (README, Links). A new one means a
# new place to decide about, so verify stops on it.
KEPT_TG_LINKS = {
    "Telegram/WatchApp/tgwatch Watch App/Auth/QrLoginView.swift": 1,
    "submodules/BrowserUI/Sources/BrowserWebContent.swift": 3,
    "submodules/ChatListUI/Sources/ChatListController.swift": 1,
    "submodules/Pasteboard/Sources/Pasteboard.swift": 1,
    "submodules/PremiumUI/Sources/PremiumIntroScreen.swift": 1,
    "submodules/TelegramUI/Components/Chat/ChatMessageItemView/Sources/ChatMessageItemView.swift": 1,
    "submodules/TelegramUI/Components/Chat/ChatTextInputPanelNode/Sources/ChatTextInputPanelNode.swift": 1,
    "submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoScreenSettingsActions.swift": 1,
    "submodules/TelegramUI/Components/RichTextEditor/Sources/RichTextEditorCore/Serialization/RTFImport.swift": 1,
    "submodules/TelegramUI/Components/RichTextEditor/Sources/RichTextEditorUIKit/Canvas/RTFConversion.swift": 1,
    "submodules/TelegramUI/Sources/ChatPinnedMessageTitlePanelNode.swift": 2,
    "submodules/TextFormat/Sources/CustomEmojiMarkdownMarker.swift": 2,
    "submodules/TextFormat/Sources/MentionDateMarkers.swift": 4,
    "submodules/UrlWhitelist/Sources/UrlWhitelist.swift": 2,
}
KEPT_TELEGRAM_SITES = {
    "Telegram/NotificationService/Sources/NotificationRecipientAccount.swift": 1,
    "Telegram/NotificationService/Sources/NotificationService.swift": 1,
    "Telegram/SiriIntents/MessageSearchScope.swift": 1,
    "Telegram/Watch/Extension/TGMessageViewController.m": 1,
    "Telegram/Watch/Extension/TGNeoConversationController.m": 1,
    "Telegram/WatchApp/Packages/TDShim/Sources/TDShim/Generated/API/TDLibApi.swift": 4,
    "Telegram/WatchApp/Packages/TDShim/Sources/TDShim/Generated/Models/GetOption.swift": 1,
    "Telegram/WatchApp/Packages/TDShim/Sources/TDShim/Generated/Models/PhotoSize.swift": 1,
    "Telegram/WatchApp/Packages/TDShim/Sources/TDShim/Generated/Models/SetOption.swift": 1,
    "Telegram/WatchApp/Packages/TDShim/Sources/TDShim/Generated/Models/UserType.swift": 2,
    "Telegram/WatchApp/Packages/TDShim/Sources/TDShim/Transport/TDLibClientManager.swift": 2,
    "submodules/BotPaymentsUI/Sources/BotCheckoutWebInteractionControllerNode.swift": 1,
    "submodules/BrowserUI/Sources/BrowserAddressListComponent.swift": 2,
    "submodules/ChatListUI/Sources/ChatListSearchListPaneNode.swift": 2,
    "submodules/ContactListUI/Sources/ContactsController.swift": 1,
    "submodules/InstantPageCache/Sources/CachedInternalInstantPages.swift": 4,
    "submodules/LanguageLinkPreviewUI/Sources/LanguageLinkPreviewContentNode.swift": 1,
    "submodules/MtProtoKit/PublicHeaders/MtProtoKit/MTQuickAck.h": 1,
    "submodules/MtProtoKit/Sources/MTDNS.m": 1,
    "submodules/MtProtoKit/Sources/MTDiscoverConnectionSignals.m": 1,
    "submodules/PeerAvatarGalleryUI/Sources/AvatarGalleryController.swift": 1,
    "submodules/PeerInfoUI/Sources/SecretChatKeyControllerNode.swift": 2,
    "submodules/SettingsUI/Sources/Data and Storage/WebBrowserSettingsController.swift": 1,
    "submodules/SettingsUI/Sources/DeleteAccountOptionsController.swift": 2,
    "submodules/SettingsUI/Sources/LogoutOptionsController.swift": 1,
    "submodules/SettingsUI/Sources/Privacy and Security/PrivacyAndSecurityController.swift": 1,
    "submodules/SettingsUI/Sources/Privacy and Security/Recent Sessions/RecentSessionsController.swift": 1,
    "submodules/TelegramAudio/Sources/ManagedAudioSession.swift": 1,
    "submodules/TelegramCore/Sources/PendingMessages/OutgoingReplyPeer.swift": 1,
    "submodules/TelegramCore/Sources/State/Sync/SyncSequencing.swift": 1,
    "submodules/TelegramPermissionsUI/Sources/PermissionController.swift": 1,
    "submodules/TelegramUI/Components/Chat/ChatMessageRichDataBubbleContentNode/Sources/ChatMessageRichDataBubbleContentNode.swift": 1,
    "submodules/TelegramUI/Components/GroupStickerPackSetupController/Sources/GroupStickerPackSetupController.swift": 1,
    "submodules/TelegramUI/Components/HorizontalTabsComponent/Sources/HorizontalTabsComponent.swift": 1,
    "submodules/TelegramUI/Components/MessageWidget/WidgetRuntime/Sources/Host/Links.cpp": 2,
    "submodules/TelegramUI/Components/Settings/PasskeysScreen/Sources/PasskeysScreen.swift": 1,
    "submodules/TelegramUI/Sources/Chat/ChatControllerOpenLinkContextMenu.swift": 2,
    "submodules/TelegramUI/Sources/Chat/ChatControllerOpenPeer.swift": 1,
    "submodules/TelegramUI/Sources/ChatInterfaceTitlePanelNodes.swift": 1,
    "submodules/TelegramUI/Sources/OpenUrl.swift": 2,
    "submodules/TextFormat/Sources/GenerateTextEntities.swift": 4,
    "submodules/TgVoipWebrtc/Sources/OngoingCallThreadLocalContext.mm": 1,
    "submodules/UrlHandling/Sources/UrlHandling.swift": 5,
    "submodules/UrlWhitelist/Sources/UrlWhitelist.swift": 4,
    "submodules/WalletContext/Sources/WalletOperations.swift": 1,
    "submodules/WalletContext/Sources/WalletTonConnect.swift": 1,
}
TG_LITERAL = re.compile(rb'"tg://')
TELEGRAM_SITE = re.compile(rb'(?:"|://|\.)(?:telegram\.(?:org|me|dog)|telegra\.ph|telesco\.pe)(?=[/"\\?#])')
# Entries of the built-in strings that name one of Telegram's sites.
STRINGS_TELEGRAM_SITES = 33

# Telegram's client sites, which none of those files may open after the edits.
CLIENT_SITES = re.compile(r"(?:get)?desktop\.telegram\.org|web\.telegram\.org")

# pluma.chat is to Pluma what t.me is to Telegram: the domain of the links the
# app makes for people to copy, share, show and scan, and a domain whose links
# the app opens itself. The server makes its links there too (invites, the
# config's me_url_prefix). t.me, telegram.me and telegram.dog stay the app's
# own as well, as upstream. Only the host pluma.chat itself: web.pluma.chat and
# the other subdomains are sites, not usernames as those of t.me.
LINK_HOST = "pluma.chat"
OPEN_URL = "submodules/TelegramUI/Sources/OpenUrl.swift"
CHAT_FOLDERS = "submodules/TelegramCore/Sources/TelegramEngine/Peers/ChatFolders.swift"
WEB_PROXY_LINK = "submodules/TelegramCore/Sources/Settings/ProxySettings.swift"
_SETTINGS_UI = "submodules/SettingsUI/Sources/"
_UI_COMPONENTS = "submodules/TelegramUI/Components/"
_PEER_INFO = _UI_COMPONENTS + "PeerInfo/PeerInfoScreen/Sources/"
_PEER_INFO_PANES = _UI_COMPONENTS + "PeerInfo/PeerInfoVisualMediaPaneNode/Sources/"
_SETTINGS_SCREENS = _UI_COMPONENTS + "Settings/"
# The lists and checks that tell the app's own links from others':
# (file, Telegram's text, Pluma's, how many times).
LINK_HOSTS = (
    # Every link the app opens, makes previews of or parses (proxies, QR
    # codes): the parsers of UrlHandling and the check of OpenUrl.
    (URL_HANDLING, '    "t.me", "telegram.dog"\n]\n', '    "t.me", "telegram.dog",\n    "pluma.chat"\n]\n', 1),
    (OPEN_URL, '["t.me", "telegram.me", "telegram.dog"]', '["t.me", "telegram.me", "telegram.dog", "pluma.chat"]', 1),
    # Concealed links (text links of messages and bots) open without asking.
    ("submodules/UrlWhitelist/Sources/UrlWhitelist.swift",
     '    "t.me",\n    "telegram.me",\n', '    "t.me",\n    "telegram.me",\n    "pluma.chat",\n', 1),
    # Links of these hosts are found in text where only the app's own are.
    ("submodules/TextFormat/Sources/GenerateTextEntities.swift",
     '    "t.me",\n    "telegram.me",\n', '    "t.me",\n    "telegram.me",\n    "pluma.chat",\n', 1),
    # A long press on a link offers no "open in the browser" for them, but
    # for the pages of the site pluma.chat itself (PLUMA_SITE).
    ("submodules/TelegramUI/Sources/Chat/ChatControllerOpenLinkContextMenu.swift",
     'if host == "t.me" || host == "telegram.me" || host == "telegram.dog" {',
     'if host == "t.me" || host == "telegram.me" || host == "telegram.dog" '
     '|| (host == "pluma.chat" && !isPlumaSiteLink(parsedUrl.absoluteString)) {', 1),
    # The QR scanner of a profile and the story camera take Pluma's codes.
    (QR_SCAN, 'filteredCodes = codes.filter { $0.message.hasPrefix("https://t.me/") || $0.message.hasPrefix("t.me/") }',
     'filteredCodes = codes.filter { $0.message.hasPrefix("https://t.me/") || $0.message.hasPrefix("t.me/") '
     '|| $0.message.hasPrefix("https://pluma.chat/") || $0.message.hasPrefix("pluma.chat/") }', 1),
    (_UI_COMPONENTS + "CameraScreen/Sources/CameraScreen.swift",
     'message.hasPrefix("t.me/contact/") || message.hasPrefix("t.me/") {',
     'message.hasPrefix("t.me/contact/") || message.hasPrefix("t.me/") || message.hasPrefix("pluma.chat/") {', 1),
    # The preview of a message link reads "View Message".
    (_UI_COMPONENTS + "Chat/ChatMessageWebpageBubbleContentNode/Sources/ChatMessageWebpageBubbleContentNode.swift",
     'if webpage.displayUrl.hasPrefix("t.me/") {',
     'if webpage.displayUrl.hasPrefix("t.me/") || webpage.displayUrl.hasPrefix("pluma.chat/") {', 1),
    # A link pasted where the app asks for a bot or a sticker set.
    (_SETTINGS_SCREENS + "ChatbotSetupScreen/Sources/ChatbotSetupScreen.swift",
     'url.host == "t.me" {', '(url.host == "t.me" || url.host == "pluma.chat") {', 2),
    (_UI_COMPONENTS + "GroupStickerPackSetupController/Sources/GroupStickerPackSetupController.swift",
     'url.host == "t.me" || url.host == "telegram.me" {',
     'url.host == "t.me" || url.host == "telegram.me" || url.host == "pluma.chat" {', 1),
    # The link of a web proxy, which the app also makes with pluma.chat.
    (WEB_PROXY_LINK, '&& components.host?.lowercased() == "t.me"\n',
     '&& (components.host?.lowercased() == "t.me" || components.host?.lowercased() == "pluma.chat")\n', 1),
    # The slug of a shared chat folder's link (the server makes it).
    (CHAT_FOLDERS,
     '            slug = String(slug[slug.index(slug.startIndex, offsetBy: "https://t.me/addlist/".count)...])\n'
     '        }\n',
     '            slug = String(slug[slug.index(slug.startIndex, offsetBy: "https://t.me/addlist/".count)...])\n'
     '        } else if slug.hasPrefix("https://pluma.chat/addlist/") {\n'
     '            slug = String(slug[slug.index(slug.startIndex, offsetBy: "https://pluma.chat/addlist/".count)...])\n'
     '        }\n', 1),
)
# UrlHandling reads a link of a subdomain of t.me (name.t.me) as one of a
# username (t.me/name); one of pluma.chat stays a link of that site.
URL_SUBDOMAIN_OLD = ('                    if (lowercasedUrl.hasPrefix(scheme) && (lowercasedUrl.hasSuffix(".\\(basePath)") '
                     '|| lowercasedUrl.contains(".\\(basePath)/") || lowercasedUrl.contains(".\\(basePath)?"))) {\n')
URL_SUBDOMAIN = ("                    // pluma: a subdomain of pluma.chat is a site of its own (web.pluma.chat), not a username.\n"
                 + URL_SUBDOMAIN_OLD.replace("if (lowercasedUrl", f'if basePath != "{LINK_HOST}" && (lowercasedUrl', 1))
# The pages of the site pluma.chat itself: its root and the first segments of
# its paths (lower case), the same list in every client. A link of one of
# them is a link of that site, not one of a username: the app opens it as any
# site's (its in-app browser or the one the person chose), and the in-app
# browser shows it instead of handing it back to the app. The site's
# apple-app-site-association leaves the same paths out of the app's universal
# links, so the system browser keeps them as well.
PLUMA_SITE_PATHS = ("iphone", "ipad", "android", "mac", "windows", "linux", "web", "pero", "app", "en", "dl", "ios",
                    "collect", "assets", "_l", ".well-known",
                    "favicon.svg", "og.png", "apple-touch-icon.png", "404.html", "progress.json")
PLUMA_SITE_CHECK = "isPlumaSiteLink"
PLUMA_SITE_FUNC = (
    "\n"
    "// pluma: the pages of the site pluma.chat itself, its root and the first segments of its\n"
    "// paths, are a site's, not the app's links (the same list in every client).\n"
    "private let plumaSitePaths: Set<String> = [\n"
    + ",\n".join("    " + ", ".join(f'"{p}"' for p in PLUMA_SITE_PATHS[i:i + 8])
                 for i in range(0, len(PLUMA_SITE_PATHS), 8)) + "\n"
    "]\n"
    "\n"
    f"public func {PLUMA_SITE_CHECK}(_ url: String) -> Bool {{\n"
    "    var urlWithScheme = url\n"
    '    if !urlWithScheme.contains("://") {\n'
    '        urlWithScheme = "https://\\(urlWithScheme)"\n'
    "    }\n"
    f'    guard let parsedUrl = URL(string: urlWithScheme), parsedUrl.host?.lowercased() == "{LINK_HOST}" else {{\n'
    "        return false\n"
    "    }\n"
    '    if let scheme = parsedUrl.scheme?.lowercased(), scheme != "http" && scheme != "https" {\n'
    "        return false\n"
    "    }\n"
    '    guard let first = parsedUrl.path.split(separator: "/").first else {\n'
    "        return true\n"
    "    }\n"
    "    return plumaSitePaths.contains(first.lowercased())\n"
    "}\n"
)
OPEN_LINK_MENU = "submodules/TelegramUI/Sources/Chat/ChatControllerOpenLinkContextMenu.swift"
# Where the app tells its own links from the site's pages: (file, upstream's
# text, Pluma's, how many times).
PLUMA_SITE = (
    # The check itself, beside that of Telegram's web short links.
    (URL_HANDLING, "    return telegramWebShortLinkHosts.contains(host)\n}\n",
     "    return telegramWebShortLinkHosts.contains(host)\n}\n" + PLUMA_SITE_FUNC, 1),
    # Not a link of the app's own: the in-app browser and the web apps show
    # it instead of handing it back to the app.
    (URL_HANDLING, "public func isTelegramMeLink(_ url: String) -> Bool {\n",
     "public func isTelegramMeLink(_ url: String) -> Bool {\n"
     f"    if {PLUMA_SITE_CHECK}(url) {{\n        return false\n    }}\n", 1),
    # A link resolved in the app (a tap in a chat) comes back as an external
    # one, as a web short link does.
    (URL_HANDLING, "            if isTelegramWebShortLink(url) {\n"
                   "                return .single(.result(.externalUrl(url)))\n"
                   "            }\n",
     "            if isTelegramWebShortLink(url) {\n"
     "                return .single(.result(.externalUrl(url)))\n"
     "            }\n"
     f"            if {PLUMA_SITE_CHECK}(url) {{\n"
     "                return .single(.result(.externalUrl(url)))\n"
     "            }\n", 1),
    # An external link of a page opens as any site's, by the person's browser
    # settings, instead of being resolved in the app again.
    (OPEN_URL, "        if let host = parsedUrl.host, telegramMeHosts.contains(host) {\n"
               "            handleInternalUrl(parsedUrl.absoluteString)\n",
     f"        if let host = parsedUrl.host, telegramMeHosts.contains(host), !{PLUMA_SITE_CHECK}(parsedUrl.absoluteString) {{\n"
     "            handleInternalUrl(parsedUrl.absoluteString)\n", 1),
    # The long-press menu of a link calls the check (LINK_HOSTS).
    (OPEN_LINK_MENU, "import UrlWhitelist\n", "import UrlWhitelist\nimport UrlHandling\n", 1),
)
# The links the app makes, and the prefixes it shows before a username or a
# set's name: (file, text with {host}, how many times). {host} is t.me
# upstream.
SHARE_LINKS = (
    # The private link of a message in a channel's direct messages; the QR
    # Studio's code of a profile, a phone number or a channel; a web proxy.
    (_UI_COMPONENTS + "Chat/ChatMessageItemCommon/Sources/ChatMessageCopyLink.swift",
     'return "https://{host}/c/\\(messageId.peerId.id._internalGetInt64Value())/\\(messageId.id)"', 1),
    (_UI_COMPONENTS + "QrStudioScreen/Sources/QrStudioScreen.swift", 'link = "https://{host}/\\(addressName)"', 1),
    (_UI_COMPONENTS + "QrStudioScreen/Sources/QrStudioScreen.swift", 'link = "https://{host}/+\\(user.phone ?? "")"', 1),
    (_UI_COMPONENTS + "QrStudioScreen/Sources/QrStudioScreen.swift",
     'link = "https://{host}/c/\\(peer.id.id._internalGetInt64Value())"', 1),
    (WEB_PROXY_LINK, 'components.host = "{host}"\n    components.path = "/webproxy"\n', 1),
    # Profiles, channels and groups: share, copy, QR codes, the admin log.
    (_SETTINGS_UI + "UsernameSetupController.swift", 'subject: .url("https://{host}/\\(currentAddressName)")', 1),
    (_PEER_INFO + "PeerInfoScreen.swift", 'strongSelf.openShareLink(url: "https://{host}/\\(username)")', 1),
    (_PEER_INFO + "PeerInfoProfileItems.swift", 'let linkText = "https://{host}/\\(mainUsername)/\\(threadId)"', 1),
    (_PEER_INFO + "PeerInfoProfileItems.swift", 'text: "https://{host}/\\(mainUsername)",', 1),
    (_PEER_INFO + "PeerInfoScreenOpenPeerInfoContextMenu.swift", 'text = "https://{host}/\\(addressName)"', 1),
    (_PEER_INFO + "PeerInfoScreenOpenPeerInfoContextMenu.swift",
     'text = "https://{host}/@id\\(peer.id.id._internalGetInt64Value())"', 1),
    (_PEER_INFO + "PeerInfoScreenOpenURL.swift", 'url = "https://{host}/\\(value)"', 1),
    (_PEER_INFO + "PeerInfoScreenDisplayGiftsContextMenu.swift",
     'self?.openShareLink(url: "https://{host}/\\(addressName)/c/\\(id)")', 1),
    (_PEER_INFO_PANES + "PeerInfoGiftsPaneNode.swift", 'self.openShareLink?("https://{host}/\\(addressName)/c/\\(id)")', 1),
    (_PEER_INFO_PANES + "PeerInfoStoryPaneNode.swift", 'subject: .url("https://{host}/\\(urlBase)/a/\\(id)"),', 1),
    ("submodules/TelegramUI/Sources/ChatInterfaceStateContextMenus.swift", 'let link = "https://{host}/\\(addressName)"', 1),
    (_SETTINGS_SCREENS + "CollectibleItemInfoScreen/Sources/CollectibleItemInfoScreen.swift",
     'UIPasteboard.general.string = "https://{host}/\\(username.username)"', 1),
    (_SETTINGS_SCREENS + "AutomaticBusinessMessageSetupScreen/Sources/BusinessLinksSetupScreen.swift",
     'linkValue = "{host}/+\\(phoneNumber)"', 1),
    (_SETTINGS_SCREENS + "AutomaticBusinessMessageSetupScreen/Sources/BusinessLinksSetupScreen.swift",
     'linkValue = "{host}/\\(addressName)"', 1),
    (_UI_COMPONENTS + "PeerInfo/PostSuggestionsSettingsScreen/Sources/PostSuggestionsSettingsScreen.swift",
     'let link = "{host}/\\(address)?direct"', 1),
    ("submodules/InviteLinksUI/Sources/InviteLinkListController.swift", 'mainInvite = .link(link: "{host}/\\(address)",', 1),
    ("submodules/QrCodeUI/Sources/QrCodeScreen.swift", 'return "https://{host}/\\(peer.addressName ?? "")"', 1),
    ("submodules/QrCodeUI/Sources/QrCodeScreen.swift", 'return "https://{host}/addlist/\\(slug)"', 1),
    (_UI_COMPONENTS + "Chat/ChatQrCodeScreen/Sources/ChatQrCodeScreen.swift",
     'codeLink = "https://{host}/\\(peer.addressName ?? "")"', 1),
    (_UI_COMPONENTS + "Chat/ChatQrCodeScreen/Sources/ChatQrCodeScreen.swift", 'codeLink = "https://{host}/+\\(peer.phone ?? "")"', 1),
    (_UI_COMPONENTS + "Chat/ChatQrCodeScreen/Sources/ChatQrCodeScreen.swift",
     'codeLink = "https://{host}/c/\\(peer.id.id._internalGetInt64Value())"', 1),
    (_UI_COMPONENTS + "Chat/ChatRecentActionsController/Sources/ChatRecentActionsHistoryTransition.swift",
     'let prevText = "https://{host}/\\(prev)"', 1),
    (_UI_COMPONENTS + "Chat/ChatRecentActionsController/Sources/ChatRecentActionsHistoryTransition.swift",
     'text = "https://{host}/\\(new)"', 1),
    (_UI_COMPONENTS + "Chat/ChatRecentActionsController/Sources/ChatRecentActionsHistoryTransition.swift",
     'let link = "https://{host}/\\(username)"', 2),
    (_SETTINGS_UI + "Privacy and Security/SelectivePrivacySettingsController.swift",
     'let phoneLink = "https://{host}/+\\(phoneNumber)"', 1),
    ("submodules/WebUI/Sources/WebAppController.swift", 'subject: .url("https://{host}/\\(addressName)?profile")', 1),
    ("submodules/GameUI/Sources/GameControllerNode.swift", 'let url = "https://{host}/\\(addressName)?game=\\(gameName)"', 1),
    ("submodules/TelegramCallsUI/Sources/VideoChatScreenInviteMembers.swift", 'return "https://{host}/\\(addressName)"', 1),
    ("submodules/TelegramCallsUI/Sources/Components/MediaStreamComponent.swift",
     'listenerLink: "https://{host}/\\(addressName)?voicechat"', 1),
    # Messages of public channels and groups.
    ("submodules/ShareController/Sources/ShareController.swift", 'url = "https://{host}/\\(addressName)/\\(message.id.id)"', 1),
    ("submodules/TelegramUI/Sources/Chat/ChatControllerOpenTimecodeContextMenu.swift",
     'let inputCopyText = "https://{host}/\\(addressName)/\\(message.id.id)\\(timestampSuffix)"', 1),
    ("submodules/GalleryUI/Sources/Items/UniversalVideoGalleryItem.swift",
     'let visibleString = "{host}/\\(username)/\\(message.id.id)"', 1),
    (_UI_COMPONENTS + "Chat/ChatQrCodeScreen/Sources/ChatQrCodeScreen.swift", 'link = "{host}/\\(addressName)/\\(message.id.id)"', 1),
    # Sticker and emoji sets.
    (_SETTINGS_UI + "Stickers/InstalledStickerPacksController.swift", 'packNames.map { "https://{host}/addstickers/\\($0)" }', 1),
    (_SETTINGS_UI + "Stickers/ArchivedStickerPacksController.swift", 'packNames.map { "https://{host}/addstickers/\\($0)" }', 1),
    ("submodules/StickerPackPreviewUI/Sources/StickerPackScreen.swift", 'links += "https://{host}/addemoji/\\(info.shortName)"', 1),
    ("submodules/StickerPackPreviewUI/Sources/StickerPackScreen.swift", 'links += "https://{host}/addstickers/\\(info.shortName)"', 1),
    ("submodules/StickerPackPreviewUI/Sources/StickerPackScreen.swift", 'text = "https://{host}/addemoji/\\(info.shortName)"', 1),
    ("submodules/StickerPackPreviewUI/Sources/StickerPackScreen.swift", 'text = "https://{host}/addstickers/\\(info.shortName)"', 1),
    (_UI_COMPONENTS + "ChatEntityKeyboardInputNode/Sources/PaneSearchContainerNode.swift",
     'let link = "https://{host}/addstickers/\\(selectedStickerPack.info.shortName)"', 1),
    # Themes, wallpapers, languages, proxies.
    (_SETTINGS_UI + "ThemePickerController.swift", '.url("https://{host}/addtheme/\\(theme.theme.slug)")', 1),
    (_SETTINGS_UI + "ThemePickerController.swift", '.url("https://{host}/addtheme/\\(cloudTheme.theme.slug)")', 1),
    (_SETTINGS_UI + "Themes/ThemeSettingsController.swift", '.url("https://{host}/addtheme/\\(theme.theme.slug)")', 1),
    (_SETTINGS_UI + "Themes/ThemeSettingsController.swift", '.url("https://{host}/addtheme/\\(cloudTheme.theme.slug)")', 1),
    (_SETTINGS_UI + "Themes/ThemePreviewController.swift", 'subject = .url("https://{host}/addtheme/\\(theme.slug)")', 1),
    (_SETTINGS_UI + "Themes/ThemePreviewController.swift", 'subject = .url("https://{host}/addtheme/\\(slug)")', 1),
    (_SETTINGS_SCREENS + "WallpaperGalleryScreen/Sources/WallpaperGalleryController.swift",
     '.url("https://{host}/bg/\\(file.slug)\\(optionsString)")', 2),
    (_SETTINGS_SCREENS + "WallpaperGalleryScreen/Sources/WallpaperGalleryController.swift",
     '.url("https://{host}/bg/\\(UIColor(rgb: color).hexString)")', 1),
    (_SETTINGS_SCREENS + "WallpaperGalleryScreen/Sources/WallpaperGalleryController.swift",
     '.url("https://{host}/bg/\\(colorsString)")', 1),
    (_SETTINGS_SCREENS + "WallpaperGridScreen/Sources/ThemeGridController.swift", 'string.append("https://{host}/bg/\\(item)")', 1),
    (_SETTINGS_UI + "Language Selection/LocalizationListControllerNode.swift",
     '.url("https://{host}/setlanguage/\\(info.languageCode)")', 1),
    (_SETTINGS_UI + "Data and Storage/ProxyListSettingsController.swift", 'string = "https://{host}/proxy?server=', 1),
    (_SETTINGS_UI + "Data and Storage/ProxyListSettingsController.swift", 'string = "https://{host}/socks?server=', 1),
    ("submodules/QrCodeUI/Sources/QrCodeScreen.swift", '(externalLink ? "https://{host}/proxy" : ', 1),
    ("submodules/QrCodeUI/Sources/QrCodeScreen.swift", '(externalLink ? "https://{host}/socks" : ', 1),
    # The prefixes before a public link's name.
    ("submodules/PeerInfoUI/Sources/ChannelVisibilityController.swift", 'title: NSAttributedString(string: "{host}/",', 1),
    ("submodules/PeerInfoUI/Sources/ChannelVisibilityController.swift", 'label = "{host}/" + addressName', 1),
    ("submodules/TelegramUI/Sources/CreateGroupController.swift", 'title: NSAttributedString(string: "{host}/",', 1),
    ("submodules/TelegramUI/Sources/CreateChannelController.swift", 'title: NSAttributedString(string: "{host}/",', 1),
    (_SETTINGS_UI + "Themes/EditThemeController.swift", 'title: NSAttributedString(string: "{host}/addtheme/",', 1),
    (_UI_COMPONENTS + "Stickers/StickerPackEditTitleController/Sources/StickerPackEditTitleController.swift",
     'self.inputFieldNode.prefix = "{host}/addstickers/"', 1),
    (_UI_COMPONENTS + "GroupStickerPackSetupController/Sources/GroupStickerPackSetupController.swift",
     'isEmoji ? "{host}/addemoji/" : "{host}/addstickers/"', 1),
)
# The t.me links the app keeps, which no edit may miss: (file, text, how many
# times). Every other t.me literal of the app's code (TME_LITERAL) is one of
# SHARE_LINKS, so a new one upstream stops the patch.
SHARE_KEEP = (
    # Telegram's own: the wallet, which the server does not offer, and the
    # link it reads for a transfer; the hosts of a message widget, which the
    # server does not make; a code generated to warm up the QR code generator,
    # shown to nobody; the code shown before the real one is ready.
    ("submodules/InstantPageUI/Sources/InstantPageTextItem.swift", '"https://t.me/sendgrams"', 1),
    (OPEN_URL, 'handleInternalUrl("https://t.me/sendgrams"', 1),
    (URL_HANDLING, 'URLComponents(string: "https://t.me/sendgrams")!', 1),
    ("submodules/WalletContext/Sources/WalletTonConnect.swift", 'host == "t.me"', 1),
    (_UI_COMPONENTS + "Wallet/WalletCollectibleScreen/Sources/WalletCollectibleScreen.swift", '"https://t.me/nft/\\(slug)"', 1),
    (_UI_COMPONENTS + "MessageWidget/WidgetRuntime/Sources/Host/Links.cpp", '{"t.me", "telegram.me", "telegram.dog"}', 1),
    (_UI_COMPONENTS + "MessageWidget/WidgetRuntime/Sources/Host/Links.cpp", 'expected https://t.me/', 1),
    ("submodules/QrCode/Sources/QrCode.swift", 'qrCode(string: "https://t.me/telegram", ', 1),
    (_UI_COMPONENTS + "QrStudioScreen/Sources/QrStudioScreen.swift", 'return "https://t.me/contact/" + String(', 1),
    # The host lists above, beside pluma.chat, and the parsers' own forms.
    (URL_HANDLING, '    "t.me", "telegram.dog",\n', 1),
    (URL_HANDLING, '    "t.me/iv?",\n', 1),
    (URL_HANDLING, 'return .internalInstantView(url: "https://t.me/\\(query)")', 1),
    (URL_HANDLING, 'return .oauth(url: "https://t.me/\\(query)")', 1),
    (OPEN_URL, '["t.me", "telegram.me", "telegram.dog", "pluma.chat"]', 1),
    ("submodules/UrlWhitelist/Sources/UrlWhitelist.swift", '    "t.me",\n', 1),
    ("submodules/TextFormat/Sources/GenerateTextEntities.swift", '    "t.me",\n', 1),
    ("submodules/TelegramUI/Sources/Chat/ChatControllerOpenLinkContextMenu.swift", 'if host == "t.me" || ', 1),
    (QR_SCAN, '$0.message.hasPrefix("https://t.me/") || $0.message.hasPrefix("t.me/")', 1),
    (_UI_COMPONENTS + "CameraScreen/Sources/CameraScreen.swift",
     'if message.hasPrefix("t.me/c/") || message.hasPrefix("t.me/+") || message.hasPrefix("t.me/contact/") '
     '|| message.hasPrefix("t.me/")', 1),
    (_UI_COMPONENTS + "Chat/ChatMessageWebpageBubbleContentNode/Sources/ChatMessageWebpageBubbleContentNode.swift",
     'webpage.displayUrl.hasPrefix("t.me/")', 1),
    (_SETTINGS_SCREENS + "ChatbotSetupScreen/Sources/ChatbotSetupScreen.swift", 'url.host == "t.me"', 2),
    (_UI_COMPONENTS + "GroupStickerPackSetupController/Sources/GroupStickerPackSetupController.swift",
     'url.host == "t.me"', 1),
    (CHAT_FOLDERS, '"https://t.me/addlist/"', 2),
    (WEB_PROXY_LINK, '&& (components.host?.lowercased() == "t.me" || ', 1),
    # Links made only to be opened in the app, which still takes t.me.
    (OPEN_URL, 'return appendQueryItems(to: "https://t.me\\(path)", items: queryItems)', 1),
    ("submodules/WebUI/Sources/WebAppUtils.swift", 'let urlString = "https://t.me\\(pathFull)"', 1),
    ("submodules/WebUI/Sources/WebAppUtils.swift", 'guard url.host?.lowercased() == "t.me" else {', 1),
    (_UI_COMPONENTS + "Stars/StarsTransactionsScreen/Sources/StarsTransactionsScreen.swift",
     'itemLink: .url(url: "https://t.me/+\\(inviteHash)", concealed: false)', 1),
    (_UI_COMPONENTS + "Stars/StarsTransactionsScreen/Sources/StarsTransactionsScreen.swift",
     'itemLink: .url(url: "https://t.me/$\\(invoiceSlug)", concealed: false)', 1),
    # Telegram's own: gift codes, collectible gifts, auctions, text styles,
    # Stars, Cocoon, the bot of link previews, the page that adds a mini
    # app to the home screen, a payment provider's return to Telegram.
    ("submodules/PremiumUI/Sources/PremiumIntroScreen.swift", '"https://t.me/giftcode/\\(giftCode.slug)"', 2),
    ("submodules/PremiumUI/Sources/PremiumGiftCodeScreen.swift", '"https://t.me/giftcode/\\(giftCode.slug)"', 1),
    ("submodules/PremiumUI/Sources/PremiumGiftCodeScreen.swift", '"https://t.me/giftcode/\\(slug)"', 1),
    (_UI_COMPONENTS + "Gifts/GiftViewScreen/Sources/GiftViewScreen.swift", 'let link = "https://t.me/nft/\\(gift.slug)"', 2),
    (_PEER_INFO_PANES + "PeerInfoGiftsPaneNode.swift", 'let link = "https://t.me/nft/\\(gift.slug)"', 1),
    (_PEER_INFO + "PeerInfoScreen.swift", 'self.openUrl(url: "https://t.me/nft/\\(slug)", ', 1),
    ("submodules/TelegramUI/Sources/ChatController.swift", 'self.openUrl("https://t.me/nft/\\(slug)", ', 1),
    (_UI_COMPONENTS + "Stories/StoryContainerScreen/Sources/StoryItemSetContainerViewSendMessage.swift",
     'url: "https://t.me/nft/\\(slug)", ', 1),
    ("submodules/ShareController/Sources/ShareController.swift", 'link.contains("t.me/nft/")', 1),
    (_UI_COMPONENTS + "Gifts/GiftViewScreen/Sources/GiftAuctionBidScreen.swift", 'link = "https://t.me/auction/\\(slug)"', 2),
    (_UI_COMPONENTS + "Gifts/GiftViewScreen/Sources/GiftAuctionViewScreen.swift", 'link = "https://t.me/auction/\\(slug)"', 2),
    (_UI_COMPONENTS + "TextProcessingScreen/Sources/TextProcessingScreen.swift", '.url("https://t.me/addstyle/\\(slug)")', 1),
    (_UI_COMPONENTS + "Stars/StarsTransactionScreen/Sources/StarsTransactionScreen.swift",
     '"t.me/\\(peerName)/\\(messageId.id)"', 1),
    (_UI_COMPONENTS + "CocoonInfoScreen/Sources/CocoonInfoScreen.swift", '.url(url: "https://t.me/cocoon", ', 1),
    (_UI_COMPONENTS + "CocoonInfoScreen/Sources/CocoonInfoScreen.swift", '.url(url: "https://t.me/cocoon?direct", ', 1),
    ("submodules/InstantPageUI/Sources/InstantPageFeedbackNode.swift",
     'url: "https://t.me/previews?start=webpage\\(webPageId)"', 1),
    ("submodules/WebUI/Sources/WebAppController.swift",
     '"\\(scheme)://t.me/\\(addressName)\\(appName)?startapp&addToHomeScreen"', 1),
    ("submodules/BotPaymentsUI/Sources/BotCheckoutWebInteractionControllerNode.swift", 'if host == "t.me" || ', 1),
    # No link: the QR code's markers before the code is ready, a fake ad of
    # debug builds.
    (_UI_COMPONENTS + "Chat/ChatQrCodeScreen/Sources/ChatQrCodeScreen.swift",
     'qrCode(string: "https://t.me/contact/000000:abcdef", ', 1),
    ("submodules/TelegramUI/Sources/ChatHistoryListNode.swift", 'url: "t.me/telegram", ', 1),
    # The address of a username in device contacts, which the app writes and
    # reads back by this prefix (Siri's extension too): contacts already
    # written must stay readable.
    ("submodules/AccountContext/Sources/DeviceContactData.swift",
     'private let phonebookUsernamePrefix = "https://t.me/" + phonebookUsernamePathPrefix', 1),
    ("Telegram/SiriIntents/IntentContacts.swift",
     'private let phonebookUsernamePrefix = "https://t.me/" + phonebookUsernamePathPrefix', 1),
    # The old Objective-C watch extension, which no target builds.
    ("Telegram/Watch/Extension/TGUserInfoController.m", '@"t.me/%@"', 1),
)
# A t.me link written in the app's code: a string literal that starts with
# the host, or a URL with it right after the scheme.
TME_LITERAL = re.compile(rb'(?:"|://)t\.me(?=[/\\"])')
# The texts that show a link of a username, a phone number or a public link,
# by key (en.lproj, the only language the app bundles): (key, how many t.me).
STRINGS_LINKS = (
    ("Username.LinkHint", 1),
    ("Channel.Username.LinkHint", 1),
    ("EmptyGroupInfo.Line3", 1),
    ("PrivacyPhoneNumberSettings.CustomPublicLink", 1),
    ("Business.Links.SimpleLinkInfoUsernamePhone", 2),
    ("Business.Links.SimpleLinkInfoUsername", 1),
    ("Business.Links.SimpleLinkInfoPhone", 1),
    # The switch of a proxy's QR code between the app's scheme and an https link.
    ("SocksProxySetup.QrCode.TMeLink", 1),
)
# Texts that keep t.me: Premium's limits, Telegram's Cocoon.
STRINGS_KEEP = ("Premium.Limits.PublicLinksInfo", "CocoonInfo.IntergrateInfo")
STRINGS_TME = re.compile(r"(?<![0-9A-Za-z_.])t\.me(?![0-9A-Za-z_])")

# What App Store Connect asks of every upload (its notes on Pluma's build 20,
# 2026-11-01). Not here: ITMS-90068, iOS 15 at least from April 2027. The
# pinned release targets 13.0 and compiles 673 of its modules with
# -warnings-as-errors; with a target of 15.0 every unguarded API deprecated in
# iOS 14 or 15 (UIApplication.windows, used in AppDelegate.swift and others)
# becomes a warning, so a build error. Telegram has to raise the target itself
# before then, and the update of the pinned release brings it.
# ITMS-90683: the main Info.plist must name the purpose of every location
# permission the code can ask for, NSLocationAlwaysAndWhenInUseUsageDescription
# too. Every language's InfoPlist.strings translates that key already; the
# English one (en.lproj) is the text of the Info.plist.
LOCATION_ANCHOR = "    <key>NSLocationWhenInUseUsageDescription</key>\n"
LOCATION_KEY = "NSLocationAlwaysAndWhenInUseUsageDescription"
# ITMS-91198: no Apple font in the bundle (from 1 October 2027 such uploads are
# refused). SF Camera, in TelegramUI's resources and registered by the
# Info.plist, is the face of the camera's controls. Without it the camera
# falls back to the system font of the same weight, as Font.with already
# does when the font cannot be loaded.
FONT = "submodules/Display/Source/Font.swift"
CAMERA_FONTS = {
    "submodules/TelegramUI/Resources/Fonts/AremacFS-Regular.otf":
        "1a78b533ec78aacd654dc70fbad6984e72e6c265d334771d18b4773c7271f389",
    "submodules/TelegramUI/Resources/Fonts/AremacFS-Semibold.otf":
        "28eab504072291f09a095d75891dc5da01d18e5154552c9e2e60df4e9818108e",
}
CAMERA_FONTS_PLIST = ("    <key>UIAppFonts</key>\n"
                      "    <array>\n"
                      "        <string>AremacFS-Regular.otf</string>\n"
                      "        <string>AremacFS-Semibold.otf</string>\n"
                      "    </array>\n")
# The legacy camera (TGCameraController, the camera of the attachment menu)
# takes the same font through TGCameraInterfaceAssets, without a fallback:
# a nil font in its title attributes throws, and the app crashed on opening
# the camera (the owner's report of 2026-11-07, TGCameraModeControl
# _createButtonForMode:title:). It falls back as Font.swift does.
CAMERA_ASSETS = "submodules/LegacyComponents/Sources/TGCameraInterfaceAssets.m"
CAMERA_ASSETS_FALLBACKS = (
    ('    return [UIFont fontWithName:TGCameraEncodeText(@"TGDbnfsb.Sfhvmbs", -1) size:size];\n',
     '    UIFont *font = [UIFont fontWithName:TGCameraEncodeText(@"TGDbnfsb.Sfhvmbs", -1) size:size];\n'
     '    return font ?: [UIFont systemFontOfSize:size weight:UIFontWeightRegular];\n'),
    ('    return [UIFont fontWithName:TGCameraEncodeText(@"TGDbnfsb.Tfnjcpme", -1) size:size];\n',
     '    UIFont *font = [UIFont fontWithName:TGCameraEncodeText(@"TGDbnfsb.Tfnjcpme", -1) size:size];\n'
     '    return font ?: [UIFont systemFontOfSize:size weight:UIFontWeightSemibold];\n'),
)
CAMERA_FONT_FALLBACKS = (
    'font = UIFont(name: encodeText(string: "TGDbnfsb.Tfnjcpme", key: -1), size: size) '
    '?? UIFont.systemFont(ofSize: size, weight: weight.weight)',
    'font = UIFont(name: encodeText(string: "TGDbnfsb.Sfhvmbs", key: -1), size: size) '
    '?? UIFont.systemFont(ofSize: size, weight: weight.weight)',
)
# ITMS-90626: an example phrase for every system intent the Siri extension
# supports, in every language the app bundles. Upstream gives one for sending
# a message only, naming Telegram, and in English for most languages. Each
# AppIntentVocabulary.plist is replaced, checked by its SHA-256 first, with
# phrases in its own language for all five; {name} is the app's name.
SIRI_VOCABULARY = "Telegram/Telegram-iOS/{}.lproj/AppIntentVocabulary.plist"
SIRI_EXTENSION_INTENTS = ("            <key>IntentsSupported</key>\n"
                          "            <array>\n"
                          "                <string>INSendMessageIntent</string>\n"
                          "                <string>INStartAudioCallIntent</string>\n"
                          "                <string>INSearchForMessagesIntent</string>\n"
                          "                <string>INSetMessageAttributeIntent</string>\n"
                          "                <string>INSearchCallHistoryIntent</string>\n"
                          "                <string>SelectFriendsIntent</string>\n"
                          "                <string>SelectAvatarFriendsIntent</string>\n"
                          "            </array>\n")
# The order of the phrases below; SelectFriendsIntent and
# SelectAvatarFriendsIntent are the app's own intents (the widget's
# configuration), which take no phrases.
SIRI_INTENTS = ("INSendMessageIntent", "INStartAudioCallIntent", "INSearchCallHistoryIntent",
                "INSearchForMessagesIntent", "INSetMessageAttributeIntent")
SIRI_UPSTREAM = {
    "Base": "31cf9077d2d369d92e73bbf8b1bbebc3f2b6f0abaa059313a6324b390110b673",
    "ar": "822f6056cb74b2b7206c08787a6e6ddf6665712fe5825be113a760df3d119ef1",
    "be": "9d3469922a0210ba6cf629e8786af757dfd3d9dc2609a878df1a0968b3b9f9d9",
    "ca": "93dd7e49318b4436040cb1a2a49b8a0255eb6aee7da9911ec60dd63e1060cfc0",
    "de": "a0390d21e8e0294b1a13015495115dd69db2ce8c10f4e020040d9e650aa00b1a",
    "en": "31cf9077d2d369d92e73bbf8b1bbebc3f2b6f0abaa059313a6324b390110b673",
    "es": "8e45479298b1652693fba9ba3e5ab61abf056b9edbfad88f7066cdfdc10bb4fa",
    "fa": "9a871ac18b17081ada1386b1b8374fd2699cfff33510f6ad39cf1229bd020737",
    "fr": "61f8002431f4a4a1adfc38bdf2d089a3c3f008d331bf159bf8b2c37540fa6b35",
    "id": "5a9c092ac8e28a1a1874af9a901958bedcdc5cd4bd6b0cdb38a4627e37055fae",
    "it": "877e2c8efe8a9af03295a3adac267459994f31b33922f2d929ddaaf98fbe398f",
    "ko": "71ca8d0cac218bb9f8f55d88db0ddf3f89cc5d5981a645e7af99b1ca88f67ed8",
    "ms": "eb9b34066d8984444303a31161096a71dead6d87d08016b00cb115a5da46b4d9",
    "nl": "3855266144d5535dfc5f3e50550af656fa1ac4b8bda0424aadd5606e1f750720",
    "pl": "2c63f0616b8daecc3e641ac1f63ac8fb298e0e6671247dbc83f7dcbd7c9301c2",
    "pt": "d9dcd4acb1320852fffca437e849fa6cfe56217d91c302b38b8623d9919012d8",
    "ru": "8d139f7dd9aa1701e9abf37c791d4aa6f68ffe1488c0bf3be5963a50a49eb6e9",
    "tr": "bafb5e672f1376dbb0ea5e613cd3219218cc58925507a2868e1e16331e37ee9d",
    "uk": "fb4ce7af212dab518d143b4d9eccfc453c78fb485f3a7106844bd2e4602dfb62",
    "uz": "f685d6c0110c9fadae04ca07ccccf2cd1c1f29c802b1051115571cb351b784a8",
}
# The phrases are Pluma's own, in each language: upstream's name Telegram.
SIRI_PHRASES = {
    "ar": ("أرسل رسالة لخالد عبر {name} وأخبره أن هديته وصلت إلى المنزل",
           "اتصل بخالد عبر {name}",
           "اعرض المكالمات الفائتة في {name}",
           "ابحث عن رسائل خالد في {name}",
           "علّم رسائل خالد في {name} كمقروءة"),
    "be": ("Адправіць Алесю паведамленне ў {name}: буду праз 10 хвілін",
           "Патэлефанаваць Алесю ў {name}",
           "Паказаць прапушчаныя званкі ў {name}",
           "Знайсці паведамленні ад Алеся ў {name}",
           "Пазначыць паведамленні ад Алеся ў {name} як прачытаныя"),
    "ca": ("Envia un missatge de {name} a l'Anna dient que hi seré en 10 minuts",
           "Truca a l'Anna amb {name}",
           "Mostra les meves trucades perdudes a {name}",
           "Cerca missatges de l'Anna a {name}",
           "Marca com a llegits els missatges de l'Anna a {name}"),
    "de": ("Sende Lisa eine {name}-Nachricht, dass ich in 15 Minuten da bin.",
           "Ruf Lisa über {name} an",
           "Zeig meine verpassten Anrufe in {name}",
           "Such in {name} nach Nachrichten von Lisa",
           "Markiere die {name}-Nachrichten von Lisa als gelesen"),
    "en": ("Send a {name} message to Alex saying I'll be there in 10 minutes",
           "Call Alex on {name}",
           "Show my missed calls in {name}",
           "Search {name} for messages from Alex",
           "Mark my {name} messages from Alex as read"),
    "es": ("Envía un mensaje de {name} a Alicia diciéndole que estarás allí en 15 minutos",
           "Llama a Alicia por {name}",
           "Muestra mis llamadas perdidas en {name}",
           "Busca mensajes de Alicia en {name}",
           "Marca como leídos los mensajes de Alicia en {name}"),
    "fa": ("با {name} به علی پیام بده که ۱۰ دقیقه دیگر می‌رسم",
           "با {name} به علی زنگ بزن",
           "تماس‌های بی‌پاسخ من در {name} را نشان بده",
           "پیام‌های علی را در {name} جستجو کن",
           "پیام‌های علی در {name} را خوانده‌شده علامت بزن"),
    "fr": ("Envoie un message {name} à Alex pour dire que j'arrive dans 10 minutes",
           "Appelle Alex sur {name}",
           "Affiche mes appels manqués sur {name}",
           "Cherche les messages d'Alex sur {name}",
           "Marque les messages d'Alex sur {name} comme lus"),
    "id": ("Kirim pesan {name} ke Andi bilang aku sampai dalam 10 menit",
           "Telepon Andi lewat {name}",
           "Tampilkan panggilan tak terjawab di {name}",
           "Cari pesan dari Andi di {name}",
           "Tandai pesan dari Andi di {name} sebagai sudah dibaca"),
    "it": ("Invia un messaggio su {name} ad Alex dicendo che sarò lì tra 10 minuti",
           "Chiama Alex su {name}",
           "Mostra le chiamate perse su {name}",
           "Cerca i messaggi di Alex su {name}",
           "Segna come letti i messaggi di Alex su {name}"),
    "ko": ("앨리스에게 나 15분 안에 도착한다고 {name} 메시지 보내줘",
           "{name}로 앨리스에게 전화 걸어줘",
           "{name} 부재중 통화 보여줘",
           "{name}에서 앨리스가 보낸 메시지 찾아줘",
           "{name}에서 앨리스가 보낸 메시지를 읽음으로 표시해줘"),
    "ms": ("Hantar mesej {name} kepada Ali mengatakan saya akan sampai dalam 10 minit",
           "Panggil Ali melalui {name}",
           "Tunjukkan panggilan tidak dijawab saya dalam {name}",
           "Cari mesej daripada Ali dalam {name}",
           "Tandakan mesej daripada Ali dalam {name} sebagai sudah dibaca"),
    "nl": ("Stuur een {name}-bericht naar Maartje met ik ben er over 15 minuten.",
           "Bel Maartje via {name}",
           "Toon mijn gemiste oproepen in {name}",
           "Zoek berichten van Maartje in {name}",
           "Markeer de berichten van Maartje in {name} als gelezen"),
    "pl": ("Wyślij wiadomość w {name} do Ani: będę za 10 minut",
           "Zadzwoń do Ani przez {name}",
           "Pokaż nieodebrane połączenia w {name}",
           "Wyszukaj wiadomości od Ani w {name}",
           "Oznacz wiadomości od Ani w {name} jako przeczytane"),
    "pt": ("Enviar uma mensagem no {name} para a Alice dizendo que eu chegarei lá em 15 minutos",
           "Ligar para a Alice pelo {name}",
           "Mostrar minhas chamadas perdidas no {name}",
           "Procurar mensagens da Alice no {name}",
           "Marcar como lidas as mensagens da Alice no {name}"),
    "ru": ("Отправить Алисе сообщение в {name}: я буду через 10 минут",
           "Позвонить Алисе в {name}",
           "Показать пропущенные звонки в {name}",
           "Найти сообщения от Алисы в {name}",
           "Отметить сообщения от Алисы в {name} как прочитанные"),
    "tr": ("{name}'dan Ali'ye 10 dakika içinde orada olacağım diye mesaj gönder",
           "{name}'dan Ali'yi ara",
           "{name}'daki cevapsız aramalarımı göster",
           "{name}'da Ali'den gelen mesajları ara",
           "{name}'da Ali'den gelen mesajları okundu olarak işaretle"),
    "uk": ("Надіслати Олені повідомлення в {name}: буду за 10 хвилин",
           "Зателефонувати Олені в {name}",
           "Показати пропущені дзвінки в {name}",
           "Знайти повідомлення від Олени в {name}",
           "Позначити повідомлення від Олени в {name} як прочитані"),
    "uz": ("{name} orqali Aliga xabar yubor: 10 daqiqada yetib boraman",
           "{name} orqali Aliga qo‘ng‘iroq qil",
           "{name}dagi javobsiz qo‘ng‘iroqlarimni ko‘rsat",
           "{name}da Alidan kelgan xabarlarni qidir",
           "{name}da Alidan kelgan xabarlarni o‘qilgan deb belgila"),
}
# Upstream's fallback for a language without its own vocabulary (13.2).
SIRI_PHRASES["Base"] = SIRI_PHRASES["en"]

# Everything the patch reads, edits or checks: the check job fetches only
# these (ci/fetch-upstream.sh sparse).
UPSTREAM_PATHS = ((VERSIONS, BAZELRC, APP_BUILD, "build-system/Make") + NETWORK_DIRS
                  + (APP_ICON, INTRO_RESOURCES)
                  + tuple(sorted(r for r in BRAND_REPLACED if not r.startswith((APP_ICON + "/", INTRO_RESOURCES + "/"))))
                  + (APP_DELEGATE, INTRO_ANIMATIONS, INTRO_CONTROLLER, INTRO_HEADER, INTRO_TEXTURES, INTRO_SPLASH, STRINGS)
                  + tuple(INFOPLIST_STRINGS.format(lang) for lang in INFOPLIST_NAMES)
                  + tuple(sorted({rel for rel, _, _ in CODE_NAMES}))
                  + tuple(sorted({rel for rel, _, _ in SCHEME_LINKS})) + (URL_HANDLING,)
                  + tuple(sorted({rel for rel, _, _, _, _ in CLIENT_LINKS}))
                  + tuple(sorted({rel for rel, _, _, _ in LINK_HOSTS} | {rel for rel, _, _ in SHARE_LINKS + SHARE_KEEP}))
                  + (DAY_THEME, DARK_THEME, PRESENTATION_DATA, THEME_SETTINGS, LEGACY_COLORS, AVATAR_NODE)
                  + (PEER_NAME_COLORS, NOTIFICATION_AVATARS, WIDGET_AVATARS, LIVE_STREAM_AVATARS)
                  + (SETTINGS_ITEMS, SETTINGS_SEARCH, WALLET_CONFIGURATION, NEWS_CONFIGURATION, AGENT_CONFIGURATION)
                  + (CHAT_LIST, CHAT_LIST_NOTICE, CHAT_LIST_PANELS, PROFILE_ITEMS, CONTEXT_MENUS)
                  + (CHAT_STATE, CHAT_CONTROLLER, TAG_CONTEXT_MENU, MESSAGE_CONTEXT_MENU, TAG_PANEL, TITLE_PANELS)
                  + (MESSAGE_REACTIONS, UPDATE_INFO)
                  + (MEDIA_FILE, SEARCH_STICKERS, ENTITY_KEYBOARD_INPUT, ENTITY_KEYBOARD_SIGNALS, STICKER_PACK_SCREEN)
                  + (VIDEO_PRESETS_LEGACY, VIDEO_PRESETS, ROUND_VIDEO_RECORDER, ROUND_VIDEO_RECORDER_NEO, GIF_CONVERTER, VIDEO_FETCH)
                  + (FONT, CAMERA_ASSETS) + tuple(CAMERA_FONTS) + tuple(SIRI_VOCABULARY.format(lang) for lang in SIRI_PHRASES))


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


def is_unit_test(rel):
    """Whether a source file belongs to the unit tests, none of which are in
    the app: the directories Tests, RichTextEditorCoreTests, SiriIntentsTests."""
    return any(part.endswith("Tests") for part in rel.split("/")[:-1])


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
                rel = p.relative_to(self.root).as_posix()
                if p.is_file() and p.suffix in (".swift", ".m", ".h", ".mm", ".c", ".cpp") and not is_unit_test(rel):
                    yield rel


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
            # No App Store or in-app purchases.
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

# Upstream's list of a call's connections, with no reflector of Telegram's
# added (12.9.2 added one for the 12.0.0 protocol; the release dropped it).
CALL_CONNECTIONS = ("                let unfilteredConnections: [CallSessionConnection]\n"
                    "                unfilteredConnections = [connections.primary] + connections.alternatives\n"
                    "\n"
                    "                var reflectorIdList: [Int64] = []\n")

# How a proxy's host name resolves: the system resolver, with the host name
# itself after 10 s; the release dropped the query to Google's DNS-over-HTTPS.
DNS_NATIVE = ("    return [[[self resolveHostnameNative:hostname port:port] timeout:10.0 onQueue:[MTQueue concurrentDefaultQueue] "
              "orSignal:[MTSignal single:hostname]] take:1];\n")

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
    tree.expect(APP_BUILD, '        ":disableProvisioningProfilesSetting": None,\n', count=9)
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
    # Proxy host names resolve through the system, not Google's DNS-over-HTTPS:
    # upstream's code already, and it must stay so.
    tree.expect(DNS, DNS_NATIVE)

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

    tree.expect(NETWORK_ENGINE, NETWORK_ENGINE_DEFAULT)

    # New sections that open on the server's app config alone, which does not
    # turn them on: they must stay behind it.
    for rel, s in OFF_BY_SERVER:
        tree.expect(rel, s)

    # Calls: the reflectors are the server's, none of Telegram's is added.
    tree.expect(CALLS, CALL_CONNECTIONS)

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
    patch_intro_mark(tree)
    patch_names(tree, c)
    patch_scheme(tree, c)
    patch_client_links(tree)
    patch_links(tree)
    patch_palette(tree)
    patch_identity(tree)
    patch_support(tree)
    patch_birthdays(tree)
    patch_read_date(tree)
    patch_saved_tags(tree)
    patch_premium_stickers(tree)
    premium_for_everyone(tree)
    patch_app_update(tree)
    patch_video_quality(tree)
    patch_store(tree, c)

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

# The intro's pages, made in viewDidLoad of RMIntroViewController. The first
# one's title is Tour.Title1, the name ("Pluma" after the renaming); the
# Android app shows the wordmark there instead (IntroActivity: an ImageSpan of
# R.drawable.telegram_logo over Page1Title, tinted with the colour of action
# bar titles at 90%), and so does this one, in the colour of the intro's text
# at 90%. The label stays and only its text changes, so animateIn, which moves
# it, and the text snapshot work as before. The other pages keep their titles.
INTRO_PAGES = ("        [_pageScrollView addSubview:p];\n"
               "    }\n")
INTRO_PAGE_ZERO = "    [_pageScrollView setPage:0];\n"
# The intro's animations, the pictures of its pages, are an OpenGL ES view
# that loadGL makes; upstream returns from it at once in an arm64 simulator
# build, with no reason given, and the pages show nothing there. Pluma's
# simulator builds are arm64 only and are where the intro is checked, so they
# make the view as devices do. Device builds compile the same code either way.
INTRO_GL_OLD = ("- (void)loadGL\n{\n#if TARGET_OS_SIMULATOR && defined(__aarch64__)\n"
                "    return;\n#endif\n")
INTRO_GL = "- (void)loadGL\n{\n    // pluma: the GL view in the arm64 simulator too, as on devices.\n"
INTRO_WORDMARK = src(" " * 4, """
    // pluma: the title of the first page is the wordmark, as in the Android
    // app: in the colour of the text at 90%, its baseline on the title's (5 pt
    // above the bottom of the image, brand/render.sh). VoiceOver reads the name.
    UIImage *wordmarkMask = [UIImage imageNamed:@"pluma_wordmark.png"];
    if (wordmarkMask != nil) {
        UIColor *wordmarkColor = [_primaryColor colorWithAlphaComponent:0.9];
        UIGraphicsImageRendererFormat *wordmarkFormat = [UIGraphicsImageRendererFormat preferredFormat];
        wordmarkFormat.scale = wordmarkMask.scale;
        UIImage *wordmark = [[[UIGraphicsImageRenderer alloc] initWithSize:wordmarkMask.size format:wordmarkFormat] imageWithActions:^(__unused UIGraphicsImageRendererContext *context) {
            CGRect rect = CGRectMake(0.0, 0.0, wordmarkMask.size.width, wordmarkMask.size.height);
            [wordmarkMask drawInRect:rect];
            [wordmarkColor setFill];
            UIRectFillUsingBlendMode(rect, kCGBlendModeSourceIn);
        }];
        NSTextAttachment *attachment = [[NSTextAttachment alloc] init];
        attachment.image = [wordmark imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
        attachment.bounds = CGRectMake(0.0, -5.0, wordmark.size.width, wordmark.size.height);
        RMIntroPageView *firstPage = _pageViews.firstObject;
        NSMutableParagraphStyle *titleStyle = [[NSMutableParagraphStyle alloc] init];
        titleStyle.alignment = NSTextAlignmentCenter;
        NSMutableAttributedString *title = [[NSMutableAttributedString alloc] initWithAttributedString:[NSAttributedString attributedStringWithAttachment:attachment]];
        [title addAttributes:@{NSFontAttributeName: firstPage.headerLabel.font, NSParagraphStyleAttributeName: titleStyle} range:NSMakeRange(0, title.length)];
        firstPage.headerLabel.attributedText = title;
        firstPage.headerLabel.accessibilityLabel = _headlines.firstObject;
    }
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
    the laptop of Settings > Devices and the first page of the intro (blank
    textures where the sphere was, the mark writing itself, the wordmark as its
    title)."""
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

    # The intro: the wordmark as the title of its first page, the page of the
    # name (Tour.Title1); sage instead of Telegram's blues behind the pages
    # "Powerful" (#4F6E52) and "Cloud-Based" (#6F8F72).
    tree.expect(INTRO_CONTROLLER, '_headlines = @[ _englishStrings[@"Tour.Title1"], ')
    tree.replace(INTRO_CONTROLLER, INTRO_PAGES + INTRO_PAGE_ZERO, INTRO_PAGES + INTRO_WORDMARK + INTRO_PAGE_ZERO)
    tree.replace(INTRO_CONTROLLER, INTRO_GL_OLD, INTRO_GL)
    tree.replace(INTRO_ANIMATIONS, "    vec4 powerful_bg_color = {47/255., 90/255., 131/255., 1};\n",
                 "    vec4 powerful_bg_color = {79/255., 110/255., 82/255., 1}; // pluma: #4F6E52\n")
    tree.replace(INTRO_ANIMATIONS, "    vec4 cloud_color = {42/255., 180/255., 247/255., 1};\n",
                 "    vec4 cloud_color = {111/255., 143/255., 114/255., 1}; // pluma: #6F8F72\n")


# --- the intro's first page --------------------------------------------------
#
# The first page of the intro shows the mark writing itself, as Pluma's site
# does (writeMark of its components/mark.ts), above the wordmark: no disc and no
# paper plane. The mark is pluma_mark_write.json (brand/mark_write.py), which
# the screen that hosts the intro, AuthorizationSequenceSplashController,
# plays with the app's own Lottie player (ManagedAnimationNode, rlottie, as the
# sign-in screens play theirs) and hands to RMIntroViewController as a view.
# The kit's ink on light themes; on dark ones the ink of the app icon's dark
# appearance (brand/render.sh) by colour replacement, which rlottie applies to
# each colour of the file once, by its exact RGB (applyReplacements of the
# rlottie submodule). The intro lays the view out over its GL view, brings it in
# with the GL view (animateIn), shows it while it is on screen on its first
# page, fades it with the scroll, and asks the host to write it from its start
# whenever the page appears; with Reduce Motion the host shows the finished
# mark.
#
# The GL view still draws on the first page, but nothing that shows at rest.
# The textures of the sphere and the plane are transparent (BRAND_REPLACED),
# and the intro fills the sphere's texture with its background colour before
# it draws the image on it (setup_texture of texture_helper.m, with the colour
# setupGL passes), so the sphere is an opaque square of that colour. On the
# first page the GL view draws the next page's speedometer (fast_body) and that
# square over it, a little larger (on_draw_frame of animations.c, LAYER0 and
# LAYER4): the blank sphere is the mask that hides the speedometer. As the page
# changes, the square fades over the speedometer, in over 0.24 s and out over
# 0.3 s, and the mark fades in and out over the same times, so the mark and the
# speedometer cross-fade, as Telegram's sphere and the speedometer do. Nothing
# here edits those lines, but the page relies on them, so the patch pins them
# (INTRO_SPHERE_MASK): without them the speedometer would show under the mark.
#
# The pages are one group between the status bar and the start button, placed
# by the first page: the mark 128 pt high, the wordmark's glyphs 32 pt under it,
# the group at 0.44 of the free space (PlumaIntroMarkHeight, PlumaIntroMarkGap,
# PlumaIntroGroupBias). The free space starts where the app's own screens start
# under the status bar: the host passes the larger of its layout's status bar
# height and top safe inset, which Display takes from its DeviceMetrics, not
# from UIKit's safe area (the status bar is 54 pt on the screens of the iPhone
# 14 Pro to 16 Pro Max, more only when UIKit's status bar frame is taller).
# Upstream places the pages at fixed heights from the top for each screen size
# and leaves all the height of newer phones between the dots and the button.
# The start button keeps upstream's place; the pictures of the other pages end
# where the mark ends, so their titles sit under them about as the wordmark sits
# under the mark. The GL view, opaque, then reaches over the titles' frames, so
# loadGL puts it under everything, as on the first load, when it makes the view
# again after the intro was away.

# Upstream's lines that make the blank sphere the mask of the first page: the
# intro fills the sphere's texture with its background colour; the sphere is
# as large as the speedometer; on the first page the speedometer is drawn
# first, then the sphere over it, opaque 0.24 s after the page changes to it
# (and already when the GL view starts on it: animations.c times the fade from
# the last change of page only).
INTRO_SPHERE_MASK = (
    (INTRO_TEXTURES, src(" " * 4, """
        if ([fileName isEqualToString:@"telegram_sphere.png"]) {
            CGContextSetFillColorWithColor(spriteContext, color.CGColor);
            CGContextFillRect(spriteContext, CGRectMake(0, 0, width, height));
        }
    """)),
    (INTRO_CONTROLLER, "    UIColor *color = _backgroundColor;\n"),
    (INTRO_CONTROLLER, '    set_telegram_textures(setup_texture(@"telegram_sphere.png", color), '),
    (INTRO_ANIMATIONS, "    telegram_sphere = create_textured_rectangle(CSizeMake(148, 148), telegram_sphere_texture);\n"),
    (INTRO_ANIMATIONS, "    fast_body = create_textured_rectangle(CSizeMake(148, 148), fast_body_texture);\n"),
    (INTRO_ANIMATIONS, ("    // LAYER0 - PREPARATION ///// ///// ///// ///// ///// ///// ///// /////\n"
                        "    if (current_page == 0)\n    {\n        rglNormalDraw();\n\n"
                        "        telegram_sphere.params.alpha = 1;\n\n        scale = 1;\n\n"
                        "        float alpha = 1;\n        if (direct == 0) {\n"
                        "            alpha = t(0, 1, 0, duration_const, Linear);\n\n            scale = 1;\n\n"
                        "            fast_body.params.alpha = 1;\n"
                        "            fast_body.params.scale = xyzMake(scale, scale, 1);\n"
                        "            draw_textured_shape(&fast_body, main_matrix, NORMAL);\n        }\n")),
    (INTRO_ANIMATIONS, ("    // LAYER4 - DETAILS ///// ///// ///// ///// ///// ///// ///// /////\n"
                        "    if (current_page == 0)\n    {\n        rglNormalDraw();\n\n"
                        "        if (direct == 0) {\n\n"
                        "            telegram_sphere.params.alpha = t(0, 1, 0, duration_const*.8, Linear);\n\n"
                        "            scale = 1.005;\n\n"
                        "            telegram_sphere.params.scale = xyzMake(scale, scale, 1);\n"
                        "            draw_textured_shape(&telegram_sphere, main_matrix, NORMAL);\n")),
)

INTRO_LAYOUT_CONSTANTS = "\n" + src("", """
    // pluma: the layout of the first page, which places all of them: its mark
    // PlumaIntroMarkHeight pt high (the ink, strokes included), the glyphs of
    // the wordmark PlumaIntroMarkGap pt under it, and the group of the mark, the
    // wordmark, the text and the dots at PlumaIntroGroupBias of the free space
    // between the top inset and the start button.
    static const CGFloat PlumaIntroMarkHeight = 128.0;
    static const CGFloat PlumaIntroMarkGap = 32.0;
    static const CGFloat PlumaIntroGroupBias = 0.44;
    // The mark's animation, pluma_mark_write.json (brand/mark_write.py): a canvas
    // of 512 units, the ink of the mark at rest within x 79.6-433.1, y 99.95-405.15.
    static const CGFloat PlumaIntroMarkCanvas = 512.0;
    static const CGFloat PlumaIntroMarkInkLeft = 79.6;
    static const CGFloat PlumaIntroMarkInkTop = 99.95;
    static const CGFloat PlumaIntroMarkInkRight = 433.1;
    static const CGFloat PlumaIntroMarkInkBottom = 405.15;

    // The side of the mark's view in whole points, so that its canvas is drawn
    // pixel for pixel; the ink is then PlumaIntroMarkHeight high to 0.2 pt.
    static CGFloat PlumaIntroMarkSide(void)
    {
        return ceil(PlumaIntroMarkCanvas * PlumaIntroMarkHeight / (PlumaIntroMarkInkBottom - PlumaIntroMarkInkTop));
    }
""")
INTRO_DEVICE_SCREEN = "} DeviceScreen;\n"

INTRO_HEADER_ANCHOR = "@property (nonatomic, copy) UIView *(^createStartButton)(CGFloat);\n"
INTRO_HEADER_MARK = "\n" + src("", """
    // pluma: the mark of the first page, a view of the host's, set before the view
    // loads: the intro lays it out over its GL view, firstPageMarkSize large,
    // brings it in and shows it on the first page; firstPageMarkAppeared asks the
    // host to write the mark from its start when the page appears. topInset is
    // where the host's screens start under the status bar: the larger of its
    // layout's status bar height and top safe inset.
    @property (nonatomic, strong) UIView *firstPageMarkView;
    @property (nonatomic, copy) void (^firstPageMarkAppeared)(void);
    @property (nonatomic) CGFloat topInset;
    @property (class, nonatomic, readonly) CGSize firstPageMarkSize;
""")

INTRO_IVARS_ANCHOR = "    bool _loadedView;\n"
INTRO_IVARS = src(" " * 4, """
    bool _loadedView;

    // pluma: the container of firstPageMarkView, whether the intro is on screen,
    // whether the mark is shown, and whether it is to write itself as soon as
    // the scroll lets it show.
    UIView *_firstPageMarkContainer;
    bool _firstPageMarkOnScreen;
    bool _firstPageMarkShown;
    bool _firstPageMarkWritePending;
""")

# animateIn: the mark comes in as the GL view does, and writes itself from its
# start as it fades in: (upstream's line, what follows it).
INTRO_ANIMATE_IN = (
    ("    _glkView.transform = CGAffineTransformMakeScale(0.66, 0.66);\n", "    \n" + src(" " * 4, """
        // pluma: the first page's mark comes in as the GL view does.
        CGPoint markTargetPosition = _firstPageMarkContainer.center;
        _firstPageMarkContainer.center = CGPointMake(self.view.bounds.size.width / 2.0, self.view.bounds.size.height / 2.0);
        _firstPageMarkContainer.transform = CGAffineTransformMakeScale(0.66, 0.66);
    """)),
    ("        _glkView.transform = CGAffineTransformIdentity;\n", src(" " * 8, """
        _firstPageMarkContainer.center = markTargetPosition;
        _firstPageMarkContainer.transform = CGAffineTransformIdentity;
    """)),
    ("    _glkView.alpha = 0.0;\n", "    _firstPageMarkContainer.alpha = 0.0;\n"),
    ("        _glkView.alpha = 1.0;\n", "        _firstPageMarkContainer.alpha = _firstPageMarkShown ? 1.0 : 0.0;\n"),
    ("        _startButton.alpha = 1.0;\n    } completion:nil];\n", "    \n" + src(" " * 4, """
        // pluma: and the mark writes itself from its start as it fades in.
        if (_firstPageMarkShown && _firstPageMarkAppeared != nil) {
            void (^firstPageMarkAppeared)(void) = _firstPageMarkAppeared;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                firstPageMarkAppeared();
            });
        }
    """)),
)

INTRO_GL_ADD_OLD = "        [self.view addSubview:_glkView];\n"
INTRO_GL_ADD = src(" " * 8, """
    // pluma: under everything, as on the first load, also when the intro makes
    // the view again after it was away: opaque, it reaches over the titles'
    // frames and lies under the first page's mark.
    [self.view insertSubview:_glkView atIndex:0];
""")

INTRO_LOAD_ANCHOR = "    [_wrapperView addSubview:_pageControl];\n}\n"
INTRO_LOAD_MARK = "    \n" + src(" " * 4, """
    // pluma: the first page's mark, the host's view, in a container between the
    // GL view and the pages: the intro lays the container out, brings it in and
    // shows it on the first page, the scroll fades the view. VoiceOver reads the
    // name from the wordmark.
    if (_firstPageMarkView != nil) {
        _firstPageMarkContainer = [[UIView alloc] init];
        _firstPageMarkContainer.userInteractionEnabled = false;
        _firstPageMarkContainer.accessibilityElementsHidden = true;
        _firstPageMarkContainer.alpha = 0.0;
        [_firstPageMarkContainer addSubview:_firstPageMarkView];
        [self.view insertSubview:_firstPageMarkContainer belowSubview:_wrapperView];
    }
""")

INTRO_SNAPSHOT_ANCHOR = "- (UIView *)createAnimationSnapshot {\n"
INTRO_SNAPSHOT = src(" " * 4, """
    // pluma: on the first page the picture is the mark; the GL view shows only
    // the background colour there.
    if (_firstPageMarkContainer != nil && _currentPage == 0) {
        UIView *snapshotView = [_firstPageMarkContainer snapshotViewAfterScreenUpdates:false];
        snapshotView.frame = _firstPageMarkContainer.frame;
        return snapshotView;
    }
""")

# updateLayout: upstream's heights for each screen size, then the frames of
# the page control and the GL view.
INTRO_LAYOUT_OLD = src(" " * 4, """
    UIInterfaceOrientation isVertical = (self.view.bounds.size.height / self.view.bounds.size.width > 1.0f);

    CGFloat statusBarHeight = 0;

    CGFloat pageControlY = 0;
    CGFloat glViewY = 0;
    CGFloat startButtonY = 0;
    CGFloat pageY = 0;

    CGFloat languageButtonSpread = 60.0f;
    CGFloat languageButtonOffset = 26.0f;

    DeviceScreen deviceScreen = [self deviceScreen];
    switch (deviceScreen)
    {
        case iPad:
            glViewY = isVertical ? 121 + 90 : 121;
            startButtonY = 120;
            pageY = isVertical ? 485 : 335;
            pageControlY = pageY + 200.0f;
            break;

        case iPadPro:
            glViewY = isVertical ? 221 + 110 : 221;
            startButtonY = 120;
            pageY = isVertical ? 605 : 435;
            pageControlY = pageY + 200.0f;
            break;

        case Inch35:
            pageControlY = 162 / 2;
            glViewY = 62 - 20;
            startButtonY = 75;
            pageY = 215;
            pageControlY = pageY + 160.0f;
            if (!_alternativeLanguageButton.isHidden) {
                glViewY -= 40.0f;
                pageY -= 40.0f;
                pageControlY -= 40.0f;
                startButtonY -= 30.0f;
            }
            languageButtonSpread = 65.0f;
            languageButtonOffset = 15.0f;
            break;

        case Inch4:
            glViewY = 62;
            startButtonY = 75;
            pageY = 245;
            pageControlY = pageY + 160.0f;
            languageButtonSpread = 50.0f;
            languageButtonOffset = 20.0f;
            break;

        case Inch47:
            pageControlY = 162 / 2 + 10;
            glViewY = 62 + 25;
            startButtonY = 75 + 5;
            pageY = 245 + 50;
            pageControlY = pageY + 160.0f;
            break;

        case Inch55:
            glViewY = 62 + 45;
            startButtonY = 75 + 20;
            pageY = 245 + 85;
            pageControlY = pageY + 160.0f;
            break;

        case Inch65:
            glViewY = 62 + 85;
            startButtonY = 75 + 30;
            pageY = 245 + 125;
            pageControlY = pageY + 160.0f;
            break;

        default:
            break;
    }

    if (!_alternativeLanguageButton.isHidden) {
        startButtonY += languageButtonSpread;
    }

    _pageControl.frame = CGRectMake(0, pageControlY, self.view.bounds.size.width, 7);
    _glkView.frame = CGRectChangedOriginY(_glkView.frame, glViewY - statusBarHeight);
""")
INTRO_LAYOUT = src(" " * 4, """
    // pluma: the pages as one group between the top inset and the start button,
    // placed by the first page (PlumaIntroMarkHeight, PlumaIntroMarkGap,
    // PlumaIntroGroupBias); the start button keeps upstream's place.
    bool isIpad = ([UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad);

    CGFloat statusBarHeight = 0;

    CGFloat startButtonY = 0;

    CGFloat languageButtonSpread = 60.0f;
    CGFloat languageButtonOffset = 26.0f;

    DeviceScreen deviceScreen = [self deviceScreen];
    switch (deviceScreen)
    {
        case iPad:
        case iPadPro:
            startButtonY = 120;
            break;

        case Inch35:
            startButtonY = 75;
            if (!_alternativeLanguageButton.isHidden) {
                startButtonY -= 30.0f;
            }
            languageButtonSpread = 65.0f;
            languageButtonOffset = 15.0f;
            break;

        case Inch4:
            startButtonY = 75;
            languageButtonSpread = 50.0f;
            languageButtonOffset = 20.0f;
            break;

        case Inch47:
            startButtonY = 75 + 5;
            break;

        case Inch55:
            startButtonY = 75 + 20;
            break;

        case Inch65:
            startButtonY = 75 + 30;
            break;

        default:
            break;
    }

    if (!_alternativeLanguageButton.isHidden) {
        startButtonY += languageButtonSpread;
    }

    // From the top of a page's frame, 20 pt into the scroll view, the wordmark's
    // glyphs start 26.8 pt down (RMIntroPageView's 72-pt title, its baseline at
    // 48.5), and the dots end 7.5 pt below the top of the page control, which
    // is dotsOffset down. The GL view's pictures of the other pages, 148 pt
    // across its 200 (or 240 on iPad), end where the mark ends.
    CGFloat glSize = isIpad ? 240.0f : 200.0f;
    CGFloat dotsOffset = isIpad ? 200.0f : 160.0f;
    CGFloat glyphTop = 20.0f + 26.8f;
    CGFloat groupHeight = PlumaIntroMarkHeight + PlumaIntroMarkGap + (dotsOffset + 7.5f - glyphTop);
    CGFloat buttonTop = self.view.bounds.size.height - startButtonY;
    CGFloat markTop = round(_topInset + PlumaIntroGroupBias * MAX(0.0f, buttonTop - _topInset - groupHeight));

    CGFloat pageY = round(markTop + PlumaIntroMarkHeight + PlumaIntroMarkGap - glyphTop);
    CGFloat pageControlY = pageY + dotsOffset;
    CGFloat glViewY = round(markTop + PlumaIntroMarkHeight - glSize / 2.0f - 74.0f * glSize / 200.0f);

    _pageControl.frame = CGRectMake(0, pageControlY, self.view.bounds.size.width, 7);
    _glkView.frame = CGRectChangedOriginY(_glkView.frame, glViewY - statusBarHeight);

    // The mark's canvas, its ink centred across and at the top of the group;
    // bounds and center, which animateIn's transform leaves alone.
    if (_firstPageMarkContainer != nil) {
        CGFloat markSide = PlumaIntroMarkSide();
        CGFloat markScale = markSide / PlumaIntroMarkCanvas;
        CGFloat markX = round(self.view.bounds.size.width / 2.0f - (PlumaIntroMarkInkLeft + PlumaIntroMarkInkRight) / 2.0f * markScale);
        CGFloat markY = round(markTop - PlumaIntroMarkInkTop * markScale);
        _firstPageMarkContainer.bounds = CGRectMake(0.0f, 0.0f, markSide, markSide);
        _firstPageMarkContainer.center = CGPointMake(markX + markSide / 2.0f, markY + markSide / 2.0f);
        _firstPageMarkView.frame = _firstPageMarkContainer.bounds;
    }
""").replace("            break;\n    \n", "            break;\n            \n")  # the switch's blank lines, as upstream's

INTRO_APPEAR_OLD = ("- (void)viewWillAppear:(BOOL)animated\n{\n    [super viewWillAppear:animated];\n    \n    [self loadGL];\n}\n\n"
                    "- (void)viewDidDisappear:(BOOL)animated\n{\n    [super viewDidDisappear:animated];\n    \n    [self freeGL];\n}\n")
INTRO_APPEAR = (INTRO_APPEAR_OLD
                .replace("    [self loadGL];\n", "    [self loadGL];\n    \n" + src(" " * 4, """
                    // pluma: on screen again, the first page's mark shows if the page is
                    // current, and writes itself.
                    _firstPageMarkOnScreen = true;
                    [self updateFirstPageMarkAnimated:true];
                """))
                .replace("    [self freeGL];\n", "    [self freeGL];\n    \n" + src(" " * 4, """
                    // pluma: away, it hides at once, to write itself again when it is back.
                    _firstPageMarkOnScreen = false;
                    [self updateFirstPageMarkAnimated:false];
                """)))

INTRO_SCROLL_ANCHOR = "    [_pageControl setCurrentPage:_currentPage];\n}\n"
INTRO_SCROLL = src(" " * 4, """
    [_pageControl setCurrentPage:_currentPage];

    // pluma: the first page's mark follows the scroll and the page.
    [self updateFirstPageMarkAnimated:true];
""") + "}\n"

INTRO_METHODS_ANCHOR = "\n@end\n\n@implementation TGAvailableLocalization\n"
INTRO_METHODS = "\n" + src("", """
    // pluma: the first page's mark shows while the intro is on screen on that
    // page. As the page changes it fades in over 0.24 s and out over 0.3 s, the
    // times of the GL view's sphere (animations.c), now a square of the
    // background colour over the next page's speedometer: the mark and the
    // speedometer cross-fade. On its page it fades with the scroll, gone half way
    // to the next one. Shown again after it was out of sight, it writes itself
    // from its start (firstPageMarkAppeared), once the scroll lets it show: the
    // page changes when the finger lifts (scrollViewDidScroll:), often while the
    // scroll still holds the mark faded out.
    - (void)updateFirstPageMarkAnimated:(bool)animated
    {
        if (_firstPageMarkContainer == nil) {
            return;
        }

        CGFloat pageWidth = _pageScrollView.frame.size.width;
        if (pageWidth > 0.0f) {
            _firstPageMarkView.alpha = MAX(0.0f, MIN(1.0f, 1.0f - _pageScrollView.contentOffset.x / (pageWidth / 2.0f)));
        }

        bool shown = _firstPageMarkOnScreen && _currentPage == 0;
        if (shown != _firstPageMarkShown) {
            _firstPageMarkShown = shown;

            CALayer *layer = _firstPageMarkContainer.layer.presentationLayer;
            float opacity = layer != nil ? layer.opacity : _firstPageMarkContainer.layer.opacity;
            _firstPageMarkWritePending = shown && opacity * _firstPageMarkView.alpha < 0.01f;

            CGFloat alpha = shown ? 1.0f : 0.0f;
            if (animated) {
                [UIView animateWithDuration:shown ? 0.24 : 0.3 delay:0.0 options:UIViewAnimationOptionBeginFromCurrentState | UIViewAnimationOptionCurveLinear animations:^{
                    _firstPageMarkContainer.alpha = alpha;
                } completion:nil];
            } else {
                // At once, with no fade left running into its next appearance.
                [_firstPageMarkContainer.layer removeAllAnimations];
                _firstPageMarkContainer.alpha = alpha;
            }
        }

        if (_firstPageMarkWritePending && _firstPageMarkView.alpha > 0.0f) {
            _firstPageMarkWritePending = false;
            if (_firstPageMarkAppeared != nil) {
                _firstPageMarkAppeared();
            }
        }
    }

    - (void)setTopInset:(CGFloat)topInset
    {
        if (_topInset != topInset) {
            _topInset = topInset;
            [self.viewIfLoaded setNeedsLayout];
        }
    }

    + (CGSize)firstPageMarkSize
    {
        CGFloat side = PlumaIntroMarkSide();
        return CGSizeMake(side, side);
    }
""")

# The host: the mark's node, given to the intro, and the top inset.
INTRO_SPLASH_EDITS = (
    ("import RMIntro\n", "import ManagedAnimationNode\n"),
    ("    private let controller: RMIntroViewController\n", src(" " * 4, """
        // pluma: the mark of the intro's first page.
        private let markNode: IntroMarkNode
    """)),
    ("suggestedLocalizationSignal: localizationSignal)\n", src(" " * 8, """
        self.markNode = IntroMarkNode(size: RMIntroViewController.firstPageMarkSize, dark: theme.overallDarkAppearance)
    """)),
    ("            return self?.startButton.view\n        }\n", "        \n" + src(" " * 8, """
        // pluma: the intro shows the mark on its first page and asks it to write
        // itself whenever the page appears.
        self.controller.firstPageMarkView = self.markNode.view
        self.controller.firstPageMarkAppeared = { [weak self] in
            self?.markNode.write()
        }
    """)),
    ("        self.controller.defaultFrame = controllerFrame\n", src(" " * 8, """
        // pluma: the intro's pages start where the app's screens start under the
        // status bar: the layout's status bar height and top safe inset, both
        // from Display's DeviceMetrics rather than UIKit's safe area.
        self.controller.topInset = max(layout.safeInsets.top, layout.statusBarHeight ?? 0.0)
    """)),
    ("            self.nextPressed?(strings)\n        }\n    }\n}\n", "\n" + src("", """
    // pluma: the mark of the intro's first page writing itself, as on Pluma's
    // site: pluma_mark_write.json (brand/mark_write.py), the ring drawn in 1.05 s
    // with the feathers riding the nib, then one breath of the feathers; at rest
    // from frame 127 of 132. Dark themes take the dark appearance of the app
    // icon (brand/render.sh): the ring, then the feathers from the nib outwards;
    // the middle feather's grey is the same in both.
    private final class IntroMarkNode: ManagedAnimationNode {
        private let writeItem: ManagedAnimationItem
        private let restItem: ManagedAnimationItem

        init(size: CGSize, dark: Bool) {
            let source = ManagedAnimationSource.local("pluma_mark_write")
            let replaceColors: [UInt32: UInt32]? = dark ? [0x111111: 0xe8ece8, 0x4a4a4a: 0xbdbdbd, 0xbdbdbd: 0x6b6f6b] : nil
            self.writeItem = ManagedAnimationItem(source: source, replaceColors: replaceColors)
            self.restItem = ManagedAnimationItem(source: source, replaceColors: replaceColors, frames: .still(.end), duration: 0.01)

            super.init(size: size)

            // Until it first writes itself: the pen alone, at the start of the ring.
            self.trackTo(item: ManagedAnimationItem(source: source, replaceColors: replaceColors, frames: .still(.start), duration: 0.01))
        }

        // From its start, at the file's own 60 frames a second; with Reduce
        // Motion the finished mark at once, as the site shows it.
        func write() {
            self.trackTo(item: UIAccessibility.isReduceMotionEnabled ? self.restItem : self.writeItem, immediately: true)
        }

        // The writing ends on its last frame, the mark at rest, also when a late
        // tick of the display link takes it past the end before that frame.
        override func advanceState() {
            if self.trackStack.isEmpty, let state = self.state, state.item.frames == nil {
                self.trackStack.append(self.restItem)
            }
            super.advanceState()
        }
    }
""")),
)


def patch_intro_mark(tree):
    """The first page of the intro: the mark writing itself where the disc was,
    and the pages laid out around it."""
    # The blank sphere hides the next page's speedometer: upstream's lines it
    # relies on, which nothing here edits.
    for rel, s in INTRO_SPHERE_MASK:
        tree.expect(rel, s)
    tree.replace(INTRO_HEADER, INTRO_HEADER_ANCHOR, INTRO_HEADER_ANCHOR + INTRO_HEADER_MARK)
    tree.replace(INTRO_CONTROLLER, INTRO_DEVICE_SCREEN, INTRO_DEVICE_SCREEN + INTRO_LAYOUT_CONSTANTS)
    tree.replace(INTRO_CONTROLLER, INTRO_IVARS_ANCHOR, INTRO_IVARS)
    for line, added in INTRO_ANIMATE_IN:
        tree.replace(INTRO_CONTROLLER, line, line + added)
    tree.replace(INTRO_CONTROLLER, INTRO_GL_ADD_OLD, INTRO_GL_ADD)
    tree.replace(INTRO_CONTROLLER, INTRO_LOAD_ANCHOR, INTRO_LOAD_ANCHOR[:-len("}\n")] + INTRO_LOAD_MARK + "}\n")
    tree.replace(INTRO_CONTROLLER, INTRO_SNAPSHOT_ANCHOR, INTRO_SNAPSHOT_ANCHOR + INTRO_SNAPSHOT)
    tree.replace_lines(INTRO_CONTROLLER, INTRO_LAYOUT_OLD, INTRO_LAYOUT)
    tree.replace(INTRO_CONTROLLER, INTRO_APPEAR_OLD, INTRO_APPEAR)
    tree.replace(INTRO_CONTROLLER, INTRO_SCROLL_ANCHOR, INTRO_SCROLL)
    tree.replace(INTRO_CONTROLLER, INTRO_METHODS_ANCHOR, INTRO_METHODS + INTRO_METHODS_ANCHOR)
    for anchor, added in INTRO_SPLASH_EDITS:
        tree.replace(INTRO_SPLASH, anchor, anchor + added)


def verify_intro_mark(tree):
    header, controller, splash = (tree.read(rel) for rel in (INTRO_HEADER, INTRO_CONTROLLER, INTRO_SPLASH))
    if header.count("@property (nonatomic, strong) UIView *firstPageMarkView;\n") != 1:
        raise PatchError(f"{INTRO_HEADER}: the intro takes no mark for its first page")
    if (controller.count(INTRO_LAYOUT_CONSTANTS) != 1 or controller.count(INTRO_LAYOUT) != 1 or "isVertical" in controller
            or controller.count("[self updateFirstPageMarkAnimated:") != 3):
        raise PatchError(f"{INTRO_CONTROLLER}: the intro's pages are not laid out around the first page's mark")
    if "[self.view addSubview:_glkView];" in controller or controller.count("[self.view insertSubview:_glkView atIndex:0];\n") != 1:
        raise PatchError(f"{INTRO_CONTROLLER}: the GL view can come back over the pages and the mark")
    name = pathlib.PurePath(INTRO_MARK).stem
    if (splash.count("self.controller.firstPageMarkView = self.markNode.view\n") != 1
            or splash.count(f'ManagedAnimationSource.local("{name}")') != 1):
        raise PatchError(f"{INTRO_SPLASH}: the intro's first page has no mark")


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
        // pluma: no Premium gifts; the chat with the contact (openBirthdayChats).
        self.openBirthdayChats(peers)
""")
# The list of several contacts is a method of its own: the notice's action is
# a closure inside one long expression (the panels of updateNavigationBar),
# which the Swift compiler could not type-check in time with it inside.
BIRTHDAY_METHOD_ANCHOR = ("    private func updateNavigationBar(layout: ContainerViewLayout, deferScrollApplication: Bool, "
                          "transition: ComponentTransition) -> (navigationHeight: CGFloat, storiesInset: CGFloat) {\n")
BIRTHDAY_METHOD = src(" " * 4, """
    // pluma: the chat with a contact whose birthday is today; with several,
    // a list of them to choose the chat from, as the live location panel
    // lists its chats. The list goes by name, the same on every launch: the
    // notice's peers come in the order of a dictionary.
    private func openBirthdayChats(_ peers: [EnginePeer]) {
        if peers.count == 1, let peer = peers.first {
            self.effectiveContainerNode.peerSelected?(peer, nil, true, true, nil)
            return
        }
        guard !peers.isEmpty, let controller = self.controller else {
            return
        }
        let strings = self.presentationData.strings
        let nameDisplayOrder = self.presentationData.nameDisplayOrder
        var named: [(peer: EnginePeer, title: String)] = []
        for peer in peers {
            named.append((peer: peer, title: peer.displayTitle(strings: strings, displayOrder: nameDisplayOrder)))
        }
        named.sort(by: { (lhs: (peer: EnginePeer, title: String), rhs: (peer: EnginePeer, title: String)) -> Bool in
            if lhs.title == rhs.title {
                return lhs.peer.id < rhs.peer.id
            }
            return lhs.title.localizedCaseInsensitiveCompare(rhs.title) == .orderedAscending
        })
        let actionSheet = ActionSheetController(presentationData: self.presentationData)
        let dismissAction: () -> Void = { [weak actionSheet] in
            actionSheet?.dismissAnimated()
        }
        var items: [ActionSheetItem] = []
        items.append(ActionSheetTextItem(title: strings.ChatList_BirthdayMultipleTitle(Int32(peers.count))))
        for (peer, title) in named {
            items.append(ActionSheetButtonItem(title: title, action: { [weak self] in
                dismissAction()
                self?.effectiveContainerNode.peerSelected?(peer, nil, true, true, nil)
            }))
        }
        actionSheet.setItemGroups([
            ActionSheetItemGroup(items: items),
            ActionSheetItemGroup(items: [ActionSheetButtonItem(title: strings.Common_Cancel, action: { dismissAction() })])
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
    tree.replace(CHAT_LIST, BIRTHDAY_METHOD_ANCHOR, BIRTHDAY_METHOD + BIRTHDAY_METHOD_ANCHOR)
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
    chat_list = tree.read(CHAT_LIST)
    if ("openPremiumGift(" in opened or "self.openBirthdayChats(peers)\n" not in opened
            or chat_list.count(BIRTHDAY_METHOD) != 1 or BIRTHDAY_METHOD.count(".peerSelected?(peer, nil, true, true, nil)") != 2):
        raise PatchError(f"{CHAT_LIST}: the birthday notice does not open the chat")
    if ("ChatList_BirthdaySingleText" in text or "ChatList_BirthdayMultipleText" in text
            or text.count("text = item.strings.ContactList_Context_SendMessage\n") != 2):
        raise PatchError(f"{CHAT_LIST_NOTICE}: the birthday notice still offers a gift")
    if "ChatList_PremiumGiftInSettingsInfo" in closed or "suggestion: ServerProvidedSuggestion.todayBirthdays.id" not in closed:
        raise PatchError(f"{CHAT_LIST_PANELS}: closing the birthday notice does not dismiss it, or offers a gift")
    profile = tree.read(PROFILE_ITEMS)
    if any(old in profile for old, _ in BIRTHDAY_PROFILE[1:]) or not all(new in profile for _, new in BIRTHDAY_PROFILE):
        raise PatchError(f"{PROFILE_ITEMS}: the birthday row offers a gift without Premium for sale")


# --- read date ---------------------------------------------------------------
#
# The context menu of an outgoing message in a private chat shows when it was
# read (messages.getOutboxReadDate), but upstream shows it to a user without
# Premium only where Premium is sold: with premium_purchase_blocked, which the
# Pluma server sends, the row goes (canViewReadStats). The owner's decision
# (task 033): the read date is shown as the Android app shows it, which has no
# such check. Where the date is hidden (the peer's privacy), upstream shows
# "Read" with a badge that opens Premium's privacy screen to buy it; without
# Premium for sale the row says "Read" only, with no badge and no action.

READ_DATE_GATE_OLD = src(" " * 8, """
    if !isPremium {
        let premiumConfiguration = PremiumConfiguration.with(appConfiguration: appConfig)
        if premiumConfiguration.isPremiumDisabled {
            return false
        }
    }
""")
READ_DATE_GATE = src(" " * 8, """
    // pluma: the read date is shown without Premium, which is not sold (task 033).
""")
READ_DATE_TAP_OLD = src(" " * 12, """
    self.buttonNode.isUserInteractionEnabled = self.item.action != nil && stats.peers.isEmpty
""")
READ_DATE_TAP = src(" " * 12, """
    // pluma: a hidden read date offers no Premium where it is not sold.
    self.buttonNode.isUserInteractionEnabled = self.item.action != nil && stats.peers.isEmpty && !PremiumConfiguration.with(appConfiguration: self.item.context.currentAppConfiguration.with { $0 }).isPremiumDisabled
""")
READ_DATE_BADGE_OLD = src(" " * 20, """
    self.textNode.attributedText = text
    showReadBadge = true
""")
READ_DATE_BADGE = src(" " * 20, """
    self.textNode.attributedText = text
    // pluma: no badge offering Premium where it is not sold.
    showReadBadge = !PremiumConfiguration.with(appConfiguration: self.item.context.currentAppConfiguration.with { $0 }).isPremiumDisabled
""")


def patch_read_date(tree):
    """The read date of an outgoing message shows without Premium, which is
    not sold, and a hidden one offers no Premium."""
    tree.replace_lines(CONTEXT_MENUS, READ_DATE_GATE_OLD, READ_DATE_GATE)
    tree.replace(CONTEXT_MENUS, READ_DATE_TAP_OLD, READ_DATE_TAP)
    tree.replace(CONTEXT_MENUS, READ_DATE_BADGE_OLD, READ_DATE_BADGE)


def verify_read_date(tree):
    text = tree.read(CONTEXT_MENUS)
    start = text.find("private func canViewReadStats(")
    end = text.find("\n}\n", start)
    if start < 0 or end < 0:
        raise PatchError(f"{CONTEXT_MENUS}: no canViewReadStats")
    if "isPremiumDisabled" in text[start:end]:
        raise PatchError(f"{CONTEXT_MENUS}: the read date is still hidden without Premium for sale")
    if READ_DATE_TAP not in text or READ_DATE_BADGE not in text or "showReadBadge = true\n" in text:
        raise PatchError(f"{CONTEXT_MENUS}: a hidden read date still offers Premium")


# --- app update ----------------------------------------------------------------
#
# Task 054 of the server repository (ADR 0035). The app asks help.getAppUpdate
# at start and every 12 hours and shows the update screen for whatever the
# server answers (TelegramCore AppUpdate.swift 37-49, ApplicationContext.swift
# 586-596); its button opens the App Store page (UpdateInfoController.swift
# 117-119), which Pluma does not have. TestFlight updates its own builds, so
# the server offers updates only to builds installed from the site (ad hoc),
# with the site's install page as help.appUpdate.url; the button opens it.
# The server tells them apart by app_version: MtProtoKit sends "<version>
# (<build>) <suffix>" (MTApiEnvironment.m 384-394), the suffix empty on iOS;
# a build whose profile lists devices, which only an ad hoc (or a development)
# profile does, gives "adhoc". The App Store build shares the compiled code
# with the ad hoc one (ci/build.sh), so this is decided when the app runs, not
# when it is built.
APP_UPDATE = "submodules/TelegramCore/Sources/State/AppUpdate.swift"
MT_API_ENVIRONMENT = "submodules/MtProtoKit/Sources/MTApiEnvironment.m"
APP_UPDATE_EDITS = (
    (APP_UPDATE,
     "    public let entities: [MessageTextEntity]\n"
     "    \n"
     "    public init(blocking: Bool, version: String, text: String, entities: [MessageTextEntity]) {\n",
     "    public let entities: [MessageTextEntity]\n"
     "    // pluma: the page that installs the update, for a build from the site.\n"
     "    public let url: String?\n"
     "    \n"
     "    public init(blocking: Bool, version: String, text: String, entities: [MessageTextEntity], url: String? = nil) {\n"),
    (APP_UPDATE,
     "        self.entities = entities\n"
     "    }\n",
     "        self.entities = entities\n"
     "        self.url = url\n"
     "    }\n"),
    (APP_UPDATE,
     "                self.entities = messageTextEntitiesFromApiEntities(entities)\n",
     "                self.entities = messageTextEntitiesFromApiEntities(entities)\n"
     "                self.url = appUpdateData.url\n"),
    (UPDATE_INFO,
     "    let arguments = UpdateInfoControllerArguments(openAppStorePage: {\n"
     "        context.sharedContext.applicationBindings.openAppStorePage()\n"
     "    }, linkAction: { action, itemLink in\n",
     "    let arguments = UpdateInfoControllerArguments(openAppStorePage: {\n"
     "        // pluma: the server's install page for a build from the site; Pluma has no App Store page.\n"
     "        if let url = appUpdateInfo.url {\n"
     "            context.sharedContext.applicationBindings.openUrl(url)\n"
     "        } else {\n"
     "            context.sharedContext.applicationBindings.openAppStorePage()\n"
     "        }\n"
     "    }, linkAction: { action, itemLink in\n"),
    (MT_API_ENVIRONMENT,
     "            suffix = [NSString stringWithFormat:@\"%@\", value];\n"
     "        }\n"
     "#endif\n",
     "            suffix = [NSString stringWithFormat:@\"%@\", value];\n"
     "        }\n"
     "#endif\n"
     "#if TARGET_OS_IPHONE\n"
     "        // pluma: a build installed from the site (an ad hoc profile, which lists\n"
     "        // devices) says so in app_version; the server offers it the site's\n"
     "        // install page for an update. TestFlight updates its own builds.\n"
     "        NSString *profilePath = [[NSBundle mainBundle] pathForResource:@\"embedded\" ofType:@\"mobileprovision\"];\n"
     "        NSData *profile = profilePath != nil ? [NSData dataWithContentsOfFile:profilePath] : nil;\n"
     "        NSData *devicesKey = [@\"<key>ProvisionedDevices</key>\" dataUsingEncoding:NSUTF8StringEncoding];\n"
     "        if (profile != nil && [profile rangeOfData:devicesKey options:0 range:NSMakeRange(0, profile.length)].location != NSNotFound) {\n"
     "            suffix = @\"adhoc\";\n"
     "        }\n"
     "#endif\n"),
)


def patch_app_update(tree):
    """The update screen opens the server's install page, and a build from
    the site says so in app_version."""
    for rel, old, new in APP_UPDATE_EDITS:
        tree.replace(rel, old, new)


def verify_app_update(tree):
    for rel, old, new in APP_UPDATE_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the app update edit {new.strip().splitlines()[-1]!r} is not there")


# --- tags of Saved Messages ----------------------------------------------------
#
# Task 053 of the server repository. In Saved Messages the reactions of a
# message are its tags (messageReactions.reactions_as_tags; areReactionsTags in
# MessageUtils.swift): the user tags messages, filters the chat by a tag
# (messages.search with saved_reaction) and names the tags
# (messages.getSavedReactionTags, messages.updateSavedReactionTag). Upstream
# lets only Premium users do it, and Pluma does not sell Premium. The owner's
# decision: tags for every user, with as many tags on a message as Premium
# allows in Telegram.
#
# No key of appConfiguration says whether tags are available: every gate
# checks isPremium of the chat's state. canUseSavedTags, true, takes its place
# at the gates of tags only; isPremium stays everywhere else, and so does every
# other Premium feature. The gates:
#   a. a tap on a tag of a message (ChatController.swift, updateMessageReaction);
#   b. the context menu of a tag: rename, filter, remove
#      (ChatControllerOpenMessageReactionContextMenu.swift);
#   c. the bar of tags in a message's context menu, locked with its title
#      Chat_MessageContextMenu_NonPremiumTagsTitle
#      (ChatControllerOpenMessageContextMenu.swift);
#   d. a tag outside the bar's top list, from the expanded list; a custom
#      emoji tag still needs Premium, as a custom emoji reaction does in other
#      chats (the same function);
#   e-h. the panel of tags over the chat: the promo "unlock / add tags" in its
#      place, a tap that filters, a long press that renames, the locks
#      (ChatSearchTitleAccessoryPanelNode.swift);
#   i-j. when the panel shows: as for Premium, only once the chat has tags,
#      and in the embedded chat too (ChatInterfaceTitlePanelNodes.swift).
#
# How many reactions a message takes (updateMessageReactionsInteractively,
# MessageReactions.swift): Premium takes reactions_user_max_premium of
# appConfiguration, everybody else 1, whatever reactions_user_max_default says.
# Now everybody takes the server's limit (UserLimitsConfiguration), and in
# Saved Messages the Premium one: the Pluma server sends 3 for both. The
# toast that more reactions need Premium (ChatController.swift,
# Chat_Reactions_MultiplePremiumTooltip) shows only while Premium is sold.
#
# The texts of the promos become unreachable; the patch adds none.

SAVED_TAGS_FLAG_ANCHOR = "    public let isPremium: Bool\n"
SAVED_TAGS_FLAG = SAVED_TAGS_FLAG_ANCHOR + src(" " * 4, """
    // pluma: the tags of Saved Messages without Premium, which Pluma does not
    // sell (task 053). The gates of tags check this; all others isPremium.
    public var canUseSavedTags: Bool {
        return true
    }
""")

# (file, upstream, Pluma) for each gate of tags.
SAVED_TAGS_GATES = (
    # a. A tap on a tag of a message.
    (CHAT_CONTROLLER, src(" " * 16, """
        if !strongSelf.presentationInterfaceState.isPremium {
            strongSelf.presentTagPremiumPaywall()
            return
        }
    """), src(" " * 16, """
        // pluma: tags without Premium (task 053).
        if !strongSelf.presentationInterfaceState.canUseSavedTags {
            strongSelf.presentTagPremiumPaywall()
            return
        }
    """)),
    # b. The context menu of a tag.
    (TAG_CONTEXT_MENU, src(" " * 12, """
        if !self.presentationInterfaceState.isPremium {
            self.presentTagPremiumPaywall()
            return
        }
    """), src(" " * 12, """
        // pluma: tags without Premium (task 053).
        if !self.presentationInterfaceState.canUseSavedTags {
            self.presentTagPremiumPaywall()
            return
        }
    """)),
    # c. The bar of tags in a message's context menu.
    (MESSAGE_CONTEXT_MENU, src(" " * 24, """
        if self.presentationInterfaceState.isPremium {
            actions.reactionsTitle = presentationData.strings.Chat_ContextMenuTagsTitle
    """), src(" " * 24, """
        // pluma: tags without Premium (task 053).
        if self.presentationInterfaceState.canUseSavedTags {
            actions.reactionsTitle = presentationData.strings.Chat_ContextMenuTagsTitle
    """)),
    # d. A tag outside the top list.
    (MESSAGE_CONTEXT_MENU, src(" " * 32, """
        if !self.presentationInterfaceState.isPremium {
            controller?.premiumReactionsSelected?()
            return
        }
    """), src(" " * 32, """
        // pluma: tags without Premium (task 053); a custom emoji tag still
        // needs it, as a custom emoji reaction does in other chats.
        var isTagLocked = !self.presentationInterfaceState.canUseSavedTags
        if case .custom = chosenReaction, !self.presentationInterfaceState.isPremium {
            isTagLocked = true
        }
        if isTagLocked {
            controller?.premiumReactionsSelected?()
            return
        }
    """)),
    # e. The promo in place of the panel's tags.
    (TAG_PANEL, src(" " * 8, """
        if !params.interfaceState.isPremium {
            let promoView: PromoView
    """), src(" " * 8, """
        // pluma: tags without Premium (task 053).
        if !params.interfaceState.canUseSavedTags {
            let promoView: PromoView
    """)),
    # f. A tap on a tag of the panel: the filter.
    (TAG_PANEL, src(" " * 20, """
        if !params.interfaceState.isPremium {
            if let chatController = self.interfaceInteraction?.chatController() {
    """), src(" " * 20, """
        // pluma: tags without Premium (task 053).
        if !params.interfaceState.canUseSavedTags {
            if let chatController = self.interfaceInteraction?.chatController() {
    """)),
    # g. A long press on it: the name.
    (TAG_PANEL, src(" " * 20, """
        if !params.interfaceState.isPremium {
            (chatController as? ChatControllerImpl)?.presentTagPremiumPaywall()
    """), src(" " * 20, """
        // pluma: tags without Premium (task 053).
        if !params.interfaceState.canUseSavedTags {
            (chatController as? ChatControllerImpl)?.presentTagPremiumPaywall()
    """)),
    # h. The locks on the panel's tags.
    (TAG_PANEL, "isLocked: !params.interfaceState.isPremium,", "isLocked: !params.interfaceState.canUseSavedTags,"),
    # i. The panel shows without tags only to offer them.
    (TITLE_PANELS, src(" " * 12, """
        if chatPresentationInterfaceState.hasSearchTags || !chatPresentationInterfaceState.isPremium {
    """), src(" " * 12, """
        // pluma: tags without Premium (task 053): the panel once there are tags.
        if chatPresentationInterfaceState.hasSearchTags || !chatPresentationInterfaceState.canUseSavedTags {
    """)),
    # j. The embedded chat hides it without Premium.
    (TITLE_PANELS, src(" " * 8, """
        if case .standard(.embedded) = chatPresentationInterfaceState.mode {
            if !chatPresentationInterfaceState.isPremium {
    """), src(" " * 8, """
        if case .standard(.embedded) = chatPresentationInterfaceState.mode {
            // pluma: tags without Premium (task 053).
            if !chatPresentationInterfaceState.canUseSavedTags {
    """)),
)

REACTIONS_LIMIT_OLD = src(" " * 8, """
    let maxCount: Int
    if isPremium {
        let limitsConfiguration = UserLimitsConfiguration(appConfiguration: appConfiguration, isPremium: isPremium)
        maxCount = Int(limitsConfiguration.maxReactionsPerMessage)
    } else {
        maxCount = 1
    }
""")
REACTIONS_LIMIT = src(" " * 8, """
    // pluma: the server's limit without Premium too, not 1, and in Saved
    // Messages, where reactions are tags, the limit of Premium (task 053).
    let limitsConfiguration = UserLimitsConfiguration(appConfiguration: appConfiguration, isPremium: isPremium || chatPeerId == account.peerId)
    let maxCount = Int(limitsConfiguration.maxReactionsPerMessage)
""")

REACTIONS_TOAST_OLD = ("                        if !strongSelf.presentationInterfaceState.isPremium && mappedUpdatedReactions.count > "
                       "strongSelf.context.userLimits.maxReactionsPerMessage {\n")
REACTIONS_TOAST = ("                        // pluma: no offer of Premium for more reactions where it is not sold (task 053).\n"
                   "                        if !strongSelf.presentationInterfaceState.isPremium && mappedUpdatedReactions.count > "
                   "strongSelf.context.userLimits.maxReactionsPerMessage && !PremiumConfiguration.with(appConfiguration: "
                   "strongSelf.context.currentAppConfiguration.with { $0 }).isPremiumDisabled {\n")


# --- premium stickers ---------------------------------------------------------
# Task 058 of the server repository: a premium sticker (a file with a video
# thumbnail of size "f", SyncCore_TelegramMediaFile.swift 1060) is sent and
# played by every user, as with Premium in Telegram. Pluma sells no Premium
# and the owner reported the gate as a defect. No key of appConfiguration
# opens it: each place checks the account's isPremium, and
# PremiumConfiguration.isPremiumDisabled (the server's
# premium_purchase_blocked) drops premium stickers from every list. The
# function premiumStickersAvailable(), true, stands in at these places only:
#   a. the sticker pane: a tap opens the Premium screen instead of sending
#      (ChatEntityKeyboardInputNode.swift 1278); the long press shows no send
#      items and an unlock accessory (2996);
#   b. the pane's lists drop or lock them (EmojiPagerContentSignals.swift 1282,
#      1825, 1862, 1897, 1945, 2089; the same text at 327 is of the emoji pane,
#      where no file has the "f" thumbnail);
#   c. a sticker set: they are left out while Premium is not sold and locked
#      otherwise (StickerPackScreen.swift 594, 1748-1751, 1867-1870);
#   d. "add to favourites" in the context menu of a sticker message
#      (ChatInterfaceStateContextMenus.swift 1007);
#   e. stickers found for an emoji or a search, in the three functions of
#      stickers (SearchStickers.swift 166, 756, 1154); searchEmoji (1545) keeps
#      isPremium.
# The recipient plays the effect from the file alone (ChatMessageAnimatedSticker
# ItemNode.swift 2591, unless the server sends nopremium, which Pluma's does
# not). Custom emoji are another matter and stay.

PREMIUM_STICKERS_FLAG_ANCHOR = "public final class TelegramMediaFile: Media, Equatable, Codable {\n"
PREMIUM_STICKERS_FLAG = """// pluma: premium stickers are open to every user; Pluma does not sell Premium
// (task 058). Only the gates of premium stickers ask this.
public func premiumStickersAvailable() -> Bool {
    return true
}

""" + PREMIUM_STICKERS_FLAG_ANCHOR
PREMIUM_STICKERS_COMMENT = "// pluma: premium stickers without Premium (task 058).\n"
_SEARCH_PREMIUM = "        let isPremium = transaction.getPeer(account.peerId)?.isPremium ?? false\n"
_SEARCH_FREE = "        " + PREMIUM_STICKERS_COMMENT + (
    "        let isPremium = (transaction.getPeer(account.peerId)?.isPremium ?? false) || premiumStickersAvailable()\n")
_SEARCH_AFTER = ("        \n"
                 "        var result: [FoundStickerItem] = []\n"
                 "        if scope.contains(.installed) {\n"
                 "            for entry in transaction.getOrderedListItems(collectionId: Namespaces.OrderedItemList.CloudSavedStickers) {\n")

# (file, upstream, Pluma, how many times upstream has it)
PREMIUM_STICKERS_GATES = (
    (SEARCH_STICKERS, _SEARCH_PREMIUM + _SEARCH_AFTER, _SEARCH_FREE + _SEARCH_AFTER, 3),
    (ENTITY_KEYBOARD_INPUT,
     "                        if file.isPremiumSticker && !hasPremium {\n",
     "                        " + PREMIUM_STICKERS_COMMENT +
     "                        if file.isPremiumSticker && !hasPremium && !premiumStickersAvailable() {\n", 1),
    (ENTITY_KEYBOARD_INPUT,
     "                        let isLocked = file.isPremiumSticker && !hasPremium\n",
     "                        " + PREMIUM_STICKERS_COMMENT +
     "                        let isLocked = file.isPremiumSticker && !hasPremium && !premiumStickersAvailable()\n", 1),
    (ENTITY_KEYBOARD_SIGNALS,
     "                    let isPremiumLocked: Bool = item.file.isPremiumSticker && !hasPremium\n",
     "                    " + PREMIUM_STICKERS_COMMENT +
     "                    let isPremiumLocked: Bool = item.file.isPremiumSticker && !hasPremium && !premiumStickersAvailable()\n", 3),
    (ENTITY_KEYBOARD_SIGNALS,
     "                    if isPremiumDisabled && item.file.isPremiumSticker {\n",
     "                    " + PREMIUM_STICKERS_COMMENT +
     "                    if isPremiumDisabled && !premiumStickersAvailable() && item.file.isPremiumSticker {\n", 3),
    (ENTITY_KEYBOARD_SIGNALS,
     "                    if isPremiumDisabled && item.media.isPremiumSticker {\n",
     "                    " + PREMIUM_STICKERS_COMMENT +
     "                    if isPremiumDisabled && !premiumStickersAvailable() && item.media.isPremiumSticker {\n", 1),
    (STICKER_PACK_SCREEN,
     "isLocked: item.file.isPremiumSticker && !hasPremium,",
     "isLocked: item.file.isPremiumSticker && !hasPremium && !premiumStickersAvailable(),", 1),
    (STICKER_PACK_SCREEN,
     "                    if !premiumConfiguration.isPremiumDisabled {\n",
     "                    " + PREMIUM_STICKERS_COMMENT +
     "                    if !premiumConfiguration.isPremiumDisabled || premiumStickersAvailable() {\n", 1),
    (STICKER_PACK_SCREEN,
     "                                addItem(item, true, !hasPremium)\n",
     "                                addItem(item, true, !hasPremium && !premiumStickersAvailable())\n", 1),
    (STICKER_PACK_SCREEN,
     "        if !premiumConfiguration.isPremiumDisabled {\n"
     "            if !premiumItems.isEmpty {\n",
     "        " + PREMIUM_STICKERS_COMMENT +
     "        if !premiumConfiguration.isPremiumDisabled || premiumStickersAvailable() {\n"
     "            if !premiumItems.isEmpty {\n", 1),
    (STICKER_PACK_SCREEN,
     "                    addItem(item, true, !hasPremium)\n"
     "                    currentIndex += 1\n",
     "                    addItem(item, true, !hasPremium && !premiumStickersAvailable())\n"
     "                    currentIndex += 1\n", 1),
    (CONTEXT_MENUS,
     "            if !isPremiumSticker || chatPresentationInterfaceState.isPremium {\n",
     "            " + PREMIUM_STICKERS_COMMENT +
     "            if !isPremiumSticker || chatPresentationInterfaceState.isPremium || premiumStickersAvailable() {\n", 1),
)
# How many times each file asks premiumStickersAvailable(); nothing else may.
PREMIUM_STICKERS_USES = {
    SEARCH_STICKERS: 3,
    ENTITY_KEYBOARD_INPUT: 2,
    ENTITY_KEYBOARD_SIGNALS: 7,
    STICKER_PACK_SCREEN: 5,
    CONTEXT_MENUS: 1,
}


def patch_premium_stickers(tree):
    """Premium stickers are sent, shown and suggested without Premium, which
    Pluma does not sell; custom emoji keep their gates."""
    tree.expect(MEDIA_FILE, "premiumStickersAvailable", count=0)
    tree.replace(MEDIA_FILE, PREMIUM_STICKERS_FLAG_ANCHOR, PREMIUM_STICKERS_FLAG)
    for rel, old, new, count in PREMIUM_STICKERS_GATES:
        tree.replace_lines(rel, old, new, count=count)


def verify_premium_stickers(tree):
    if tree.read(MEDIA_FILE).count(PREMIUM_STICKERS_FLAG) != 1:
        raise PatchError(f"{MEDIA_FILE}: no premiumStickersAvailable() that is true")
    for rel, old, new, count in PREMIUM_STICKERS_GATES:
        text = tree.read(rel)
        if text.count(new) != count or old in text.replace(new, ""):
            raise PatchError(f"{rel}: a gate of premium stickers still checks Premium")
    for rel, count in PREMIUM_STICKERS_USES.items():
        found = tree.read(rel).count("premiumStickersAvailable()")
        if found != count:
            raise PatchError(f"{rel}: {found} uses of premiumStickersAvailable(), expected {count}")
    if tree.read(SEARCH_STICKERS).count("?.isPremium ?? false\n") != 1:
        raise PatchError(f"{SEARCH_STICKERS}: the search of custom emoji must keep isPremium")


def patch_saved_tags(tree):
    """Tags of Saved Messages without Premium, which Pluma does not sell, and
    the server's limit of reactions on a message for everybody."""
    tree.expect(CHAT_STATE, "canUseSavedTags", count=0)
    tree.replace(CHAT_STATE, SAVED_TAGS_FLAG_ANCHOR, SAVED_TAGS_FLAG)
    for rel, old, new in SAVED_TAGS_GATES:
        tree.replace_lines(rel, old, new)
    tree.replace(MESSAGE_REACTIONS, REACTIONS_LIMIT_OLD, REACTIONS_LIMIT)
    tree.replace(CHAT_CONTROLLER, REACTIONS_TOAST_OLD, REACTIONS_TOAST)


def verify_saved_tags(tree):
    if tree.read(CHAT_STATE).count(SAVED_TAGS_FLAG) != 1:
        raise PatchError(f"{CHAT_STATE}: no canUseSavedTags that is true")
    uses = {}
    for rel, old, new in SAVED_TAGS_GATES:
        text = tree.read(rel)
        if new not in text or old in text:
            raise PatchError(f"{rel}: a gate of tags still checks Premium")
        uses[rel] = uses.get(rel, 0) + new.count("canUseSavedTags")
    # The flag stays at the gates of tags.
    for rel, count in uses.items():
        if tree.read(rel).count("canUseSavedTags") != count:
            raise PatchError(f"{rel}: canUseSavedTags outside the gates of tags")
    # The panel of tags and when it shows no longer look at Premium at all.
    for rel in (TAG_PANEL, TITLE_PANELS):
        if "isPremium" in tree.read(rel):
            raise PatchError(f"{rel}: a gate of tags still checks Premium")
    reactions = tree.read(MESSAGE_REACTIONS)
    if REACTIONS_LIMIT not in reactions or "maxCount = 1\n" in reactions:
        raise PatchError(f"{MESSAGE_REACTIONS}: a message takes one reaction without Premium")
    if REACTIONS_TOAST not in tree.read(CHAT_CONTROLLER):
        raise PatchError(f"{CHAT_CONTROLLER}: the toast offers Premium for more reactions where it is not sold")


# --- video quality -------------------------------------------------------------
#
# Task 052 of the server repository. The owner's decision: the user chooses
# the quality of a video as in Telegram (240p-1080p in the editor's quality
# tab, TGPhotoQualityController.m), but every quality is sent at a higher
# bitrate than Telegram's.
#
# The app re-encodes a video before sending (H.264, AVFoundation) at a fixed
# bitrate per preset, whatever the source's. The presets are in two tables
# that must agree:
#   - TGMediaVideoConverter.m, _videoBitrateKbpsForPreset (1408-1445),
#     _audioBitrateKbpsForPreset (1447-1479), _audioChannelsCountForPreset
#     (1481-1510): an unedited video, the size estimate of the quality slider
#     and the legacy round video recorder (TGVideoCameraPipeline.m 683-689);
#   - MediaQualityPreset in MediaEditorValues.swift, videoBitrateKbps
#     (180-207), audioBitrateKbps (209-218), audioChannelsCount (220-227): an
#     edited video and a trimmed round video, through MediaEditorVideoExport
#     (recommendedVideoExportConfiguration, 1929-2050).
# The sizes of the presets stay upstream's.
#
#   preset        Telegram: video kbit/s, audio   Pluma
#   240p          400, 32 mono                    800, 64 stereo
#   360p          700, 32 mono                    1500, 64 stereo
#   480p          1600, 64 stereo                 2500, 128 stereo
#   720p          3000, 64 stereo                 5000, 128 stereo
#   1080p         6600, 64 stereo                 12000, 128 stereo
#   animation     900, no sound                   1800 (a video sent as a GIF)
#   round video   1000, 64                        2000, 96 (channels upstream's)
#
# A round video without a trim is sent as CameraOutput.swift records it
# (VideoMessageCameraScreen.swift 2000), at the recorder's own bitrate (374):
# 1000 kbit/s there too. A GIF file becomes an mp4 in TGGifConverter.m at 500
# kbit/s (103).
#
# No video is scaled up to a preset. An unedited one goes through the legacy
# converter, which caps the preset by the source's size
# (TGMediaVideoConverter.m 134-139, bestAvailablePresetForDimensions 930-943),
# and so does the quality slider (TGPhotoQualityController.m 136). An edited
# one with no quality chosen takes the default preset as it is
# (FetchVideoMediaResource.swift 1022-1025), and the export fits the source
# into the preset's size, larger or smaller (MediaEditorValues.swift
# 1967-1973, aspectFitted in UIKitUtils.swift 517-520): a trimmed 720p video
# went out as 1080p. The patch caps that default the way the legacy
# converter does.
#
# Not changed: the default quality is the server's video_upload_maxbitrate
# (LegacyAttachmentMenu.swift 14-53): v*5/100, so 85 on mobile data gives 720p
# and 100 on Wi-Fi 1080p.

# (preset, Telegram's value, Pluma's) for the legacy table's functions.
LEGACY_VIDEO_KBPS = (("CompressedVeryLow", 400, 800), ("CompressedLow", 700, 1500), ("CompressedMedium", 1600, 2500),
                     ("CompressedHigh", 3000, 5000), ("CompressedVeryHigh", 6600, 12000), ("VideoMessage", 1000, 2000))
LEGACY_AUDIO_KBPS = (("CompressedVeryLow", 32, 64), ("CompressedLow", 32, 64), ("CompressedMedium", 64, 128),
                     ("CompressedHigh", 64, 128), ("CompressedVeryHigh", 64, 128), ("VideoMessage", 64, 96))
LEGACY_AUDIO_CHANNELS = (("CompressedVeryLow", 1, 2), ("CompressedLow", 1, 2))
# (case, Telegram's value, Pluma's) for MediaQualityPreset.videoBitrateKbps.
VIDEO_KBPS = (("compressedVeryLow", 400, 800), ("compressedLow", 700, 1500), ("compressedMedium", 1600, 2500),
              ("compressedHigh", 3000, 5000), ("compressedVeryHigh", 6600, 12000), ("videoMessage", 1200, 2000))
ANIMATION_KBPS = (900, 1800)
# The default preset of an edited video, capped by the source's size.
VIDEO_DEFAULT_PRESET_OLD = src(" " * 8, """
    var qualityPreset = MediaQualityPreset(preset: legacyAdjustments.preset)
    if qualityPreset == .compressedDefault {
        qualityPreset = defaultPreset
    }
""")
VIDEO_DEFAULT_PRESET = src(" " * 8, """
    var qualityPreset = MediaQualityPreset(preset: legacyAdjustments.preset)
    if qualityPreset == .compressedDefault {
        qualityPreset = defaultPreset
        // pluma: no larger than the source, as the legacy converter caps it
        // (TGMediaVideoConverter.m 134-139); the export scales a source up to
        // the preset's size (task 052).
        let dimensions = legacyAdjustments.originalSize
        if dimensions != .zero && qualityPreset.rawValue >= MediaQualityPreset.compressedVeryLow.rawValue && qualityPreset.rawValue <= MediaQualityPreset.compressedVeryHigh.rawValue {
            let bestPreset = MediaQualityPreset(preset: TGMediaVideoConverter.bestAvailablePreset(forDimensions: dimensions))
            if qualityPreset.rawValue > bestPreset.rawValue {
                qualityPreset = bestPreset
            }
        }
    }
""")


def video_quality_edits():
    """The edits of the presets, as (file, upstream's text, Pluma's)."""
    edits = []
    for table in (LEGACY_VIDEO_KBPS, LEGACY_AUDIO_KBPS, LEGACY_AUDIO_CHANNELS):
        for preset, old, new in table:
            case = f"        case TGMediaVideoConversionPreset{preset}:\n"
            edits.append((VIDEO_PRESETS_LEGACY, f"{case}            return {old};\n",
                          f"{case}            return {new}; // pluma: {old} in Telegram (task 052)\n"))
    old, new = ANIMATION_KBPS
    edits.append((VIDEO_PRESETS_LEGACY, f"        default:\n            return {old};\n",
                  "        case TGMediaVideoConversionPresetAnimation:\n"
                  f"            return {new}; // pluma: {old} in Telegram, the default below (task 052)\n"
                  f"        default:\n            return {old};\n"))
    for case, old, new in VIDEO_KBPS:
        edits.append((VIDEO_PRESETS, f"        case .{case}:\n            return {old}\n",
                      f"        case .{case}:\n            return {new} // pluma: {old} in Telegram (task 052)\n"))
    old, new = ANIMATION_KBPS
    edits.append((VIDEO_PRESETS, f"        default:\n            return {old}\n",
                  f"        case .animation:\n            return {new} // pluma: {old} in Telegram, the default below (task 052)\n"
                  f"        default:\n            return {old}\n"))
    edits.append((VIDEO_PRESETS, src(" " * 8, """
        case .compressedVeryLow, .compressedLow:
            return 32
        case .compressedMedium, .compressedHigh, .compressedVeryHigh, .videoMessage:
            return 64
        default:
            return 0
    """), src(" " * 8, """
        // pluma: Telegram's are 32 for 240p and 360p, 64 for the rest (task 052).
        case .compressedVeryLow, .compressedLow:
            return 64
        case .compressedMedium, .compressedHigh, .compressedVeryHigh:
            return 128
        case .videoMessage:
            return 96
        default:
            return 0
    """)))
    edits.append((VIDEO_PRESETS, src(" " * 8, """
        case .compressedVeryLow, .compressedLow:
            return 1
        default:
            return 2
    """), src(" " * 8, """
        // pluma: 240p and 360p in stereo too; mono in Telegram (task 052).
        default:
            return 2
    """)))
    edits.append((ROUND_VIDEO_RECORDER, "                AVVideoAverageBitRateKey: 1000 * 1000,\n",
                   "                AVVideoAverageBitRateKey: 2000 * 1000, // pluma: 1000 kbit/s in Telegram (task 052)\n"))
    edits.append((ROUND_VIDEO_RECORDER_NEO, "            AVVideoAverageBitRateKey: 1_200_000,\n",
                   "            AVVideoAverageBitRateKey: 2_000_000, // pluma: 1200 kbit/s in Telegram (task 052)\n"))
    edits.append((GIF_CONVERTER, "              AVVideoAverageBitRateKey: @(500000),\n",
                   "              AVVideoAverageBitRateKey: @(1000000), // pluma: 500000 in Telegram (task 052)\n"))
    edits.append((VIDEO_FETCH, VIDEO_DEFAULT_PRESET_OLD, VIDEO_DEFAULT_PRESET))
    return tuple(edits)


def patch_video_quality(tree):
    """Higher bitrates than Telegram's for every video quality, round videos
    and GIF files."""
    for rel, old, new in video_quality_edits():
        tree.replace(rel, old, new)


def verify_video_quality(tree):
    for rel, old, new in video_quality_edits():
        text = tree.read(rel)
        if text.count(new) != 1 or (old not in new and old in text):
            raise PatchError(f"{rel}: not Pluma's video bitrates ({old.strip().splitlines()[-1]!r} in Telegram)")


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


# --- App Store ---------------------------------------------------------------


def infoplist_value(tree, rel, key):
    """The value of key in an InfoPlist.strings, unescaped."""
    m = re.search(r'^"' + re.escape(key) + r'" = "((?:[^"\\]|\\.)*)";$', tree.read(rel), re.M)
    if not m:
        raise PatchError(f"{rel}: no {key}; upstream changed it")
    return re.sub(r"\\(.)", r"\1", m.group(1))


def xml_text(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def siri_vocabulary(phrases, name):
    """An AppIntentVocabulary.plist with one example phrase per intent, laid
    out as upstream's."""
    entries = "".join(
        "\t\t<dict>\n"
        "\t\t\t<key>IntentName</key>\n"
        f"\t\t\t<string>{intent}</string>\n"
        "\t\t\t<key>IntentExamples</key>\n"
        "\t\t\t<array>\n"
        f"\t\t\t\t<string>{xml_text(phrase.format(name=name))}</string>\n"
        "\t\t\t</array>\n"
        "\t\t</dict>\n"
        for intent, phrase in zip(SIRI_INTENTS, phrases))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n<dict>\n\t<key>IntentPhrases</key>\n\t<array>\n'
            + entries + "\t</array>\n</dict>\n</plist>\n")


def patch_store(tree, c):
    """What App Store Connect warns about on upload: the purpose of
    background location, no Apple font in the bundle, and Siri phrases for
    every intent in every language."""
    purpose = infoplist_value(tree, INFOPLIST_STRINGS.format("en"), LOCATION_KEY)
    tree.replace(APP_BUILD, LOCATION_ANCHOR,
                 f"    <key>{LOCATION_KEY}</key>\n    <string>{xml_text(purpose)}</string>\n" + LOCATION_ANCHOR)

    for fallback in CAMERA_FONT_FALLBACKS:
        tree.expect(FONT, fallback)
    for old, new in CAMERA_ASSETS_FALLBACKS:
        tree.replace(CAMERA_ASSETS, old, new)
    tree.replace(APP_BUILD, CAMERA_FONTS_PLIST, "")
    for rel, sha256 in CAMERA_FONTS.items():
        tree.remove_file(rel, sha256)

    tree.expect(APP_BUILD, SIRI_EXTENSION_INTENTS)
    for lang, phrases in SIRI_PHRASES.items():
        tree.replace_file(SIRI_VOCABULARY.format(lang), SIRI_UPSTREAM[lang],
                          siri_vocabulary(phrases, c.app_name).encode("utf-8"))


def verify_store(tree, c):
    build = tree.read(APP_BUILD)
    if f"<key>{LOCATION_KEY}</key>" not in build:
        raise PatchError(f"{APP_BUILD}: no purpose of background location ({LOCATION_KEY})")
    if "AremacFS" in build or any(tree.sha256(rel) for rel in CAMERA_FONTS):
        raise PatchError(f"{APP_BUILD}: the bundle still carries SF Camera, an Apple font")
    assets = tree.read(CAMERA_ASSETS)
    if any(new not in assets for _, new in CAMERA_ASSETS_FALLBACKS):
        raise PatchError(f"{CAMERA_ASSETS}: the camera's font has no fallback without SF Camera")
    bundled = (p.parent.name.removesuffix(".lproj") for p in (tree.root / SIRI_VOCABULARY).parent.parent.glob("*.lproj/AppIntentVocabulary.plist"))
    unknown = sorted(set(bundled) - set(SIRI_PHRASES))
    if unknown:
        raise PatchError(f"{SIRI_VOCABULARY.format(unknown[0])}: a vocabulary the patch does not replace")
    for lang, phrases in SIRI_PHRASES.items():
        rel = SIRI_VOCABULARY.format(lang)
        text = tree.read(rel)
        if TELEGRAM_WORD.search(text) or any(f"<string>{i}</string>" not in text for i in SIRI_INTENTS):
            raise PatchError(f"{rel}: not a phrase in {c.app_name}'s name for every Siri intent")


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
    # The other avatar colours are the peer colours, one per user
    # (verify_identity).
    avatars = tree.read(AVATAR_NODE)
    for name in ("savedMessagesColors", "repostColors"):
        found = re.search(r"    static let %s: \[UIColor\] = \[\n(.*)\n" % name, avatars)
        if not found or any(blue.lower() in found.group(1).lower() for blue in TELEGRAM_BLUES):
            raise PatchError(f"{AVATAR_NODE}: {name} is not sage")


# --- people's identity colours -----------------------------------------------
#
# Telegram gives every user and chat one of seven colours: its own, or the
# one of its id, id % 7 (nameColor, PeerUtils.swift). 0 red, 1 orange,
# 2 violet, 3 green, 4 cyan, 5 blue, 6 pink. It is the letter avatar, the
# name in groups, the bar and title of replies and link previews
# (PeerNameColors.get in ChatMessageBubbleItemNode, ChatMessageReplyInfoNode,
# ChatMessageAttachedContentNode) and, chosen by the user, the tag of a chat
# folder (getChatFolderTag in ChatListItem.swift). Blue becomes the palette's
# sage and cyan a teal without Telegram's blue; the other five stay
# Telegram's (the owner's decision, as in the Android client). Colours 7 and
# above are the server's (help.getPeerColors) and stay as they come.
#
# The app keeps the seven in tables of its own, by number:
# - letter avatars: a gradient each, the same in light and dark themes, as
#   (bottom, top), since AvatarNode draws the pair from the top with the
#   locations [1, 0]. AvatarNode.gradientColors, and copies of it for the
#   avatars of notifications, the widget, the chat picker of the widget's
#   settings (the SiriIntents extension) and the reactions of a live
#   stream. Upstream's avatars of colours 7 to 13 take
#   the gradient of their number % 7, and of the others the one their hue
#   falls on (calculateAvatarColors), so a blue one among them is sage too.
#   That hue is the one of the light name colour, so a colour above 13 the
#   app has none for, whose name colour is the fallback (below), falls on
#   green: the hue of sage is green's;
# - names, bars and folder tags: one colour each. defaultSingleColors
#   (PeerNameColors.swift), which the app takes while the server lists no
#   colours (PeerNameColors.with), and the map TelegramCore takes for colours
#   0-6 that the server lists without values (ManagedPeerColorUpdates.swift);
#   colours the server lists with values are the server's. Neither table has
#   colours for dark themes, which show the light ones
#   (PeerNameColors.get(_:dark:)). Pluma's cyan and blue get dark colours of
#   their own: the dark name colour of the palette for blue, and for cyan the
#   teal Telegram's Android app shows at night (this app's one cyan, which
#   it shows in dark themes too, leans to blue). The fallback of
#   get and getChatFolderTag, for a colour the app has none for, is blue's
#   light colour in any theme; Telegram's blue reads on dark backgrounds, the
#   palette's light sage does not, so it takes blue's dark one in dark themes.
#   Callers that do not pass dark (the quote of a channel in the text input,
#   ChatTextInputPanelNode and AttachmentTextInputPanelNode) get the light
#   colours in any theme, as upstream.
# The places that take the blue slot as a plain blue take it from these
# tables: the name colour of an author the app has none for and of the theme
# previews (.blue, also the fallback of PeerNameColors.get), and the icons
# generateAvatarImage draws in AvatarBackgroundColor.blue: the "Contacts" and
# "Read" chats of a folder (ChatListFilterPresetController.swift), the
# contacts among the recipients of business messages, Saved Messages in the
# menu of a profile (PeerInfoScreen.swift; upstream's Saved Messages avatar
# is the same blue, Pluma's is the palette's sage, AVATAR_SAVED_MESSAGES).

# Telegram's seven colours, by number: the letter avatar's gradient as
# (bottom, top), and the name colour.
TELEGRAM_IDENTITY = (
    ((0xff516a, 0xff885e), 0xcc5049),  # 0 red
    ((0xffa85c, 0xffcd6a), 0xd67722),  # 1 orange
    ((0x665fff, 0x82b1ff), 0x955cdb),  # 2 violet
    ((0x54cb68, 0xa0de7e), 0x40a920),  # 3 green
    ((0x4acccd, 0x00fcfd), 0x309eba),  # 4 cyan
    ((0x2a9ef1, 0x72d5fd), 0x368ad1),  # 5 blue
    ((0xd669ed, 0xe0a2f3), 0xc7508b),  # 6 pink
)
# Pluma's, where they differ: number -> (name, the letter avatar's gradient as
# (bottom, top), the name colour, the name colour of dark themes or None for
# Telegram's).
IDENTITY_COLOURS = {
    4: ("teal", (0x2c9c98, 0x5bcbc4), 0x1f8a80, 0x53ccc6),
    5: ("sage", (0x5b7a5e, 0x7fa082), 0x4f6e52, 0x9dbb9f),
}

# The tables of the seven: (file, the line that opens the table, a row, the
# line that closes it, whether the last row has a comma). A row takes {bottom}
# and {top}, a letter avatar, or {id} and {colour}, a name colour.
_AVATAR_COPY = ("private let gradientColors: [NSArray] = [\n",
                "    [UIColor(rgb: {bottom}).cgColor, UIColor(rgb: {top}).cgColor]", "]\n", True)
IDENTITY_TABLES = (
    (AVATAR_NODE, "    public static let gradientColors: [[UIColor]] = [\n",
     "        [UIColor(rgb: {bottom}), UIColor(rgb: {top})]", "    ]\n", True),
    (NOTIFICATION_AVATARS, *_AVATAR_COPY),
    (WIDGET_AVATARS, *_AVATAR_COPY),
    (INTENT_AVATARS, *_AVATAR_COPY),
    (LIVE_STREAM_AVATARS, *_AVATAR_COPY),
    (PEER_NAME_COLORS, "    public static var defaultSingleColors: [Int32: Colors] {\n        return [\n",
     "            {id}: Colors(main: UIColor(rgb: {colour}))", "        ]\n    }\n", False),
    (PEER_COLOR_UPDATES, "                    let staticMap: [UInt32] = [\n",
     "                        {colour}", "                    ]\n", False),
)

# Where the dark name colours go: the default colours of PeerNameColors, and
# the options TelegramCore makes of its map.
NAME_DARK_OLD = "            colors: defaultSingleColors,\n            darkColors: [:],\n"
STATIC_DARK_OLD = src(" " * 20, """
    let colorPack = MultiColorPack(colors: [staticMap[Int(colorId)]])
    let defaultColors = EngineAvailableColorOptions.ColorOption(palette: colorPack, background: colorPack, stories: nil)
    mappedOptions.append(Option(key: colorId, value: ColorOptionPack(light: defaultColors, dark: nil, isHidden: isHidden, requiredChannelMinBoostLevel: requiredChannelMinBoostLevel, requiredGroupMinBoostLevel: requiredGroupMinBoostLevel)))
""")
# The fallback of PeerNameColors.get and getChatFolderTag, the same line in
# both: blue, its light colour in any theme.
NAME_FALLBACK_OLD = "            return PeerNameColors.defaultSingleColors[5]!\n"
NAME_FALLBACK = ("            // pluma: dark themes take blue's dark colour (Pluma's sage has one).\n"
                 "            return dark ? (PeerNameColors.defaultValue.darkColors[5] ?? PeerNameColors.defaultSingleColors[5]!) "
                 ": PeerNameColors.defaultSingleColors[5]!\n")


def identity_colours():
    """The seven colours of the patched app, [(letter avatar, name colour)],
    and the name colours of dark themes, {number: colour}."""
    colours, dark = [], {}
    for i, (avatar, name) in enumerate(TELEGRAM_IDENTITY):
        if i in IDENTITY_COLOURS:
            _, avatar, light, dark_name = IDENTITY_COLOURS[i]
            colours.append((avatar, light))
            dark[i] = name if dark_name is None else dark_name
        else:
            colours.append((avatar, name))
    return colours, dark


def identity_table(table, colours, marks):
    """The text of one of IDENTITY_TABLES with these colours; marks names
    Pluma's in a comment after their rows."""
    _, head, row, tail, last_comma = table
    out = head
    for i, ((bottom, top), name) in enumerate(colours):
        line = row.format(id=i, bottom=f"0x{bottom:06x}", top=f"0x{top:06x}", colour=f"0x{name:06x}")
        if last_comma or i < len(colours) - 1:
            line += ","
        if i in marks:
            line += f" // pluma: {marks[i]}"
        out += line + "\n"
    return out + tail


def name_dark(dark):
    """The colours of PeerNameColors.defaultValue, with the dark name colours."""
    rows = ",\n".join(f"                {i}: Colors(main: UIColor(rgb: 0x{c:06x}))" for i, c in sorted(dark.items()))
    return ("            colors: defaultSingleColors,\n"
            "            // pluma: Pluma's cyan and blue have colours of their own in dark themes.\n"
            f"            darkColors: [\n{rows}\n            ],\n")


def static_dark(dark):
    """TelegramCore's options for the colours 0-6 the server lists without
    values, with the dark name colours."""
    entries = ", ".join(f"{i}: 0x{c:06x}" for i, c in sorted(dark.items()))
    return src(" " * 20, f"""
        let colorPack = MultiColorPack(colors: [staticMap[Int(colorId)]])
        let defaultColors = EngineAvailableColorOptions.ColorOption(palette: colorPack, background: colorPack, stories: nil)
        // pluma: Pluma's cyan and blue have colours of their own in dark themes,
        // as in PeerNameColors.defaultValue.
        let staticDarkMap: [Int32: UInt32] = [{entries}]
        let defaultDarkColors = staticDarkMap[colorId].map {{ darkColor -> EngineAvailableColorOptions.ColorOption in
            let darkColorPack = MultiColorPack(colors: [darkColor])
            return EngineAvailableColorOptions.ColorOption(palette: darkColorPack, background: darkColorPack, stories: nil)
        }}
        mappedOptions.append(Option(key: colorId, value: ColorOptionPack(light: defaultColors, dark: defaultDarkColors, isHidden: isHidden, requiredChannelMinBoostLevel: requiredChannelMinBoostLevel, requiredGroupMinBoostLevel: requiredGroupMinBoostLevel)))
    """)


def patch_identity(tree):
    """Sage for blue and teal for cyan in every table of the seven colours
    (each one must hold Telegram's seven, in order), and dark name colours of
    their own for both; the fallback of the name colours, blue, takes its dark
    one in dark themes."""
    colours, dark = identity_colours()
    marks = {i: c[0] for i, c in IDENTITY_COLOURS.items()}
    for table in IDENTITY_TABLES:
        tree.replace(table[0], identity_table(table, TELEGRAM_IDENTITY, {}), identity_table(table, colours, marks))
    tree.replace(PEER_NAME_COLORS, NAME_DARK_OLD, name_dark(dark))
    tree.replace(PEER_NAME_COLORS, NAME_FALLBACK_OLD, NAME_FALLBACK, count=2)
    tree.replace(PEER_COLOR_UPDATES, STATIC_DARK_OLD, static_dark(dark))


def table_colours(tree, table):
    """The colours of one of IDENTITY_TABLES as the file has them, in order."""
    rel, head, _, tail, _ = table
    text = tree.read(rel)
    if text.count(head) != 1:
        raise PatchError(f"{rel}: {text.count(head)} tables {head.strip()!r}, expected 1")
    start = text.index(head) + len(head)
    end = text.find(tail, start)
    if end < 0:
        raise PatchError(f"{rel}: no {tail.strip()!r} after {head.strip()!r}")
    return [int(c, 16) for c in re.findall(r"\b0x([0-9A-Fa-f]{6})\b", text[start:end])]


def verify_identity(tree):
    colours, dark = identity_colours()
    for table in IDENTITY_TABLES:
        avatars = "{bottom}" in table[2]
        want = [c for avatar, name in colours for c in (avatar if avatars else (name,))]
        if table_colours(tree, table) != want:
            raise PatchError(f"{table[0]}: the seven {'letter avatars' if avatars else 'name colours'} are not Pluma's")
    names = tree.read(PEER_NAME_COLORS)
    if name_dark(dark) not in names:
        raise PatchError(f"{PEER_NAME_COLORS}: no dark name colours of Pluma's")
    if names.count(NAME_FALLBACK) != 2 or NAME_FALLBACK_OLD in names:
        raise PatchError(f"{PEER_NAME_COLORS}: the fallback name colour is the light one in dark themes")
    updates = tree.read(PEER_COLOR_UPDATES)
    if static_dark(dark) not in updates or "ColorOptionPack(light: defaultColors, dark: nil," in updates:
        raise PatchError(f"{PEER_COLOR_UPDATES}: no dark name colours of Pluma's")


# An entry of a .strings file, "key" = "value";, where the value may span
# lines: the key with what precedes the value, the value, the end.
STRINGS_ENTRY = re.compile(r'^("(?:[^"\\]|\\.)*"\s*=\s*")((?:[^"\\]|\\.)*)(";)', re.M)
# The name as a word, also right after an escaped line break (\nTelegram).
TELEGRAM_WORD = re.compile(r"(?:(?<![0-9A-Za-z_])|(?<=\\n))(Telegram|TELEGRAM)(?![0-9A-Za-z_])")
# The entries of the English strings that name Telegram, and how many times
# they do, in the pinned commit. Keys never change (the code refers to them),
# nor do URLs, user names or link targets: they are lower case or part of
# another word (telegram.org, t.me, TelegramTips, (telegram)).
STRINGS_RENAMED = (585, 638)


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
    # replaces telegram:// (patch()); tg:// is no longer registered beside it,
    # nor TON's ton:// and tc://, which open the wallet Pluma's server does not
    # offer (wallet_available) and are for the apps that have one.
    tree.replace(APP_BUILD, "                <string>tg</string>\n                <string>tonsite</string>\n"
                 "                <string>ton</string>\n                <string>tc</string>\n",
                 "                <string>tonsite</string>\n")
    for rel, text, count in SCHEME_LINKS:
        tree.replace(rel, text.replace("{scheme}", "tg"), text.replace("{scheme}", c.url_scheme), count=count)
    # The switch of a proxy's QR code names the scheme of the link it makes.
    tree.replace(STRINGS, SCHEME_TEXT.format(scheme="tg"), SCHEME_TEXT.format(scheme=c.url_scheme))
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


# The app's universal links (task 026): upstream gives the associated
# domains of t.me only to Telegram's own bundle ids and none to another.
# Pluma's app opens https://pluma.chat links itself; the App ID has the
# Associated Domains capability and the site serves
# /.well-known/apple-app-site-association.
ASSOCIATED_DOMAINS_OLD = 'associated_domains_fragment = "" if telegram_bundle_id not in official_bundle_ids else """\n'
ASSOCIATED_DOMAINS = (
    'associated_domains_fragment = """\n'
    "<key>com.apple.developer.associated-domains</key>\n"
    "<array>\n"
    "    <string>applinks:" + LINK_HOST + "</string>\n"
    "</array>\n"
    '""" if telegram_bundle_id not in official_bundle_ids else """\n'
)


def patch_links(tree):
    """pluma.chat for the links the app makes, and among the hosts whose
    links it opens itself."""
    tree.replace(APP_BUILD, ASSOCIATED_DOMAINS_OLD, ASSOCIATED_DOMAINS)
    for rel, old, new, count in LINK_HOSTS:
        tree.replace(rel, old, new, count=count)
    tree.replace(URL_HANDLING, URL_SUBDOMAIN_OLD, URL_SUBDOMAIN)
    for rel, old, new, count in PLUMA_SITE:
        tree.replace(rel, old, new, count=count)
    for rel, text, count in SHARE_LINKS:
        tree.replace(rel, text.replace("{host}", "t.me"), text.replace("{host}", LINK_HOST), count=count)
    for key, count in STRINGS_LINKS:
        tree.replace_in_line(STRINGS, f'"{key}" = "', (("t.me", LINK_HOST, count),))


def link_sources(tree):
    """The app's source files in the tree (all of them in a full checkout)."""
    for top in ("submodules", "Telegram"):
        for p in sorted((tree.root / top).rglob("*")):
            if p.suffix in (".swift", ".m", ".mm", ".h", ".cpp") and p.is_file() and not is_unit_test(p.relative_to(tree.root).as_posix()):
                yield p.relative_to(tree.root).as_posix()


def verify_links(tree):
    if tree.read(APP_BUILD).count("<string>applinks:" + LINK_HOST + "</string>") != 1:
        raise PatchError(f"{APP_BUILD}: the app has no universal links of {LINK_HOST}")
    for rel, _, new, count in LINK_HOSTS:
        if tree.read(rel).count(new) != count:
            raise PatchError(f"{rel}: does not take {LINK_HOST} for the app's own links")
    if tree.read(URL_HANDLING).count(URL_SUBDOMAIN) != 1:
        raise PatchError(f"{URL_HANDLING}: reads a subdomain of {LINK_HOST} as a username")
    for rel, _, new, count in PLUMA_SITE:
        if tree.read(rel).count(new) != count:
            raise PatchError(f"{rel}: takes the pages of the site {LINK_HOST} for the app's own links")
    if tree.read(URL_HANDLING).count(PLUMA_SITE_CHECK + "(") != 3:
        raise PatchError(f"{URL_HANDLING}: the check of the pages of {LINK_HOST} is not where the patch put it")
    for rel, text, count in SHARE_LINKS:
        if tree.read(rel).count(text.replace("{host}", LINK_HOST)) != count:
            raise PatchError(f"{rel}: does not make its links with {LINK_HOST}")
    kept = {}
    for rel, text, count in SHARE_KEEP:
        found = tree.read(rel).count(text)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of the t.me link {text.strip()!r}, expected {count}; "
                             "upstream changed it")
        kept[rel] = kept.get(rel, 0) + count * len(TME_LITERAL.findall(text.encode("utf-8")))
    for rel in link_sources(tree):
        found = len(TME_LITERAL.findall((tree.root / rel).read_bytes()))
        if found != kept.get(rel, 0):
            raise PatchError(f"{rel}: {found} t.me links, {kept.get(rel, 0)} of them kept (SHARE_KEEP); "
                             f"the links the app makes are {LINK_HOST}'s")
    for rel in link_sources(tree):
        data = (tree.root / rel).read_bytes()
        for literal, kept_table, what in ((TG_LITERAL, KEPT_TG_LINKS, "tg://"), (TELEGRAM_SITE, KEPT_TELEGRAM_SITES, "telegram.org")):
            found = len(literal.findall(data))
            if found != kept_table.get(rel, 0):
                raise PatchError(f"{rel}: {found} {what} literals, {kept_table.get(rel, 0)} of them kept; upstream changed them")
    strings = tree.read(STRINGS)
    for m in STRINGS_ENTRY.finditer(strings):
        if STRINGS_TME.search(m.group(2)) and m.group(1).split('"')[1] not in STRINGS_KEEP:
            raise PatchError(f"{STRINGS}: {m.group(0)[:80]!r} still shows a t.me link")
    sites = sum(1 for m in STRINGS_ENTRY.finditer(strings) if TELEGRAM_SITE.search(m.group(2).encode("utf-8")))
    if sites != STRINGS_TELEGRAM_SITES:
        raise PatchError(f"{STRINGS}: {sites} entries name Telegram's sites, expected {STRINGS_TELEGRAM_SITES}; upstream changed them")
    for key, count in STRINGS_LINKS:
        lines = [line for line in strings.split("\n") if line.startswith(f'"{key}" = "')]
        if len(lines) != 1 or lines[0].count(LINK_HOST) != count:
            raise PatchError(f"{STRINGS}: {key} does not show a {LINK_HOST} link")


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
    if SCHEME_TEXT.format(scheme=c.url_scheme) not in tree.read(STRINGS):
        raise PatchError(f"{STRINGS}: the QR code of a proxy does not name {c.url_scheme}://")


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
    if tree.read(INTRO_CONTROLLER).count('[UIImage imageNamed:@"pluma_wordmark.png"]') != 1:
        raise PatchError(f"{INTRO_CONTROLLER}: the first page of the intro has no wordmark")
    if "TARGET_OS_SIMULATOR" in tree.read(INTRO_CONTROLLER):
        raise PatchError(f"{INTRO_CONTROLLER}: the intro's animations are off in the simulator")


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
    verify_intro_mark(tree)
    verify_names(tree, c)
    verify_scheme(tree, c)
    verify_client_links(tree)
    verify_links(tree)
    verify_palette(tree)
    verify_identity(tree)
    verify_support(tree)
    verify_birthdays(tree)
    verify_read_date(tree)
    verify_saved_tags(tree)
    verify_premium_stickers(tree)
    verify_premium_for_everyone(tree)
    verify_app_update(tree)
    verify_video_quality(tree)
    verify_store(tree, c)

    build = tree.read(APP_BUILD)
    if "<string>Telegram</string>" in build or "<string>telegram</string>" in build:
        raise PatchError(f"{APP_BUILD}: Telegram's name or URL scheme is still there")
    conf = json.loads(tree.read(CONFIGURATION))
    if (conf["bundle_id"], conf["api_id"], conf["team_id"]) != (c.bundle_id, str(c.api_id), c.team_id):
        raise PatchError(f"{CONFIGURATION}: not the Pluma app")



# --- Premium for everyone -----------------------------------------------------
# Task 071 (ADR 0041): every user has Premium and every boost-gated feature is
# open, so the server sends the Premium flag for everybody. Only what the flag
# would make wrong is edited: the star by every name, the purchase rows that
# show for anyone with Premium, and what the server does not serve.
PREMIUM_FOR_EVERYONE_EDITS = (
    ("submodules/TelegramUI/Sources/Chat/ChatControllerOpenMessageContextMenu.swift",
     "                                    areCustomEmojiEnabled: !premiumConfiguration.isPremiumDisabled,\n",
     "                                    areCustomEmojiEnabled: true, // pluma: everybody has Premium\n",
     1),
    ("submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoSettingsItems.swift",
     "    if !isPremiumDisabled || context.isPremium {\n        items[.payment]!.append(PeerInfoScreenDisclosureItem(id: 100,",
     "    if !isPremiumDisabled { // pluma: the row is the purchase; everybody has Premium\n        items[.payment]!.append(PeerInfoScreenDisclosureItem(id: 100,", 1),
    ("submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoSettingsItems.swift",
     "    if !isPremiumDisabled || context.isPremium {\n        items[.payment]!.append(PeerInfoScreenDisclosureItem(id: 104,",
     "    if !isPremiumDisabled { // pluma: the row is the purchase; everybody has Premium\n        items[.payment]!.append(PeerInfoScreenDisclosureItem(id: 104,", 1),
    ("submodules/TelegramUI/Components/EntityKeyboard/Sources/EmojiPagerContentSignals.swift",
     "        let isPremiumDisabled = premiumConfiguration.isPremiumDisabled\n",
     "        // pluma: custom emoji and premium stickers stay in the keyboard: everybody has Premium.\n        let isPremiumDisabled = false\n", 3),
    ("submodules/TelegramUI/Components/Chat/ChatMessageInteractiveFileNode/Sources/ChatMessageInteractiveFileNode.swift",
     "                if Namespaces.Message.allNonRegular.contains(arguments.message.id.namespace) {\n                    displayTranscribe = false\n",
     "                // pluma: the server has no transcription to offer.\n                if true || Namespaces.Message.allNonRegular.contains(arguments.message.id.namespace) {\n                    displayTranscribe = false\n", 1),
    ("submodules/TelegramUI/Components/Chat/ChatMessageInteractiveInstantVideoNode/Sources/ChatMessageInteractiveInstantVideoNode.swift",
     "                    if item.message.id.peerId.namespace != Namespaces.Peer.SecretChat && statusDisplayType == .free && !isViewOnceMessage && !item.presentationData.isPreview {\n                        let premiumConfiguration",
     "                    // pluma: the server has no transcription to offer.\n                    if false && item.message.id.peerId.namespace != Namespaces.Peer.SecretChat && statusDisplayType == .free && !isViewOnceMessage && !item.presentationData.isPreview {\n                        let premiumConfiguration", 1),
    # Boosts do not exist here: nothing waits for a level of a channel, no
    # screen, prompt or link offers one.
    ("submodules/TelegramUI/Components/PeerAllowedReactionsScreen/Sources/PeerAllowedReactionsScreen.swift",
     "            if let boostStatus = self.boostStatus, !customReactions.isEmpty, customReactions.count > boostStatus.level {\n",
     "            if let boostStatus = self.boostStatus, false && !customReactions.isEmpty && customReactions.count > boostStatus.level { // pluma: custom reactions need no boost level\n", 1),
    ("submodules/TelegramUI/Components/PeerAllowedReactionsScreen/Sources/PeerAllowedReactionsScreen.swift",
     "                                        if nextCustomReactionCount > boostStatus.level {\n",
     "                                        if false && nextCustomReactionCount > boostStatus.level { // pluma: custom reactions need no boost level\n", 1),
    ("submodules/TelegramUI/Components/PeerAllowedReactionsScreen/Sources/PeerAllowedReactionsScreen.swift",
     "            if let boostStatus = self.boostStatus, customReactionCount > boostStatus.level {\n",
     "            if let boostStatus = self.boostStatus, false && customReactionCount > boostStatus.level { // pluma: custom reactions need no boost level\n", 1),
    ("submodules/PremiumUI/Sources/PremiumBoostLevelsScreen.swift",
     "func requiredBoostSubjectLevel(subject: BoostSubject, group: Bool, context: AccountContext, configuration: PremiumConfiguration) -> Int32 {\n    switch subject {\n",
     "func requiredBoostSubjectLevel(subject: BoostSubject, group: Bool, context: AccountContext, configuration: PremiumConfiguration) -> Int32 {\n    // pluma: nothing needs a boost level, colours included: some have none in the\n    // server's list and fall back to 1 below (ADR 0041).\n    if true || group {\n        return 0\n    }\n    switch subject {\n", 1),
    ("submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoScreenPerformButtonAction.swift",
     "                        let boostTitle: String\n                        switch channel.info {\n                        case .group:\n                            boostTitle = presentationData.strings.PeerInfo_Group_Boost\n                        case .broadcast:\n                            boostTitle = presentationData.strings.PeerInfo_Channel_Boost\n                        }\n                        items.append(.action(ContextMenuActionItem(text: boostTitle, badge: nil, icon: { theme in\n                            generateTintedImage(image: UIImage(bundleImageName: \"Chat/Context Menu/Boost\"), color: theme.contextMenu.primaryColor)\n                        }, action: { [weak self] _, f in\n                            f(.dismissWithoutContent)\n                            \n                            self?.openBoost()\n                        })))\n",
     "                        // pluma: boosts do not exist here (ADR 0041), no item to boost.\n", 1),
    ("submodules/UrlHandling/Sources/UrlHandling.swift",
     "                            case .boost:\n                                return .single(.progress) \n                                |> then(\n                                    combineLatest(\n                                        context.engine.peers.getChannelBoostStatus(peerId: peer.id),\n                                        context.engine.peers.getMyBoostStatus()\n                                    )\n                                    |> map { boostStatus, myBoostStatus -> ResolveInternalUrlResult in\n                                        return .result(.boost(peerId: peer.id, status: boostStatus, myBoostStatus: myBoostStatus))\n                                    }\n                                )\n",
     "                            case .boost:\n                                // pluma: a boost link opens the channel.\n                                return .single(.result(.peer(peer._asPeer(), .chat(textInputState: nil, subject: nil, peekData: nil))))\n", 1),
    ("submodules/UrlHandling/Sources/UrlHandling.swift",
     "                    if case .boost = parameter {\n                        return .single(.result(.boost(peerId: nil, status: nil, myBoostStatus: nil)))\n                    } else {\n                        return .single(.result(.peer(nil, .info(nil))))\n                    }\n",
     "                    // pluma: a boost link of an unknown channel is a link to nothing, like any other.\n                    return .single(.result(.peer(nil, .info(nil))))\n", 1),
    ("submodules/PeerInfoUI/Sources/ChannelPermissionsController.swift",
     "        if !canSendText || !canSendMedia || slowModeTimeout > 0 {\n            let unrestrictBoosters = state.modifiedUnrestrictBoosters ?? (cachedData.boostsToUnrestrict ?? 0)\n",
     "        if false && (!canSendText || !canSendMedia || slowModeTimeout > 0) { // pluma: boosts do not exist here (ADR 0041)\n            let unrestrictBoosters = state.modifiedUnrestrictBoosters ?? (cachedData.boostsToUnrestrict ?? 0)\n", 1),
    ("submodules/TelegramUI/Components/Settings/PeerNameColorScreen/Sources/ChannelAppearanceScreen.swift",
     "            let boostSectionFrame = CGRect(origin: CGPoint(x: sideInset, y: contentHeight), size: boostSectionSize)\n            if let boostSectionView = self.boostSection.view {\n                if boostSectionView.superview == nil {\n                    self.scrollView.addSubview(boostSectionView)\n                }\n                transition.setFrame(view: boostSectionView, frame: boostSectionFrame)\n            }\n            contentHeight += boostSectionSize.height\n            contentHeight += sectionSpacing - 8.0\n",
     "            // pluma: boosts do not exist here (ADR 0041), the section is never added.\n            let _ = boostSectionSize\n", 1),
)
# The check job fetches only the paths the patch reads (ci/fetch-upstream.sh sparse).
UPSTREAM_PATHS += tuple(sorted({edit[0] for edit in PREMIUM_FOR_EVERYONE_EDITS} - set(UPSTREAM_PATHS)))


def premium_for_everyone(tree):
    for rel, old, new, count in PREMIUM_FOR_EVERYONE_EDITS:
        tree.replace(rel, old, new, count=count)


def verify_premium_for_everyone(tree):
    for rel, old, new, count in PREMIUM_FOR_EVERYONE_EDITS:
        text = tree.read(rel)
        if text.count(new) != count or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the edit of task 071 is not there")

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
