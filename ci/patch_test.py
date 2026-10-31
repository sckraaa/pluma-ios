#!/usr/bin/env python3
import gzip
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import patch  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Telegram's production and test server keys, as MtProtoKit carries them,
# with the fingerprints the server announces for them.
TELEGRAM_PROD = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
-----END RSA PUBLIC KEY-----"""

TELEGRAM_TEST = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB
-----END RSA PUBLIC KEY-----"""

# A 2048-bit key of no server, for a server build.
OTHER_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAmVCNU9+WBRzHykS1SspkijEuCZxIep2MXqf7c0d+6QcgEdMWTZjh
wBLkrfGiDtNvsVD5ij8JQZpFJvXohmKdh5UZb0mBLKOJFCpvSqSp0Ia3GJxkUG1t
BTvVvC34pf0wLoJQPULUs5bORnzubr+MEIn5maS2yXyI0blKrop9utO3ke7FSpAw
Q6c0Bs+LgoJq8vAhBsetZWVRImNPx8jgrnGts/oIvepCds6NQjPNEsEcraWHoVrM
pPrdMoxq2eXN5HmKAGwqJc68udQzrXH3tF0evqNMI2g2dUI/gjsD5F7q4/gJbAC8
b9dKEFwjKCugpszC92HAbuFIxS8VG/fNvQIDAQAB
-----END RSA PUBLIC KEY-----"""

# A 1024-bit key.
SHORT_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALq+uxafbIeJrZUD2Toafbh0znXSHjOEGmp0OYsbqh1WOL//KGwa8WcM
vJey5IOJDKqmyFBURdP6+0IuF3RgEvhPrCXTLFLSWgGTIZOUGkGO/NOVyzzKP9I4
cHpcIp/hW3HkD564M7f9BbGSkXItXbTwpiEWj0kXJ0b0I1OSFYxRAgMBAAE=
-----END RSA PUBLIC KEY-----"""

DEV_KEY = (ROOT / "config/dev/server_public.pem").read_text()


def fingerprint(pem):
    return patch.key_fingerprint(*patch.parse_pkcs1_public_key(pem))


class KeyTest(unittest.TestCase):
    def test_telegram_fingerprints(self):
        self.assertEqual(fingerprint(TELEGRAM_PROD), 0xD09D1D85DE64FD85)
        self.assertEqual(fingerprint(TELEGRAM_TEST), 0xB25898DF208D2603)
        self.assertEqual((fingerprint(TELEGRAM_PROD), fingerprint(TELEGRAM_TEST)), patch.TELEGRAM_FINGERPRINTS)

    def test_dev_key_fingerprint(self):
        # The fingerprint the server prints for the development key
        # (tools/genserverkey in the server repository).
        self.assertEqual(fingerprint(DEV_KEY), 14037083214707814241)

    def test_canonical_pem_round_trip(self):
        n, e = patch.parse_pkcs1_public_key(TELEGRAM_PROD)
        self.assertEqual("\n".join(patch.canonical_pem(n, e)), TELEGRAM_PROD)

    def test_rejects_other_formats(self):
        spki = TELEGRAM_PROD.replace("RSA PUBLIC KEY", "PUBLIC KEY")
        with self.assertRaises(patch.PatchError):
            patch.parse_pkcs1_public_key(spki)
        with self.assertRaises(patch.PatchError):
            patch.parse_pkcs1_public_key(TELEGRAM_PROD.replace("5nKaMBwK", "5nKa*BwK"))

    def test_objc_literal_holds_the_key(self):
        n, e = patch.parse_pkcs1_public_key(DEV_KEY)
        literal = patch.objc_key(patch.canonical_pem(n, e), " " * 13)
        self.assertTrue(literal.startswith('@"-----BEGIN RSA PUBLIC KEY-----\\n"\n             "MIIB'))
        self.assertEqual(patch.embedded_keys(literal), [(n, e)])


def config(**over):
    upstream = patch.load_env(ROOT / "upstream.env")
    app = patch.load_env(ROOT / "config/app.env")
    app.update(over.pop("app", {}))
    args = dict(server_ipv4="203.0.113.7", server_port="443", server_ipv6="", rsa_pem=OTHER_KEY, team_id="ABCDE12345")
    args.update(over)
    return patch.Config(upstream, app, **args)


class ConfigTest(unittest.TestCase):
    def test_repository_config(self):
        c = config(server_ipv6="2001:db8:0:0::1")
        self.assertEqual((c.bundle_id, c.app_name, c.api_id, c.layer), ("chat.pluma.app", "Pluma", 10002, 228))
        self.assertEqual(c.ipv6, "2001:db8::1")
        conf = c.build_configuration()
        self.assertEqual((conf["bundle_id"], conf["api_id"], conf["team_id"]), ("chat.pluma.app", "10002", "ABCDE12345"))
        self.assertEqual((conf["is_internal_build"], conf["is_appstore_build"]), ("false", "true"))
        self.assertIs(conf["enable_icloud"], False)

    def test_dev_server(self):
        dev = patch.load_env(ROOT / "config/dev/server.env")
        c = config(server_ipv4=dev["PLUMA_SERVER_IPV4"], server_port=dev["PLUMA_SERVER_PORT"],
                   rsa_pem=DEV_KEY, team_id=dev["PLUMA_TEAM_ID"])
        self.assertEqual((c.ipv4, c.port), ("127.0.0.1", 10443))

    def test_rejects(self):
        for over in (
            {"server_ipv4": "pluma.chat"},
            {"server_ipv4": "2001:db8::1"},
            {"server_ipv4": "149.154.167.50"},
            {"server_ipv6": "2001:67c:4e8:f002::a"},
            {"server_port": "0"},
            {"server_port": "https"},
            {"server_ipv6": "203.0.113.7"},
            {"rsa_pem": SHORT_KEY},
            {"rsa_pem": TELEGRAM_PROD},
            {"team_id": ""},
            {"team_id": "abcde12345"},
            {"team_id": "ABCDE1234"},
            {"app": {"PLUMA_API_HASH": "F25C102168E1B20E51A4F8E90ABEBAA4"}},
            {"app": {"PLUMA_URL_SCHEME": "tg"}},
            {"app": {"PLUMA_BUNDLE_ID": "Pluma"}},
            {"app": {"PLUMA_APP_NAME": "Pluma Messenger Beta"}},
        ):
            with self.subTest(over=over), self.assertRaises(patch.PatchError):
                config(**over)


class ScanTest(unittest.TestCase):
    def test_finds_telegram_addresses(self):
        text = '1: ["149.154.175.50", "2001:b28:f23d:f001::a"], 2: ["95.161.76.100"], ip: "91.108.9.38"'
        self.assertEqual(patch.telegram_addresses(text),
                         ["149.154.175.50", "95.161.76.100", "91.108.9.38", "2001:b28:f23d:f001::a"])

    def test_ignores_other_numbers(self):
        text = 'version == "12.0.0"; "127.0.0.1"; 1.149.154.175; "2001:db8::1"; 12:30:45; "8.8.8.8"'
        self.assertEqual(patch.telegram_addresses(text), [])

    def test_keys_in_objc_literals(self):
        source = ('NSString *k = @"-----BEGIN RSA PUBLIC KEY-----\\n"\n'
                  + "".join(f'"{l}\\n"\n' for l in TELEGRAM_TEST.splitlines()[1:-1])
                  + '"-----END RSA PUBLIC KEY-----";\n')
        self.assertEqual(patch.embedded_keys(source), [patch.parse_pkcs1_public_key(TELEGRAM_TEST)])

    def test_ignores_code_around_the_markers(self):
        # MTRsa.m turns a PKCS#1 key into a SubjectPublicKeyInfo.
        source = ('[key_s stringByReplacingOccurrencesOfString:@"-----BEGIN RSA PUBLIC KEY-----\\n" '
                  'withString:@"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"] '
                  'stringByReplacingOccurrencesOfString:@"-----END RSA PUBLIC KEY-----" withString:@"-----END PUBLIC KEY-----"]')
        self.assertEqual(patch.embedded_keys(source), [])


class TreeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        (root / "a.txt").write_text("one two two\nvoid f() {\n    body;\n        \n    end;\n}\n")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def test_replace_counts(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace("a.txt", "two", "2")
        with self.assertRaises(patch.PatchError):
            self.tree.replace("a.txt", "three", "3")
        self.tree.replace("a.txt", "two", "2", count=2)
        self.assertTrue(self.tree.read("a.txt").startswith("one 2 2\n"))

    def test_replace_lines_takes_any_blank_line(self):
        old = patch.src("    ", """
            body;

            end;
        """)
        self.assertEqual(old, "    body;\n    \n    end;\n")
        self.tree.replace_lines("a.txt", old, "    other;\n")
        self.assertEqual(self.tree.read("a.txt"), "one two two\nvoid f() {\n    other;\n}\n")
        with self.assertRaises(patch.PatchError):
            self.tree.replace_lines("a.txt", old, "")

    def test_replace_body(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace_body("a.txt", "void f() {\n", "\n}\n", "    other;", must_contain=("missing",))
        self.tree.replace_body("a.txt", "void f() {\n", "\n}\n", "    other;", must_contain=("body;",))
        self.assertTrue(self.tree.read("a.txt").endswith("void f() {\n    other;\n}\n"))

    def test_replace_block(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace_block("a.txt", "void g() {", "\n}\n", "")
        self.tree.replace_block("a.txt", "void f() {", "\n}\n", "int x;\n", must_contain=("body;",))
        self.assertEqual(self.tree.read("a.txt"), "one two two\nint x;\n")

    def test_not_a_checkout(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(patch.PatchError):
            patch.Tree(d)

    def test_replace_in_line(self):
        self.tree.replace_in_line("a.txt", "one two", (("two", "2", 2), ("one", "1", 1)))
        self.assertTrue(self.tree.read("a.txt").startswith("1 2 2\nvoid f() {\n"))
        with self.assertRaises(patch.PatchError):
            self.tree.replace_in_line("a.txt", "    ", (("x", "y", 0),))  # two lines
        with self.assertRaises(patch.PatchError):
            self.tree.replace_in_line("a.txt", "body", (("body", "b", 2),))

    def test_files_by_hash(self):
        sha = hashlib.sha256(b"one two two\nvoid f() {\n    body;\n        \n    end;\n}\n").hexdigest()
        with self.assertRaises(patch.PatchError):
            self.tree.replace_file("a.txt", "0" * 64, b"x")
        with self.assertRaises(patch.PatchError):
            self.tree.replace_file("b.txt", sha, b"x")
        with self.assertRaises(patch.PatchError):
            self.tree.add_file("a.txt", b"x")
        self.tree.replace_file("a.txt", sha, b"\x89PNG")
        self.assertEqual((self.tree.root / "a.txt").read_bytes(), b"\x89PNG")
        self.tree.add_file("b/c.png", b"c")
        self.tree.remove_file("b/c.png", hashlib.sha256(b"c").hexdigest())
        self.assertFalse((self.tree.root / "b/c.png").exists())


class RenameTest(unittest.TestCase):
    def test_values_only(self):
        text = ('/* Telegram */\n'
                '"Application.Name" = "Telegram";\n'
                '"Contacts.InviteToTelegram" = "Invite to Telegram";\n'
                '"Passcode.AppLockedAlert" = "Telegram\\nLocked";\n'
                '"Conversation.UpdateTelegram" = "UPDATE TELEGRAM";\n'
                '"Settings.TipsUsername" = "TelegramTips";\n'
                '"Settings.FAQ_URL" = "https://telegram.org/faq#general";\n'
                '"Cocoon.Text" = "[@cocoon](telegram) on Telegram\'s \\"Telegram\\" network";\n'
                '"AppUpgrade.Running" = "Optimizing Telegram...\nPlease keep Telegram open.";\n')
        out, entries, occurrences = patch.rename_strings(text, "Pluma")
        self.assertEqual((entries, occurrences), (6, 8))
        self.assertEqual(out, '/* Telegram */\n'
                              '"Application.Name" = "Pluma";\n'
                              '"Contacts.InviteToTelegram" = "Invite to Pluma";\n'
                              '"Passcode.AppLockedAlert" = "Pluma\\nLocked";\n'
                              '"Conversation.UpdateTelegram" = "UPDATE PLUMA";\n'
                              '"Settings.TipsUsername" = "TelegramTips";\n'
                              '"Settings.FAQ_URL" = "https://telegram.org/faq#general";\n'
                              '"Cocoon.Text" = "[@cocoon](telegram) on Pluma\'s \\"Pluma\\" network";\n'
                              '"AppUpgrade.Running" = "Optimizing Pluma...\nPlease keep Pluma open.";\n')


class BrandTest(unittest.TestCase):
    def test_brand_files_are_the_patch_list(self):
        # brand/render.sh writes exactly the files the patch copies.
        self.assertEqual(patch.brand_files(), sorted(set(patch.BRAND_REPLACED) | set(patch.BRAND_ADDED)))
        self.assertFalse(set(patch.BRAND_ADDED) & set(patch.BRAND_REPLACED))
        for rel in patch.BRAND_REMOVED:
            self.assertTrue(rel.startswith(patch.APP_ICON + "/"))

    def test_upstream_paths_cover_the_brand(self):
        paths = patch.UPSTREAM_PATHS
        for rel in list(patch.BRAND_REPLACED) + list(patch.BRAND_REMOVED) + list(patch.BRAND_ADDED):
            self.assertTrue(any(rel == p or rel.startswith(p + "/") for p in paths), rel)

    def test_devices_animation(self):
        # brand/render.sh copies the source as it is; a sticker-sized Lottie
        # animation, gzipped like upstream's.
        data = (patch.BRAND / "Telegram/Telegram-iOS/Resources/Devices.tgs").read_bytes()
        self.assertEqual(data, (ROOT / "brand/pluma-devices.tgs").read_bytes(), "re-run brand/render.sh")
        anim = json.loads(gzip.decompress(data))
        self.assertEqual((anim["w"], anim["h"]), (512, 512))
        self.assertGreater(anim["op"], anim["ip"])
        self.assertTrue(anim["layers"])


class ClientLinksTest(unittest.TestCase):
    # The closures of RecentSessionsController.swift that open the links of
    # Settings > Devices: "Learn More", then the header's two.
    SOURCE = ('    }, openOtherAppsUrl: {\n'
              '        context.sharedContext.openExternalUrl(context: context, urlContext: .generic, '
              'url: "https://telegram.org/apps", forceExternal: true, presentationData: p, dismissInput: {})\n'
              '    }, openDesktopLink: {\n'
              '        context.sharedContext.openExternalUrl(context: context, urlContext: .generic, '
              'url: "https://getdesktop.telegram.org", forceExternal: true, presentationData: p, dismissInput: {})\n'
              '    }, openWebLink: {\n'
              '        context.sharedContext.openExternalUrl(context: context, urlContext: .generic, '
              'url: "https://web.telegram.org", forceExternal: true, presentationData: p, dismissInput: {})\n'
              '    })\n')
    # Its QR scanner: the two links under the viewfinder and their text.
    SCAN = ('                                    case "desktop":\n'
            '                                        self.context.sharedContext.openExternalUrl(context: self.context, urlContext: .generic, '
            'url: "https://getdesktop.telegram.org", forceExternal: true, presentationData: p, dismissInput: {})\n'
            '                                    case "web":\n'
            '                                        self.context.sharedContext.openExternalUrl(context: self.context, urlContext: .generic, '
            'url: "https://web.telegram.org", forceExternal: true, presentationData: p, dismissInput: {})\n')
    TEXT = ('"AuthSessions.AddDevice.ScanInstallInfo" = "Go to [getdesktop.telegram.org](desktop) or '
            '[web.telegram.org](web) to get the QR code";\n')

    def write(self, sessions=SOURCE, scan=SCAN, text=TEXT):
        self.tree.write(patch.SESSIONS, sessions)
        self.tree.write(patch.QR_SCAN, scan)
        self.tree.write(patch.STRINGS, text)

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def test_links(self):
        self.write()
        with self.assertRaises(patch.PatchError):
            patch.verify_client_links(self.tree)
        patch.patch_client_links(self.tree)
        patch.verify_client_links(self.tree)
        self.assertEqual(self.tree.read(patch.SESSIONS),
                         self.SOURCE.replace('"https://getdesktop.telegram.org"', '"https://pluma.chat/"')
                         .replace('"https://web.telegram.org"', '"https://web.pluma.chat/"'))
        self.assertEqual(self.tree.read(patch.QR_SCAN),
                         self.SCAN.replace('"https://getdesktop.telegram.org"', '"https://pluma.chat/"')
                         .replace('"https://web.telegram.org"', '"https://web.pluma.chat/"'))
        self.assertEqual(self.tree.read(patch.STRINGS),
                         '"AuthSessions.AddDevice.ScanInstallInfo" = "Go to [pluma.chat](desktop) or '
                         '[web.pluma.chat](web) to get the QR code";\n')

    def test_scanner_changed(self):
        for scan, text in ((self.SCAN.replace('case "web":', 'case "webClient":'), self.TEXT),             # another case
                           (self.SCAN, self.TEXT.replace("to get the QR code", "to get a QR code"))):   # another text
            with self.subTest(scan=scan[:20], text=text[-24:]):
                self.write(scan=scan, text=text)
                with self.assertRaises(patch.PatchError):
                    patch.patch_client_links(self.tree)
                    patch.verify_client_links(self.tree)

    def test_upstream_changed(self):
        for old, new in (('"https://getdesktop.telegram.org"', '"https://desktop.telegram.org"'),  # another URL
                         ("openWebLink", "openWebClientLink"),                                     # another closure
                         ('"https://telegram.org/apps"', '"https://web.telegram.org/a/"')):        # one more link
            with self.subTest(old=old):
                self.write(sessions=self.SOURCE.replace(old, new))
                with self.assertRaises(patch.PatchError) as e:
                    patch.patch_client_links(self.tree)
                    patch.verify_client_links(self.tree)
                self.assertIn(patch.SESSIONS, str(e.exception))

    def test_table(self):
        self.assertIn(patch.SESSIONS, patch.UPSTREAM_PATHS)
        self.assertIn(patch.QR_SCAN, patch.UPSTREAM_PATHS)
        self.assertIn(patch.STRINGS, patch.UPSTREAM_PATHS)
        for _, text, old, new, _ in patch.CLIENT_LINKS:
            with self.subTest(old=old):
                self.assertEqual(text.count("{url}"), 1)
                self.assertRegex(old, patch.CLIENT_SITES)
                self.assertRegex(new, r"\Ahttps://(web\.)?pluma\.chat/\Z")


class BirthdayTest(unittest.TestCase):
    # The birthday notice of the chat list, each place with the case after it:
    # what a tap does (ChatListControllerNode.swift)...
    TAP = (patch.BIRTHDAY_METHOD_ANCHOR
           + '                        case let .birthdayPremiumGift(peers, birthdays):\n'
           '                            self.effectiveContainerNode.currentItemNode.interaction?.openPremiumGift(peers, birthdays)\n'
           '                        case .reviewLogin:\n'
           '                            break\n')
    # ... its text (ChatListNoticeItem.swift)...
    TEXT = ('            case let .birthdayPremiumGift(peers, _):\n'
            '                let title: String\n'
            '                let text: String\n'
            '                if peers.count == 1, let peer = peers.first {\n'
            '                    var peerName = peer.compactDisplayTitle\n'
            '                    if peerName.count > 20 {\n'
            '                        peerName = peerName.prefix(20).trimmingCharacters(in: .whitespacesAndNewlines) + "\\u{2026}"\n'
            '                    }\n'
            '                    title = item.strings.ChatList_BirthdaySingleTitle(peerName).string\n'
            '                    text = item.strings.ChatList_BirthdaySingleText\n'
            '                } else {\n'
            '                    title = item.strings.ChatList_BirthdayMultipleTitle(Int32(peers.count))\n'
            '                    text = item.strings.ChatList_BirthdayMultipleText\n'
            '                }\n'
            '                avatarPeers = Array(peers.prefix(3))\n'
            '            case let .reviewLogin(newSessionReview, totalCount):\n')
    # ... and its close (GlobalControlPanelsContext.swift), with the toast.
    CLOSE = ('            case .birthdayPremiumGift:\n'
             '                let _ = self.context.engine.notices.dismissServerProvidedSuggestion(suggestion: '
             'ServerProvidedSuggestion.todayBirthdays.id).startStandalone()\n'
             '                parentController.present(UndoOverlayController(presentationData: presentationData, content: '
             '.universal(animation: "anim_gift", scale: 0.058, colors: ["__allcolors__": UIColor.white], title: nil, '
             'text: presentationData.strings.ChatList_PremiumGiftInSettingsInfo, customUndoText: nil, timeout: 5.0), '
             'elevatedLayout: false, action: { _ in\n'
             '                    return true\n'
             '                }), in: .current)\n'
             '            case .premiumGrace:\n')
    KEY = '"ContactList.Context.SendMessage" = "Send Message";\n'
    # The birthday row of a contact's profile (PeerInfoProfileItems.swift): the
    # lines the patch edits.
    PROFILE = "".join(old if old.endswith("\n") else old + "\n" for old, _ in patch.BIRTHDAY_PROFILE)

    def write(self, tap=TAP, text=TEXT, close=CLOSE, key=KEY, profile=PROFILE):
        self.tree.write(patch.CHAT_LIST, tap)
        self.tree.write(patch.CHAT_LIST_NOTICE, text)
        self.tree.write(patch.CHAT_LIST_PANELS, close)
        self.tree.write(patch.STRINGS, key)
        self.tree.write(patch.PROFILE_ITEMS, profile)

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def test_notice(self):
        self.write()
        with self.assertRaises(patch.PatchError):
            patch.verify_birthdays(self.tree)
        patch.patch_birthdays(self.tree)
        patch.verify_birthdays(self.tree)
        # A tap opens the chat: the one contact's, or the chosen one's from
        # the list of them, which goes by name.
        tap = self.tree.read(patch.CHAT_LIST)
        self.assertNotIn("openPremiumGift", tap)
        self.assertTrue(tap.endswith("                        case .reviewLogin:\n                            break\n"))
        self.assertIn("                        case let .birthdayPremiumGift(peers, _):\n"
                      "                            // pluma: no Premium gifts; the chat with the contact (openBirthdayChats).\n"
                      "                            self.openBirthdayChats(peers)\n"
                      "                        case .reviewLogin:\n", tap)
        # The list is a method of its own, before updateNavigationBar.
        self.assertTrue(tap.startswith(patch.BIRTHDAY_METHOD + patch.BIRTHDAY_METHOD_ANCHOR))
        for line in ("    private func openBirthdayChats(_ peers: [EnginePeer]) {\n",
                     "        if peers.count == 1, let peer = peers.first {\n"
                     "            self.effectiveContainerNode.peerSelected?(peer, nil, true, true, nil)\n",
                     "        items.append(ActionSheetTextItem(title: strings.ChatList_BirthdayMultipleTitle(Int32(peers.count))))\n",
                     "            return lhs.title.localizedCaseInsensitiveCompare(rhs.title) == .orderedAscending\n",
                     "        for (peer, title) in named {\n"
                     "            items.append(ActionSheetButtonItem(title: title, action: { [weak self] in\n",
                     "                self?.effectiveContainerNode.peerSelected?(peer, nil, true, true, nil)\n",
                     "ActionSheetButtonItem(title: strings.Common_Cancel, action: { dismissAction() })"):
            self.assertIn(line, tap)
        # The text offers no gift; the rest of the notice is as it was.
        self.assertEqual(self.tree.read(patch.CHAT_LIST_NOTICE), self.TEXT
                         .replace("    case let .birthdayPremiumGift(peers, _):\n",
                                  "    case let .birthdayPremiumGift(peers, _):\n"
                                  '                // pluma: "Send Message", not the offer of a Premium gift: the\n'
                                  "                // notice opens the chat (ChatListControllerNode.swift).\n")
                         .replace("ChatList_BirthdaySingleText", "ContactList_Context_SendMessage")
                         .replace("ChatList_BirthdayMultipleText", "ContactList_Context_SendMessage"))
        # Closing it dismisses it, without the toast about gifts.
        self.assertEqual(self.tree.read(patch.CHAT_LIST_PANELS),
                         "            case .birthdayPremiumGift:\n"
                         "                // pluma: no toast that sends to Settings to gift Premium; they offer no gifts.\n"
                         "                let _ = self.context.engine.notices.dismissServerProvidedSuggestion(suggestion: "
                         "ServerProvidedSuggestion.todayBirthdays.id).startStandalone()\n"
                         "            case .premiumGrace:\n")

    def test_verify(self):
        # Each part of the result is checked on its own.
        for rel, old, new in (
            (patch.CHAT_LIST, "self?.effectiveContainerNode.peerSelected?(peer, nil, true, true, nil)", "dismissAction()"),
            (patch.CHAT_LIST, "                            self.openBirthdayChats(peers)\n",
             "                            self.effectiveContainerNode.currentItemNode.interaction?.openPremiumGift(peers, [:])\n"
             "                            self.openBirthdayChats(peers)\n"),
            (patch.CHAT_LIST_NOTICE, "text = item.strings.ContactList_Context_SendMessage\n                } else {",
             "text = item.strings.ChatList_BirthdaySingleText\n                } else {"),
            (patch.CHAT_LIST_PANELS, "dismissServerProvidedSuggestion(suggestion: ServerProvidedSuggestion.todayBirthdays.id)",
             "dismissServerProvidedSuggestion(suggestion: ServerProvidedSuggestion.setupBirthday.id)"),
            (patch.PROFILE_ITEMS, "icon: canGiftOnBirthday ? .premiumGift : nil", "icon: isBirthdayToday ? .premiumGift : nil"),
            (patch.CHAT_LIST_PANELS, "ServerProvidedSuggestion.todayBirthdays.id).startStandalone()\n",
             "ServerProvidedSuggestion.todayBirthdays.id).startStandalone()\n"
             "                parentController.present(UndoOverlayController(presentationData: presentationData, content: "
             ".universal(animation: \"anim_gift\", scale: 0.058, colors: [\"__allcolors__\": UIColor.white], title: nil, "
             "text: presentationData.strings.ChatList_PremiumGiftInSettingsInfo, customUndoText: nil, timeout: 5.0), "
             "elevatedLayout: false, action: { _ in return true }), in: .current)\n"),
        ):
            with self.subTest(rel=rel, new=new[:60]):
                self.write()
                patch.patch_birthdays(self.tree)
                text = self.tree.read(rel)
                self.assertEqual(text.count(old), 1)
                self.tree.write(rel, text.replace(old, new))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify_birthdays(self.tree)
                self.assertIn(rel, str(e.exception))

    def test_upstream_changed(self):
        for part, old, new, rel in (
            ("tap", "openPremiumGift(peers, birthdays)", "openPremiumGift(peers, birthdays, nil)", patch.CHAT_LIST),
            ("text", "ChatList_BirthdayMultipleText", "ChatList_BirthdayMultipleGiftText", patch.CHAT_LIST_NOTICE),
            ("close", "timeout: 5.0", "timeout: 4.0", patch.CHAT_LIST_PANELS),
            ("key", '"Send Message"', '"Message"', patch.STRINGS),
        ):
            with self.subTest(part=part):
                parts = dict(tap=self.TAP, text=self.TEXT, close=self.CLOSE, key=self.KEY)
                parts[part] = parts[part].replace(old, new)
                self.write(**parts)
                with self.assertRaises(patch.PatchError) as e:
                    patch.patch_birthdays(self.tree)
                self.assertIn(rel, str(e.exception))

    def test_table(self):
        for rel in (patch.CHAT_LIST, patch.CHAT_LIST_NOTICE, patch.CHAT_LIST_PANELS, patch.STRINGS):
            self.assertIn(rel, patch.UPSTREAM_PATHS)
        self.assertEqual([rel for rel, _, _ in patch.BIRTHDAY_CASES],
                         [patch.CHAT_LIST, patch.CHAT_LIST_NOTICE, patch.CHAT_LIST_PANELS])


class IdentityTest(unittest.TestCase):
    # The letter avatars of AvatarNode.swift, with the Saved Messages avatar
    # after them...
    AVATARS = ('    public static let gradientColors: [[UIColor]] = [\n'
               '        [UIColor(rgb: 0xff516a), UIColor(rgb: 0xff885e)],\n'
               '        [UIColor(rgb: 0xffa85c), UIColor(rgb: 0xffcd6a)],\n'
               '        [UIColor(rgb: 0x665fff), UIColor(rgb: 0x82b1ff)],\n'
               '        [UIColor(rgb: 0x54cb68), UIColor(rgb: 0xa0de7e)],\n'
               '        [UIColor(rgb: 0x4acccd), UIColor(rgb: 0x00fcfd)],\n'
               '        [UIColor(rgb: 0x2a9ef1), UIColor(rgb: 0x72d5fd)],\n'
               '        [UIColor(rgb: 0xd669ed), UIColor(rgb: 0xe0a2f3)],\n'
               '    ]\n'
               '    \n'
               '    static let savedMessagesColors: [UIColor] = [\n'
               '        UIColor(rgb: 0x2a9ef1), UIColor(rgb: 0x72d5fd)\n'
               '    ]\n')
    # ... their copies in the extensions...
    COPY = ('private let gradientColors: [NSArray] = [\n'
            '    [UIColor(rgb: 0xff516a).cgColor, UIColor(rgb: 0xff885e).cgColor],\n'
            '    [UIColor(rgb: 0xffa85c).cgColor, UIColor(rgb: 0xffcd6a).cgColor],\n'
            '    [UIColor(rgb: 0x665fff).cgColor, UIColor(rgb: 0x82b1ff).cgColor],\n'
            '    [UIColor(rgb: 0x54cb68).cgColor, UIColor(rgb: 0xa0de7e).cgColor],\n'
            '    [UIColor(rgb: 0x4acccd).cgColor, UIColor(rgb: 0x00fcfd).cgColor],\n'
            '    [UIColor(rgb: 0x2a9ef1).cgColor, UIColor(rgb: 0x72d5fd).cgColor],\n'
            '    [UIColor(rgb: 0xd669ed).cgColor, UIColor(rgb: 0xe0a2f3).cgColor],\n'
            ']\n')
    # ... the name colours (PeerNameColors.swift)...
    NAMES = ('    public static var defaultSingleColors: [Int32: Colors] {\n'
             '        return [\n'
             '            0: Colors(main: UIColor(rgb: 0xcc5049)),\n'
             '            1: Colors(main: UIColor(rgb: 0xd67722)),\n'
             '            2: Colors(main: UIColor(rgb: 0x955cdb)),\n'
             '            3: Colors(main: UIColor(rgb: 0x40a920)),\n'
             '            4: Colors(main: UIColor(rgb: 0x309eba)),\n'
             '            5: Colors(main: UIColor(rgb: 0x368ad1)),\n'
             '            6: Colors(main: UIColor(rgb: 0xc7508b))\n'
             '        ]\n'
             '    }\n'
             '    \n'
             '    public static var defaultValue: PeerNameColors {\n'
             '        return PeerNameColors(\n'
             '            colors: defaultSingleColors,\n'
             '            darkColors: [:],\n'
             '            displayOrder: [5, 3, 1, 0, 2, 4, 6],\n')
    # ... and those TelegramCore takes for the server's colours 0-6 without
    # values (ManagedPeerColorUpdates.swift).
    STATIC = ('                } else if colorId >= 0 && colorId <= 6 {\n'
              '                    let staticMap: [UInt32] = [\n'
              '                        0xcc5049,\n'
              '                        0xd67722,\n'
              '                        0x955cdb,\n'
              '                        0x40a920,\n'
              '                        0x309eba,\n'
              '                        0x368ad1,\n'
              '                        0xc7508b\n'
              '                    ]\n'
              '                    let colorPack = MultiColorPack(colors: [staticMap[Int(colorId)]])\n'
              '                    let defaultColors = EngineAvailableColorOptions.ColorOption(palette: colorPack, '
              'background: colorPack, stories: nil)\n'
              '                    mappedOptions.append(Option(key: colorId, value: ColorOptionPack(light: defaultColors, '
              'dark: nil, isHidden: isHidden, requiredChannelMinBoostLevel: requiredChannelMinBoostLevel, '
              'requiredGroupMinBoostLevel: requiredGroupMinBoostLevel)))\n'
              '                }\n')
    COPIES = (patch.NOTIFICATION_AVATARS, patch.WIDGET_AVATARS, patch.INTENT_AVATARS, patch.LIVE_STREAM_AVATARS)

    def upstream(self):
        files = {patch.AVATAR_NODE: self.AVATARS, patch.PEER_NAME_COLORS: self.NAMES, patch.PEER_COLOR_UPDATES: self.STATIC}
        files.update({rel: self.COPY for rel in self.COPIES})
        return files

    def write(self, over=None):
        files = self.upstream()
        files.update(over or {})
        for rel, text in files.items():
            self.tree.write(rel, text)

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def test_owner_colours(self):
        # Blue is the palette's sage and cyan a teal: the letter avatar from
        # its top to its bottom, the name colour, the one of dark themes,
        # where cyan keeps Telegram's. The other five are Telegram's.
        colours, dark = patch.identity_colours()
        self.assertEqual(colours[5], ((0x5b7a5e, 0x7fa082), 0x4f6e52))
        self.assertEqual(colours[4], ((0x2c9c98, 0x5bcbc4), 0x1f8a80))
        self.assertEqual(dark, {4: 0x309eba, 5: 0x9dbb9f})
        self.assertEqual([c for i, c in enumerate(colours) if i not in (4, 5)],
                         [c for i, c in enumerate(patch.TELEGRAM_IDENTITY) if i not in (4, 5)])

    def test_colours(self):
        self.write()
        with self.assertRaises(patch.PatchError):
            patch.verify_identity(self.tree)
        patch.patch_identity(self.tree)
        patch.verify_identity(self.tree)
        # Two rows of each table; the Saved Messages avatar is the palette's
        # (patch_palette).
        self.assertEqual(self.tree.read(patch.AVATAR_NODE), self.AVATARS.replace(
            "        [UIColor(rgb: 0x4acccd), UIColor(rgb: 0x00fcfd)],\n",
            "        [UIColor(rgb: 0x2c9c98), UIColor(rgb: 0x5bcbc4)], // pluma: teal\n").replace(
            "        [UIColor(rgb: 0x2a9ef1), UIColor(rgb: 0x72d5fd)],\n",
            "        [UIColor(rgb: 0x5b7a5e), UIColor(rgb: 0x7fa082)], // pluma: sage\n"))
        for rel in self.COPIES:
            self.assertEqual(self.tree.read(rel), self.COPY.replace(
                "    [UIColor(rgb: 0x4acccd).cgColor, UIColor(rgb: 0x00fcfd).cgColor],\n",
                "    [UIColor(rgb: 0x2c9c98).cgColor, UIColor(rgb: 0x5bcbc4).cgColor], // pluma: teal\n").replace(
                "    [UIColor(rgb: 0x2a9ef1).cgColor, UIColor(rgb: 0x72d5fd).cgColor],\n",
                "    [UIColor(rgb: 0x5b7a5e).cgColor, UIColor(rgb: 0x7fa082).cgColor], // pluma: sage\n"))
        # The name colours, and those of dark themes.
        self.assertEqual(self.tree.read(patch.PEER_NAME_COLORS), self.NAMES.replace(
            "            4: Colors(main: UIColor(rgb: 0x309eba)),\n",
            "            4: Colors(main: UIColor(rgb: 0x1f8a80)), // pluma: teal\n").replace(
            "            5: Colors(main: UIColor(rgb: 0x368ad1)),\n",
            "            5: Colors(main: UIColor(rgb: 0x4f6e52)), // pluma: sage\n").replace(
            "            darkColors: [:],\n",
            "            // pluma: Pluma's cyan and blue have colours of their own in dark themes.\n"
            "            darkColors: [\n"
            "                4: Colors(main: UIColor(rgb: 0x309eba)),\n"
            "                5: Colors(main: UIColor(rgb: 0x9dbb9f))\n"
            "            ],\n"))
        updates = self.tree.read(patch.PEER_COLOR_UPDATES)
        for line in ("                        0x40a920,\n                        0x1f8a80, // pluma: teal\n"
                     "                        0x4f6e52, // pluma: sage\n                        0xc7508b\n",
                     "                    let staticDarkMap: [Int32: UInt32] = [4: 0x309eba, 5: 0x9dbb9f]\n",
                     "                    let defaultDarkColors = staticDarkMap[colorId].map { darkColor -> "
                     "EngineAvailableColorOptions.ColorOption in\n",
                     "ColorOptionPack(light: defaultColors, dark: defaultDarkColors, isHidden: isHidden,"):
            self.assertIn(line, updates)
        self.assertTrue(updates.endswith("requiredGroupMinBoostLevel: requiredGroupMinBoostLevel)))\n                }\n"))

    def test_upstream_changed(self):
        # Every table must hold Telegram's seven, in order.
        for rel, old, new in (
            (patch.AVATAR_NODE, "0x00fcfd", "0x00fcfe"),                                      # cyan
            (patch.AVATAR_NODE, "0xff516a", "0xff516b"),                                      # one of the other five
            (patch.WIDGET_AVATARS, "]\n", "    [UIColor(rgb: 0x8e8e93).cgColor, UIColor(rgb: 0xb1b1b1).cgColor],\n]\n"),
            (patch.LIVE_STREAM_AVATARS, "private let gradientColors: [NSArray]", "private let avatarColors: [NSArray]"),
            (patch.PEER_NAME_COLORS, "0x368ad1", "0x3d72ed"),                                 # blue
            (patch.PEER_NAME_COLORS, "darkColors: [:],", "darkColors: defaultDarkColors,"),   # dark colours of its own
            (patch.PEER_COLOR_UPDATES, "0x309eba", "0x309ebb"),
            (patch.PEER_COLOR_UPDATES, "dark: nil,", "dark: defaultColors,"),
        ):
            with self.subTest(rel=rel, new=new[:40]):
                text = self.upstream()[rel]
                self.assertEqual(text.count(old), 1)
                self.write({rel: text.replace(old, new)})
                with self.assertRaises(patch.PatchError) as e:
                    patch.patch_identity(self.tree)
                self.assertIn(rel, str(e.exception))

    def test_verify(self):
        # Each table and both dark ones are checked on their own.
        for rel, old, new in (
            (patch.AVATAR_NODE, "[UIColor(rgb: 0x5b7a5e), UIColor(rgb: 0x7fa082)]", "[UIColor(rgb: 0x2a9ef1), UIColor(rgb: 0x72d5fd)]"),
            (patch.INTENT_AVATARS, "[UIColor(rgb: 0x5b7a5e).cgColor, UIColor(rgb: 0x7fa082).cgColor]",
             "[UIColor(rgb: 0x7fa082).cgColor, UIColor(rgb: 0x5b7a5e).cgColor]"),          # upside down
            (patch.NOTIFICATION_AVATARS, "UIColor(rgb: 0x5bcbc4).cgColor", "UIColor(rgb: 0x00fcfd).cgColor"),
            (patch.PEER_NAME_COLORS, "5: Colors(main: UIColor(rgb: 0x4f6e52))", "5: Colors(main: UIColor(rgb: 0x368ad1))"),
            (patch.PEER_NAME_COLORS, "                5: Colors(main: UIColor(rgb: 0x9dbb9f))\n", ""),
            (patch.PEER_COLOR_UPDATES, "0x1f8a80, // pluma: teal", "0x309eba,"),
            (patch.PEER_COLOR_UPDATES, "dark: defaultDarkColors,", "dark: nil,"),
        ):
            with self.subTest(rel=rel, old=old[:40]):
                self.write()
                patch.patch_identity(self.tree)
                text = self.tree.read(rel)
                self.assertEqual(text.count(old), 1)
                self.tree.write(rel, text.replace(old, new))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify_identity(self.tree)
                self.assertIn(rel, str(e.exception))

    def test_table(self):
        self.assertEqual(len(patch.TELEGRAM_IDENTITY), 7)
        self.assertLessEqual(set(patch.IDENTITY_COLOURS), set(range(7)))
        for rel, head, row, tail, _ in patch.IDENTITY_TABLES:
            with self.subTest(rel=rel):
                self.assertTrue(any(rel == p or rel.startswith(p + "/") for p in patch.UPSTREAM_PATHS))
                self.assertIn(row.count("{bottom}") + row.count("{top}") + row.count("{colour}"), (1, 2))
                self.assertTrue(head.endswith("[\n") and tail.endswith("\n"))


# --- the patch on the pinned upstream ------------------------------------------

NETWORK, ACCOUNT, AUTH_KEYS, ENCRYPTION = patch.NETWORK, patch.ACCOUNT, patch.AUTH_KEYS, patch.ENCRYPTION
BACKUP, DNS, CALLS, BUILD, MAKE = patch.BACKUP, patch.DNS, patch.CALLS, patch.APP_BUILD, patch.MAKE
APP_DELEGATE, INTRO = patch.APP_DELEGATE, patch.INTRO_ANIMATIONS

# Damage to each place the patch edits or checks, as (file, text in the
# pinned upstream, replacement): every one must stop the patch with an error
# that names the file.
DAMAGE = (
    (patch.SERIALIZATION, "        return 228\n", "        return 229\n"),
    (patch.VERSIONS, '"app": "12.9.2"', '"app": "12.9.3"'),
    (patch.VERSIONS, '"xcode": "26.2"', '"xcode": "26.3"'),
    (patch.VERSIONS, '"bazel": "8.4.2:', '"bazel": "8.5.0:'),
    (MAKE, "elif configuration == 'debug_sim_arm64':", "elif configuration == 'debug_sim':"),
    (MAKE, "codesigning_group.add_argument(\n        '--xcodeManagedCodesigning',",
     "codesigning_group.add_argument(\n        '--xcodeManaged',"),
    (MAKE, "cacheTypeGroup.add_argument(\n        '--cacheDir',", "cacheTypeGroup.add_argument(\n        '--cachePath',"),
    (patch.BUILD_CONFIGURATION, "'.SiriIntents': 'Intents',", "'.Intents': 'Intents',"),
    (patch.BUILD_CONFIGURATION, "'enable_icloud'\n        ]", "'enable_icloud',\n            'enable_carplay'\n        ]"),
    (BUILD, '            ":WidgetExtension",\n', '            ":WidgetExtension",\n            ":WatchExtension",\n'),
    (BUILD, '    name = "disableProvisioningProfiles",\n', '    name = "noProvisioningProfiles",\n'),
    (BUILD, "<string>group.{telegram_bundle_id}</string>", "<string>group.{telegram_bundle_id}.shared</string>"),
    (BUILD, "<string>Telegram</string>\n    <key>CFBundleIdentifier</key>",
     "<string>Telegram Messenger</string>\n    <key>CFBundleIdentifier</key>"),
    (BUILD, "                <string>telegram</string>\n", "                <string>telegram-app</string>\n"),
    (NETWORK, '1: ["149.154.175.50", "2001:b28:f23d:f001::a"]', '1: ["149.154.175.51", "2001:b28:f23d:f001::a"]'),
    (NETWORK, "MTDatacenterAddress(ip: $0, port: 443,", "MTDatacenterAddress(ip: $0, port: 80,"),
    (NETWORK, "if #available(iOS 10.0, *), !supplementary, arguments.isICloudEnabled {",
     "if #available(iOS 11.0, *), !supplementary, arguments.isICloudEnabled {"),
    (NETWORK, "phoneNumber: phoneNumber, mainDatacenterId: datacenterId))",
     "phoneNumber: phoneNumber, mainDatacenterId: datacenterId, delay: 0))"),
    (ACCOUNT, "let initialDatacenterId: Int = 2", "let initialDatacenterId: Int = 4"),
    (ACCOUNT, "datacenterIds.append(contentsOf: [4])", "datacenterIds.append(contentsOf: [4, 5])"),
    (AUTH_KEYS, '             "MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR\\n"\n',
     '             "MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIr\\n"\n'),
    (ENCRYPTION, "MIIBCgKCAQEAyr+18Rex2ohtVy8sroGPBwXD3DOoKCSpjDqYoXgCqB7ioln4eDCF",
     "MIIBCgKCAQEAyr+18Rex2ohtVy8sroGPBwXD3DOoKCSpjDqYoXgCqB7ioln4eDCG"),
    (BACKUP, "MTSignal *signal = [self fetchConfigFromAddress:address", "MTSignal *signal = [self fetchConfigFrom:address"),
    (BACKUP, "mainDatacenterId:(NSInteger)mainDatacenterId {\n    NSMutableArray",
     "mainDatacenterId:(NSInteger)mainDatacenterId delay:(double)delay {\n    NSMutableArray"),
    (DNS, "timeout:10.0 onQueue:[MTQueue concurrentDefaultQueue] orSignal", "timeout:5.0 onQueue:[MTQueue concurrentDefaultQueue] orSignal"),
    (CALLS, 'ip: "91.108.9.38",', 'ip: "91.108.9.39",'),
    (patch.BAZELRC, "build --action_env=ZERO_AR_DATE=1\n", "build --action_env=ZERO_AR_DATE=1\ntry-import %workspace%/user.bazelrc\n"),
    # The brand.
    (BUILD, '    "PremiumTurbo",\n]\n', '    "PremiumTurbo",\n    "Premium2",\n]\n'),
    (APP_DELEGATE, 'PresentationAppIcon(name: "New2", imageName: "New2"),', 'PresentationAppIcon(name: "New3", imageName: "New3"),'),
    (INTRO, "cloud_color = {42/255., 180/255., 247/255., 1};", "cloud_color = {42/255., 181/255., 247/255., 1};"),
    (INTRO, "powerful_bg_color = {47/255., 90/255., 131/255., 1};", "powerful_bg_color = {47/255., 90/255., 132/255., 1};"),
    (patch.APP_ICON + "/icon.json", '"image-name" : "Plane.svg"', '"image-name" : "Plane2.svg"'),
    # The names.
    (patch.STRINGS, '"Watch.AppName" = "Telegram";\n', '"Watch.AppName" = "Watch";\n'),
    (patch.STRINGS, '"Application.Name" = "Telegram";\n', '"Application.Name" = "Telegram";\n"Application.Title" = "Telegram";\n'),
    (patch.INFOPLIST_STRINGS.format("ru"), "облаке Telegram", "облаке Телеграм"),
    (patch.INFOPLIST_STRINGS.format("ko"), '"CFBundleDisplayName" = "텔레그램";', '"CFBundleDisplayName" = "Telegram";'),
    (BUILD, "<string>Telegram iOS Color Theme File</string>", "<string>Telegram Color Theme File</string>"),
    (BUILD, "your friends, Telegram needs access to show them a map. You also", "your friends, Telegram needs access to show them the map. You also"),
    ("submodules/TelegramUI/Sources/StoreDownloadedMedia.swift", 'let albumName = "Telegram"', 'let albumName = "Telegram Media"'),
    ("submodules/TelegramUI/Sources/DeviceContactDataManager.swift", 'if address.label == "Telegram", let peerId',
     'if address.label == "Telegram" || address.label == "TG", let peerId'),
    # The scheme.
    (BUILD, "                <string>tg</string>\n", "                <string>tg</string>\n                <string>tgapp</string>\n"),
    # The palette.
    (patch.DAY_THEME, "public let defaultDayAccentColor = UIColor(rgb: 0x0088ff)", "public let defaultDayAccentColor = UIColor(rgb: 0x0087ff)"),
    (patch.DAY_THEME, "accentControlColor: UIColor(rgb: 0x3fc33b),", "accentControlColor: UIColor(rgb: 0x3fc33c),"),
    (patch.DARK_THEME, "fill: [UIColor(rgb: 0x61BCF9), UIColor(rgb: 0x0088ff)],", "fill: [UIColor(rgb: 0x61BCF9), UIColor(rgb: 0x0077ff)],"),
    (patch.DARK_THEME, "mediaControlInnerBackgroundColor:  UIColor(rgb: 0x313131)", "mediaControlInnerBackgroundColor:  UIColor(rgb: 0x323232)"),
    (patch.PRESENTATION_DATA, "effectiveColors = PresentationThemeAccentColor(baseColor: .blue)\n",
     "effectiveColors = PresentationThemeAccentColor(baseColor: .cyan)\n"),
    (patch.THEME_SETTINGS, "                value = 0x0088ff\n", "                value = 0x0089ff\n"),
    (patch.LEGACY_COLORS, "TGColorWithHex(0x0088ff)", "TGColorWithHex(0x0089ff)"),
    (patch.AVATAR_NODE, "UIColor(rgb: 0x2a9ef1), UIColor(rgb: 0x72d5fd)\n    ]", "UIColor(rgb: 0x2a9ef1), UIColor(rgb: 0x72d5fe)\n    ]"),
    (patch.AVATAR_NODE, "UIColor(rgb: 0x3DA1FD), UIColor(rgb: 0x34C76F)", "UIColor(rgb: 0x3DA1FD), UIColor(rgb: 0x34C76E)"),
    # People's identity colours: each table holds Telegram's seven.
    (patch.AVATAR_NODE, "[UIColor(rgb: 0x4acccd), UIColor(rgb: 0x00fcfd)],", "[UIColor(rgb: 0x4acccd), UIColor(rgb: 0x00fcfe)],"),
    (patch.NOTIFICATION_AVATARS, "[UIColor(rgb: 0xff516a).cgColor, UIColor(rgb: 0xff885e).cgColor],",
     "[UIColor(rgb: 0xff516b).cgColor, UIColor(rgb: 0xff885e).cgColor],"),
    (patch.WIDGET_AVATARS, "[UIColor(rgb: 0x2a9ef1).cgColor, UIColor(rgb: 0x72d5fd).cgColor],",
     "[UIColor(rgb: 0x2a9ef2).cgColor, UIColor(rgb: 0x72d5fd).cgColor],"),
    (patch.INTENT_AVATARS, "    [UIColor(rgb: 0xd669ed).cgColor, UIColor(rgb: 0xe0a2f3).cgColor],\n]\n",
     "    [UIColor(rgb: 0xd669ed).cgColor, UIColor(rgb: 0xe0a2f3).cgColor],\n"
     "    [UIColor(rgb: 0x8e8e93).cgColor, UIColor(rgb: 0xb1b1b1).cgColor],\n]\n"),
    (patch.LIVE_STREAM_AVATARS, "[UIColor(rgb: 0x4acccd).cgColor, UIColor(rgb: 0x00fcfd).cgColor],",
     "[UIColor(rgb: 0x4acccd).cgColor, UIColor(rgb: 0x00fcfe).cgColor],"),
    (patch.PEER_NAME_COLORS, "5: Colors(main: UIColor(rgb: 0x368ad1)),", "5: Colors(main: UIColor(rgb: 0x3d72ed)),"),
    (patch.PEER_NAME_COLORS, "            darkColors: [:],\n            displayOrder:",
     "            darkColors: defaultDarkColors,\n            displayOrder:"),
    (patch.PEER_COLOR_UPDATES, "                        0x309eba,\n", "                        0x309ebb,\n"),
    (patch.PEER_COLOR_UPDATES, "ColorOptionPack(light: defaultColors, dark: nil,", "ColorOptionPack(light: defaultColors, dark: defaultColors,"),
    # Telegram's support.
    (patch.SETTINGS_ITEMS, "interaction.openSettings(.faq)", "interaction.openSettings(.faqPage)"),
    (patch.SETTINGS_SEARCH, "        allItems.append(contentsOf: helpItems)\n", "        allItems += helpItems\n"),
    ("submodules/QrCodeUI/Sources/QrCodeScanScreen.swift", 'filteredCodes = codes.filter { $0.message.hasPrefix("tg://") }',
     'filteredCodes = codes.filter { $0.message.hasPrefix("tg://login") }'),
    ("submodules/TelegramUI/Components/ShareExtensionContext/Sources/ShareExtensionContext.swift",
     'self.openUrl("tg://shareStory?session=', 'self.openUrl("tg://share-story?session='),
    (patch.URL_HANDLING, "    if let parsedUrl = URL(string: url), parsedUrl.scheme == \"tg\", let host = parsedUrl.host, let query = parsedUrl.query {\n"
     "        if let internalUrl = parseInternalUrl(sharedContext: sharedContext, context: context, query: host + \"?\" + query), case .peer",
     "    if let parsedUrl = URL(string: url), [\"tg\"].contains(parsedUrl.scheme), let host = parsedUrl.host, let query = parsedUrl.query {\n"
     "        if let internalUrl = parseInternalUrl(sharedContext: sharedContext, context: context, query: host + \"?\" + query), case .peer"),
    # The links of Settings > Devices.
    (patch.SESSIONS, 'url: "https://getdesktop.telegram.org", forceExternal', 'url: "https://desktop.telegram.org", forceExternal'),
    (patch.SESSIONS, "    }, openWebLink: {\n", "    }, openWebClientLink: {\n"),
    (patch.SESSIONS, 'url: "https://telegram.org/apps", forceExternal', 'url: "https://web.telegram.org/a/", forceExternal'),
    (patch.QR_SCAN, 'url: "https://getdesktop.telegram.org", forceExternal', 'url: "https://desktop.telegram.org", forceExternal'),
    (patch.STRINGS, "or [web.telegram.org](web) to get the QR code", "or [web.telegram.org](web) to get a QR code"),
    # The birthday notice of the chat list.
    (patch.CHAT_LIST, "interaction?.openPremiumGift(peers, birthdays)", "interaction?.openPremiumGift(peers, birthdays, nil)"),
    (patch.CHAT_LIST_NOTICE, "text = item.strings.ChatList_BirthdaySingleText", "text = item.strings.ChatList_BirthdaySingleGiftText"),
    (patch.CHAT_LIST_PANELS, "ServerProvidedSuggestion.todayBirthdays.id).startStandalone()\n"
     "                parentController.present(UndoOverlayController(",
     "ServerProvidedSuggestion.todayBirthdays.id).start()\n"
     "                parentController.present(UndoOverlayController("),
    (patch.STRINGS, '"ContactList.Context.SendMessage" = "Send Message";', '"ContactList.Context.SendMessage" = "Message";'),
    # The birthday row of a contact's profile.
    (patch.PROFILE_ITEMS, "} else if isBirthdayToday && cachedData.disallowedGifts != TelegramDisallowedGifts.All {",
     "} else if isBirthdayToday && cachedData.disallowedGifts.isEmpty {"),
    (patch.PROFILE_ITEMS, "icon: isBirthdayToday ? .premiumGift : nil, action: birthdayAction,",
     "icon: isBirthdayToday ? .gift : nil, action: birthdayAction,"),
    # Traces of Telegram elsewhere in the network code.
    (NETWORK, "            context.keychain = keychain\n",
     '            context.keychain = keychain\n            let fallbackAddress = "149.154.167.51"\n'),
    (CALLS, "                var reflectorIdList: [Int64] = []\n",
     '                let benchmarkReflector = "2001:67c:4e8:f004::b"\n                var reflectorIdList: [Int64] = []\n'),
    (AUTH_KEYS, "static MTDatacenterAuthPublicKey *selectPublicKey(",
     "// MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\nstatic MTDatacenterAuthPublicKey *selectPublicKey("),
    ("submodules/MtProtoKit/Sources/MTContext.m", "@implementation MTContext\n",
     '@implementation MTContext\nstatic NSString *extraKey = @"-----BEGIN RSA PUBLIC KEY-----\\n"\n'
     + "".join(f'"{l}\\n"\n' for l in DEV_KEY.strip().splitlines()[1:-1]) + '"-----END RSA PUBLIC KEY-----";\n'),
)


def upstream_files():
    """The files the patch reads, as {path: bytes} of the pinned commit, or
    None without a checkout of it in ./upstream (ci/fetch-upstream.sh)."""
    env = patch.load_env(ROOT / "upstream.env")
    git = ["git", "-C", str(ROOT / "upstream")]
    try:
        head = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    if head != env["UPSTREAM_REF"]:
        return None
    archive = subprocess.run(git + ["archive", "--format=tar", "HEAD", *patch.UPSTREAM_PATHS],
                             capture_output=True, check=True).stdout
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for m in tar.getmembers():
            if m.isfile():
                files[m.name] = tar.extractfile(m).read()
    return files


class RecordingTree(patch.Tree):
    """A tree that remembers what the patch wrote or removed."""

    def __init__(self, root, written):
        super().__init__(root)
        self.written = written

    def write_bytes(self, rel, data):
        self.written.add(str(rel))
        super().write_bytes(rel, data)

    def unlink(self, rel):
        self.written.add(str(rel))
        super().unlink(rel)


@unittest.skipIf(not os.environ.get("CI") and upstream_files() is None,
                 "no checkout of the pinned upstream (ci/fetch-upstream.sh sparse)")
class UpstreamTest(unittest.TestCase):
    """The patch on the commit upstream.env pins. CI fetches it first, and
    there these tests never skip."""

    @classmethod
    def setUpClass(cls):
        cls.files = upstream_files()
        if cls.files is None:
            raise AssertionError("no checkout of the pinned upstream in ./upstream (ci/fetch-upstream.sh sparse)")
        cls.dir = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.dir.name)
        for name, data in cls.files.items():
            p = cls.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        self.written = set()

    def tearDown(self):
        # Back to the pinned upstream: what the patch or a test wrote.
        for rel in self.written:
            if rel in self.files:
                (self.root / rel).write_bytes(self.files[rel])
            else:
                (self.root / rel).unlink(missing_ok=True)
        self.written.clear()

    def run_patch(self, **over):
        c = config(**over)
        tree = RecordingTree(self.root, self.written)
        patch.patch(tree, c)
        patch.verify(tree, c)
        return tree, c

    def test_patch(self):
        tree, c = self.run_patch(server_ipv6="2001:db8::7", server_port="8443")
        net = tree.read(NETWORK)
        self.assertIn('                1: ["203.0.113.7", "2001:db8::7"]\n', net)
        self.assertIn("MTDatacenterAddress(ip: $0, port: 8443, ", net)
        self.assertNotIn("= makeCloudDataContext(", net)
        self.assertNotIn("wrappedAdditionalSource", net)
        account = tree.read(ACCOUNT)
        self.assertIn("            let datacenterIds: [Int] = [1]\n", account)
        self.assertNotIn("#if DEBUG\n                        let initialDatacenterId", account)
        keys = tree.read(AUTH_KEYS)
        self.assertEqual(keys.count(c.rsa_pem[1]), 2)
        self.assertEqual(tree.read(ENCRYPTION).count(c.rsa_pem[1]), 1)
        self.assertIn("    return [MTSignal complete];\n}\n\n@end\n", tree.read(BACKUP))
        self.assertIn("    return [self resolveHostnameNative:hostname port:port];\n", tree.read(DNS))
        self.assertNotIn("CallSessionConnection.Reflector(", tree.read(CALLS))
        build = tree.read(BUILD)
        self.assertEqual(build.count("<string>Pluma</string>"), 9)
        self.assertIn("                <string>plm</string>\n", build)
        conf = json.loads(tree.read(patch.CONFIGURATION))
        self.assertEqual(conf["team_id"], "ABCDE12345")
        self.assertEqual(set(conf), patch.required_configuration_keys(tree))
        self.assertTrue(tree.read(patch.BAZELRC).endswith("try-import %workspace%/pluma.bazelrc\n"))
        # The brand: Pluma's images, one alternate icon, the intro in sage.
        for rel in list(patch.BRAND_REPLACED) + list(patch.BRAND_ADDED):
            self.assertEqual((self.root / rel).read_bytes(), (patch.BRAND / rel).read_bytes(), rel)
        for rel in patch.BRAND_REMOVED:
            self.assertFalse((self.root / rel).exists(), rel)
        self.assertIn('alternate_icon_folders = [\n    "BlueIcon",\n]\n', build)
        self.assertEqual(tree.read(APP_DELEGATE).count("PresentationAppIcon("), 1)
        self.assertIn("vec4 cloud_color = {111/255., 143/255., 114/255., 1};", tree.read(INTRO))
        # The names.
        strings = tree.read(patch.STRINGS)
        for entry in ('"Application.Name" = "Pluma";', '"Tour.Title1" = "Pluma";', '"Settings.FAQ" = "Pluma FAQ";',
                      '"Passcode.AppLockedAlert" = "Pluma\\nLocked";', '"Conversation.UpdateTelegram" = "UPDATE PLUMA";',
                      '"Settings.TipsUsername" = "TelegramTips";', '"Settings.FAQ_URL" = "https://telegram.org/faq#general";'):
            self.assertIn(entry, strings)
        self.assertIn('"CFBundleDisplayName" = "Pluma";', tree.read(patch.INFOPLIST_STRINGS.format("ar")))
        self.assertIn('"CFBundleDisplayName" = "Pluma";', tree.read(patch.INFOPLIST_STRINGS.format("ko")))
        self.assertIn("위치를 지도에 표시하기 위해 Pluma가 위치", tree.read(patch.INFOPLIST_STRINGS.format("ko")))
        self.assertIn("<string>Pluma stores your contacts heavily encrypted", build)
        self.assertIn('CXProviderConfiguration(localizedName: "Pluma")',
                      tree.read("submodules/TelegramCallsUI/Sources/CallKitIntegration.swift"))
        # plm:// instead of tg://.
        self.assertNotIn("<string>tg</string>", build)
        self.assertIn('let urlString = "plm://login?token=\\(tokenString)"',
                      tree.read("submodules/AuthorizationUI/Sources/AuthorizationSequencePhoneEntryControllerNode.swift"))
        self.assertIn('codes.filter { $0.message.hasPrefix("plm://") }', tree.read("submodules/QrCodeUI/Sources/QrCodeScanScreen.swift"))
        self.assertEqual(tree.read(patch.URL_HANDLING).count(patch.URL_HANDLING_OWN), 4)
        # Settings > Devices: Pluma's site and web client behind the header,
        # whose text names no site; "Learn More" is left as it is.
        sessions = tree.read(patch.SESSIONS)
        self.assertIn('url: "https://pluma.chat/", forceExternal: true', sessions)
        self.assertIn('url: "https://web.pluma.chat/", forceExternal: true', sessions)
        self.assertIn('url: "https://telegram.org/apps", forceExternal: true', sessions)
        self.assertIn('"AuthSessions.HeaderInfo" = "Link [Pluma Desktop](desktop) or [Pluma Web](web) by scanning a QR code.";',
                      strings)
        # Its QR scanner names and opens the same two sites.
        scan = tree.read(patch.QR_SCAN)
        self.assertIn('url: "https://pluma.chat/", forceExternal: true', scan)
        self.assertIn('url: "https://web.pluma.chat/", forceExternal: true', scan)
        self.assertNotRegex(scan, patch.CLIENT_SITES)
        self.assertIn('"AuthSessions.AddDevice.ScanInstallInfo" = "Go to [pluma.chat](desktop) or [web.pluma.chat](web) to get the QR code";',
                      strings)
        # The palette.
        day, dark = tree.read(patch.DAY_THEME), tree.read(patch.DARK_THEME)
        self.assertIn("public let defaultDayAccentColor = UIColor(rgb: 0x5b7a5e)", day)
        self.assertEqual(day.count("fill: [UIColor(rgb: 0xe3eae2), UIColor(rgb: 0xd5e1d4)],"), 2)
        self.assertIn("let defaultPatternWallpaper: TelegramWallpaper = .color(0xffffff)\n", day)
        self.assertEqual(dark.count("fill: [UIColor(rgb: 0x2c3a2d), UIColor(rgb: 0x36473a)],"), 2)
        self.assertIn("secondaryTextColor: UIColor(rgb: 0xb2ceb4), linkTextColor: UIColor(rgb: 0xb2ceb4),", dark)
        self.assertIn("let defaultPatternWallpaper: TelegramWallpaper = .color(0x131513)\n", dark)
        self.assertNotIn("baseColor: .blue", tree.read(patch.PRESENTATION_DATA))
        avatars = tree.read(patch.AVATAR_NODE)
        self.assertIn("    static let savedMessagesColors: [UIColor] = [\n"
                      "        UIColor(rgb: 0x5b7a5e), UIColor(rgb: 0x9dbb9f) // pluma: sage\n", avatars)
        self.assertIn("    static let repostColors: [UIColor] = [\n"
                      "        UIColor(rgb: 0x4f6e52), UIColor(rgb: 0x9dbb9f) // pluma: sage\n", avatars)
        # People's identity colours: blue is sage and cyan a teal, in the
        # letter avatars of the app and its extensions, the names and, in dark
        # themes, names of their own; the other five are Telegram's.
        self.assertIn("        [UIColor(rgb: 0x5b7a5e), UIColor(rgb: 0x7fa082)], // pluma: sage\n", avatars)
        self.assertIn("        [UIColor(rgb: 0x2c9c98), UIColor(rgb: 0x5bcbc4)], // pluma: teal\n", avatars)
        self.assertIn("        [UIColor(rgb: 0xff516a), UIColor(rgb: 0xff885e)],\n", avatars)
        for rel in (patch.NOTIFICATION_AVATARS, patch.WIDGET_AVATARS, patch.INTENT_AVATARS, patch.LIVE_STREAM_AVATARS):
            self.assertIn("    [UIColor(rgb: 0x5b7a5e).cgColor, UIColor(rgb: 0x7fa082).cgColor], // pluma: sage\n", tree.read(rel))
        names = tree.read(patch.PEER_NAME_COLORS)
        self.assertIn("            5: Colors(main: UIColor(rgb: 0x4f6e52)), // pluma: sage\n", names)
        self.assertIn("            3: Colors(main: UIColor(rgb: 0x40a920)),\n", names)
        self.assertIn("            darkColors: [\n                4: Colors(main: UIColor(rgb: 0x309eba)),\n"
                      "                5: Colors(main: UIColor(rgb: 0x9dbb9f))\n            ],\n", names)
        updates = tree.read(patch.PEER_COLOR_UPDATES)
        self.assertIn("                        0x4f6e52, // pluma: sage\n", updates)
        self.assertIn("                    let staticDarkMap: [Int32: UInt32] = [4: 0x309eba, 5: 0x9dbb9f]\n", updates)
        # No support section.
        self.assertNotIn("Settings_Support", tree.read(patch.SETTINGS_ITEMS))
        self.assertNotIn("let helpItems = ", tree.read(patch.SETTINGS_SEARCH))
        # The birthday notice opens the chat, says "Send Message" and no longer
        # offers a gift; closing it still dismisses it.
        chat_list = tree.read(patch.CHAT_LIST)
        self.assertIn(patch.BIRTHDAY_OPEN, chat_list)
        self.assertIn(patch.BIRTHDAY_METHOD + patch.BIRTHDAY_METHOD_ANCHOR, chat_list)
        self.assertEqual(chat_list.count("for (peer, title) in named {\n"), 1)
        self.assertNotIn("openPremiumGift(peers, birthdays)", chat_list)
        self.assertIn("openPremiumGift([], nil)", chat_list)  # the Christmas notice's, kept
        notice = tree.read(patch.CHAT_LIST_NOTICE)
        self.assertEqual(notice.count("text = item.strings.ContactList_Context_SendMessage\n"), 2)
        self.assertNotIn("ChatList_BirthdaySingleText", notice)
        self.assertNotIn("ChatList_BirthdayMultipleText", notice)
        panels = tree.read(patch.CHAT_LIST_PANELS)
        self.assertIn(patch.BIRTHDAY_CLOSE, panels)
        self.assertEqual(panels.count("ChatList_PremiumGiftInSettingsInfo"), 1)  # the Christmas notice's, kept
        self.assertIn('"ContactList.Context.SendMessage" = "Send Message";', strings)
        # The birthday row of a contact's profile offers a gift only while
        # Premium can be bought.
        profile = tree.read(patch.PROFILE_ITEMS)
        self.assertIn("let canGiftOnBirthday = isBirthdayToday && !PremiumConfiguration.with(", profile)
        self.assertIn("} else if canGiftOnBirthday && cachedData.disallowedGifts != TelegramDisallowedGifts.All {", profile)
        self.assertIn("icon: canGiftOnBirthday ? .premiumGift : nil, action: birthdayAction,", profile)

    def test_dev_server(self):
        dev = patch.load_env(ROOT / "config/dev/server.env")
        tree, _ = self.run_patch(server_ipv4=dev["PLUMA_SERVER_IPV4"], server_port=dev["PLUMA_SERVER_PORT"],
                                 rsa_pem=DEV_KEY, team_id=dev["PLUMA_TEAM_ID"])
        net = tree.read(NETWORK)
        self.assertIn('                1: ["127.0.0.1"]\n', net)
        self.assertIn("MTDatacenterAddress(ip: $0, port: 10443, ", net)

    def test_patched_tree_is_refused(self):
        self.run_patch()
        with self.assertRaises(patch.PatchError):
            self.run_patch()

    def test_damaged_images(self):
        # A changed or missing upstream image stops the patch too.
        for rel in ("Telegram/Telegram-iOS/BlueIcon.alticon/BlueIcon@3x.png", "Telegram/Telegram-iOS/Resources/PlaneLogo.tgs",
                    "Telegram/Telegram-iOS/Resources/Devices.tgs",
                    "submodules/TelegramUI/Images.xcassets/Chat/Context Menu/Telegram.imageset/tlogo_24.pdf",
                    patch.APP_ICON + "/Assets/Oval.svg"):
            for damage in ("byte", "missing"):
                with self.subTest(rel=rel, damage=damage):
                    self.tearDown()
                    self.written.add(rel)
                    if damage == "byte":
                        data = bytearray(self.files[rel])
                        data[-1] ^= 1
                        (self.root / rel).write_bytes(bytes(data))
                    else:
                        (self.root / rel).unlink()
                    with self.assertRaises(patch.PatchError) as e:
                        self.run_patch()
                    self.assertIn(rel, str(e.exception))
        # A file of Pluma's icon that upstream has already.
        self.tearDown()
        rel = patch.BRAND_ADDED[0]
        self.written.add(rel)
        (self.root / rel).write_bytes(b"\x89PNG")
        with self.assertRaises(patch.PatchError) as e:
            self.run_patch()
        self.assertIn(rel, str(e.exception))

    def test_damage(self):
        for rel, old, new in DAMAGE:
            with self.subTest(rel=rel, old=old[:60]):
                self.tearDown()
                text = self.files[rel].decode("utf-8")
                self.assertIn(old, text, "the damage does not apply to the pinned upstream")
                self.written.add(rel)
                (self.root / rel).write_text(text.replace(old, new), encoding="utf-8")
                with self.assertRaises(patch.PatchError) as e:
                    self.run_patch()
                self.assertIn(pathlib.PurePath(rel).name, str(e.exception))


if __name__ == "__main__":
    unittest.main()
