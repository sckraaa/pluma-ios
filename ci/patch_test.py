#!/usr/bin/env python3
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
        self.assertIn("                <string>pluma</string>\n", build)
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
