#!/usr/bin/env python3
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import plistlib
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
import zlib

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

# brand/mark_write.py, which writes the mark of the intro's first page, and the
# animation it writes from the kit's mark.
MARK_WRITE_SHA256 = "3a100a36a7897718d523ef76c64595e2bbb1e64ce4b7dc0cc652543871016966"
INTRO_MARK_SHA256 = "f5d89139ddab9cc3d1ffb2ec42c574307c37e92eb92f5d2413e8fc0855221c41"


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
        self.assertEqual((c.bundle_id, c.app_name, c.api_id, c.layer), ("chat.pluma.app", "Pluma", 10002, 233))
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


def png_header(path):
    """Width, height, bit depth and colour type of a PNG."""
    data = pathlib.Path(path).read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError(f"{path}: not a PNG")
    return struct.unpack(">IIBB", data[16:26])


def png_rgba(path):
    """The rows of an 8-bit RGBA PNG without interlacing, each as bytes
    R, G, B, A per pixel: (width, height, rows)."""
    data = pathlib.Path(path).read_bytes()
    width, height, depth, colour = png_header(path)
    if (depth, colour, data[28]) != (8, 6, 0):
        raise ValueError(f"{path}: not 8-bit RGBA without interlacing")
    pos, idat = 8, b""
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        if kind == b"IDAT":
            idat += data[pos + 8:pos + 8 + length]
        pos += 12 + length
    raw, stride = zlib.decompress(idat), width * 4
    rows, prev = [], bytes(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind, line = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        for i in range(stride):
            a, b = line[i - 4] if i >= 4 else 0, prev[i]
            c = prev[i - 4] if i >= 4 else 0
            if kind == 1:
                line[i] = (line[i] + a) & 0xFF
            elif kind == 2:
                line[i] = (line[i] + b) & 0xFF
            elif kind == 3:
                line[i] = (line[i] + (a + b) // 2) & 0xFF
            elif kind == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 0xFF
        rows.append(bytes(line))
        prev = line
    return width, height, rows


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

    def test_intro(self):
        # The textures of the first page keep upstream's sizes and are
        # transparent: the page's picture is the mark, a view of its own. The
        # sphere is 8-bit RGBA, as upstream's is (the intro draws it into an
        # 8-bit RGBA bitmap in the image's own colour space, filled with its
        # background first, texture_helper.m).
        intro = patch.BRAND / patch.INTRO_RESOURCES
        self.assertEqual(png_header(intro / "telegram_sphere@2x.png"), (296, 296, 8, 6))
        self.assertEqual(png_header(intro / "telegram_plane1@2x.png")[:2], (164, 148))
        for name in ("telegram_sphere@2x.png", "telegram_plane1@2x.png"):
            with self.subTest(texture=name):
                _, _, rows = png_rgba(intro / name)
                self.assertFalse(any(row[3::4].strip(b"\0") for row in rows), "not transparent")
        # They stay a mask of the background colour, by upstream's lines that
        # the patch pins, which the check job fetches.
        for rel, _ in patch.INTRO_SPHERE_MASK:
            self.assertIn(rel, patch.UPSTREAM_PATHS)
        self.assertIn(patch.INTRO_TEXTURES, {rel for rel, _ in patch.INTRO_SPHERE_MASK})
        # brand/render.sh places the glyphs of the wordmark, and the intro lays
        # the mark out, by figures measured on these files of the kit.
        for name, sha in (("pluma-mark.svg", "34b88ecfd7831685b326f4a2ea47a90c4d4913940cf8591931b2604ea9aa78e8"),
                          ("pluma-wordmark.svg", "33b097ac94f2ab54423a089ee81dcbcad7397b2f9464131240f31241558a6eb2")):
            with self.subTest(svg=name):
                self.assertEqual(hashlib.sha256((ROOT / "brand" / name).read_bytes()).hexdigest(), sha,
                                 "a new file of the kit: measure render.sh's figures for the intro again")
        # Its title, the wordmark: a black mask of 106 x 27 pt, the glyphs
        # 105.1 x 26.33 pt (as the Android app draws them) centred across it
        # and whole (no edge of the image is more than half covered), the
        # baseline 22 pt from the top.
        size, baseline = (106, 27), 22
        for scale in (2, 3):
            with self.subTest(scale=scale):
                width, height, rows = png_rgba(intro / f"pluma_wordmark@{scale}x.png")
                self.assertEqual((width, height), (size[0] * scale, size[1] * scale))
                self.assertFalse(any(row[i] for row in rows for i in range(len(row)) if i % 4 != 3), "not black")
                ink = [(x, y) for y, row in enumerate(rows) for x in range(width) if row[4 * x + 3]]
                xs, ys = [x for x, _ in ink], [y for _, y in ink]
                self.assertLessEqual(abs(min(xs) - (width - 1 - max(xs))), 1, "not centred")
                self.assertAlmostEqual((max(xs) + 1 - min(xs)) / scale, 105.1, delta=1)
                self.assertAlmostEqual((max(ys) + 1 - min(ys)) / scale, 26.33, delta=1)
                edges = (rows[0][3::4], rows[-1][3::4], bytes(row[3] for row in rows), bytes(row[-1] for row in rows))
                self.assertLess(max(max(edge) for edge in edges), 128, "clipped")
                # 1 pt above the baseline the glyphs span the image; 1 pt
                # below it only the stem of the "p" is left.
                self.assertGreater(max(x for x, y in ink if y == (baseline - 1) * scale), 100 * scale)
                self.assertLess(max(x for x, y in ink if y >= (baseline + 1) * scale), 7 * scale)
        # The intro sets that baseline on the title's: the image reaches below
        # the title's baseline by the rest of its height.
        bounds = re.search(r"CGRectMake\(0\.0, (-?[\d.]+), wordmark\.size\.width", patch.INTRO_WORDMARK)
        self.assertIsNotNone(bounds)
        self.assertEqual(-float(bounds.group(1)), size[1] - baseline)
        # The intro loads the mask by that name, and its host the mark's
        # animation by its own (the app's resources are flat in its bundle).
        names = {re.sub(r"@[23]x\.png$", ".png", pathlib.PurePath(rel).name)
                 for rel in patch.BRAND_ADDED if rel.startswith(patch.INTRO_RESOURCES + "/")}
        self.assertEqual(names, {"pluma_wordmark.png", "pluma_mark_write.json"})
        self.assertIn('[UIImage imageNamed:@"pluma_wordmark.png"]', patch.INTRO_WORDMARK)
        self.assertEqual(sum(added.count('ManagedAnimationSource.local("pluma_mark_write")')
                             for _, added in patch.INTRO_SPLASH_EDITS), 1)

    def test_intro_mark(self):
        # brand/mark_write.py writes the mark's animation from the kit's mark;
        # brand/ios holds what it writes, and a re-run writes the same bytes.
        script = ROOT / "brand/mark_write.py"
        self.assertEqual(hashlib.sha256(script.read_bytes()).hexdigest(), MARK_WRITE_SHA256,
                         "a new brand/mark_write.py: check its animation again and pin both")
        data = (patch.BRAND / patch.INTRO_MARK).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), INTRO_MARK_SHA256)
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "mark.json"
            subprocess.run([sys.executable, "-I", str(script), str(ROOT / "brand/pluma-mark.svg"), str(out)],
                           check=True, capture_output=True)
            self.assertEqual(out.read_bytes(), data, "re-run brand/render.sh")
        # What the app's player takes (LottieInstance.mm: up to 1536 px, 360
        # fps and 9 s): 132 frames at 60 a second on the kit's 512 grid.
        anim = json.loads(data)
        self.assertEqual((anim["fr"], anim["ip"], anim["op"], anim["w"], anim["h"]), (60, 0, 132, 512, 512))
        self.assertLessEqual(anim["op"] / anim["fr"], 9)
        self.assertEqual([layer["nm"] for layer in anim["layers"]], ["Quill", "Feather1", "Feather2", "Feather3", "Ring"])
        # The inks as rlottie's colour replacement keys them, round(c * 255) as
        # 0xRRGGBB: the kit's, the feathers from the nib outwards, then the ring.
        inks = []
        for layer in anim["layers"][1:]:
            (stroke,) = [item for item in layer["shapes"][0]["it"] if item["ty"] == "st"]
            inks.append(int("".join(f"{round(c * 255):02x}" for c in stroke["c"]["k"][:3]), 16))
        self.assertEqual(inks, [0x4A4A4A, 0x8A8A8A, 0xBDBDBD, 0x111111])
        # Dark themes replace them with the dark appearance of the app icon
        # (the solid fills of its layers in icon.json).
        swift = "".join(added for _, added in patch.INTRO_SPLASH_EDITS)
        (pairs,) = re.findall(r"dark \? \[([^\]]*)\] : nil", swift)
        dark = {int(k, 16): int(v, 16) for k, v in re.findall(r"0x([0-9a-f]{6}): 0x([0-9a-f]{6})", pairs)}
        icon = json.loads((patch.BRAND / patch.APP_ICON / "icon.json").read_text())
        icon_dark = {}
        for layer in icon["groups"][0]["layers"]:
            (fill,) = [f["value"]["solid"] for f in layer["fill-specializations"] if f["appearance"] == "dark"]
            rgb = fill.removeprefix("srgb:").split(",")[:3]
            icon_dark[layer["name"]] = int("".join(f"{round(float(c) * 255):02x}" for c in rgb), 16)
        self.assertEqual([dark.get(ink, ink) for ink in inks],
                         [icon_dark[name] for name in ("Feather1", "Feather2", "Feather3", "Ring")])
        self.assertLessEqual(set(dark), set(inks))
        # The intro lays the mark out by the box of its ink at rest, which the
        # script computes, on the animation's canvas.
        spec = importlib.util.spec_from_file_location("mark_write", script)
        mark_write = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mark_write)
        _, facts = mark_write.build(mark_write.read_kit(str(ROOT / "brand/pluma-mark.svg")))
        figures = dict(re.findall(r"static const CGFloat (PlumaIntro\w+) = ([\d.]+);\n", patch.INTRO_LAYOUT_CONSTANTS))
        self.assertEqual(float(figures["PlumaIntroMarkCanvas"]), anim["w"])
        self.assertEqual([float(figures[f"PlumaIntroMarkInk{side}"]) for side in ("Left", "Top", "Right", "Bottom")],
                         [round(v, 2) for v in facts["ink_box"]])
        # The animation ends on the mark at rest, which the host shows from
        # its last frame.
        self.assertLess(facts["rest_from"], anim["op"])
        # The layout's three figures, each once: the mark's height, the gap to
        # the wordmark and the share of the free space above the group.
        for name in ("PlumaIntroMarkHeight", "PlumaIntroMarkGap", "PlumaIntroGroupBias"):
            with self.subTest(figure=name):
                self.assertIn(name, figures)
                self.assertIn(name, patch.INTRO_LAYOUT)

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


class LinksTest(unittest.TestCase):
    """pluma.chat links (task 026): the patterns and the tables."""

    def test_literals(self):
        for text, count in (('"https://t.me/\\(name)"', 1), ('"t.me/"', 1), ('"t.me"', 1), ('"https://t.me\\(path)"', 1),
                            ('@"t.me/%@"', 1), ('"\\(scheme)://t.me/\\(name)"', 1), ('"t.me/c/" || "t.me/+"', 2),
                            ('"a.t.me"', 0), ('"https://telegram.me/"', 0), ('"https://t.mega/"', 0),
                            ('"https://pluma.chat/\\(name)"', 0), ("/// an internal https://t.me or tg: link", 0)):
            with self.subTest(text=text):
                self.assertEqual(len(patch.TME_LITERAL.findall(text.encode("utf-8"))), count)
        for text, found in (("t.me link", True), ("[https://t.me/%@]()", True), ("such as t.me/title", True),
                            ("pluma.chat link", False), ("a.t.me", False), ("t.messages", False)):
            with self.subTest(text=text):
                self.assertEqual(bool(patch.STRINGS_TME.search(text)), found)

    def test_table(self):
        for rel, old, new, count in patch.LINK_HOSTS:
            with self.subTest(rel=rel, old=old[:40]):
                self.assertIn(rel, patch.UPSTREAM_PATHS)
                self.assertIn("t.me", old)
                self.assertNotIn(patch.LINK_HOST, old)
                self.assertGreater(new.count(patch.LINK_HOST), 0)
        for rel, text, count in patch.SHARE_LINKS:
            with self.subTest(rel=rel, text=text):
                self.assertIn(rel, patch.UPSTREAM_PATHS)
                self.assertGreater(text.count("{host}"), 0)
                self.assertGreater(len(patch.TME_LITERAL.findall(text.replace("{host}", "t.me").encode("utf-8"))), 0)
        for rel, text, count in patch.SHARE_KEEP:
            with self.subTest(rel=rel, text=text):
                self.assertIn(rel, patch.UPSTREAM_PATHS)
                self.assertGreater(len(patch.TME_LITERAL.findall(text.encode("utf-8"))), 0)
        self.assertEqual(len({(rel, text) for rel, text, _ in patch.SHARE_LINKS}), len(patch.SHARE_LINKS))
        self.assertEqual(len({(rel, text) for rel, text, _ in patch.SHARE_KEEP}), len(patch.SHARE_KEEP))
        self.assertFalse({key for key, _ in patch.STRINGS_LINKS} & set(patch.STRINGS_KEEP))
        self.assertIn(patch.STRINGS, patch.UPSTREAM_PATHS)

    def test_site_pages(self):
        # The pages of the site pluma.chat itself, one list in every client.
        self.assertEqual(set(patch.PLUMA_SITE_PATHS), {
            "iphone", "ipad", "android", "mac", "windows", "linux", "web", "pero", "app", "en", "dl", "ios",
            "collect", "assets", "_l", ".well-known",
            "favicon.svg", "og.png", "apple-touch-icon.png", "404.html", "progress.json"})
        self.assertEqual(len(set(patch.PLUMA_SITE_PATHS)), len(patch.PLUMA_SITE_PATHS))
        for name in patch.PLUMA_SITE_PATHS:
            with self.subTest(name=name):
                self.assertEqual(name, name.lower())
                self.assertNotIn("/", name)
                self.assertIn(f'"{name}"', patch.PLUMA_SITE_FUNC)
        for rel, old, new, count in patch.PLUMA_SITE:
            with self.subTest(rel=rel, old=old[:40]):
                self.assertIn(rel, patch.UPSTREAM_PATHS)
                self.assertTrue(new.startswith(old) or patch.PLUMA_SITE_CHECK in new)
                self.assertNotEqual(old, new)


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


class MediaEditorAccentTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        self.tree = patch.Tree(root)
        for rel, count in patch.MEDIA_EDITOR_ACCENTS:
            self.tree.write(rel, "UIColor(rgb: 0x5b7a5e)\n" * count)

    def tearDown(self):
        self.dir.cleanup()

    def test_sage(self):
        patch.verify_media_editor_accent(self.tree)

    def test_a_new_blue_stops_the_patch(self):
        for rel, _ in patch.MEDIA_EDITOR_ACCENTS:
            with self.subTest(file=rel):
                text = self.tree.read(rel)
                self.tree.write(rel, text + "UIColor(rgb: 0x0088FF)\n")
                with self.assertRaisesRegex(patch.PatchError, "Telegram's blue"):
                    patch.verify_media_editor_accent(self.tree)
                self.tree.write(rel, text)


class CrashReportsTest(unittest.TestCase):
    PATCHED = (patch.CRASH_REPORT_TEAM + patch.CRASH_REPORT_PROMPT
               + "                TextAlertAction(type: .defaultAction, title: \"Send\", action: { self.send(report, context: context) })\n")

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def test_only_the_dead_confirmation_calls_send(self):
        self.tree.write(patch.CRASH_REPORTS, self.PATCHED)
        patch.verify_crash_reports(self.tree)

    def test_a_new_path_to_the_bot_stops_the_patch(self):
        for extra in ("actions.send(report, context: context)\n", "self.confirmSend(report)\n"):
            with self.subTest(extra=extra):
                self.tree.write(patch.CRASH_REPORTS, self.PATCHED + extra)
                with self.assertRaisesRegex(patch.PatchError, "can still be sent"):
                    patch.verify_crash_reports(self.tree)

    def test_the_prompt_goes_to_the_bot_again(self):
        self.tree.write(patch.CRASH_REPORTS, self.PATCHED.replace(patch.CRASH_REPORT_PROMPT, patch.CRASH_REPORT_PROMPT_OLD))
        with self.assertRaisesRegex(patch.PatchError, "can still be sent"):
            patch.verify_crash_reports(self.tree)


class AppUpdateTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        self.tree = patch.Tree(root)
        files = {}
        for rel, old, _ in patch.APP_UPDATE_EDITS:
            files[rel] = files.get(rel, "") + old + "\n"
        for rel, text in files.items():
            self.tree.write(rel, text)

    def tearDown(self):
        self.dir.cleanup()

    def test_app_update(self):
        with self.assertRaisesRegex(patch.PatchError, "is not there"):
            patch.verify_app_update(self.tree)
        patch.patch_app_update(self.tree)
        patch.verify_app_update(self.tree)
        info = self.tree.read(patch.APP_UPDATE)
        self.assertIn("    public let url: String?\n", info)
        self.assertIn("                self.url = appUpdateData.url\n", info)
        self.assertIn("            context.sharedContext.applicationBindings.openUrl(url)\n", self.tree.read(patch.UPDATE_INFO))
        self.assertNotIn("itms-apps:", self.tree.read(patch.APP_DELEGATE))
        self.assertIn('URL(string: "https://pluma.chat/")', self.tree.read(patch.APP_DELEGATE))
        self.assertIn('            suffix = @"adhoc";\n', self.tree.read(patch.MT_API_ENVIRONMENT))
        # A second run finds none of the upstream texts.
        with self.assertRaises(patch.PatchError):
            patch.patch_app_update(self.tree)

    def test_check(self):
        patch.patch_app_update(self.tree)
        for rel, old, new in patch.APP_UPDATE_EDITS:
            patched = self.tree.read(rel)
            with self.subTest(file=rel, edit=new.strip().splitlines()[-1]):
                self.tree.write(rel, patched.replace(new, old))
                with self.assertRaisesRegex(patch.PatchError, "is not there"):
                    patch.verify_app_update(self.tree)
            self.tree.write(rel, patched)
        patch.verify_app_update(self.tree)


class AccountCleanupTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        self.tree = patch.Tree(root)
        # The loop over the logged-out accounts before it reads view.records
        # too, and stays.
        self.other = "            outer: for record in view.records {\n"
        self.tree.write(patch.ACCOUNT_MANAGER, self.other + patch.ACCOUNT_CLEANUP_OLD + "        })\n")

    def tearDown(self):
        self.dir.cleanup()

    def test_account_cleanup(self):
        with self.assertRaisesRegex(patch.PatchError, "still matched with a view"):
            patch.verify_account_cleanup(self.tree)
        patch.patch_account_cleanup(self.tree)
        patch.verify_account_cleanup(self.tree)
        text = self.tree.read(patch.ACCOUNT_MANAGER)
        self.assertIn(self.other, text)
        self.assertIn("        for record in transaction.getRecords() {\n", text)
        self.assertIn("        if let record = transaction.getCurrentAuth() {\n", text)
        self.assertNotIn("removeItem(at: url)\n                    }\n                }\n            }\n        }\n    }).start(", text)
        with self.assertRaises(patch.PatchError):
            patch.patch_account_cleanup(self.tree)


class SavedTagsTest(unittest.TestCase):
    # Each file the patch edits, with the upstream text of its edits.
    def upstream(self):
        files = {patch.CHAT_STATE: patch.SAVED_TAGS_FLAG_ANCHOR,
                 patch.MESSAGE_REACTIONS: patch.REACTIONS_LIMIT_OLD,
                 patch.CHAT_CONTROLLER: patch.REACTIONS_TOAST_OLD}
        for rel, old, _ in patch.SAVED_TAGS_GATES:
            files[rel] = files.get(rel, "") + old + "\n"
        return files

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, files):
        for rel, text in files.items():
            self.tree.write(rel, text)

    def test_gates(self):
        self.write(self.upstream())
        with self.assertRaises(patch.PatchError):
            patch.verify_saved_tags(self.tree)
        patch.patch_saved_tags(self.tree)
        patch.verify_saved_tags(self.tree)
        # One flag, true, next to isPremium, which stays.
        self.assertEqual(self.tree.read(patch.CHAT_STATE),
                         "    public let isPremium: Bool\n"
                         "    // pluma: the tags of Saved Messages without Premium, which Pluma does not\n"
                         "    // sell (task 053). The gates of tags check this; all others isPremium.\n"
                         "    public var canUseSavedTags: Bool {\n        return true\n    }\n")
        # The gates check it instead of Premium.
        self.assertIn("                if !strongSelf.presentationInterfaceState.canUseSavedTags {\n"
                      "                    strongSelf.presentTagPremiumPaywall()\n", self.tree.read(patch.CHAT_CONTROLLER))
        self.assertIn("            if !self.presentationInterfaceState.canUseSavedTags {\n"
                      "                self.presentTagPremiumPaywall()\n", self.tree.read(patch.TAG_CONTEXT_MENU))
        menu = self.tree.read(patch.MESSAGE_CONTEXT_MENU)
        self.assertIn("                        if self.presentationInterfaceState.canUseSavedTags {\n"
                      "                            actions.reactionsTitle = presentationData.strings.Chat_ContextMenuTagsTitle\n", menu)
        # A custom emoji tag outside the top list still needs Premium.
        self.assertIn("                                var isTagLocked = !self.presentationInterfaceState.canUseSavedTags\n"
                      "                                if case .custom = chosenReaction, !self.presentationInterfaceState.isPremium {\n"
                      "                                    isTagLocked = true\n"
                      "                                }\n"
                      "                                if isTagLocked {\n"
                      "                                    controller?.premiumReactionsSelected?()\n", menu)
        panel = self.tree.read(patch.TAG_PANEL)
        self.assertEqual(panel.count("!params.interfaceState.canUseSavedTags"), 4)
        self.assertNotIn("isPremium", panel)
        titles = self.tree.read(patch.TITLE_PANELS)
        self.assertIn("            if chatPresentationInterfaceState.hasSearchTags || "
                      "!chatPresentationInterfaceState.canUseSavedTags {\n", titles)
        self.assertIn("            if !chatPresentationInterfaceState.canUseSavedTags {\n", titles)
        # The server's limit of reactions for everybody, Premium's in Saved
        # Messages; the toast about more reactions only while Premium is sold.
        reactions = self.tree.read(patch.MESSAGE_REACTIONS)
        self.assertIn("UserLimitsConfiguration(appConfiguration: appConfiguration, "
                      "isPremium: isPremium || chatPeerId == account.peerId)\n"
                      "        let maxCount = Int(limitsConfiguration.maxReactionsPerMessage)\n", reactions)
        self.assertNotIn("maxCount = 1", reactions)
        self.assertIn("strongSelf.context.userLimits.maxReactionsPerMessage && !PremiumConfiguration.with(appConfiguration: "
                      "strongSelf.context.currentAppConfiguration.with { $0 }).isPremiumDisabled {\n",
                      self.tree.read(patch.CHAT_CONTROLLER))

    def test_verify(self):
        # Each part of the result is checked on its own: a gate back on
        # Premium, the flag false or used elsewhere, the limits as upstream's.
        damage = [(rel, new, old) for rel, old, new in patch.SAVED_TAGS_GATES]
        damage += [
            (patch.CHAT_STATE, "        return true\n", "        return false\n"),
            (patch.CHAT_CONTROLLER, patch.REACTIONS_TOAST, patch.REACTIONS_TOAST_OLD),
            (patch.MESSAGE_REACTIONS, patch.REACTIONS_LIMIT, patch.REACTIONS_LIMIT_OLD),
            (patch.MESSAGE_CONTEXT_MENU, "if isTagLocked {\n",
             "if isTagLocked {\n    let shown = self.presentationInterfaceState.canUseSavedTags\n"),
            (patch.TITLE_PANELS, "            // pluma: tags without Premium (task 053).\n",
             "            // pluma: tags without Premium (task 053).\n            let isPremium = true\n"),
        ]
        for rel, new, old in damage:
            with self.subTest(rel=rel, old=old[:60]):
                self.write(self.upstream())
                patch.patch_saved_tags(self.tree)
                text = self.tree.read(rel)
                self.assertEqual(text.count(new), 1)
                self.tree.write(rel, text.replace(new, old))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify_saved_tags(self.tree)
                self.assertIn(rel, str(e.exception))

    def test_upstream_changed(self):
        # Any gate that moved, and the flag that upstream added itself, stop
        # the patch with the file's name.
        edits = [(rel, old) for rel, old, _ in patch.SAVED_TAGS_GATES]
        edits += [(patch.CHAT_STATE, patch.SAVED_TAGS_FLAG_ANCHOR), (patch.MESSAGE_REACTIONS, patch.REACTIONS_LIMIT_OLD),
                  (patch.CHAT_CONTROLLER, patch.REACTIONS_TOAST_OLD)]
        for rel, old in edits:
            with self.subTest(rel=rel, old=old[:60]):
                files = self.upstream()
                files[rel] = files[rel].replace(old, old.replace("isPremium", "hasPremium").replace("maxCount", "limit"))
                self.write(files)
                with self.assertRaises(patch.PatchError) as e:
                    patch.patch_saved_tags(self.tree)
                self.assertIn(rel, str(e.exception))
        files = self.upstream()
        files[patch.CHAT_STATE] += "    public var canUseSavedTags: Bool { return self.isPremium }\n"
        self.write(files)
        with self.assertRaises(patch.PatchError) as e:
            patch.patch_saved_tags(self.tree)
        self.assertIn(patch.CHAT_STATE, str(e.exception))

    def test_table(self):
        for rel in {rel for rel, _, _ in patch.SAVED_TAGS_GATES} | {patch.CHAT_STATE, patch.MESSAGE_REACTIONS}:
            self.assertIn(rel, patch.UPSTREAM_PATHS)


class PremiumStickersTest(unittest.TestCase):
    # Each file the patch edits, with the upstream text of its edits.
    def upstream(self):
        files = {patch.MEDIA_FILE: patch.PREMIUM_STICKERS_FLAG_ANCHOR}
        for rel, old, _, count in patch.PREMIUM_STICKERS_GATES:
            files[rel] = files.get(rel, "") + (old + "\n") * count
        # The search of custom emoji keeps isPremium.
        files[patch.SEARCH_STICKERS] += patch._SEARCH_PREMIUM
        return files

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "Telegram").mkdir()
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, files):
        for rel, text in files.items():
            self.tree.write(rel, text)

    def test_gates(self):
        self.write(self.upstream())
        with self.assertRaises(patch.PatchError):
            patch.verify_premium_stickers(self.tree)
        patch.patch_premium_stickers(self.tree)
        patch.verify_premium_stickers(self.tree)
        self.assertIn("public func premiumStickersAvailable() -> Bool {\n    return true\n}\n", self.tree.read(patch.MEDIA_FILE))
        self.assertIn("if file.isPremiumSticker && !hasPremium && !premiumStickersAvailable() {\n",
                      self.tree.read(patch.ENTITY_KEYBOARD_INPUT))
        self.assertIn("addItem(item, true, !hasPremium && !premiumStickersAvailable())\n",
                      self.tree.read(patch.STICKER_PACK_SCREEN))
        # The search of custom emoji still checks the account.
        self.assertEqual(self.tree.read(patch.SEARCH_STICKERS).count("?.isPremium ?? false\n"), 1)
        # A second run stops.
        with self.assertRaises(patch.PatchError):
            patch.patch_premium_stickers(self.tree)

    def test_verify(self):
        damage = [(rel, new, old) for rel, old, new, _ in patch.PREMIUM_STICKERS_GATES]
        damage += [(patch.MEDIA_FILE, "    return true\n", "    return false\n")]
        for rel, new, old in damage:
            with self.subTest(rel=rel, new=new[:60]):
                self.write(self.upstream())
                patch.patch_premium_stickers(self.tree)
                text = self.tree.read(rel)
                self.assertGreaterEqual(text.count(new), 1)
                self.tree.write(rel, text.replace(new, old))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify_premium_stickers(self.tree)
                self.assertIn(rel, str(e.exception))
        # The flag asked somewhere else: another feature would open.
        for rel in patch.PREMIUM_STICKERS_USES:
            with self.subTest(rel=rel):
                self.write(self.upstream())
                patch.patch_premium_stickers(self.tree)
                self.tree.write(rel, self.tree.read(rel) + "if premiumStickersAvailable() {\n")
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify_premium_stickers(self.tree)
                self.assertIn(rel, str(e.exception))

    def test_upstream_changed(self):
        for rel, old, _, _ in patch.PREMIUM_STICKERS_GATES:
            with self.subTest(rel=rel, old=old[:60]):
                files = self.upstream()
                files[rel] = files[rel].replace(old, old.replace("Premium", "Paid"))
                self.write(files)
                with self.assertRaises(patch.PatchError) as e:
                    patch.patch_premium_stickers(self.tree)
                self.assertIn(rel, str(e.exception))
        files = self.upstream()
        files[patch.MEDIA_FILE] += "public func premiumStickersAvailable() -> Bool { return false }\n"
        self.write(files)
        with self.assertRaises(patch.PatchError) as e:
            patch.patch_premium_stickers(self.tree)
        self.assertIn(patch.MEDIA_FILE, str(e.exception))

    def test_table(self):
        for rel in {rel for rel, _, _, _ in patch.PREMIUM_STICKERS_GATES} | {patch.MEDIA_FILE}:
            self.assertIn(rel, patch.UPSTREAM_PATHS)


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
    # ... the name colours (PeerNameColors.swift), with get and
    # getChatFolderTag, which fall back on blue...
    GET = ('    public func get(_ color: PeerNameColor, dark: Bool = false) -> Colors {\n'
           '        if dark, let colors = self.darkColors[color.rawValue] {\n'
           '            return colors\n'
           '        } else if let colors = self.colors[color.rawValue] {\n'
           '            return colors\n'
           '        } else {\n'
           '            return PeerNameColors.defaultSingleColors[5]!\n'
           '        }\n'
           '    }\n'
           '    \n')
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
             '            displayOrder: [5, 3, 1, 0, 2, 4, 6],\n'
             + GET + GET.replace("func get(", "func getChatFolderTag("))
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
        # Blue is the palette's sage and cyan a teal: the letter avatar as
        # (bottom, top), so #7FA082 to #5B7A5E from its top for blue and
        # #5BCBC4 to #2C9C98 for cyan, the name colour, the one of dark
        # themes, where cyan keeps Telegram's. The other five are Telegram's.
        colours, dark = patch.identity_colours()
        self.assertEqual(colours[5], ((0x5b7a5e, 0x7fa082), 0x4f6e52))
        self.assertEqual(colours[4], ((0x2c9c98, 0x5bcbc4), 0x1f8a80))
        self.assertEqual(dark, {4: 0x53ccc6, 5: 0x9dbb9f})
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
        # The name colours, those of dark themes, and the fallback, which
        # takes blue's dark one in dark themes.
        self.assertEqual(self.tree.read(patch.PEER_NAME_COLORS), self.NAMES.replace(
            "            4: Colors(main: UIColor(rgb: 0x309eba)),\n",
            "            4: Colors(main: UIColor(rgb: 0x1f8a80)), // pluma: teal\n").replace(
            "            5: Colors(main: UIColor(rgb: 0x368ad1)),\n",
            "            5: Colors(main: UIColor(rgb: 0x4f6e52)), // pluma: sage\n").replace(
            "            darkColors: [:],\n",
            "            // pluma: Pluma's cyan and blue have colours of their own in dark themes.\n"
            "            darkColors: [\n"
            "                4: Colors(main: UIColor(rgb: 0x53ccc6)),\n"
            "                5: Colors(main: UIColor(rgb: 0x9dbb9f))\n"
            "            ],\n").replace(
            "            return PeerNameColors.defaultSingleColors[5]!\n",
            "            // pluma: dark themes take blue's dark colour (Pluma's sage has one).\n"
            "            return dark ? (PeerNameColors.defaultValue.darkColors[5] ?? PeerNameColors.defaultSingleColors[5]!) "
            ": PeerNameColors.defaultSingleColors[5]!\n"))
        updates = self.tree.read(patch.PEER_COLOR_UPDATES)
        for line in ("                        0x40a920,\n                        0x1f8a80, // pluma: teal\n"
                     "                        0x4f6e52, // pluma: sage\n                        0xc7508b\n",
                     "                    let staticDarkMap: [Int32: UInt32] = [4: 0x53ccc6, 5: 0x9dbb9f]\n",
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

    def test_fallback(self):
        # get and getChatFolderTag fall back on blue alike: upstream must have
        # both, and both must take its dark colour after the patch.
        light = "            return PeerNameColors.defaultSingleColors[5]!\n"
        other = "            return PeerNameColors.defaultSingleColors[3]!\n"
        self.write({patch.PEER_NAME_COLORS: self.NAMES.replace(light, other, 1)})
        with self.assertRaises(patch.PatchError) as e:
            patch.patch_identity(self.tree)
        self.assertIn(patch.PEER_NAME_COLORS, str(e.exception))
        self.write()
        patch.patch_identity(self.tree)
        names = self.tree.read(patch.PEER_NAME_COLORS)
        self.assertNotIn(light, names)
        # Either of them as upstream's.
        for func in ("func get(", "func getChatFolderTag("):
            with self.subTest(func=func):
                at = names.index(patch.NAME_FALLBACK, names.index(func))
                self.tree.write(patch.PEER_NAME_COLORS, names[:at] + light + names[at + len(patch.NAME_FALLBACK):])
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify_identity(self.tree)
                self.assertIn(patch.PEER_NAME_COLORS, str(e.exception))

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
# The first two sets of the 1:1 call's background after the patch.
CONNECTING_SET = ("            ColorSet(colors: [\n                hexToFloat(0x3A4A3C),\n                hexToFloat(0x4F6E52),\n"
                  "                hexToFloat(0x2C3A2D),\n                hexToFloat(0x5B7A5E)\n            ])")
CONNECTED_SET = ("            ColorSet(colors: [\n                hexToFloat(0x5B7A5E),\n                hexToFloat(0x6F8F72),\n"
                 "                hexToFloat(0x4F6E52),\n                hexToFloat(0x7FA082)\n            ])")


DAMAGE = (
    (patch.CONTEXT_MENUS, "            if premiumConfiguration.isPremiumDisabled {\n                return false",
     "            if premiumConfiguration.isPremiumDisabled || true {\n                return false"),
    (patch.CONTEXT_MENUS, "self.item.action != nil && stats.peers.isEmpty\n", "self.item.action != nil && !stats.peers.isEmpty\n"),
    (patch.CONTEXT_MENUS, "                    showReadBadge = true\n", "                    showReadBadge = false\n"),
    # The tags of Saved Messages and the limit of reactions.
    (patch.CHAT_STATE, "    public let isPremium: Bool\n", "    public var isPremium: Bool\n"),
    (patch.CHAT_CONTROLLER, "                if !strongSelf.presentationInterfaceState.isPremium {\n"
     "                    strongSelf.presentTagPremiumPaywall()\n",
     "                if !strongSelf.presentationInterfaceState.isPremium {\n"
     "                    strongSelf.presentTagsPremiumPaywall()\n"),
    (patch.CHAT_CONTROLLER, "mappedUpdatedReactions.count > strongSelf.context.userLimits.maxReactionsPerMessage {",
     "mappedUpdatedReactions.count >= strongSelf.context.userLimits.maxReactionsPerMessage {"),
    (patch.TAG_CONTEXT_MENU, "            if !self.presentationInterfaceState.isPremium {\n                self.presentTagPremiumPaywall()",
     "            if self.presentationInterfaceState.isPremium == false {\n                self.presentTagPremiumPaywall()"),
    (patch.MESSAGE_CONTEXT_MENU, "if self.presentationInterfaceState.isPremium {\n"
     "                            actions.reactionsTitle = presentationData.strings.Chat_ContextMenuTagsTitle",
     "if self.presentationInterfaceState.isPremium {\n"
     "                            actions.reactionsTitle = presentationData.strings.Chat_ContextMenuTagTitle"),
    (patch.MESSAGE_CONTEXT_MENU, "$0.reaction.rawValue == chosenReaction }) {\n"
     "                                if !self.presentationInterfaceState.isPremium {\n",
     "$0.reaction.rawValue == chosenReaction }) {\n"
     "                                if self.presentationInterfaceState.isPremium == false {\n"),
    (patch.TAG_PANEL, "        if !params.interfaceState.isPremium {\n            let promoView: PromoView\n",
     "        if !params.interfaceState.isPremium {\n            let promoView: PromoView?\n"),
    (patch.TAG_PANEL, "isLocked: !params.interfaceState.isPremium,", "isLocked: params.interfaceState.isPremium == false,"),
    (patch.TITLE_PANELS, "hasSearchTags || !chatPresentationInterfaceState.isPremium {",
     "hasSearchTags || chatPresentationInterfaceState.isPremium == false {"),
    (patch.TITLE_PANELS, "            if !chatPresentationInterfaceState.isPremium {\n                matches = false\n",
     "            if chatPresentationInterfaceState.isPremium == false {\n                matches = false\n"),
    (patch.MESSAGE_REACTIONS, "            maxCount = 1\n", "            maxCount = 2\n"),
    (patch.VIDEO_PRESETS_LEGACY, "        case TGMediaVideoConversionPresetCompressedVeryHigh:\n            return 6600;\n",
     "        case TGMediaVideoConversionPresetCompressedVeryHigh:\n            return 6000;\n"),
    (patch.VIDEO_PRESETS_LEGACY, "        case TGMediaVideoConversionPresetCompressedLow:\n            return 32;\n",
     "        case TGMediaVideoConversionPresetCompressedLow:\n            return 48;\n"),
    (patch.VIDEO_PRESETS_LEGACY, "        default:\n            return 900;\n", "        default:\n            return 1000;\n"),
    (patch.VIDEO_PRESETS, "        case .compressedHigh:\n            return 3000\n", "        case .compressedHigh:\n            return 3500\n"),
    (patch.VIDEO_PRESETS, "        case .compressedMedium, .compressedHigh, .compressedVeryHigh, .videoMessage:\n            return 64\n",
     "        case .compressedMedium, .compressedHigh, .compressedVeryHigh, .videoMessage:\n            return 96\n"),
    (patch.VIDEO_PRESETS, "        case .compressedVeryLow, .compressedLow:\n            return 1\n",
     "        case .compressedVeryLow:\n            return 1\n"),
    (patch.VIDEO_PRESETS, "<= 400.0 ? 1000 : 1200\n", "<= 400.0 ? 1000 : 1500\n"),
    (patch.ROUND_VIDEO_RECORDER, "AVVideoAverageBitRateKey: 1000 * 1000,", "AVVideoAverageBitRateKey: 1500 * 1000,"),
    (patch.ROUND_VIDEO_RECORDER_NEO, "audioSettings[AVSampleRateKey] = streamDescription.pointee.mSampleRate\n",
     "audioSettings[AVSampleRateKey] = 48000.0\n"),
    (patch.GIF_CONVERTER, "AVVideoAverageBitRateKey: @(500000),", "AVVideoAverageBitRateKey: @(750000),"),
    (patch.VIDEO_FETCH, "            qualityPreset = defaultPreset\n", "            qualityPreset = .compressedMedium\n"),
    (patch.SERIALIZATION, "        return 233\n", "        return 234\n"),
    (patch.VERSIONS, '"app": "13.2"', '"app": "13.2.1"'),
    (patch.VERSIONS, '"xcode": "27.1"', '"xcode": "27.2"'),
    (patch.VERSIONS, '"bazel": "9.2.0:', '"bazel": "9.3.0:'),
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
    (BACKUP, "mainDatacenterId:(NSInteger)mainDatacenterId {\n    __weak MTContext",
     "mainDatacenterId:(NSInteger)mainDatacenterId delay:(double)delay {\n    __weak MTContext"),
    (DNS, "timeout:10.0 onQueue:[MTQueue concurrentDefaultQueue] orSignal", "timeout:5.0 onQueue:[MTQueue concurrentDefaultQueue] orSignal"),
    (CALLS, "                unfilteredConnections = [connections.primary] + connections.alternatives\n",
     "                unfilteredConnections = connections.alternatives\n"),
    (patch.BAZELRC, "build --action_env=ZERO_AR_DATE=1\n", "build --action_env=ZERO_AR_DATE=1\ntry-import %workspace%/user.bazelrc\n"),
    # The engine of a build and the sections the server does not turn on.
    (patch.NETWORK_ENGINE, "        return NetworkEngineSettings(engine: .mtProtoKit)\n", "        return NetworkEngineSettings(engine: .rust)\n"),
    (patch.WALLET_CONFIGURATION, "            isAvailable: false,\n", "            isAvailable: true,\n"),
    (patch.SETTINGS_ITEMS, ".isAvailable {\n            let balanceText", " {\n            let balanceText"),
    (patch.NEWS_CONFIGURATION, "newsFeedSwitch(appConfiguration: appConfiguration) == true\n", "newsFeedSwitch(appConfiguration: appConfiguration) != false\n"),
    (patch.AGENT_CONFIGURATION, 'data["agent_bot_ids"] as? [Any]', 'data["agent_bots"] as? [Any]'),
    (patch.APP_BUILD, "                <string>tc</string>\n", "                <string>tonconnect</string>\n"),
    (patch.STRINGS, '"SocksProxySetup.QrCode.TgLink" = "tg:// link";', '"SocksProxySetup.QrCode.TgLink" = "tg link";'),
    # The brand.
    (BUILD, '    "PremiumTurbo",\n]\n', '    "PremiumTurbo",\n    "Premium2",\n]\n'),
    (APP_DELEGATE, 'PresentationAppIcon(name: "New2", imageName: "New2"),', 'PresentationAppIcon(name: "New3", imageName: "New3"),'),
    (INTRO, "cloud_color = {42/255., 180/255., 247/255., 1};", "cloud_color = {42/255., 181/255., 247/255., 1};"),
    (INTRO, "powerful_bg_color = {47/255., 90/255., 131/255., 1};", "powerful_bg_color = {47/255., 90/255., 132/255., 1};"),
    (patch.INTRO_CONTROLLER, "    [_pageScrollView setPage:0];\n", "    [_pageScrollView setPage:1];\n"),
    (patch.INTRO_CONTROLLER, "#if TARGET_OS_SIMULATOR && defined(__aarch64__)\n", "#if TARGET_OS_SIMULATOR && defined(__arm64__)\n"),
    (patch.INTRO_CONTROLLER, '_headlines = @[ _englishStrings[@"Tour.Title1"], _englishStrings[@"Tour.Title2"],',
     '_headlines = @[ _englishStrings[@"Tour.Title2"], _englishStrings[@"Tour.Title1"],'),
    (patch.APP_ICON + "/icon.json", '"image-name" : "Plane.svg"', '"image-name" : "Plane2.svg"'),
    # The mark of the intro's first page and the layout of the pages.
    (patch.INTRO_HEADER, "@property (nonatomic, copy) UIView *(^createStartButton)(CGFloat);",
     "@property (nonatomic, copy) UIView *(^createStartButton)(CGFloat width);"),
    (patch.INTRO_CONTROLLER, "} DeviceScreen;", "} RMDeviceScreen;"),
    (patch.INTRO_CONTROLLER, "    bool _loadedView;\n", "    BOOL _loadedView;\n"),
    (patch.INTRO_CONTROLLER, "    _glkView.transform = CGAffineTransformMakeScale(0.66, 0.66);",
     "    _glkView.transform = CGAffineTransformMakeScale(0.7, 0.7);"),
    (patch.INTRO_CONTROLLER, "        _startButton.alpha = 1.0;\n    } completion:nil];",
     "        _startButton.alpha = 1.0;\n    } completion:^(__unused BOOL finished) {}];"),
    (patch.INTRO_CONTROLLER, "        [self.view addSubview:_glkView];", "        [self.view addSubview:_glkView]; // the GL view"),
    (patch.INTRO_CONTROLLER, "    [_wrapperView addSubview:_pageControl];\n}", "    [_wrapperView addSubview:_pageControl];\n    [self updateLayout];\n}"),
    (patch.INTRO_CONTROLLER, "- (UIView *)createAnimationSnapshot {", "- (UIView *)createAnimationSnapshot\n{"),
    (patch.INTRO_CONTROLLER, "            startButtonY = 75 + 20;", "            startButtonY = 75 + 25;"),
    (patch.INTRO_CONTROLLER, "            pageY = isVertical ? 605 : 435;", "            pageY = isVertical ? 605 : 436;"),
    (patch.INTRO_CONTROLLER, "    [super viewDidDisappear:animated];", "    [super viewDidDisappear:animated];\n    [self stopTimer];"),
    (patch.INTRO_CONTROLLER, "    [_pageControl setCurrentPage:_currentPage];\n}", "    _pageControl.currentPage = _currentPage;\n}"),
    (patch.INTRO_CONTROLLER, "@implementation TGAvailableLocalization\n", "@implementation TGAvailableLocalizationInfo\n"),
    (patch.INTRO_SPLASH, "import RMIntro\n", "import RMIntroUI\n"),
    # What App Store Connect asks.
    (patch.APP_BUILD, "        <string>AremacFS-Semibold.otf</string>\n", ""),
    (patch.APP_BUILD, "                <string>INSearchCallHistoryIntent</string>\n",
     "                <string>INSearchCallHistoryIntent</string>\n                <string>INAnswerCallIntent</string>\n"),
    (patch.FONT, 'UIFont(name: encodeText(string: "TGDbnfsb.Sfhvmbs", key: -1), size: size) ?? UIFont.systemFont(ofSize: size, weight: weight.weight)',
     'UIFont(name: encodeText(string: "TGDbnfsb.Sfhvmbs", key: -1), size: size)!'),
    (patch.CAMERA_ASSETS, 'TGCameraEncodeText(@"TGDbnfsb.Tfnjcpme", -1) size:size];', 'TGCameraEncodeText(@"TGDbnfsb.Tfnjcpme", -1) size:size + 1];'),
    (patch.INFOPLIST_STRINGS.format("en"), '"NSLocationAlwaysAndWhenInUseUsageDescription"', '"NSLocationAlwaysAndWhenInUse"'),
    (patch.SIRI_VOCABULARY.format("ru"), "\u0410\u043b\u0438\u0441\u0435", "\u0410\u043b\u0435\u043a\u0441\u0443"),
    (patch.INTRO_SPLASH, "    private let controller: RMIntroViewController\n", "    private let controller: RMIntroViewController?\n"),
    (patch.INTRO_SPLASH, "suggestedLocalizationSignal: localizationSignal)", "suggestedLocalizationSignal: localizationSignal, animated: true)"),
    (patch.INTRO_SPLASH, "            return self?.startButton.view\n", "            return self?.startButton.view ?? UIView()\n"),
    (patch.INTRO_SPLASH, "        self.controller.defaultFrame = controllerFrame\n", "        self.controller.defaultFrame = layout.bounds\n"),
    (patch.INTRO_SPLASH, "            self.nextPressed?(strings)\n", "            self.nextPressed?(strings ?? nil)\n"),
    # What makes the blank sphere the mask of the first page.
    (patch.INTRO_TEXTURES, "        CGContextFillRect(spriteContext, CGRectMake(0, 0, width, height));\n", ""),
    (patch.INTRO_TEXTURES, '[fileName isEqualToString:@"telegram_sphere.png"]', '[fileName isEqualToString:@"telegram_sphere@2x.png"]'),
    (patch.INTRO_CONTROLLER, "    UIColor *color = _backgroundColor;\n", "    UIColor *color = [UIColor clearColor];\n"),
    (patch.INTRO_CONTROLLER, 'set_telegram_textures(setup_texture(@"telegram_sphere.png", color), ',
     'set_telegram_textures(setup_texture(@"telegram_sphere.png", nil), '),
    (INTRO, "telegram_sphere = create_textured_rectangle(CSizeMake(148, 148),", "telegram_sphere = create_textured_rectangle(CSizeMake(140, 140),"),
    (INTRO, "fast_body = create_textured_rectangle(CSizeMake(148, 148),", "fast_body = create_textured_rectangle(CSizeMake(156, 156),"),
    (INTRO, "            scale = 1;\n\n            fast_body.params.alpha = 1;\n", "            scale = 1.1;\n\n            fast_body.params.alpha = 1;\n"),
    (INTRO, "telegram_sphere.params.alpha = t(0, 1, 0, duration_const*.8, Linear);",
     "telegram_sphere.params.alpha = t(0, .8, 0, duration_const*.8, Linear);"),
    (INTRO, "            scale = 1.005;\n", "            scale = 0.9;\n"),
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
    # The verified badge: every place takes the theme's check colours, or
    # white over a photo or a video.
    ("submodules/ChatListUI/Sources/Node/ChatListItem.swift",
     "currentCredibilityIconContent = .verified(fillColor: item.presentationData.theme.list.itemCheckColors.fillColor, "
     "foregroundColor: item.presentationData.theme.list.itemCheckColors.foregroundColor, sizeType: .compact)\n"
     "                    }",
     "currentCredibilityIconContent = .verified(fillColor: UIColor(rgb: 0x2ea6ff), "
     "foregroundColor: item.presentationData.theme.list.itemCheckColors.foregroundColor, sizeType: .compact)\n"
     "                    }"),
    ("submodules/TelegramUI/Components/ChatTitleView/Sources/ChatTitleView.swift",
     "titleVerifiedContent = .verified(fillColor: self.theme.list.itemCheckColors.fillColor,",
     "titleVerifiedContent = .verified(fillColor: self.theme.list.itemAccentColor,"),
    ("submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoHeaderNode.swift",
     "                emojiExpandedStatusContent = .verified(fillColor: navigationContentsAccentColor, foregroundColor: .clear, sizeType: .large)\n"
     "            case .fake:",
     "                emojiExpandedStatusContent = .verified(fillColor: .white, foregroundColor: .clear, sizeType: .large)\n"
     "            case .fake:"),
    ("submodules/TelegramUI/Components/Stories/StoryContainerScreen/Sources/StoryAuthorInfoComponent.swift",
     "iconBackgroundColor: component.theme.list.itemCheckColors.fillColor,", "iconBackgroundColor: UIColor(rgb: 0x2ea6ff),"),
    ("submodules/TelegramPresentationData/Sources/Resources/PresentationResourcesChatList.swift",
     "context.setFillColor(theme.list.itemCheckColors.fillColor.cgColor)\n                        context.fill(CGRect(origin: CGPoint(), size: size))\n"
     "                        context.restoreGState()\n                        \n                        context.clip(to: CGRect(origin: .zero, size: size), mask: foregroundCgImage)",
     "context.setFillColor(theme.chatList.verifiedIconFillColor.cgColor)\n                        context.fill(CGRect(origin: CGPoint(), size: size))\n"
     "                        context.restoreGState()\n                        \n                        context.clip(to: CGRect(origin: .zero, size: size), mask: foregroundCgImage)"),
    (patch.DARK_THEME, "itemCheckColors: list.itemCheckColors.withUpdated(fillColor: accentColor, foregroundColor: secondaryBadgeTextColor),",
     "itemCheckColors: list.itemCheckColors.withUpdated(fillColor: accentColor, foregroundColor: badgeTextColor),"),
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
    (patch.PEER_NAME_COLORS, "            return PeerNameColors.defaultSingleColors[5]!\n",
     "            return PeerNameColors.defaultSingleColors[3]!\n"),
    (patch.PEER_COLOR_UPDATES, "                        0x309eba,\n", "                        0x309ebb,\n"),
    (patch.PEER_COLOR_UPDATES, "ColorOptionPack(light: defaultColors, dark: nil,", "ColorOptionPack(light: defaultColors, dark: defaultColors,"),
    # Telegram's support.
    (patch.SETTINGS_ITEMS, "interaction.openSettings(.faq)", "interaction.openSettings(.faqPage)"),
    (patch.SETTINGS_SEARCH, "        allItems.append(contentsOf: helpItems)\n", "        allItems += helpItems\n"),
    (patch.CRASH_REPORTS, 'text: "Send to Telegram Team"', 'text: "Send to the Telegram Team"'),
    (patch.CRASH_REPORTS, 'Sign in to a Telegram account to share', 'Sign in to Telegram to share'),
    (patch.APP_DELEGATE, "itms-apps://itunes.apple.com/app/id", "itms-apps://apps.apple.com/app/id"),
    (patch.MAKE_THEME, "neutralNightAccentColor = UIColor(rgb: 0x3e88f7)", "neutralNightAccentColor = UIColor(rgb: 0x3e88f8)"),
    (patch.SEND_BUTTON, "if saturation < 0.2 ||", "if saturation < 0.25 ||"),
    (patch.SEND_BUTTON, "generateTintedImage(image: image, color: .white) else {", "generateTintedImage(image: image, color: .black) else {"),
    (patch.CHAT_EDITOR_CONTROLS, "UIColor(rgb: 0x0088ff)", "UIColor(rgb: 0x0088FE)"),
    (patch.CHAT_EDITOR_COVER, "UIColor(rgb: 0x0088ff)", "UIColor(rgb: 0x0088FE)"),
    (patch.MEDIA_EDITOR, "pressedColor: UIColor(rgb: 0x0088ff)", "pressedColor: UIColor(rgb: 0x0088FE)"),
    (patch.MEDIA_TOOLS, "UIColor(rgb: 0x0088ff)", "UIColor(rgb: 0x0088FE)"),
    (patch.DRAWING_SCREEN, ".color(UIColor(rgb: 0x0088ff))", ".color(UIColor(rgb: 0x0088FE))"),
    (patch.PICKER_TOOLBAR, "UIColor(rgb: 0x0088ff)", "UIColor(rgb: 0x0088FE)"),
    (patch.CRASH_REPORTS, "actions.send(pending[0], context: context)", "actions.send(pending.first!, context: context)"),
    (patch.CRASH_REPORTS, "    private func share(_ report: CrashReport) {", "    fileprivate func share(_ report: CrashReport) {"),
    ("submodules/QrCodeUI/Sources/QrCodeScanScreen.swift", 'filteredCodes = codes.filter { $0.message.hasPrefix("tg://") }',
     'filteredCodes = codes.filter { $0.message.hasPrefix("tg://login") }'),
    ("submodules/TelegramUI/Components/ShareExtensionContext/Sources/ShareExtensionContext.swift",
     'self.openUrl("tg://shareStory?session=', 'self.openUrl("tg://share-story?session='),
    (patch.URL_HANDLING, "    if let parsedUrl = URL(string: url), parsedUrl.scheme == \"tg\", let host = parsedUrl.host, let query = parsedUrl.query {\n"
     "        if let internalUrl = parseInternalUrl(sharedContext: sharedContext, context: context, query: host + \"?\" + query), case .peer",
     "    if let parsedUrl = URL(string: url), [\"tg\"].contains(parsedUrl.scheme), let host = parsedUrl.host, let query = parsedUrl.query {\n"
     "        if let internalUrl = parseInternalUrl(sharedContext: sharedContext, context: context, query: host + \"?\" + query), case .peer"),
    # pluma.chat links: a host list, the subdomain check, a new t.me link in
    # a file the patch edits, a changed link it keeps, a text with one more.
    ("submodules/TelegramUI/Sources/OpenUrl.swift", '["t.me", "telegram.me", "telegram.dog"]',
     '["t.me", "telegram.me", "telegram.dog", "telegram.org"]'),
    (patch.URL_HANDLING, 'lowercasedUrl.contains(".\\(basePath)?"))) {', 'lowercasedUrl.contains(".\\(basePath)#"))) {'),
    (patch.URL_HANDLING, "    return telegramWebShortLinkHosts.contains(host)\n", "    return telegramWebShortLinkHosts.contains(host.lowercased())\n"),
    (patch.URL_HANDLING, "public func isTelegramMeLink(_ url: String) -> Bool {\n", "public func isTelegramMeLink(_ url: String, strict: Bool = false) -> Bool {\n"),
    (patch.URL_HANDLING, "            if isTelegramWebShortLink(url) {\n                return .single(.result(.externalUrl(url)))\n",
     "            if isTelegramWebShortLink(url) {\n                return .single(.result(.externalUrl(url, forceExternal: true)))\n"),
    ("submodules/TelegramUI/Sources/OpenUrl.swift", "telegramMeHosts.contains(host) {\n            handleInternalUrl(parsedUrl.absoluteString)\n",
     "telegramMeHosts.contains(host.lowercased()) {\n            handleInternalUrl(parsedUrl.absoluteString)\n"),
    ("submodules/TelegramUI/Sources/Chat/ChatControllerOpenLinkContextMenu.swift", "import UrlWhitelist\n", ""),
    ("submodules/ShareController/Sources/ShareController.swift", 'url = "https://t.me/\\(addressName)/\\(message.id.id)"',
     'url = "https://t.me/\\(addressName)/\\(message.id.id)"; let profile = "https://t.me/\\(addressName)"'),
    ("submodules/PremiumUI/Sources/PremiumGiftCodeScreen.swift", 'link = "https://t.me/giftcode/\\(slug)"',
     'link = "https://t.me/giftcode/\\(slug)/"'),
    (patch.STRINGS, '"EmptyGroupInfo.Line3" = "Public links such as t.me/title";',
     '"EmptyGroupInfo.Line3" = "Public links such as t.me/title or t.me/name";'),
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
    # The login code screens.
    (patch.LOGIN_CODE_NODE, '                animationName = "IntroFragment"\n', '                animationName = "IntroFragmentNew"\n'),
    (patch.APP_DELEGATE, '                if parsed.scheme == "tg" {\n', '                if parsed.scheme == "tg" || parsed.scheme == "ton" {\n'),
    (patch.STRINGS, '"Login.EnterCodeSMSTitle" = "Enter Code";\n',
     '"Login.EnterCodeSMSTitle" = "Enter Code";\n"Pluma.Login.SendAgain" = "Send again";\n'),
    # tgcalls: a value of the call engine or the camera that moved.
    (patch.CALL_ENGINE, "                codec.SetParam(cricket::kCodecParamPTime, 60);\n",
     "                codec.SetParam(cricket::kCodecParamPTime, 40);\n"),
    (patch.CALL_ENGINE, "            _outgoingVideoChannel->setMaxBitrate(1000 * 1024);\n",
     "            _outgoingVideoChannel->setMaxBitrate(1200 * 1024);\n"),
    (patch.CALL_CAPTURE, "_videoCapturerResolution.second, 25);\n", "_videoCapturerResolution.second, 30);\n"),
    # No AI message editor: each edit.
    *((rel, old, old.replace(", ", ",  ", 1)) for rel, old, _, _ in patch.NO_AI_EDITOR_EDITS),
    # Transcription: a gate that no longer keeps a view-once message out, a
    # view-once message no longer recognised, the button set before the gate
    # or after it.
    *((rel, s, s.replace(" && !isViewOnceMessage", "")) for rel, s, _ in patch.TRANSCRIBE_VIEW_ONCE_GATES if "var displayTranscribe" in s),
    *((rel, s, s.replace("viewOnceTimeout", "0")) for rel, s, _ in patch.TRANSCRIBE_VIEW_ONCE_GATES if "let isViewOnceMessage" in s),
    (patch.TRANSCRIBE_FILE_NODE, "                var displayTranscribe = false\n                if Namespaces",
     "                var displayTranscribe = isVoice\n                if Namespaces"),
    (patch.TRANSCRIBE_FILE_NODE, "                let transcribedText = forcedAudioTranscriptionText",
     "                displayTranscribe = true\n                let transcribedText = forcedAudioTranscriptionText"),
    (patch.TRANSCRIBE_VIDEO_NODE, "                        if !scaleProgress.isZero {\n                            displayTranscribe = false\n",
     "                        if !scaleProgress.isZero {\n                            displayTranscribe = true\n"),
    # The service account: a place that shows a support account's line gone,
    # one more of them, a row of a contact or of a list changed, Telegram's
    # text changed.
    *((rel, "Bot_GenericSupportStatus", "Bot_GenericBotStatus") for rel, _ in patch.SERVICE_ACCOUNT_SITES),
    (patch.CONTACTS_ITEM, "                            userPresence = presence\n",
     "                            userPresence = presence\n"
     "                            let support = item.presentationData.strings.Bot_GenericSupportStatus\n"),
    (patch.CONTACTS_ITEM, "                        } else {\n                            userPresence = presence\n",
     "                        } else if !item.selectionOnly {\n                            userPresence = presence\n"),
    (patch.PEER_ITEM, "                } else if let presence = item.presence {\n",
     "                } else if let presence = item.presence, !item.editing.editing {\n"),
    (patch.PEER_ITEM, "                    let botStatus: String\n",
     "                    let botStatus: String\n"
     "                    let support = user.flags.contains(.isSupport)\n"),
    (patch.STRINGS, '"Bot.GenericSupportStatus" = "support";\n', '"Bot.GenericSupportStatus" = "Support";\n'),
    # Group calls end to end: a place of each edited file that moved, the
    # patch's key already upstream, an entry to RTMP elsewhere, another
    # message over the data channel.
    (patch.CALL_MANAGER, "            joinAsPeerId: joinAsPeerId,\n", "            joinAsPeerId: joinAsPeerId ?? nil,\n"),
    (patch.CALL_MANAGER, "                            initialCall: nil,\n", "                            initialCall: Optional.none,\n"),
    (patch.GROUP_CALL, "guard let self, isFailed else {", "guard let self, isFailed == true else {"),
    (patch.GROUP_CALL, '"ios_use_inprocess_screencast"', '"ios_use_inprocess_screencast_v2"'),
    (patch.GROUP_CALL, 'let _ = try? "ipc".write(', 'try? "ipc".write('),
    (patch.GROUP_CALL, "let userId = self.joinAsPeerId.id._internalGetInt64Value()", "let userId = self.joinAsPeerId.toInt64()"),
    (patch.GROUP_CALL, "        self.startDisposable.set((self.accountContext.engine.calls.createGroupCall(peerId: peerId, title: nil, scheduleDate: timestamp, isExternalStream: false)\n"
     "        |> deliverOnMainQueue).start(next: { [weak self] callInfo in\n",
     "        self.startDisposable.set((self.accountContext.engine.calls.createGroupCall(peerId: peerId, title: nil, scheduleDate: timestamp, isExternalStream: false)\n"
     "        |> deliverOnMainQueue).startStandalone(next: { [weak self] callInfo in\n"),
    (patch.GROUP_CALL_SCREENCAST, "// Prevent non-encrypted conference calls", "// Prevent unencrypted conference calls"),
    (patch.VIDEO_CHAT_SCREEN, "                    navigationHeight -= 2.0\n", "                    navigationHeight -= 4.0\n"),
    (patch.VIDEO_CHAT_SCREEN, "            var encryptionKeyFrame: CGRect?\n",
     "            var encryptionKeyFrame: CGRect?\n            let _ = environment.strings.ChannelInfo_CreateExternalStream\n"),
    (patch.E2E_CONTEXT, "guard let state = initializeState(keyPair, userId, block) else {",
     "guard let state = self.initializeState(keyPair, userId, block) else {"),
    (patch.ENGINE_CALLS, "_internal_cachedGroupCallDisplayAsAvailablePeers(account: self.account, peerId: peerId)",
     "_internal_cachedGroupCallDisplayAsAvailablePeers(account: self.account, peerId: peerId, includeSelf: false)"),
    (patch.GROUP_CALL_CONTEXT, "            self.context.addExternalAudioData(data)\n", "            self.context.addExternalAudioData(data as Data)\n"),
    (patch.CALL_CONTEXT_HEADER, "- (void)getStats:(void (^ _Nonnull)(OngoingGroupCallStats * _Nonnull))completion;",
     "- (void)getStats:(void (^ _Nullable)(OngoingGroupCallStats * _Nonnull))completion;"),
    (patch.CALL_CONTEXT, "- (void)getStats:(void (^ _Nonnull)(OngoingGroupCallStats * _Nonnull))completion {",
     "- (void)getStats:(void (^ _Nullable)(OngoingGroupCallStats * _Nonnull))completion {"),
    (patch.GROUP_INSTANCE, "virtual void internal_addCustomNetworkEvent(bool isRemoteConnected) = 0;",
     "virtual void internal_addCustomNetworkEvent(bool isRemoteConnected, bool isLocal) = 0;"),
    (patch.GROUP_INSTANCE_CUSTOM_HEADER, "    void internal_addCustomNetworkEvent(bool isRemoteConnected);\n",
     "    void internal_addCustomNetworkEvent(bool connected);\n"),
    (patch.GROUP_INSTANCE_CUSTOM, "            networkManager->sendDataChannelMessage(result);\n",
     "            networkManager->sendDataChannelMessage(result);\n            networkManager->sendDataChannelMessage(\"{}\");\n"),
    (patch.TD_BINDING, "tde2e_api::call_decrypt(_callId, userId, 0, mappedMessage);", "tde2e_api::call_decrypt(_callId, userId, 1, mappedMessage);"),
    (patch.TD_BINDING, "    auto result = tde2e_api::call_apply_block(_callId, mappedBlock);\n    if (!result.is_ok()) {\n        return false;\n",
     "    auto result = tde2e_api::call_apply_block(_callId, mappedBlock);\n    if (result.is_error()) {\n        return false;\n"),
    (patch.TD_BINDING_HEADER, "- (nullable NSData *)decrypt:(NSData *)message userId:(int64_t)userId;",
     "- (nullable NSData *)decrypt:(NSData *)message userId:(int64_t)userId channelId:(int32_t)channelId;"),
    (patch.PEER_INFO_CALLS, "strings.ChannelInfo_CreateExternalStream", "strings.ChannelInfo_StreamWith"),
    (patch.MEDIA_STREAM, "strings.LiveStream_ViewCredentials", "strings.LiveStream_ViewStreamKey"),
    (patch.STORY_CAMERA, "                self.canLivestream = true\n", "                self.canLivestream = !self.isTablet\n"),
    (patch.STRINGS, '"Common.OK" = "OK";\n', '"Common.OK" = "OK";\n"Pluma.GroupCall.EncryptionFailed" = "x";\n'),
    # The self-healing rule: where the server's next offset comes from, a
    # write to the chain, the lock the report is made under.
    (patch.E2E_CONTEXT, "                self.e2ePoll0Offset = initialState.subChain0.offset\n",
     "                self.e2ePoll0Offset = initialState.subChain0.offset + 0\n"),
    (patch.E2E_CONTEXT, "            let updateBaseOffset = nextOffset - blocks.count\n", "            let updateBaseOffset = nextOffset - blocks.count + 0\n"),
    (patch.E2E_CONTEXT, "            let accountPeerId = engine.account.peerId\n", "            let accountPeerId = self.engine.account.peerId\n"),
    (patch.E2E_CONTEXT, "        public var pendingIncomingBroadcastBlocks: [Data] = []\n",
     "        public var pendingIncomingBroadcastBlocks = [Data]()\n"),
    (patch.E2E_CONTEXT, "mode: .cleanup, participantIds: removedPeerIds, block: removeBlock)", "mode: .cleanup, participantIds: removedPeerIds, block: removeBlock!)"),
    (patch.ENGINE_GROUP_CALLS, "        return .single(.pollBlocksAndRetry)\n", "        return Signal.single(.pollBlocksAndRetry)\n"),
    (patch.ENGINE_GROUP_CALLS, "    |> retry(retryOnError: { _ in\n        return true\n    }, delayIncrement: 0.1, maxDelay: 1.0, maxRetries: 5,",
     "    |> retry(retryOnError: { _ in\n        return true\n    }, delayIncrement: 0.1, maxDelay: 1.0, maxRetries: 3,"),
    (patch.ENGINE_CALLS, "block: Data) -> Signal<Never, NoError> {", "block: Data) -> Signal<Never, NoError>  {"),
    # The join and its repeat on CONF_WRITE_CHAIN_INVALID.
    (patch.ENGINE_GROUP_CALLS, "    enum InternalJoinError {\n        case error(JoinGroupCallError)\n",
     "    enum InternalJoinError: Error {\n        case error(JoinGroupCallError)\n"),
    (patch.ENGINE_GROUP_CALLS, "            guard let block = result.blocks.last else {\n                return generateE2E(nil)\n",
     "            guard let block = result.blocks.first else {\n                return generateE2E(nil)\n"),
    (patch.ENGINE_GROUP_CALLS, "    |> mapToSignal { e2eData -> Signal<JoinGroupCallResult, InternalJoinError> in\n",
     "    |> mapToSignal { (e2eData) -> Signal<JoinGroupCallResult, InternalJoinError> in\n"),
    (patch.ENGINE_GROUP_CALLS, "        case .restart:\n            return .restart\n        case let .error(e):\n",
     "        case .restart:\n            return RestartOrMapErrorCondition.restart\n        case let .error(e):\n"),
    # Recording: each entry that starts one.
    (patch.VIDEO_CHAT_MORE_MENU, "                    text = environment.strings.LiveStream_StartRecording\n",
     "                    text = environment.strings.LiveStream_StartRecording.uppercased()\n"),
    (patch.VIDEO_CHAT_MORE_MENU, "groupCall.setShouldBeRecording(true, title: title, videoOrientation: videoOrientation)",
     "groupCall.setShouldBeRecording(!false, title: title, videoOrientation: videoOrientation)"),
    (patch.MEDIA_STREAM, "                            let text = presentationData.strings.LiveStream_StartRecording\n",
     "                            let text: String = presentationData.strings.LiveStream_StartRecording\n"),
    # Call colours: one more of Telegram's, a fraction that moved.
    (patch.CALL_BACKGROUND, "                hexToFloat(0x7664DA)\n", "                hexToFloat(0x7664DA),\n                hexToFloat(0x7664DA)\n"),
    (patch.MEDIA_STREAM, "UIColor(red: 0.314, green: 0.161, blue: 0.197, alpha: 1)", "UIColor(red: 0.314, green: 0.161, blue: 0.197, alpha: 1.0)"),
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
    files = archived_files(git, "", patch.UPSTREAM_PATHS)
    # Each submodule at the commit the checkout pins for it.
    for sub, _, paths in patch.SUBMODULES:
        pinned = subprocess.run(git + ["ls-tree", "HEAD", sub], capture_output=True, text=True, check=True).stdout.split()
        sub_git = ["git", "-C", str(ROOT / "upstream" / sub)]
        try:
            head = subprocess.run(sub_git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return None
        if pinned[1:3] != ["commit", head]:
            return None
        files.update(archived_files(sub_git, sub + "/", [p[len(sub) + 1:] for p in paths]))
    return files


def archived_files(git, prefix, paths):
    """{prefix + path: bytes} of paths at HEAD of the repository git names."""
    archive = subprocess.run(git + ["archive", "--format=tar", "HEAD", *paths], capture_output=True, check=True).stdout
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for m in tar.getmembers():
            if m.isfile():
                files[prefix + m.name] = tar.extractfile(m).read()
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
        self.assertIn(patch.DNS_NATIVE, tree.read(DNS))
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
        # The wordmark as the title of the intro's first page.
        intro = tree.read(patch.INTRO_CONTROLLER)
        self.assertIn(patch.INTRO_PAGES + patch.INTRO_WORDMARK + patch.INTRO_PAGE_ZERO, intro)
        self.assertEqual(intro.count("firstPage.headerLabel.attributedText = title;\n"), 1)
        self.assertEqual(intro.count("firstPage.headerLabel.accessibilityLabel = _headlines.firstObject;\n"), 1)
        # Its animations in the arm64 simulator build too.
        self.assertIn(patch.INTRO_GL, intro)
        self.assertNotIn("TARGET_OS_SIMULATOR", intro)
        # The mark of its first page: a view of the host's, which the intro
        # lays out with the pages, brings in, shows on the first page and has
        # written whenever the page appears; the GL view under everything.
        self.assertIn(patch.INTRO_HEADER_ANCHOR + patch.INTRO_HEADER_MARK, tree.read(patch.INTRO_HEADER))
        self.assertIn(patch.INTRO_DEVICE_SCREEN + patch.INTRO_LAYOUT_CONSTANTS, intro)
        self.assertIn(patch.INTRO_LAYOUT, intro)
        self.assertNotIn("isVertical", intro)
        self.assertIn("        [self.view insertSubview:_glkView atIndex:0];\n", intro)
        self.assertNotIn("[self.view addSubview:_glkView];", intro)
        self.assertIn("[self.view insertSubview:_firstPageMarkContainer belowSubview:_wrapperView];\n", intro)
        for line, added in patch.INTRO_ANIMATE_IN:
            self.assertIn(line + added, intro)
        self.assertIn(patch.INTRO_SNAPSHOT_ANCHOR + patch.INTRO_SNAPSHOT, intro)
        self.assertIn(patch.INTRO_APPEAR, intro)
        self.assertIn(patch.INTRO_SCROLL, intro)
        self.assertIn(patch.INTRO_METHODS + patch.INTRO_METHODS_ANCHOR, intro)
        # Back on the first page, the page changes when the finger lifts, the
        # mark often still faded out by the scroll: it writes itself once the
        # scroll lets it show, not before.
        self.assertIn("    bool _firstPageMarkWritePending;\n", intro)
        self.assertEqual(intro.count("_firstPageMarkAppeared();"), 1)
        self.assertIn(patch.src(" " * 4, """
            if (_firstPageMarkWritePending && _firstPageMarkView.alpha > 0.0f) {
                _firstPageMarkWritePending = false;
                if (_firstPageMarkAppeared != nil) {
                    _firstPageMarkAppeared();
        """), intro)
        # The lines that make the blank sphere the mask of the first page stay
        # as upstream has them.
        for rel, s in patch.INTRO_SPHERE_MASK:
            self.assertEqual(tree.read(rel).count(s), 1, rel)
        splash = tree.read(patch.INTRO_SPLASH)
        for anchor, added in patch.INTRO_SPLASH_EDITS:
            self.assertIn(anchor + added, splash)
        self.assertEqual(splash.count("private final class IntroMarkNode: ManagedAnimationNode {\n"), 1)
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
        # plm:// instead of tg://, which the app only asks about (whether the
        # Telegram app is installed, for the login code screens); the wallet's
        # schemes stay with the apps that have one.
        self.assertNotIn("                <string>tg</string>\n", build)
        self.assertEqual(build.count("<string>tg</string>"), 1)
        self.assertIn("        <string>rizogo</string>\n        <string>tg</string>\n    </array>\n", build)
        self.assertNotIn("<string>ton</string>", build)
        self.assertNotIn("<string>tc</string>", build)
        self.assertIn('"SocksProxySetup.QrCode.TgLink" = "plm:// link";', tree.read(patch.STRINGS))
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
        # pluma.chat: among the hosts of the app's own links, no username in
        # its subdomains, in the links the app makes and the texts that show
        # them; t.me where the app keeps it.
        self.assertIn('    "t.me", "telegram.dog",\n    "pluma.chat"\n]\n', tree.read(patch.URL_HANDLING))
        self.assertIn('if basePath != "pluma.chat" && (lowercasedUrl.hasPrefix(scheme) && ', tree.read(patch.URL_HANDLING))
        # The pages of the site itself are a site's: not the app's links, an
        # external result when resolved, opened as any site's.
        handling = tree.read(patch.URL_HANDLING)
        self.assertIn('    "favicon.svg", "og.png", "apple-touch-icon.png", "404.html", "progress.json"\n]\n', handling)
        self.assertIn('parsedUrl.host?.lowercased() == "pluma.chat" else {', handling)
        self.assertIn('public func isTelegramMeLink(_ url: String) -> Bool {\n    if isPlumaSiteLink(url) {\n        return false\n', handling)
        self.assertIn('            if isPlumaSiteLink(url) {\n                return .single(.result(.externalUrl(url)))\n', handling)
        self.assertIn('telegramMeHosts.contains(host), !isPlumaSiteLink(parsedUrl.absoluteString) {\n'
                      '            handleInternalUrl(', tree.read(patch.OPEN_URL))
        menu = tree.read(patch.OPEN_LINK_MENU)
        self.assertIn('|| (host == "pluma.chat" && !isPlumaSiteLink(parsedUrl.absoluteString)) {', menu)
        self.assertIn("import UrlHandling\n", menu)
        self.assertIn('["t.me", "telegram.me", "telegram.dog", "pluma.chat"]', tree.read(patch.OPEN_URL))
        self.assertIn('$0.message.hasPrefix("https://pluma.chat/") || $0.message.hasPrefix("pluma.chat/") }', scan)
        self.assertIn('} else if slug.hasPrefix("https://pluma.chat/addlist/") {', tree.read(patch.CHAT_FOLDERS))
        self.assertIn('url = "https://pluma.chat/\\(addressName)/\\(message.id.id)"',
                      tree.read("submodules/ShareController/Sources/ShareController.swift"))
        self.assertIn('link = "\\(externalLink ? "https://pluma.chat/proxy" : "plm://proxy")?server=',
                      tree.read("submodules/QrCodeUI/Sources/QrCodeScreen.swift"))
        self.assertIn('title: NSAttributedString(string: "pluma.chat/",',
                      tree.read("submodules/TelegramUI/Sources/CreateChannelController.swift"))
        self.assertIn('private let phonebookUsernamePrefix = "https://t.me/" + phonebookUsernamePathPrefix',
                      tree.read("submodules/AccountContext/Sources/DeviceContactData.swift"))
        self.assertIn('"Username.LinkHint" = "This link opens a chat with you in Pluma:[\\nhttps://pluma.chat/%@]";', strings)
        self.assertIn('"Business.Links.SimpleLinkInfoUsernamePhone" = "You can also use a simple link for a chat with you '
                      '— [pluma.chat/%1$@](username) or [pluma.chat/\\\\u{2060}+\\\\u{2060}%2$@](phone).";', strings)
        self.assertIn('"Premium.Limits.PublicLinksInfo" = "Reserve up to 20 [t.me/name]() links";', strings)
        # The palette.
        day, dark = tree.read(patch.DAY_THEME), tree.read(patch.DARK_THEME)
        self.assertIn("public let defaultDayAccentColor = UIColor(rgb: 0x5b7a5e)", day)
        self.assertEqual(day.count("fill: [UIColor(rgb: 0xe3eae2), UIColor(rgb: 0xd5e1d4)],"), 2)
        self.assertIn("let defaultPatternWallpaper: TelegramWallpaper = .color(0xffffff)\n", day)
        self.assertEqual(dark.count("fill: [UIColor(rgb: 0x2c3a2d), UIColor(rgb: 0x36473a)],"), 2)
        self.assertIn("secondaryTextColor: UIColor(rgb: 0xb2ceb4), linkTextColor: UIColor(rgb: 0xb2ceb4),", dark)
        self.assertIn("let defaultPatternWallpaper: TelegramWallpaper = .color(0x131513)\n", dark)
        self.assertNotIn("baseColor: .blue", tree.read(patch.PRESENTATION_DATA))
        # Night with the palette's accent picked: #131513 on it, the check of
        # the verified badge too.
        self.assertIn(patch.NIGHT_SAGE_TEXT + "            } else if initialAccentColor.lightness > 0.735 {\n"
                      "                secondaryBadgeTextColor = UIColor(rgb: 0x000000)\n", dark)
        self.assertNotIn("|| initialAccentColor.rgb == 0x9dbb9f", dark)
        avatars = tree.read(patch.AVATAR_NODE)
        self.assertIn("    static let savedMessagesColors: [UIColor] = [\n"
                      "        UIColor(rgb: 0x5b7a5e), UIColor(rgb: 0x9dbb9f) // pluma: sage\n", avatars)
        self.assertIn("    static let repostColors: [UIColor] = [\n"
                      "        UIColor(rgb: 0x4f6e52), UIColor(rgb: 0x9dbb9f) // pluma: sage\n", avatars)
        # People's identity colours: blue is sage and cyan a teal, in the
        # letter avatars of the app and its extensions, the names and, in dark
        # themes, names of their own, which the fallback of the names takes
        # too; the other five are Telegram's.
        self.assertIn("        [UIColor(rgb: 0x5b7a5e), UIColor(rgb: 0x7fa082)], // pluma: sage\n", avatars)
        self.assertIn("        [UIColor(rgb: 0x2c9c98), UIColor(rgb: 0x5bcbc4)], // pluma: teal\n", avatars)
        self.assertIn("        [UIColor(rgb: 0xff516a), UIColor(rgb: 0xff885e)],\n", avatars)
        for rel in (patch.NOTIFICATION_AVATARS, patch.WIDGET_AVATARS, patch.INTENT_AVATARS, patch.LIVE_STREAM_AVATARS):
            self.assertIn("    [UIColor(rgb: 0x5b7a5e).cgColor, UIColor(rgb: 0x7fa082).cgColor], // pluma: sage\n", tree.read(rel))
        names = tree.read(patch.PEER_NAME_COLORS)
        self.assertIn("            5: Colors(main: UIColor(rgb: 0x4f6e52)), // pluma: sage\n", names)
        self.assertIn("            3: Colors(main: UIColor(rgb: 0x40a920)),\n", names)
        self.assertIn("            darkColors: [\n                4: Colors(main: UIColor(rgb: 0x53ccc6)),\n"
                      "                5: Colors(main: UIColor(rgb: 0x9dbb9f))\n            ],\n", names)
        self.assertEqual(names.count("            return dark ? (PeerNameColors.defaultValue.darkColors[5] ?? "
                                     "PeerNameColors.defaultSingleColors[5]!) : PeerNameColors.defaultSingleColors[5]!\n"), 2)
        self.assertNotIn("            return PeerNameColors.defaultSingleColors[5]!\n", names)
        updates = tree.read(patch.PEER_COLOR_UPDATES)
        self.assertIn("                        0x4f6e52, // pluma: sage\n", updates)
        self.assertIn("                    let staticDarkMap: [Int32: UInt32] = [4: 0x53ccc6, 5: 0x9dbb9f]\n", updates)
        # No support section.
        self.assertNotIn("Settings_Support", tree.read(patch.SETTINGS_ITEMS))
        self.assertNotIn("let helpItems = ", tree.read(patch.SETTINGS_SEARCH))
        for rel, count in patch.MEDIA_EDITOR_ACCENTS:
            self.assertEqual(tree.read(rel).count("UIColor(rgb: 0x5b7a5e)"), count, rel)
        self.assertIn("neutralNightAccentColor = UIColor(rgb: 0x9dbb9f)", tree.read(patch.MAKE_THEME))
        self.assertIn(patch.SEND_GLASS, tree.read(patch.SEND_BUTTON))
        self.assertIn(patch.SEND_GLASS_ICON, tree.read(patch.SEND_BUTTON))
        crash_reports = tree.read(patch.CRASH_REPORTS)
        self.assertNotIn("Send to Telegram Team", crash_reports)
        self.assertNotIn("actions.send(", crash_reports)
        self.assertIn("                actions.share(pending[0])\n", crash_reports)
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
        # Tags of Saved Messages without Premium, at the gates of tags only;
        # the server's limit of reactions on a message for everybody.
        state = tree.read(patch.CHAT_STATE)
        self.assertIn("    public let isPremium: Bool\n", state)
        self.assertIn("    public var canUseSavedTags: Bool {\n        return true\n    }\n", state)
        controller = tree.read(patch.CHAT_CONTROLLER)
        self.assertIn("                if !strongSelf.presentationInterfaceState.canUseSavedTags {\n"
                      "                    strongSelf.presentTagPremiumPaywall()\n", controller)
        self.assertEqual(controller.count("canUseSavedTags"), 1)
        self.assertIn(").isPremiumDisabled {\n                            let _ = (ApplicationSpecificNotice."
                      "incrementMultipleReactionsSuggestion(", controller)
        self.assertEqual(tree.read(patch.TAG_CONTEXT_MENU).count("canUseSavedTags"), 1)
        menu = tree.read(patch.MESSAGE_CONTEXT_MENU)
        self.assertEqual(menu.count("canUseSavedTags"), 2)
        # A custom emoji reaction outside Saved Messages still needs Premium.
        self.assertEqual(menu.count("                                    if !self.presentationInterfaceState.isPremium {\n"
                                    "                                        controller?.premiumReactionsSelected?()\n"), 1)
        for rel, uses in ((patch.TAG_PANEL, 4), (patch.TITLE_PANELS, 2)):
            text = tree.read(rel)
            self.assertEqual(text.count("canUseSavedTags"), uses, rel)
            self.assertNotIn("isPremium", text, rel)
        reactions = tree.read(patch.MESSAGE_REACTIONS)
        self.assertIn(patch.REACTIONS_LIMIT, reactions)
        self.assertNotIn("maxCount = 1\n", reactions)
        self.assertEqual(reactions.count("let isPremium = (transaction.getPeer(account.peerId) as? TelegramUser)?.isPremium ?? false\n"), 1)
        # Pluma's video bitrates in both preset tables, the round video
        # recorder and the GIF converter; an edited video's default preset
        # capped by the source's size.
        legacy = tree.read(patch.VIDEO_PRESETS_LEGACY)
        self.assertIn("        case TGMediaVideoConversionPresetCompressedVeryHigh:\n"
                      "            return 12000; // pluma: 6600 in Telegram (task 052)\n", legacy)
        self.assertIn("        case TGMediaVideoConversionPresetCompressedHigh:\n"
                      "            return 128; // pluma: 64 in Telegram (task 052)\n", legacy)
        self.assertIn("        case TGMediaVideoConversionPresetCompressedVeryLow:\n"
                      "            return 2; // pluma: 1 in Telegram (task 052)\n", legacy)
        self.assertIn("        case TGMediaVideoConversionPresetAnimation:\n            return 1800;", legacy)
        for value in ("return 400;", "return 700;", "return 1600;", "return 3000;", "return 6600;"):
            self.assertNotIn(value + "\n", legacy)
        presets = tree.read(patch.VIDEO_PRESETS)
        self.assertIn("        case .compressedHigh:\n            return 5000 // pluma: 3000 in Telegram (task 052)\n", presets)
        self.assertIn("        case .videoMessage:\n            return 2000 // pluma: 1200 in Telegram (task 052)\n", presets)
        self.assertIn("        case .sticker:\n            return 1000\n", presets)  # not a video message, kept
        self.assertIn("        case .animation:\n            return 1800", presets)
        self.assertIn("        case .compressedMedium, .compressedHigh, .compressedVeryHigh:\n            return 128\n", presets)
        self.assertNotIn("            return 1\n", presets)
        self.assertIn("        self.bitrateKbps = 2000 //", presets)
        self.assertIn("AVVideoAverageBitRateKey: 2000 * 1000,", tree.read(patch.ROUND_VIDEO_RECORDER))
        self.assertIn("AVVideoAverageBitRateKey: 2_000_000,", tree.read(patch.ROUND_VIDEO_RECORDER_NEO))
        self.assertIn("audioSettings[AVEncoderBitRateKey] = 96_000", tree.read(patch.ROUND_VIDEO_RECORDER_NEO))
        self.assertIn("AVVideoAverageBitRateKey: @(1000000),", tree.read(patch.GIF_CONVERTER))
        self.assertIn(patch.VIDEO_DEFAULT_PRESET, tree.read(patch.VIDEO_FETCH))
        # What App Store Connect asks: the purpose of background location,
        # no SF Camera, Siri phrases for every intent.
        self.assertIn("    <key>NSLocationAlwaysAndWhenInUseUsageDescription</key>\n"
                      "    <string>When you choose to share your Live Location with friends in a chat, Pluma needs "
                      "background access to your location to keep them updated for the duration of the live sharing."
                      "</string>\n    <key>NSLocationWhenInUseUsageDescription</key>\n", build)
        self.assertNotIn("UIAppFonts", build)
        for rel in patch.CAMERA_FONTS:
            self.assertFalse((self.root / rel).exists(), rel)
        assets = tree.read(patch.CAMERA_ASSETS)
        self.assertIn("return font ?: [UIFont systemFontOfSize:size weight:UIFontWeightRegular];", assets)
        self.assertIn("return font ?: [UIFont systemFontOfSize:size weight:UIFontWeightSemibold];", assets)
        self.assertEqual(set(patch.SIRI_PHRASES), set(patch.SIRI_UPSTREAM))
        en = tree.read(patch.SIRI_VOCABULARY.format("en"))
        self.assertIn("<string>Send a Pluma message to Alex saying I&apos;ll be there in 10 minutes</string>", en)
        self.assertIn("<string>INSearchCallHistoryIntent</string>\n\t\t\t<key>IntentExamples</key>\n"
                      "\t\t\t<array>\n\t\t\t\t<string>Show my missed calls in Pluma</string>", en)
        for lang, phrases in patch.SIRI_PHRASES.items():
            with self.subTest(lang=lang):
                self.assertEqual(len(phrases), len(patch.SIRI_INTENTS))
                vocabulary = tree.read(patch.SIRI_VOCABULARY.format(lang))
                self.assertEqual(vocabulary.count("Pluma"), len(patch.SIRI_INTENTS))
                self.assertNotIn("{name}", vocabulary)
                plistlib.loads(vocabulary.encode("utf-8"))
        # The call quality from phoneCall.custom_parameters, Telegram's values
        # where the server sets none.
        engine = tree.read(patch.CALL_ENGINE)
        self.assertEqual(engine.count("plumaCallParameters(_customParameters)"), 1)
        self.assertIn("    int audioPacketMs = 60;\n    int audioMaxBitrateBps = 32 * 1024;\n", engine)
        self.assertIn("    int audioJitterMinDelayMs = 50;\n", engine)
        self.assertIn("    int videoMaxBitrateBps = 1000 * 1024;\n", engine)
        self.assertEqual(engine.count("_plumaParameters.audioPacketMs\n"), 1)
        self.assertEqual(engine.count("_plumaParameters.audioJitterMinDelayMs\n"), 1)
        self.assertIn("    int _adaptationFramerate = 25;", tree.read(patch.CALL_CAPTURE_HEADER))
        self.assertEqual(tree.read(patch.CALL_CAPTURE).count(", _adaptationFramerate);\n"), 2)

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
                    "Telegram/Telegram-iOS/Resources/Devices.tgs", patch.INTRO_RESOURCES + "/telegram_sphere@2x.png",
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
        # A file of Pluma's that upstream has already: a layer of the icon,
        # the wordmark of the intro.
        for rel in (patch.BRAND_ADDED[0], patch.INTRO_RESOURCES + "/pluma_wordmark@2x.png"):
            with self.subTest(rel=rel, damage="exists"):
                self.tearDown()
                self.written.add(rel)
                (self.root / rel).write_bytes(b"\x89PNG")
                with self.assertRaises(patch.PatchError) as e:
                    self.run_patch()
                self.assertIn(rel, str(e.exception))

    def test_links(self):
        # The check after the edits finds a t.me link the patch does not know
        # (in a new file too), a list of the app's hosts without pluma.chat, a
        # subdomain of pluma.chat read as a username, a page of the site read
        # as the app's link, a text with a t.me link.
        share = "submodules/ShareController/Sources/ShareController.swift"
        sample = "submodules/TelegramUI/Sources/ShareProfileLink.swift"
        for rel, old, new in (
            (sample, None, 'let link = "https://t.me/\\(addressName)"\n'),
            (share, 'url = "https://pluma.chat/\\(addressName)/', 'url = "https://t.me/\\(addressName)/'),
            (patch.OPEN_URL, '"telegram.dog", "pluma.chat"]', '"telegram.dog"]'),
            (patch.URL_HANDLING, patch.URL_SUBDOMAIN, patch.URL_SUBDOMAIN_OLD),
            (patch.URL_HANDLING, "    if isPlumaSiteLink(url) {\n        return false\n    }\n", ""),
            (patch.URL_HANDLING, "            if isPlumaSiteLink(url) {\n                return .single(.result(.externalUrl(url)))\n"
                                 "            }\n", ""),
            (patch.URL_HANDLING, '"iphone", ', ""),
            (patch.OPEN_URL, ", !isPlumaSiteLink(parsedUrl.absoluteString) {", " {"),
            (patch.OPEN_LINK_MENU, '(host == "pluma.chat" && !isPlumaSiteLink(parsedUrl.absoluteString))', 'host == "pluma.chat"'),
            (patch.STRINGS, '"pluma.chat link"', '"t.me link"'),
            (patch.STRINGS, '"plm:// link"', '"tg:// link"'),
            (patch.STRINGS, '"Settings.FAQ" = "Pluma FAQ";', '"Settings.FAQ" = "Pluma FAQ at t.me/faq";'),
        ):
            with self.subTest(rel=rel, old=(old or new)[:60]):
                self.tearDown()
                tree, c = self.run_patch()
                if old is None:
                    tree.write(rel, new)
                else:
                    text = tree.read(rel)
                    self.assertEqual(text.count(old), 1)
                    tree.write(rel, text.replace(old, new))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn(rel, str(e.exception))

    def test_new_links_stop_the_patch(self):
        # A new tg:// literal or a new host of Telegram's is a new place to
        # decide about, in the app's code and in its strings; a unit test is
        # not in the app.
        target = patch.URL_HANDLING
        for text in ('let a = "tg://resolve?domain=x"\n', 'let a = "https://telegram.org/new"\n',
                     'let a = "https://t.me/new"\n', 'let a = "http://telesco.pe/x"\n', 'let a = "Send to Telegram"\n'):
            with self.subTest(text=text):
                self.tearDown()
                tree, c = self.run_patch()
                tree.write(target, tree.read(target) + text)
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn(target, str(e.exception))
        self.tearDown()
        tree, c = self.run_patch()
        tree.write(patch.STRINGS, tree.read(patch.STRINGS) + '"Pluma.New" = "See https://telegram.org/new";\n')
        with self.assertRaises(patch.PatchError) as e:
            patch.verify(tree, c)
        self.assertIn(patch.STRINGS, str(e.exception))

        self.tearDown()
        tree, c = self.run_patch()
        for rel in ("submodules/TextFormat/Tests/New.swift", "Telegram/SiriIntentsTests/New.swift"):
            tree.write(rel, 'let a = "tg://resolve?domain=x", b = "https://telegram.org", c = "https://t.me/x", d = "Telegram"\n')
        patch.verify(tree, c)
        self.assertTrue(patch.is_unit_test("submodules/TelegramUI/Components/RichTextEditor/Tests/RichTextEditorCoreTests/A.swift"))
        self.assertFalse(patch.is_unit_test("submodules/TelegramUI/Components/Tests.swift"))

    def test_every_siri_vocabulary_is_replaced(self):
        tree, c = self.run_patch()
        self.assertNotIn("Telegram", tree.read(patch.SIRI_VOCABULARY.format("Base")))
        rel = patch.SIRI_VOCABULARY.format("xx")
        tree.write(rel, "<plist></plist>")
        with self.assertRaises(patch.PatchError) as e:
            patch.verify(tree, c)
        self.assertIn(rel, str(e.exception))

    def test_login_code_texts(self):
        # The texts of the login code screens name the Telegram app exactly as
        # the patch writes them; any other text that names Telegram, or one of
        # theirs changed, fails the check of the names.
        for old, new in (
            ('"Pluma.Login.CheckTelegramTitle" = "Check Telegram";', '"Pluma.Login.CheckTelegramTitle" = "Open Telegram now";'),
            ('"Pluma.Login.SendAgain" = "Send again";', '"Pluma.Login.SendAgain" = "Send again to Telegram";'),
            ('"Pluma.Login.SendAgain" = "Send again";',
             '"Pluma.Login.SendAgain" = "Send again";\n"Pluma.Login.SendAgainTelegram" = "Send again to Telegram";'),
        ):
            with self.subTest(new=new):
                self.tearDown()
                tree, c = self.run_patch()
                text = tree.read(patch.STRINGS)
                self.assertEqual(text.count(old), 1)
                tree.write(patch.STRINGS, text.replace(old, new))
                with self.assertRaisesRegex(patch.PatchError, "still names Telegram"):
                    patch.verify_names(tree, c)

    def test_service_account(self):
        # A support account's line reads "service account", under upstream's
        # key, at each place upstream shows it, in the row of a contact and
        # in the row of the settings' lists.
        tree, _ = self.run_patch()
        strings = tree.read(patch.STRINGS)
        self.assertIn('"Bot.GenericBotStatus" = "bot";\n"Bot.GenericSupportStatus" = "service account";\n', strings)
        self.assertNotIn('= "support";', strings)
        self.assertEqual(sum(tree.read(rel).count("strings.Bot_GenericSupportStatus") for rel, _ in patch.SERVICE_ACCOUNT_SITES), 5)
        contact = tree.read(patch.CONTACTS_ITEM)
        bot = contact.index("strings.Bot_GenericBotStatus, font: statusFont")
        support = contact.index("user.flags.contains(.isSupport) {\n")
        self.assertLess(bot, support)
        self.assertLess(support, contact.index("strings.Bot_GenericSupportStatus, font: statusFont"))
        self.assertLess(support, contact.index("                            userPresence = presence\n"))
        row = tree.read(patch.PEER_ITEM)
        bot = row.index("string: botStatus, font: statusFont")
        support = row.index("} else if case let .user(user) = item.peer, user.flags.contains(.isSupport) {\n")
        self.assertLess(bot, support)
        self.assertLess(support, row.index("strings.Bot_GenericSupportStatus, font: statusFont"))
        self.assertLess(support, row.index("                } else if let presence = item.presence {\n"))
        self.assertLess(support, row.index("strings.LastSeen_Offline, font: statusFont"))

    def test_intro_without_wordmark(self):
        # The check after the edits finds a first page of the intro without
        # the wordmark.
        tree, c = self.run_patch()
        (self.root / patch.INTRO_CONTROLLER).write_bytes(self.files[patch.INTRO_CONTROLLER])
        with self.assertRaises(patch.PatchError) as e:
            patch.verify(tree, c)
        self.assertIn(patch.INTRO_CONTROLLER, str(e.exception))

    def test_intro_without_mark(self):
        # The check after the edits finds an intro without the first page's
        # mark, with its pages laid out as upstream's, or with the GL view
        # that comes back over them.
        for rel, old, new in (
            (patch.INTRO_HEADER, "@property (nonatomic, strong) UIView *firstPageMarkView;\n", ""),
            (patch.INTRO_CONTROLLER, patch.INTRO_LAYOUT, patch.INTRO_LAYOUT_OLD),
            (patch.INTRO_CONTROLLER, "[self.view insertSubview:_glkView atIndex:0];", "[self.view addSubview:_glkView];"),
            (patch.INTRO_CONTROLLER, "    [self updateFirstPageMarkAnimated:true];\n}\n", "}\n"),
            (patch.INTRO_SPLASH, "        self.controller.firstPageMarkView = self.markNode.view\n", ""),
            (patch.INTRO_SPLASH, '.local("pluma_mark_write")', '.local("PlumaIntroMark")'),
        ):
            with self.subTest(rel=rel, old=old[:60]):
                self.tearDown()
                tree, c = self.run_patch()
                text = tree.read(rel)
                self.assertGreaterEqual(text.count(old), 1)
                tree.write(rel, text.replace(old, new, 1))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn(rel, str(e.exception))

    def test_group_calls(self):
        # Each file of the group calls is upstream's with the edits and
        # nothing else.
        # The rest of the patch alone, then the whole of it.
        with unittest.mock.patch.object(patch, "patch_group_calls", lambda tree: None):
            tree = RecordingTree(self.root, self.written)
            patch.patch(tree, config())
        rels = {rel for rel, _, _ in patch.group_call_edits()} | {rel for rel, *_ in patch.RECORDING_STARTS} | {patch.STRINGS}
        before = {rel: tree.read(rel) for rel in rels}
        self.tearDown()
        tree, _ = self.run_patch()
        expected = {patch.STRINGS: before[patch.STRINGS] + patch.GROUP_CALL_STRINGS_HEAD
                    + "".join(entry + "\n" for entry in patch.group_call_entries())}
        for rel, old, new in patch.group_call_edits():
            text = expected.get(rel, before[rel])
            self.assertEqual(text.count(old), 1, (rel, old[:60]))
            expected[rel] = text.replace(old, new)
        # The entries that start a recording go whole, from the branch's
        # first line to its last.
        for rel, head, tail, block, must_contain in patch.RECORDING_STARTS:
            text = expected.get(rel, before[rel])
            self.assertEqual(text.count(head), 1, rel)
            start = text.index(head)
            end = text.index(tail, start) + len(tail)
            for s in must_contain:
                self.assertIn(s, text[start:end])
            self.assertNotIn(tail, text[start + len(head):end - len(tail)], rel)
            expected[rel] = text[:start] + block + text[end:]
        for rel, text in expected.items():
            self.assertEqual(tree.read(rel), text, rel)
        self.assertEqual(len(expected), 20)
        for rel, *_ in patch.RECORDING_STARTS:
            self.assertIsNone(patch.RECORDING_START.search(tree.read(rel)), rel)
            self.assertIsNotNone(patch.RECORDING_START.search(before[rel]), rel)
        # A recording that is on still shows, and can be stopped.
        self.assertIn("if let recordingStartTimestamp = callState.recordingStartTimestamp {", tree.read(patch.VIDEO_CHAT_MORE_MENU))
        self.assertIn("call.setShouldBeRecording(false, title: nil, videoOrientation: nil)", tree.read(patch.MEDIA_STREAM))
        # Every group call the manager makes has its own key and joins as
        # oneself; a call made at init or scheduled gets its context.
        manager = tree.read(patch.CALL_MANAGER)
        self.assertEqual(manager.count("guard let keyPair = TelegramE2EEncryptionProviderImpl.shared.generateKeyPair() else {"), 2)
        self.assertEqual(manager.count("keyPair: keyPair,"), 3)
        self.assertNotIn("keyPair: nil", manager)
        call = tree.read(patch.GROUP_CALL)
        self.assertEqual(call.count("PresentationGroupCallImpl.plumaMakeE2EContext("), 2)
        self.assertEqual(call.count("ConferenceCallE2EContext(\n"), 1)
        self.assertEqual(call.count("OngoingGroupCallEncryptionContextImpl(e2eCall: Atomic(value: ConferenceCallE2EContext.ContextStateHolder()), channelId: 0)"), 1)
        self.assertIn("                self.e2eContext = e2eContext\n"
                      "                (self.screencastIPCContext as? ScreencastInProcessIPCContext)?.e2eContext = e2eContext\n", call)
        schedule = call.index("    public func schedule(timestamp: Int32) {")
        self.assertLess(schedule, call.index("PresentationGroupCallImpl.plumaMakeE2EContext(accountContext: self.accountContext"))
        # The screen goes out of the app's engine only, with no branch left
        # that could never run (a warning, an error under -warnings-as-errors).
        self.assertEqual(call.count("ScreencastInProcessIPCContext(basePath:"), 1)
        self.assertNotIn("ScreencastEmbeddedIPCContext(", call)
        self.assertNotIn("useIPCContext", call)
        # A reason to rejoin rejoins: 3 in 5 minutes, after 0, 2 and 5 s and
        # up to 1 s more, one at a time, with a new key; the fourth leaves
        # with the notice.
        self.assertIn("isFailed else {\n                        return\n                    }\n"
                      "                    self.plumaRejoinAfterE2EFailure()", call)
        rejoin = call[call.index("    private func plumaRejoinAfterE2EFailure() {"):call.index("    public func reconnect(with invite: String) {")]
        self.assertIn("let delays: [Double] = [0.0, 2.0, 5.0]", rejoin)
        self.assertIn("if self.plumaE2ERejoinTimestamps.count >= delays.count {\n            self.plumaLeaveAfterE2EFailure()", rejoin)
        self.assertIn("timestamp - $0 >= 5.0 * 60.0", rejoin)
        self.assertIn("Queue.mainQueue().after(delays[self.plumaE2ERejoinTimestamps.count] + Double.random(in: 0.0 ..< 1.0), {", rejoin)
        self.assertIn("!self.plumaE2ERejoinScheduled", rejoin)
        self.assertLess(rejoin.index("self.plumaE2ERejoinScheduled = true"), rejoin.index("Queue.mainQueue().after("))
        self.assertLess(rejoin.index("let keyPair = TelegramE2EEncryptionProviderImpl.shared.generateKeyPair()"),
                        rejoin.index("e2eContext.reset(keyPair: keyPair)"))
        self.assertLess(rejoin.index("e2eContext.reset(keyPair: keyPair)"), rejoin.index("self.requestCall(movingFromBroadcastToRtc: false)"))
        self.assertLess(rejoin.index("Pluma_GroupCall_EncryptionFailed"), rejoin.index("self.leave(terminateIfPossible: false)"))
        # The report: requested by the context, taken by tgcalls on its
        # thread while the data channel is open, through the engine.
        self.assertIn("callContext.sendE2EStatus({\n                return e2eContext?.plumaTakeStatusReport()\n            })", call)
        self.assertIn("self.context.sendE2EStatus(takeStatus)", tree.read(patch.GROUP_CALL_CONTEXT))
        self.assertIn("_instance->sendE2EStatus([takeStatus]() -> std::string {", tree.read(patch.CALL_CONTEXT))
        custom = tree.read(patch.GROUP_INSTANCE_CUSTOM)
        self.assertIn("internal->sendE2EStatus(takeStatus);", custom)
        self.assertIn('json["colibriClass"].string_value() != "PlumaE2EStatus"', custom)
        send = custom[custom.index("    void sendE2EStatus(std::function<std::string()> const &takeStatus) {"):]
        self.assertLess(send.index("if (!_isDataChannelOpen) {"), send.index("std::string status = takeStatus();"))
        self.assertIn("    virtual void sendE2EStatus(std::function<std::string()> const &) {}\n", tree.read(patch.GROUP_INSTANCE))
        context = tree.read(patch.E2E_CONTEXT)
        self.assertIn("return ([], Data(), [], [:], true)", context)
        self.assertEqual(context.count("withTimeInterval: 5.0, repeats: true"), 1)
        self.assertEqual(context.count("withTimeInterval: 1.0, repeats: true"), 1)
        # The checks of the chain: behind the server for over 12 s, nothing
        # decrypted for 15 s while current; both fail the state as a block
        # that does not apply does, and so does a write the server forbids.
        check = context[context.index("        private func plumaCheckChain() {"):context.index("        func kickPeer(id: EnginePeer.Id) {")]
        self.assertIn("serverOffset0 > height + 1", check)
        self.assertIn("timestamp - behindSince.since > 12.0", check)
        self.assertIn("state.plumaDecryptionStalled(window: 15.0)", check)
        self.assertIn("self.plumaBehindSince = nil\n            if isStalled {", check)
        self.assertEqual(check.count("self.isFailed.set(true)"), 2)
        self.assertEqual(context.count("self.plumaServerHas(nextOffset: "), 3)
        self.assertEqual(context.count("                            isFailed.set(true)\n                            return false\n"), 2)
        self.assertIn("if isForbidden {\n                        isFailed.set(true)", context)
        engine = tree.read(patch.ENGINE_GROUP_CALLS)
        self.assertEqual(engine.count('error.errorDescription == "GROUPCALL_FORBIDDEN"'), 2)
        self.assertIn('return error.errorDescription != "GROUPCALL_FORBIDDEN"', engine)
        self.assertIn("-> Signal<Bool, NoError> {\n", tree.read(patch.ENGINE_CALLS))
        # A join CONF_WRITE_CHAIN_INVALID refuses goes again: the refusal
        # counts toward 10 in a row only when the next read of the chain finds
        # the same last block; 100 joins at most; past either, the error of a
        # join, before the next join is sent.
        join = engine[engine.index("func _internal_joinGroupCall("):engine.index("public enum InviteConferenceCallParticipantError {")]
        self.assertIn("let plumaChainStalledLimit = 10\n", join)
        self.assertIn("let plumaChainJoinsLimit = 100\n", join)
        self.assertEqual(join.count("Atomic<PlumaChainRetries>(value: PlumaChainRetries())"), 1)
        self.assertIn("value.stalled = value.block == lastBlock ? value.stalled + 1 : 0", join)
        self.assertLess(join.index("let lastBlock = result.blocks.last"), join.index("return generateE2E(nil)"))
        self.assertLess(join.index("$0.stalled >= plumaChainStalledLimit"), join.index("Api.functions.phone.joinGroupCall("))
        restart = join[join.index("    return signal |> restartOrMapError {"):]
        self.assertLess(restart.index("value.refused = true"), restart.index("if joins >= plumaChainJoinsLimit {\n                return .error(.generic)"))
        self.assertLess(restart.index("return .error(.generic)"), restart.index("return .restart"))
        # A rejoin starts the report and the checks over.
        reset = context[context.index("        func reset(keyPair: TelegramKeyPair) {"):context.index("        private func plumaBegin() {")]
        for s in ("self.plumaStatusTimer = nil", "self.plumaChainTimer = nil", "self.plumaServerOffset0 = nil", "callState.plumaSeq = 0",
                  "callState.state = nil", "self.isFailed.set(false)"):
            self.assertIn(s, reset)
        # No join as a channel, no RTMP, no live story.
        self.assertIn("            return .single([])\n", tree.read(patch.ENGINE_CALLS))
        self.assertNotIn("CreateExternalMediaStreamScreen(", tree.read(patch.MEDIA_STREAM))
        self.assertNotIn("getGroupCallStreamCredentials(", tree.read(patch.PEER_INFO_CALLS))
        self.assertNotIn("canLivestream = true", tree.read(patch.STORY_CAMERA))
        self.assertIn('\n// pluma: group calls (task 094).\n"Pluma.GroupCall.EncryptionFailed" = ', tree.read(patch.STRINGS))

    def test_group_calls_check(self):
        # The check after the edits finds a group call without a key or
        # joined as a channel, an entry to RTMP or a live story, another
        # message over the data channel.
        for rel, old, new in (
            (patch.CALL_MANAGER, "                            keyPair: keyPair, // pluma: task 094\n", "                            keyPair: nil,\n"),
            (patch.CALL_MANAGER, "            joinAsPeerId: nil, // pluma", "            joinAsPeerId: joinAsPeerId, // pluma"),
            (patch.CALL_MANAGER, "    public func joinConferenceCall(\n",
             "    func another() {\n        let call = PresentationGroupCallImpl(\n            joinAsPeerId: nil\n        )\n    }\n\n"
             "    public func joinConferenceCall(\n"),
            (patch.GROUP_CALL, "                    } else {\n                        // pluma: no group call goes unencrypted",
             "                    } else if self.isConference {\n                        // pluma: no group call goes unencrypted"),
            (patch.STORY_CAMERA, "            // pluma: no live stories", "            self.canLivestream = true\n            // pluma: no live stories"),
            (patch.GROUP_CALL, "        self.screencastIPCContext = screencastIPCContext\n",
             "        self.screencastIPCContext = ScreencastEmbeddedIPCContext(basePath: self.accountContext.sharedContext.basePath)\n"),
            (patch.MEDIA_STREAM, "                        let _ = peerId\n", "                        let _ = presentationData.strings.LiveStream_ViewCredentials\n"),
            (patch.ENGINE_CALLS, "            return .single([])\n",
             "            return _internal_cachedGroupCallDisplayAsAvailablePeers(account: self.account, peerId: peerId)\n"),
            (patch.ENGINE_GROUP_CALLS, "            if joins >= plumaChainJoinsLimit {\n", "            if joins >= plumaChainJoinsLimit * 10 {\n"),
            (patch.ENGINE_GROUP_CALLS, "value.stalled = value.block == lastBlock ? value.stalled + 1 : 0",
             "value.stalled = value.stalled + 1"),
            (patch.GROUP_INSTANCE_CUSTOM, "            networkManager->sendDataChannelMessage(status);\n",
             "            networkManager->sendDataChannelMessage(status);\n            networkManager->sendDataChannelMessage(status);\n"),
            (patch.VIDEO_CHAT_MORE_MENU, "        if canManageCall && !isConference {\n            if let recordingStartTimestamp",
             "        let _ = environment.strings.VoiceChat_StartRecording\n"
             "        if canManageCall && !isConference {\n            if let recordingStartTimestamp"),
            (patch.MEDIA_STREAM, "                        if let recordingStartTimestamp = state.recordingStartTimestamp {\n",
             "                        call.setShouldBeRecording(true, title: nil, videoOrientation: false)\n"
             "                        if let recordingStartTimestamp = state.recordingStartTimestamp {\n"),
        ):
            with self.subTest(rel=rel, old=old[:60]):
                self.tearDown()
                tree, c = self.run_patch()
                text = tree.read(rel)
                self.assertEqual(text.count(old), 1)
                tree.write(rel, text.replace(old, new))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn(pathlib.PurePath(rel).name, str(e.exception))

    def test_call_colors(self):
        # Every colour of Telegram's call screens becomes Pluma's: the 1:1
        # call's three sets point for point, the rest by meaning; greys and
        # the reds and greens of the buttons that end, decline, leave and
        # answer a call stay, and nothing else in the files changes. The rest
        # of the patch alone, then the whole of it.
        with unittest.mock.patch.object(patch, "patch_call_colors", lambda tree: None):
            tree = RecordingTree(self.root, self.written)
            patch.patch(tree, config())
        rels = list(patch.call_ui_sources(tree))
        before = {rel: tree.read(rel) for rel in rels}
        self.tearDown()
        tree, _ = self.run_patch()
        self.assertIn(patch.CALL_BACKGROUND, rels)
        self.assertEqual(rels, list(patch.call_ui_sources(tree)))
        pluma = {old: new for old, new, _ in patch.CALL_COLORS}
        buttons = {(rel, color) for rel, color, _ in patch.CALL_BUTTON_COLORS}
        self.assertTrue({rel for rel, _ in buttons} <= set(rels))
        changed = 0
        for rel in rels:
            expected = patch.CALL_COLOR.sub(
                lambda m: m.group(0) if (rel, m.group(1).upper()) in buttons
                else "0x" + pluma.get(m.group(1).upper(), m.group(1)), before[rel])
            for r, old, new, count in patch.CALL_COLOR_LITERALS:
                if r == rel:
                    self.assertEqual(expected.count(old), count, rel)
                    expected = expected.replace(old, new)
            self.assertEqual(tree.read(rel), expected, rel)
            changed += expected != before[rel]
        recolored = {rel for rel in rels if any(m.group(1).upper() in pluma and (rel, m.group(1).upper()) not in buttons
                                                for m in patch.CALL_COLOR.finditer(before[rel]))}
        self.assertEqual(changed, len(recolored | {rel for rel, *_ in patch.CALL_COLOR_LITERALS}))
        self.assertGreaterEqual(changed, 25)
        # Telegram's three sets of the 1:1 call are gone, Pluma's are there in
        # their order.
        background = tree.read(patch.CALL_BACKGROUND)
        for telegram in (("568FD6", "626ED5", "A667D5", "7664DA"), ("ACBD65", "459F8D", "53A4D1", "3E917A"),
                         ("C0508D", "F09536", "CE5081", "FC7C4C")):
            for color in telegram:
                self.assertNotIn(color, background.upper())
        sets = re.findall(r"ColorSet\(colors: \[\s*hexToFloat\(0x(\w+)\),\s*hexToFloat\(0x(\w+)\),\s*hexToFloat\(0x(\w+)\),\s*hexToFloat\(0x(\w+)\)\s*\]\)",
                          background)
        self.assertEqual(tuple(sets), patch.CALL_BACKGROUND_SETS)
        self.assertEqual(patch.CALL_BACKGROUND_SETS, (("3A4A3C", "4F6E52", "2C3A2D", "5B7A5E"),
                                                      ("5B7A5E", "6F8F72", "4F6E52", "7FA082"),
                                                      ("8A5A44", "A86B4C", "7A4E3B", "B97A55")))
        # The buttons keep Telegram's colours, each as many times as
        # upstream has it in the file: the 1:1 call's End is red.
        for rel, color, count in patch.CALL_BUTTON_COLORS:
            self.assertEqual([m.group(1).upper() for m in patch.CALL_COLOR.finditer(tree.read(rel))].count(color), count, rel)
        self.assertIn("if contentParams.isDestructive {\n                context.setFillColor(UIColor(rgb: 0xFF3B30).cgColor)",
                      tree.read("submodules/TelegramUI/Components/Calls/CallScreen/Sources/Components/ContentOverlayButton.swift"))
        # No colour of the call screens is left that is neither Pluma's, nor
        # a grey, nor that of a button in its file.
        allowed = {new for _, new, _ in patch.CALL_COLORS} | set(patch.CALL_GREYS)
        for rel in rels:
            for m in patch.CALL_COLOR.finditer(tree.read(rel)):
                if (rel, m.group(1).upper()) not in buttons:
                    self.assertIn(m.group(1).upper(), allowed, rel)
            self.assertNotIn("UIColor(red:", tree.read(rel), rel)

    def test_call_colors_check(self):
        # The check after the edits finds a colour of Telegram's anywhere in
        # the call screens, as a literal or as fractions, a button's colour
        # outside its button, a button that lost it, and a background set
        # that is not Pluma's.
        for rel, old, new in (
            (patch.CALL_BACKGROUND, "hexToFloat(0x5B7A5E)\n            ]),\n            ColorSet(colors: [\n                hexToFloat(0x5B7A5E)",
             "hexToFloat(0x7664DA)\n            ]),\n            ColorSet(colors: [\n                hexToFloat(0x5B7A5E)"),
            (patch.CALL_BACKGROUND, "hexToFloat(0x8A5A44),", "hexToFloat(0xA86B4C),"),
            # Pluma's sets, each whole, but connecting and connected swapped.
            (patch.CALL_BACKGROUND, CONNECTING_SET + ",\n" + CONNECTED_SET, CONNECTED_SET + ",\n" + CONNECTING_SET),
            ("submodules/TelegramCallsUI/Sources/CallStatusBarNode.swift", "private let blue = UIColor(rgb: 0x4F6E52)",
             "private let blue = UIColor(rgb: 0x007fff)"),
            ("submodules/TelegramUI/Components/Calls/VideoChatMicButtonComponent/Sources/VideoChatMicButtonComponent.swift",
             "private let blueColor = UIColor(rgb: 0x5B7A5E)", "private let blueColor = UIColor(rgb: 0x55B3F9)"),
            (patch.MEDIA_STREAM, "UIColor(rgb: 0xA86B4C)", "UIColor(red: 1, green: 0.176, blue: 0.333, alpha: 1)"),
            ("submodules/TelegramCallsUI/Sources/CallStatusBarNode.swift", "private let blue = UIColor(rgb: 0x4F6E52)",
             "private let blue = UIColor(red: 0.0, green: 0.5, blue: 1.0, alpha: 1.0)"),
            # Telegram's red of End on the background, in the status bar, a
            # second time in the button's file; the button in sage.
            (patch.CALL_BACKGROUND, "hexToFloat(0x8A5A44),", "hexToFloat(0xFF3B30),"),
            ("submodules/TelegramCallsUI/Sources/CallStatusBarNode.swift", "private let pink = UIColor(rgb: 0xA86B4C)",
             "private let pink = UIColor(rgb: 0xd92326)"),
            ("submodules/TelegramCallsUI/Sources/VideoChatActionButtonComponent.swift", "UIColor(rgb: 0x2C3A2D)",
             "UIColor(rgb: 0x330d0b)"),
            ("submodules/TelegramUI/Components/Calls/CallScreen/Sources/Components/ContentOverlayButton.swift",
             "UIColor(rgb: 0xFF3B30)", "UIColor(rgb: 0xA86B4C)"),
        ):
            with self.subTest(rel=rel, old=old[:60]):
                self.tearDown()
                tree, c = self.run_patch()
                text = tree.read(rel)
                self.assertEqual(text.count(old), 1)
                tree.write(rel, text.replace(old, new))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn(pathlib.PurePath(rel).name, str(e.exception))

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


class CallParametersTest(unittest.TestCase):
    def tree(self, root):
        (root / "Telegram").mkdir(exist_ok=True)
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        files = {}
        for rel, old, _ in patch.call_parameter_edits():
            files[rel] = files.get(rel, "") + old + "x\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_submodule_paths(self):
        # Every file the edits touch is fetched for the check job, inside
        # the submodule it belongs to.
        (sub, url, paths), = patch.SUBMODULES
        self.assertEqual((sub, url), (patch.TGCALLS, patch.TGCALLS_URL))
        group_calls = {rel for rel, _, _ in patch.group_call_edits() if rel.startswith(sub + "/")}
        self.assertEqual({rel for rel, _, _ in patch.call_parameter_edits()} | group_calls, set(paths))
        self.assertEqual(len(paths), len(set(paths)))
        for rel in paths:
            self.assertTrue(rel.startswith(sub + "/"), rel)
            self.assertNotIn(rel, patch.UPSTREAM_PATHS)
        out = io.StringIO()
        with unittest.mock.patch("sys.stdout", out):
            self.assertEqual(patch.main(["--submodules"]), 0)
        self.assertEqual(out.getvalue(), f"{sub} {url} tgcalls/v2/InstanceV2Impl.cpp tgcalls/VideoCaptureInterfaceImpl.cpp "
                                         "tgcalls/VideoCaptureInterfaceImpl.h tgcalls/group/GroupInstanceCustomImpl.cpp "
                                         "tgcalls/group/GroupInstanceCustomImpl.h tgcalls/group/GroupInstanceImpl.h\n")

    def test_telegram_defaults(self):
        # With no key from the server every value is the literal it replaces.
        helpers = patch.CALL_ENGINE_HELPERS
        for default in ("int audioPacketMs = 60;", "int audioMaxBitrateBps = 32 * 1024;", "int audioMinBitrateBps = 0;",
                        "int audioJitterMinDelayMs = 50;", "bool audioNoiseSuppression = false;",
                        "int videoMaxBitrateBps = 1000 * 1024;", "int screencastMaxBitrateBps = 0;", "int startBitrateBps = 0;",
                        "int videoFps = 0;"):
            self.assertEqual(helpers.count(default), 1, default)
        # The server's kbit/s is 1000 bit/s; a key read as absent keeps the
        # literal.
        for key in ('"audio_max_bitrate_kbps", 6, 128, 0)) {\n        result.audioMaxBitrateBps = kbps * 1000;',
                    '"audio_jitter_min_ms", 1, 500, 50)', '"start_bitrate_kbps", 30, 20000, 0) * 1000;',
                    '"video_max_bitrate_kbps", 100, 20000, 0)) {\n        result.videoMaxBitrateBps = kbps * 1000;',
                    '"screen_max_bitrate_kbps", 100, 20000, 0) * 1000;', '"video_fps", 1, 60, 0);'):
            self.assertIn(key, helpers)
        self.assertNotIn("kbps * 1024", helpers)
        # The bitrate range goes into the field trials only when a minimum is
        # set, and the screen keeps WebRTC's default unless a cap is set.
        self.assertIn("if (_plumaParameters.audioMinBitrateBps != 0) {\n", patch.CALL_PARSED)
        edited = "".join(new for _, _, new in patch.call_parameter_edits())
        self.assertIn("if (_outgoingScreencastChannel && _plumaParameters.screencastMaxBitrateBps != 0) {\n", edited)
        self.assertIn('"WebRTC-Audio-Allocation/min:"', helpers)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "the call quality from the server is not there"):
                patch.verify_call_parameters(tree)
            patch.patch_call_parameters(tree)
            patch.verify_call_parameters(tree)
            engine = tree.read(patch.CALL_ENGINE)
            self.assertIn("codec.SetParam(cricket::kCodecParamPTime, audioPacketMs);\n", engine)
            self.assertIn("audio_jitter_buffer_min_delay_ms = jitterBufferMinDelayMs;\n", engine)
            self.assertIn("builder.SetCapturePostProcessing(std::make_unique<PlumaNoiseSuppressor>());\n", engine)
            self.assertIn("callConfig.bitrate_config.start_bitrate_bps = _plumaParameters.startBitrateBps;\n", engine)
            self.assertIn("videoCaptureImpl->setAdaptationFramerate(_plumaParameters.videoFps);\n", engine)
            # A second run is refused: nothing is left to edit.
            with tempfile.TemporaryDirectory() as d2:
                again = self.tree(pathlib.Path(d2))
                patch.patch_call_parameters(again)
                with self.assertRaises(patch.PatchError):
                    patch.patch_call_parameters(again)

    def test_server_contract(self):
        # The keys and ranges are the server's (pkg/phonecalls/parameters.go of
        # the server repository). screen_fps and screen_max_size_px are not
        # read: nothing in an iOS call sets a screen size or rate for them to
        # replace (the comment above CALL_ENGINE_INCLUDES_ANCHOR).
        helpers = patch.CALL_ENGINE_HELPERS
        ranges = {key: (int(lo), int(hi)) for key, lo, hi in
                  re.findall(r'plumaCustomParameterInt\(parameters, "([a-z0-9_]+)", (\d+), (\d+), ', helpers)}
        self.assertEqual(ranges, {
            "audio_ptime_ms": (10, 120), "audio_max_bitrate_kbps": (6, 128), "audio_min_bitrate_kbps": (6, 128),
            "audio_jitter_min_ms": (1, 500), "video_max_bitrate_kbps": (100, 20000),
            "screen_max_bitrate_kbps": (100, 20000), "start_bitrate_kbps": (30, 20000), "video_fps": (1, 60)})
        # Of 10-120 ms, only the server's packet times.
        self.assertIn("if (packetMs == 10 || packetMs == 20 || packetMs == 40 || packetMs == 60 || packetMs == 120) {\n",
                      helpers)
        # The flag only as a JSON bool, a number only as a whole one.
        self.assertIn("noiseSuppression->second.is_bool() && noiseSuppression->second.bool_value()", helpers)
        self.assertIn("number != std::floor(number)", helpers)
        for key in ("screen_fps", "screen_max_size_px", "video_camera_fps"):
            self.assertNotIn(f'"{key}"', helpers)

    def test_literal_left_is_refused(self):
        # A Telegram literal the edits missed, upstream's second copy of it,
        # stops the patch.
        for rel, literal in ((patch.CALL_ENGINE, "kCodecParamPTime, 60)"), (patch.CALL_ENGINE, "setMaxBitrate(32 * 1024)"),
                             (patch.CALL_ENGINE, "setMaxBitrate(1000 * 1024)"),
                             (patch.CALL_ENGINE, "audio_jitter_buffer_min_delay_ms = 50;"), (patch.CALL_CAPTURE, ", 25);")):
            with self.subTest(literal=literal), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d))
                patch.patch_call_parameters(tree)
                tree.write(rel, tree.read(rel) + literal + "\n")
                with self.assertRaisesRegex(patch.PatchError, "Telegram's"):
                    patch.verify_call_parameters(tree)


class PremiumForEveryoneTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect.
    def tree(self, root, edits=patch.PREMIUM_FOR_EVERYONE_EDITS):
        (root / "Telegram").mkdir(exist_ok=True)
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        files = {}
        for edit in edits:
            rel, old = edit[0], edit[1]
            count = edit[3] if len(edit) > 3 else 1
            files[rel] = files.get(rel, "") + (old + "x\n") * count
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_upstream_paths_cover_the_edits(self):
        for edit in patch.PREMIUM_FOR_EVERYONE_EDITS:
            self.assertIn(edit[0], patch.UPSTREAM_PATHS)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "the edit of task 071 is not there"):
                patch.verify_premium_for_everyone(tree)
            patch.premium_for_everyone(tree)
            patch.verify_premium_for_everyone(tree)
            # A second run is refused: nothing is left to edit.
            with self.assertRaises(patch.PatchError):
                patch.premium_for_everyone(tree)

    def test_upstream_changed(self):
        for i, edit in enumerate(patch.PREMIUM_FOR_EVERYONE_EDITS):
            changed = edit[1][:-2] + "~" + edit[1][-1]
            edits = [e if j != i else (edit[0], changed) + tuple(edit[2:]) for j, e in enumerate(patch.PREMIUM_FOR_EVERYONE_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.premium_for_everyone(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.premium_for_everyone(tree)
            for edit in patch.PREMIUM_FOR_EVERYONE_EDITS:
                rel, old, new = edit[0], edit[1], edit[2]
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(file=rel), self.assertRaisesRegex(patch.PatchError, "the edit of task 071 is not there"):
                    patch.verify_premium_for_everyone(tree)
                tree.write(rel, patched)
            patch.verify_premium_for_everyone(tree)

    def test_transcription_offered(self):
        # The server transcribes for everybody: no edit hides the button of
        # a voice or round message any more.
        for edit in patch.PREMIUM_FOR_EVERYONE_EDITS:
            with self.subTest(file=edit[0]):
                self.assertNotIn("displayTranscribe", edit[1] + edit[2])
                self.assertNotIn("transcription", edit[2])
                self.assertNotIn(edit[0], {gate[0] for gate in patch.TRANSCRIBE_VIEW_ONCE_GATES})


class TranscribeViewOnceTest(unittest.TestCase):
    # The upstream files, made of what the check expects.
    CHECKS = patch.TRANSCRIBE_VIEW_ONCE_GATES + patch.TRANSCRIBE_BUTTON_SETTERS

    def tree(self, root):
        (root / "Telegram").mkdir(exist_ok=True)
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        files = {}
        for rel, s, count in self.CHECKS:
            files[rel] = files.get(rel, "") + ("x\n" + s) * count
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_upstream_paths_cover_the_gates(self):
        for rel, _, _ in self.CHECKS:
            self.assertIn(rel, patch.UPSTREAM_PATHS)

    def test_gates(self):
        # Each gate keeps a view-once message out of the button, and is the
        # first condition on it.
        for rel, s, _ in patch.TRANSCRIBE_VIEW_ONCE_GATES:
            self.assertIn("isViewOnceMessage", s)
            if "var displayTranscribe = false\n" in s:
                self.assertIn("!isViewOnceMessage", s)
        self.assertEqual({rel for rel, _, _ in patch.TRANSCRIBE_BUTTON_SETTERS},
                         {rel for rel, _, _ in patch.TRANSCRIBE_VIEW_ONCE_GATES})
        with tempfile.TemporaryDirectory() as d:
            patch.verify_transcribe_view_once(self.tree(pathlib.Path(d)))

    def test_upstream_changed(self):
        # A gate that upstream dropped, changed or repeated, or one more or
        # one less place that shows the button, stops the patch.
        for rel, s, count in self.CHECKS:
            for changed in {s.replace("isViewOnceMessage", "isViewOnce"), s + s, ""} - {s}:
                with self.subTest(check=s.strip()[:40], changed=changed.strip()[:40]), tempfile.TemporaryDirectory() as d:
                    tree = self.tree(pathlib.Path(d))
                    tree.write(rel, tree.read(rel).replace(s, changed, 1))
                    with self.assertRaisesRegex(patch.PatchError, "upstream changed it"):
                        patch.verify_transcribe_view_once(tree)


class VerifiedBadgeTest(unittest.TestCase):
    # A tree of the files the check reads: each place of the badge with its
    # calls, the colours and images as the patched upstream has them.
    THEME = ".verified(fillColor: item.presentationData.theme.list.itemCheckColors.fillColor, " \
            "foregroundColor: item.presentationData.theme.list.itemCheckColors.foregroundColor, sizeType: .compact)"

    def tree(self, root):
        (root / "Telegram").mkdir(exist_ok=True)
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        files = {}
        for rel, theme_calls, others in patch.VERIFIED_BADGE_SITES:
            files[rel] = "".join(f"x = {c}\n" for c in [self.THEME] * theme_calls + list(others))
        for rel, s, count in patch.VERIFIED_BADGE_COLOURS:
            files[rel] = files.get(rel, "") + s * count
        for rel, head, fills in patch.VERIFIED_BADGE_IMAGES:
            files[rel] = head + "".join(f"        {f}\n" for f in fills) + "    }\n"
        for rel, s in patch.VERIFIED_BADGE_THEMES:
            files[rel] = files.get(rel, "") + s
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_upstream_paths_cover_the_badge(self):
        for rel in patch.VERIFIED_BADGE_PATHS + (patch.DAY_THEME, patch.DARK_THEME):
            self.assertIn(rel, patch.UPSTREAM_PATHS)

    def test_theme_calls(self):
        # The theme's check colours of any owner of the theme, the same owner
        # for both colours.
        self.assertEqual(len(patch.VERIFIED_THEME_CALL.findall(
            ".verified(fillColor: self.theme.list.itemCheckColors.fillColor, "
            "foregroundColor: self.theme.list.itemCheckColors.foregroundColor, sizeType: .large)")), 1)
        self.assertEqual(patch.VERIFIED_THEME_CALL.findall(
            ".verified(fillColor: self.theme.list.itemCheckColors.fillColor, "
            "foregroundColor: other.list.itemCheckColors.foregroundColor, sizeType: .large)"), [])

    def test_check(self):
        site = patch.VERIFIED_BADGE_SITES[0][0]
        profile = "submodules/TelegramUI/Components/PeerInfo/PeerInfoScreen/Sources/PeerInfoHeaderNode.swift"
        image = patch.VERIFIED_BADGE_IMAGES[0][0]
        for name, rel, damage in (
            ("a colour of its own", site, lambda t: t.replace("fillColor: item.presentationData.theme.list.itemCheckColors.fillColor",
                                                              "fillColor: UIColor(rgb: 0x2ea6ff)", 1)),
            ("one more badge", site, lambda t: t + "y = " + self.THEME + "\n"),
            ("another badge over the photo", profile, lambda t: t.replace(patch.VERIFIED_OVER_MEDIA,
                                                                       patch.VERIFIED_OVER_MEDIA.replace("navigationContentsAccentColor", ".white"), 1)),
            ("a caller's colour", patch.VERIFIED_BADGE_COLOURS[1][0], lambda t: t.replace("component.theme.list.itemCheckColors.fillColor",
                                                                                         "UIColor(rgb: 0x2ea6ff)")),
            ("the image's fill", image, lambda t: t.replace("theme.list.itemCheckColors.fillColor", "theme.chatList.verifiedIconFillColor")),
            ("a fill more in the image", image, lambda t: t.replace("    }\n", "        context.setFillColor(UIColor.blue.cgColor)\n    }\n")),
            ("black on Night's sage", patch.DARK_THEME, lambda t: t.replace("UIColor(rgb: 0x131513)\n", "UIColor(rgb: 0x000000)\n", 1)),
            ("Day's accent", patch.DAY_THEME, lambda t: t.replace("0x5b7a5e", "0x0088ff")),
        ):
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d))
                patch.verify_verified_badge(tree)
                damaged = damage(tree.read(rel))
                self.assertNotEqual(damaged, tree.read(rel))
                tree.write(rel, damaged)
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify_verified_badge(tree)
                self.assertIn(rel, str(e.exception))


class LoginCodesTest(unittest.TestCase):
    STRINGS = '"Login.EnterCodeSMSTitle" = "Enter Code";\n"Login.EnterCodeTelegramText" = "In the **Pluma app**.";'

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.c = config()

    def tearDown(self):
        self.dir.cleanup()

    # The upstream files, made of the texts the edits expect.
    def tree(self, edits=patch.LOGIN_CODE_EDITS, strings=STRINGS):
        (self.root / "versions.json").write_text("{}")
        files = {patch.APP_BUILD: "", patch.STRINGS: strings}
        for rel, old, _ in edits:
            files[rel] = files.get(rel, "") + old + "x\n"
        for rel, text in files.items():
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(self.root)

    def test_upstream_paths_cover_the_edits(self):
        for rel, _, _ in patch.LOGIN_CODE_EDITS:
            self.assertIn(rel, patch.UPSTREAM_PATHS)

    def test_applies(self):
        tree = self.tree()
        with self.assertRaises(patch.PatchError):
            patch.verify_login_codes(tree, self.c)
        patch.patch_login_codes(tree, self.c)
        patch.verify_login_codes(tree, self.c)
        # The texts follow the strings of upstream, after its last entry
        # (which has no line break), in the English of the brief of task 076.
        strings = tree.read(patch.STRINGS)
        self.assertTrue(strings.startswith(self.STRINGS + "\n\n// pluma: the login code screens (task 076);"))
        for line in ('"Pluma.Login.CheckTelegramTitle" = "Check Telegram";\n',
                     '"Pluma.Login.CheckTelegramText" = "We\'ve sent the code for **%@** to your Telegram, '
                     'in a message from the Pluma account.";\n',
                     '"Pluma.Login.OpenTelegram" = "Open Telegram";\n',
                     '"Pluma.Login.DidNotGetCode" = "Didn\'t get the code?";\n',
                     '"Pluma.Login.NotDeliveredTitle" = "Code didn\'t reach Telegram";\n',
                     '"Pluma.Login.NotDeliveredText" = "The code for **%@** didn\'t reach your Telegram. Let Telegram '
                     'find you by your number: **Settings → Privacy and Security → Phone Number → Who can find me '
                     'by my number? → Everybody**.\\n\\nNo Telegram? Ask the administrator for the code and enter it here.";\n',
                     '"Pluma.Login.OpenTelegramSettings" = "Open Telegram settings";\n',
                     '"Pluma.Login.SendAgainIn" = "Send again in %@";\n',
                     '"Pluma.Login.SendAgain" = "Send again";\n',
                     '"Pluma.Login.AskAdministratorTitle" = "Ask the administrator";\n',
                     '"Pluma.Login.AskAdministratorText" = "Ask the Pluma administrator for your code and enter it here.";\n'):
            self.assertEqual(strings.count(line), 1, line)
        self.assertEqual(len(patch.LOGIN_CODE_STRINGS), 11)
        # The code reads each text by its generated name, and only those.
        used = set(re.findall(r"\bPluma_Login_(\w+)", "".join(new for _, _, new in patch.LOGIN_CODE_EDITS)))
        self.assertEqual(used, {key.split(".")[-1] for key, _ in patch.LOGIN_CODE_STRINGS})
        # Every entry parses as the strings generator of upstream reads them.
        entries = [m.group(0) for m in patch.STRINGS_ENTRY.finditer(strings)]
        self.assertEqual(entries[2:], patch.login_code_entries(self.c))
        # The app's name follows the configuration.
        self.assertIn('"Ask the Plume administrator for your code', "".join(
            patch.login_code_entries(config(app={"PLUMA_APP_NAME": "Plume"}))))
        # The guard of openUrl lets Telegram's two links through, nothing else.
        delegate = tree.read(patch.APP_DELEGATE)
        self.assertIn('parsed.host == "resolve" && parsed.path.isEmpty && parsed.query?.range(of: "^domain=[A-Za-z0-9_]+$", '
                      'options: .regularExpression) != nil', delegate)
        self.assertIn('(parsed.host == "settings" && parsed.path == "/phone_privacy" && parsed.query == nil)', delegate)
        self.assertIn('                if parsed.scheme == "tg" && !opensTelegram {\n                    return\n', delegate)
        self.assertIn("        <string>rizogo</string>\n        <string>tg</string>\n    </array>\n", tree.read(patch.APP_BUILD))
        # A second run is refused: the texts are there, nothing is left to edit.
        with self.assertRaises(patch.PatchError):
            patch.patch_login_codes(tree, self.c)

    def test_resend(self):
        tree = self.tree()
        patch.patch_login_codes(tree, self.c)
        sequence = tree.read(patch.LOGIN_SEQUENCE)
        # Each answer restarts the countdown, also Sms after Sms with the same data.
        self.assertIn("startStrict(next: { result in\n                        controller?.inProgress = false\n"
                      "                        // pluma: the countdown starts anew, also on the same screen (task 076).\n"
                      "                        controller?.restartCountdown(afterFloodWait: false)\n", sequence)
        controller = tree.read(patch.LOGIN_CODE_CONTROLLER)
        self.assertIn("            countdown = 60\n", controller)
        self.assertIn("self.controllerNode.updateData(number: number, email: email, codeType: codeType, nextType: nextType, "
                      "timeout: countdown, appleSignInAllowed: appleSignInAllowed, previousCodeType: previousCodeType, "
                      "isPrevious: isPrevious)\n        self.requestLayout(transition: .immediate)\n", controller)
        # The errors, before upstream's alert: an expired code goes back to the
        # phone number, SEND_CODE_UNAVAILABLE asks the administrator, FLOOD_WAIT
        # holds the link and keeps upstream's text.
        failed = sequence[sequence.index("controller.inProgress = false\n                            \n"):]
        failed = failed[:failed.index("var actions: [TextAlertAction]")]
        expired = failed[failed.index('if description == "PHONE_CODE_EXPIRED" {'):failed.index('if description == "SEND_CODE_UNAVAILABLE" {')]
        self.assertIn("contents: .empty)).startStandalone()\n", expired)
        self.assertIn("text: strongSelf.presentationData.strings.Login_CodeExpired,", expired)
        self.assertTrue(expired.rstrip().endswith("return\n                                }"), expired)
        unavailable = failed[failed.index('if description == "SEND_CODE_UNAVAILABLE" {'):]
        self.assertIn("title: strongSelf.presentationData.strings.Pluma_Login_AskAdministratorTitle, "
                      "text: strongSelf.presentationData.strings.Pluma_Login_AskAdministratorText,", unavailable)
        self.assertIn("if case .limitExceeded = error {\n                                controller.restartCountdown(afterFloodWait: true)\n", failed)
        # The link: no second request while one is awaited, and inactive while
        # it waits after FLOOD_WAIT on a screen without a countdown.
        node = tree.read(patch.LOGIN_CODE_NODE)
        self.assertIn("    @objc func nextOptionNodePressed() {\n"
                      "        // pluma: one request at a time from the link of a code screen of task 076.\n"
                      "        if self.hasResendLink && self.inProgress {\n            return\n        }\n", node)
        self.assertIn("                self.nextOptionButtonNode.alpha = self.inProgress ? 0.6 : 1.0\n", node)
        self.assertIn("        if nextType != nil, let timeout, timeout > 0 {\n"
                      "            return (NSAttributedString(string: strings.Pluma_Login_DidNotGetCode, font: font, "
                      "textColor: primaryColor, paragraphAlignment: .center), false)\n", tree.read(patch.LOGIN_OPTION_TEXT))

    def test_fit(self):
        tree = self.tree()
        patch.patch_login_codes(tree, self.c)
        node = tree.read(patch.LOGIN_CODE_NODE)
        # The screen fits before the items are laid out, after upstream drops
        # the sticker: the text scrolls.
        self.assertIn("        self.fitTelegramCodeScreen(items: &items, height: layout.size.height - insets.top - insets.bottom - "
                      "additionalBottomInset, textSize: currentOptionSize)\n        let _ = layoutAuthorizationItems(", node)
        fit = node[node.index("    private func fitTelegramCodeScreen("):node.index("    func updateData(number: String,")]
        self.assertIn("        items[textIndex].node = scrollNode\n"
                      "        items[textIndex].size = CGSize(width: textSize.width, height: textHeight)\n", fit)
        self.assertIn("        scrollNode.view.contentSize = textSize\n", fit)
        # Under the code, room for the error line, not Fragment's 104 pt.
        self.assertIn("let codeSpacingAfter = self.isTelegramCodeScreen ? AuthorizationLayoutItemSpacing(weight: 30.0, maxValue: 30.0) : "
                      "AuthorizationLayoutItemSpacing(weight: canReset || pendingDate != nil ? 0.0 : 104.0, maxValue: canReset ? 0.0 : 104.0)\n", node)
        self.assertIn("spacingAfter: codeSpacingAfter))\n", node)
        self.assertIn("self.currentOptionActivateAreaNode.frame = self.currentOptionNode.supernode === self.currentOptionScrollNode ? "
                      "self.currentOptionScrollNode.frame : self.currentOptionNode.frame\n", node)

    def test_upstream_changed(self):
        for i, (rel, old, new) in enumerate(patch.LOGIN_CODE_EDITS):
            changed = old[:-2] + "~" + old[-1]
            edits = [e if j != i else (rel, changed, new) for j, e in enumerate(patch.LOGIN_CODE_EDITS)]
            with self.subTest(edit=i):
                tree = self.tree(edits)
                with self.assertRaises(patch.PatchError) as e:
                    patch.patch_login_codes(tree, self.c)
                self.assertIn(rel, str(e.exception))
        # Upstream's strings with a key of Pluma's.
        tree = self.tree(strings=self.STRINGS + '\n"Pluma.Login.SendAgain" = "Send Again";\n')
        with self.assertRaisesRegex(patch.PatchError, "Pluma.Login.SendAgain"):
            patch.patch_login_codes(tree, self.c)

    def test_check(self):
        tree = self.tree()
        patch.patch_login_codes(tree, self.c)
        # Each edit undone.
        for rel, old, new in patch.LOGIN_CODE_EDITS:
            patched = tree.read(rel)
            tree.write(rel, patched.replace(new, old))
            with self.subTest(file=rel, new=new.strip()[:60]), self.assertRaises(patch.PatchError) as e:
                patch.verify_login_codes(tree, self.c)
            self.assertIn(rel, str(e.exception))
            tree.write(rel, patched)
        # A text changed, missing or twice; the support and Fragment back
        # (old None: new is added at the end).
        for rel, old, new in (
            (patch.STRINGS, '"Send again";', '"Send Again";'),
            (patch.STRINGS, '"Pluma.Login.AskAdministratorTitle" = "Ask the administrator";\n', ""),
            (patch.STRINGS, None, '"Pluma.Login.OpenTelegram" = "Open";\n'),
            (patch.LOGIN_SEQUENCE, None, "let _ = strongSelf.engine.auth.reportMissingCode(phoneNumber: number, "
                                         "phoneCodeHash: phoneCodeHash, mnc: mnc).start()\n"),
            (patch.CHANGE_PHONE, None, "AuthorizationSequenceController.presentDidNotGetCodeUI(sharedContext: context.sharedContext, "
                                       "controller: codeController, presentationData: presentationData, phoneNumber: phoneNumber, mnc: mnc)\n"),
            (patch.LOGIN_CODE_NODE, None, '                animationName = "IntroFragment"\n'),
            (patch.LOGIN_CODE_NODE, None, "                self.proceedNode.title = self.strings.Login_OpenFragment\n"),
            (patch.LOGIN_OPTION_TEXT, None, "        return parseMarkdownIntoAttributedString(strings.Login_EnterCodeFragmentText(phoneNumber).string, "
                                            "attributes: attributes, textAlignment: .center)\n"),
        ):
            with self.subTest(rel=rel, new=new[:60]):
                patched = tree.read(rel)
                if old is None:
                    tree.write(rel, patched + new)
                else:
                    self.assertEqual(patched.count(old), 1)
                    tree.write(rel, patched.replace(old, new))
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify_login_codes(tree, self.c)
                self.assertIn(rel, str(e.exception))
                tree.write(rel, patched)
        patch.verify_login_codes(tree, self.c)


class NoAiEditorTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect and of the line
    # that shows the chat field's AI button.
    def tree(self, root, edits=patch.NO_AI_EDITOR_EDITS):
        (root / "Telegram").mkdir(exist_ok=True)
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        files = {patch.NO_AI_EDITOR_GUARDS[3][0]: "isAIButtonVisible = true\n"}
        for rel, old, _, count in edits:
            files[rel] = files.get(rel, "") + (old + "x\n") * count
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_upstream_paths_cover_the_edits(self):
        for edit in patch.NO_AI_EDITOR_EDITS:
            self.assertIn(edit[0], patch.UPSTREAM_PATHS)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "the AI editor is offered again"):
                patch.verify_no_ai_editor(tree)
            patch.patch_no_ai_editor(tree)
            patch.verify_no_ai_editor(tree)
            with self.assertRaises(patch.PatchError):
                patch.patch_no_ai_editor(tree)

    def test_upstream_changed(self):
        for i, edit in enumerate(patch.NO_AI_EDITOR_EDITS):
            changed = edit[1][:-2] + "~" + edit[1][-1]
            edits = [e if j != i else (edit[0], changed) + tuple(edit[2:]) for j, e in enumerate(patch.NO_AI_EDITOR_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.patch_no_ai_editor(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.patch_no_ai_editor(tree)
            for i, (rel, old, new, _) in enumerate(patch.NO_AI_EDITOR_EDITS):
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(edit=i), self.assertRaisesRegex(patch.PatchError, "the AI editor is offered again"):
                    patch.verify_no_ai_editor(tree)
                tree.write(rel, patched)
            patch.verify_no_ai_editor(tree)

    def test_another_way_in(self):
        # A second place that enables a caption's button or adds the rich
        # editor's, or a chat field button shown some other way.
        for rel, s, count in patch.NO_AI_EDITOR_GUARDS:
            with self.subTest(file=rel), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d))
                patch.patch_no_ai_editor(tree)
                tree.write(rel, tree.read(rel) + s + "\n")
                with self.assertRaisesRegex(patch.PatchError, "another way into the AI editor"):
                    patch.verify_no_ai_editor(tree)

    def test_chat_field_keeps_expand(self):
        # The chat field stays AI-enabled for its expand button; only the AI
        # button's condition is false.
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.patch_no_ai_editor(tree)
            rel = patch.NO_AI_EDITOR_EDITS[0][0]
            self.assertIn("        if false && self.isAIEnabled, inputHasNonWhitespaceText,", tree.read(rel))


class ServiceAccountTest(unittest.TestCase):
    STRINGS = '"Bot.GenericBotStatus" = "bot";\n"Bot.GenericSupportStatus" = "support";\n"Bot.DescriptionTitle" = "x";\n'
    LINE = "    let statusText = strings.Bot_GenericSupportStatus\n"

    # The upstream files: the strings, a line of each place, the row of a
    # contact and the row of the settings' lists.
    def tree(self, root, strings=STRINGS, contact=patch.SERVICE_ACCOUNT_CONTACT_OLD, row=patch.SERVICE_ACCOUNT_PEER_OLD):
        (root / "versions.json").write_text("{}")
        files = {patch.APP_BUILD: "", patch.STRINGS: strings, patch.CONTACTS_ITEM: contact + "x\n",
                 patch.PEER_ITEM: row + "x\n"}
        for rel, count in patch.SERVICE_ACCOUNT_SITES:
            files[rel] = self.LINE * count
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_upstream_paths_cover_the_edits(self):
        for rel in [rel for rel, _ in patch.SERVICE_ACCOUNT_SITES] + [patch.CONTACTS_ITEM, patch.PEER_ITEM, patch.STRINGS]:
            self.assertIn(rel, patch.UPSTREAM_PATHS)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "Bot.GenericSupportStatus is not the line of a service account"):
                patch.verify_service_account(tree)
            patch.patch_service_account(tree)
            patch.verify_service_account(tree)
            # The key stays (the server's language pack translates it), the
            # text is Pluma's, in lower case as "bot" and "online" are.
            self.assertEqual(tree.read(patch.STRINGS), '"Bot.GenericBotStatus" = "bot";\n'
                             '"Bot.GenericSupportStatus" = "service account";\n"Bot.DescriptionTitle" = "x";\n')
            # The places that read it are as they were.
            for rel, count in patch.SERVICE_ACCOUNT_SITES:
                self.assertEqual(tree.read(rel), self.LINE * count)
            # The row of a contact: a support account before the last seen,
            # the last seen of everyone else as it was.
            contact = tree.read(patch.CONTACTS_ITEM)
            self.assertEqual(contact.count("user.flags.contains(.isSupport) {\n"), 1)
            self.assertLess(contact.index("user.flags.contains(.isSupport)"), contact.index("userPresence = presence"))
            self.assertIn("string: item.presentationData.strings.Bot_GenericSupportStatus, font: statusFont, "
                          "textColor: item.presentationData.theme.list.itemSecondaryTextColor)\n", contact)
            self.assertTrue(contact.endswith("                        } else {\n"
                                             "                            userPresence = presence\nx\n"))
            # The row of the settings' lists: after a bot's line, before
            # the last seen and "offline".
            row = tree.read(patch.PEER_ITEM)
            self.assertEqual(row, patch.SERVICE_ACCOUNT_PEER_OLD.split("                } else if let presence")[0]
                             + "                } else if case let .user(user) = item.peer, user.flags.contains(.isSupport) {\n"
                             "                    // pluma: a support account is a service account with no last seen (task 080).\n"
                             "                    statusAttributedString = NSAttributedString(string: "
                             "item.presentationData.strings.Bot_GenericSupportStatus, font: statusFont, "
                             "textColor: item.presentationData.theme.list.itemSecondaryTextColor)\n"
                             "                } else if let presence = item.presence {\nx\n")
            # A second run is refused.
            with self.assertRaises(patch.PatchError):
                patch.patch_service_account(tree)

    def test_upstream_changed(self):
        cases = (
            # Telegram's text is not the one replaced, or the key is gone.
            ({"strings": '"Bot.GenericSupportStatus" = "Support";\n'}, None),
            ({"strings": '"Bot.GenericBotStatus" = "bot";\n'}, None),
            # The row of a contact changed, or has a line for support accounts.
            ({"contact": patch.SERVICE_ACCOUNT_CONTACT_OLD.replace("userPresence", "presenceOfUser")}, None),
            ({"contact": "if user.flags.contains(.isSupport) {}\n" + patch.SERVICE_ACCOUNT_CONTACT_OLD}, None),
            # The same of the row of the settings' lists.
            ({"row": patch.SERVICE_ACCOUNT_PEER_OLD.replace("item.presence", "item.status")}, None),
            ({"row": "if user.flags.contains(.isSupport) {}\n" + patch.SERVICE_ACCOUNT_PEER_OLD}, None),
            # A place lost its line or shows it once more.
            ({}, ""),
            ({}, self.LINE * 2),
        )
        for i, (over, site) in enumerate(cases):
            with self.subTest(case=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), **over)
                if site is not None:
                    tree.write(patch.SERVICE_ACCOUNT_SITES[0][0], site)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.patch_service_account(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.patch_service_account(tree)
            damages = [(patch.STRINGS, '= "service account";', '= "support";'),
                       (patch.STRINGS, '"Bot.GenericSupportStatus" = "service account";\n',
                        '"Bot.GenericSupportStatus" = "service account";\n"Bot.GenericSupportStatus" = "support";\n'),
                       (patch.CONTACTS_ITEM, "user.flags.contains(.isSupport)", "user.flags.contains(.isScam)"),
                       (patch.CONTACTS_ITEM, "strings.Bot_GenericSupportStatus, font", "strings.Bot_GenericBotStatus, font"),
                       (patch.PEER_ITEM, "user.flags.contains(.isSupport)", "user.flags.contains(.isScam)"),
                       (patch.PEER_ITEM, "strings.Bot_GenericSupportStatus, font", "strings.LastSeen_Offline, font")]
            damages += [(rel, "Bot_GenericSupportStatus", "Bot_GenericBotStatus") for rel, _ in patch.SERVICE_ACCOUNT_SITES]
            for i, (rel, old, new) in enumerate(damages):
                patched = tree.read(rel)
                self.assertIn(old, patched)
                tree.write(rel, patched.replace(old, new))
                with self.subTest(damage=i), self.assertRaisesRegex(patch.PatchError, pathlib.PurePath(rel).name):
                    patch.verify_service_account(tree)
                tree.write(rel, patched)
            patch.verify_service_account(tree)

    def test_another_place(self):
        # The line read anywhere else in the sources.
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.patch_service_account(tree)
            tree.write("submodules/New/Sources/New.swift", self.LINE)
            with self.assertRaisesRegex(patch.PatchError, "New.swift: 1 uses of Bot_GenericSupportStatus, expected 0"):
                patch.verify_service_account(tree)


class GroupCallsTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect, and the third
    # group call of the manager (a conference), keyed already upstream.
    CONFERENCE = "PresentationGroupCallImpl(\n    joinAsPeerId: nil,\n    keyPair: keyPair,\n)\n"

    def tree(self, root):
        (root / "Telegram").mkdir(exist_ok=True)
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        files = {patch.STRINGS: '"Common.OK" = "OK";\n',
                 patch.GROUP_INSTANCE_CUSTOM: "            networkManager->sendDataChannelMessage(result);\n"}
        for rel, old, _ in patch.group_call_edits():
            files[rel] = files.get(rel, "") + old + "x\n"
        for rel, head, tail, _, must_contain in patch.RECORDING_STARTS:
            files[rel] = files.get(rel, "") + head + "".join(must_contain) + tail + "x\n"
        # The manager's calls whole: the scheduled one, the joined one, the
        # conference.
        (_, scheduled, _), (_, scheduled_key, _), (_, joined, _), (_, joined_key, _) = patch.group_call_edits()[:4]
        files[patch.CALL_MANAGER] = (scheduled + scheduled_key + "                        )\n"
                                     + joined + joined_key + "        )\n" + self.CONFERENCE)
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaises(patch.PatchError):
                patch.verify_group_calls(tree)
            patch.patch_group_calls(tree)
            patch.verify_group_calls(tree)
            self.assertIn('"Pluma.GroupCall.EncryptionFailed" = "Couldn\'t restore end-to-end encryption, so you left the call. '
                          'Try joining again.";\n', tree.read(patch.STRINGS))
            # A second run is refused: the key is there and nothing is left to edit.
            with self.assertRaises(patch.PatchError):
                patch.patch_group_calls(tree)

    def test_paths(self):
        # Every file the edits touch is fetched for the check job: tgcalls'
        # from its submodule, the others from the app's repository (TdBinding
        # is in it; tde2e, its submodule, is not edited).
        (sub, _, paths), = patch.SUBMODULES
        for rel, _, _ in patch.group_call_edits():
            if rel.startswith(sub + "/"):
                self.assertIn(rel, paths)
                self.assertNotIn(rel, patch.UPSTREAM_PATHS)
            else:
                self.assertIn(rel, patch.UPSTREAM_PATHS)
        self.assertFalse(any(rel.startswith("third-party/td/td/") for rel, _, _ in patch.group_call_edits()))
        for rel, *_ in patch.RECORDING_STARTS:
            self.assertIn(rel, patch.UPSTREAM_PATHS)
        for d in patch.CALL_UI_DIRS:
            self.assertIn(d, patch.UPSTREAM_PATHS)

    def test_one_edit_each(self):
        # No two edits of a file touch the same text, and each adds what
        # it says (pluma:), so the result reads as the patch's.
        edits = patch.group_call_edits()
        for i, (rel, old, new) in enumerate(edits):
            self.assertNotEqual(old, new)
            self.assertIn("pluma:", new.replace(old, ""), (rel, old[:60]))
            for other_rel, other_old, _ in edits[i + 1:]:
                if other_rel == rel:
                    self.assertNotIn(other_old, old)
                    self.assertNotIn(old, other_old)

    # PlumaE2EStatus v1 (ADR 0060 §5 of the server): every field, no other.
    V1_FIELDS = {"colibriClass", "v", "seq", "height", "lastBlock", "offset0", "offset1", "error", "sendEpochs", "decryptEpochs",
                 "unknownEpochs", "encrypted", "encryptFailed", "senders"}
    V1_SENDER = {"user", "ok", "unknownEpoch", "tooOld", "duplicate", "failed", "lastOkMs"}

    def test_report_contract(self):
        # The report the SFU reads: the fields TdCall gives and those the
        # context adds are the contract's, and so are those of a report with
        # no state; none is a key, a nonce, emoji or bytes of a frame.
        take = patch._E2E_CONTEXT_TAKE
        counters = patch._TD_BINDING_DECRYPT
        from_call = set(re.findall(r'status\[@"([A-Za-z0-9]+)"\]', counters))
        added = set(re.findall(r'report\["([A-Za-z0-9]+)"\] = ', take))
        self.assertEqual(from_call | added, self.V1_FIELDS)
        self.assertEqual(from_call & added, {"senders"})
        no_state = take[take.index("?? [") + 4:take.index("            ]\n")]
        self.assertEqual(set(re.findall(r'"([A-Za-z0-9]+)": ', no_state)) | added, self.V1_FIELDS)
        self.assertIn('"height": -1,', no_state)
        self.assertIn('"lastBlock": "",', no_state)
        sender = set(re.findall(r'@"([A-Za-z0-9]+)": @\(', counters))
        self.assertEqual(sender, self.V1_SENDER)
        for name in self.V1_FIELDS | self.V1_SENDER:
            for word in ("key", "nonce", "emoji", "secret", "frame"):
                self.assertNotIn(word, name.lower())
        self.assertIn('report["colibriClass"] = "PlumaE2EStatus"', take)
        self.assertIn('report["v"] = 1', take)
        # seq counts the reports since the join: begin() and reset() start
        # it over.
        self.assertIn("callState.plumaSeq += 1\n", take)
        self.assertIn('report["seq"] = callState.plumaSeq', take)
        self.assertIn("callState.plumaSeq = 0", patch._E2E_CONTEXT_RESET)
        # Counters of frames and the epochs of received frames are since the
        # last report: the report takes them; the time of a sender's last
        # decrypted frame stays.
        take_status = counters[counters.index("- (NSDictionary<NSString *, id> *)plumaTakeStatus {"):counters.index("- (int)plumaHeight {")]
        for s in ("counters.ok = 0;", "counters.unknownEpoch = 0;", "counters.tooOld = 0;", "counters.duplicate = 0;",
                  "counters.failed = 0;", "_plumaEncrypted = 0;", "_plumaEncryptFailed = 0;", "_plumaDecryptEpochs.clear();",
                  "_plumaUnknownEpochs.clear();"):
            self.assertIn(s, take_status)
        self.assertNotIn("lastOkAt = ", take_status)
        self.assertNotIn("_plumaSendEpochs = ", take_status)
        # Only senders with frames since the last report, by user id (a
        # std::map), -1 for one never decrypted.
        self.assertIn("if (plumaSenderFrames(counters) == 0) {\n            continue;", take_status)
        self.assertIn("std::map<int64_t, PlumaSenderCounters> _plumaSenders;", patch._TD_BINDING_COUNTERS)
        self.assertIn("counters.lastOkAt > 0.0 ? (int64_t)((timestamp - counters.lastOkAt) * 1000.0) : -1", take_status)
        # Limits: 15 epochs sent and decrypted, 8 unknown, 100 senders and
        # 16 KiB, the senders decrypted longest ago dropped first.
        self.assertIn("plumaAddEpochs(_plumaDecryptEpochs, 15, ", counters)
        self.assertIn("plumaAddEpochs(_plumaUnknownEpochs, 8, ", counters)
        self.assertIn("plumaAddEpochs(epochs, 15, header);", "".join(new for _, _, new in patch.group_call_edits()))
        self.assertIn("if data.count <= 16 * 1024 && senders.count <= 100 {", take)
        self.assertIn('senders.indices.max(by: { (senders[$0]["lastOkMs"] as? Int ?? 0) < (senders[$1]["lastOkMs"] as? Int ?? 0) })', take)
        # Hashes go as their first 8 bytes in hex.
        self.assertIn('@"%02x%02x%02x%02x%02x%02x%02x%02x"', patch._TD_BINDING_COUNTERS)
        # tgcalls sends nothing but a status report.
        self.assertIn('json["colibriClass"].string_value() != "PlumaE2EStatus"', patch._TGCALLS_SEND_STATUS)
        self.assertIn("if (!_isDataChannelOpen) {", patch._TGCALLS_SEND_STATUS)

    def test_report_example(self):
        # The example of the ADR has the fields the patch writes.
        example = json.loads('{"colibriClass":"PlumaE2EStatus","v":1,"seq":12,"height":41,"lastBlock":"9f3c0a1b2c3d4e5f",'
                             '"offset0":42,"offset1":17,"error":0,"sendEpochs":["9f3c0a1b2c3d4e5f"],"decryptEpochs":["9f3c0a1b2c3d4e5f"],'
                             '"unknownEpochs":[],"encrypted":250,"encryptFailed":0,"senders":[{"user":1000002,"ok":248,"unknownEpoch":0,'
                             '"tooOld":0,"duplicate":1,"failed":0,"lastOkMs":40}]}')
        self.assertEqual(set(example), self.V1_FIELDS)
        self.assertEqual(set(example["senders"][0]), self.V1_SENDER)

    def test_epoch_header(self):
        # The open header the counters read is tde2e's: an int32 whose low
        # byte is the number of epochs (at most 15), 32 bytes per epoch, after
        # the open prefix; the decrypting side finds the prefix's length in
        # the last 4 bytes (CallEncryption::decrypt).
        counters = patch._TD_BINDING_COUNTERS
        self.assertIn("size_t count = head & 0xff;", counters)
        self.assertIn("if (count > 15 || size - offset - 4 < count * 32) {", counters)
        self.assertIn("return std::string((const char *)data + offset, 4 + count * 32);", counters)
        self.assertIn("memcpy(&prefixLength, bytes + message.length - 4, 4);", counters)
        self.assertIn("return plumaEpochHeader(bytes, message.length - 4, prefixLength);", counters)
        # A block's hash is over the form the server keeps (ADR 0060 §2: the
        # bytes its author sent, the magic one less than in the form the
        # server sends, Blockchain::from_server_to_local), which is tde2e's
        # Block::calc_hash.
        block_hash = counters.split("static NSString * _Nullable plumaBlockHashPrefix")[1].split("\n}\n")[0]
        self.assertIn("memcpy(&magic, block.bytes, 4);\n    magic -= 1;\n    memcpy(block.mutableBytes, &magic, 4);", block_hash)
        self.assertIn("CC_SHA256(block.bytes, (CC_LONG)block.length, hash);", block_hash)
        self.assertNotIn("serverBlock.bytes, (CC_LONG)", block_hash)

    def test_failure_code(self):
        # The error of a failed call is the first failure, read from the
        # CallFailed tde2e answers after it as tde2e reads any code.
        # tde2e's message is "CALL_FAILED: [Error : <code> : ...]" (Call.h
        # get_status, the Error of e2e/utils.h, Status::print): the code is
        # read where the failure starts, not at the start of the message.
        counters = patch._TD_BINDING_COUNTERS
        self.assertIn('error.message.find("[Error : ")', counters)
        self.assertIn('sscanf(error.message.c_str() + failure, "[Error : %d :", &code)', counters)
        self.assertNotIn('sscanf(error.message.c_str(), ', counters)
        self.assertIn('error_string(tde2e_api::ErrorCode(code)) == "UNKNOWN_ERROR"', counters)
        edits = "".join(new for rel, _, new in patch.group_call_edits() if rel == patch.TD_BINDING)
        self.assertIn("if (_plumaError == 0) {\n            _plumaError = plumaFailureCode(result.error());", edits)

    def test_stalled_decryption(self):
        # Nothing decrypted for 15 s: packets that could not be decrypted came
        # within the window, none from anyone was, and the call is that old.
        # Too old and duplicate packets are neither.
        counters = patch._TD_BINDING_DECRYPT
        stalled = counters[counters.index("- (bool)plumaDecryptionStalled:(double)window {"):]
        self.assertIn("timestamp - _plumaMadeAt < window", stalled)
        self.assertIn("timestamp - _plumaLastUndecryptableAt >= window", stalled)
        self.assertIn("return _plumaLastDecryptedAt == 0.0 || timestamp - _plumaLastDecryptedAt >= window;", stalled)
        decrypt = counters[:counters.index("- (NSDictionary<NSString *, id> *)plumaTakeStatus {")]
        self.assertEqual(decrypt.count("isUndecryptable = false;"), 2)
        self.assertLess(decrypt.index('"Message is too old"'), decrypt.index("isUndecryptable = false;"))

    def test_strings(self):
        # The patch's texts are used, each once, by the code it adds.
        edited = "".join(new for _, _, new in patch.group_call_edits())
        for key, _ in patch.GROUP_CALL_STRINGS:
            self.assertEqual(edited.count("strings." + key.replace(".", "_")), 1, key)


class CallColorsTest(unittest.TestCase):
    def tree(self, root, extra=""):
        (root / "Telegram").mkdir(exist_ok=True)
        (root / "Telegram/BUILD").write_text("")
        (root / "versions.json").write_text("{}")
        # Each of Telegram's colours as many times as upstream has it, a grey,
        # the fractions of a stream's screen.
        lines = [f"let c{i}_{n} = UIColor(rgb: 0x{old.lower() if n % 2 else old})"
                 for i, (old, _, count) in enumerate(patch.CALL_COLORS) for n in range(count)]
        files = {patch.CALL_BACKGROUND: "\n".join(lines) + "\nlet grey = UIColor(rgb: 0x1C1C1E)\n" + extra,
                 patch.MEDIA_STREAM: "".join(old + "\n" for _, old, _, count in patch.CALL_COLOR_LITERALS for _ in range(count))}
        # The buttons' colours, each in its file.
        for rel, color, count in patch.CALL_BUTTON_COLORS:
            files[rel] = files.get(rel, "") + "".join(f"let b = UIColor(rgb: 0x{color.lower()})\n" for _ in range(count))
        for d in patch.CALL_UI_DIRS:
            (root / d).mkdir(parents=True, exist_ok=True)
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.patch_call_colors(tree)
            text = tree.read(patch.CALL_BACKGROUND)
            for old, new, count in patch.CALL_COLORS:
                self.assertNotIn(old, text.upper())
            self.assertIn("UIColor(rgb: 0x1C1C1E)", text)
            self.assertEqual(tree.read(patch.MEDIA_STREAM).count("UIColor(red:"), 0)
            # The buttons keep theirs, Telegram's red in a button's file too.
            for rel, color, count in patch.CALL_BUTTON_COLORS:
                self.assertEqual(tree.read(rel).count(f"UIColor(rgb: 0x{color.lower()})"), count, rel)
            # A second run finds none of Telegram's colours.
            with self.assertRaises(patch.PatchError):
                patch.patch_call_colors(tree)

    def test_upstream_changed(self):
        # A colour upstream adds or drops stops the patch, which writes
        # nothing then.
        for extra in ("let more = UIColor(rgb: 0x3252EF)\n",):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), extra)
                before = tree.read(patch.CALL_BACKGROUND)
                with self.assertRaises(patch.PatchError) as e:
                    patch.patch_call_colors(tree)
                self.assertIn("0x3252EF", str(e.exception))
                self.assertEqual(tree.read(patch.CALL_BACKGROUND), before)
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            text = tree.read(patch.CALL_BACKGROUND)
            tree.write(patch.CALL_BACKGROUND, text.replace("0x568FD6", "0x568FD7"))
            with self.assertRaises(patch.PatchError) as e:
                patch.patch_call_colors(tree)
            self.assertIn("0x568FD6", str(e.exception))
        # A button that lost its colour, or has one more, stops the patch.
        rel, color, count = patch.CALL_BUTTON_COLORS[0]
        for text in ("", f"let b = UIColor(rgb: 0x{color})\n" * (count + 1)):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d))
                tree.write(rel, text)
                before = tree.read(patch.CALL_BACKGROUND)
                with self.assertRaises(patch.PatchError) as e:
                    patch.patch_call_colors(tree)
                self.assertIn(f"0x{color}", str(e.exception))
                self.assertEqual(tree.read(patch.CALL_BACKGROUND), before)

    def test_table(self):
        # Each of Telegram's colours once, each of Pluma's in the palette:
        # the call sets of the owner's decision and the sage of task 017.
        olds = [old for old, _, _ in patch.CALL_COLORS]
        self.assertEqual(len(olds), len(set(olds)))
        palette = {c for s in patch.CALL_BACKGROUND_SETS for c in s} | {"9DBB9F", "B2CEB4"}
        for old, new, count in patch.CALL_COLORS:
            self.assertIn(new, palette, old)
            self.assertGreater(count, 0)
            self.assertNotIn(old, patch.CALL_GREYS)
            self.assertRegex(old, r"^[0-9A-F]{6}$")
        self.assertFalse(palette & set(olds))
        # The buttons' colours: Telegram's, once each per file, in a call
        # screen's source; none is Pluma's or a grey.
        keys = [(rel, color) for rel, color, _ in patch.CALL_BUTTON_COLORS]
        self.assertEqual(len(keys), len(set(keys)))
        for rel, color, count in patch.CALL_BUTTON_COLORS:
            self.assertRegex(color, r"^[0-9A-F]{6}$")
            self.assertGreater(count, 0)
            self.assertNotIn(color, palette | set(patch.CALL_GREYS))
            self.assertTrue(rel.startswith(patch.CALL_UI_DIRS), rel)
        self.assertEqual({color for _, color, _ in patch.CALL_BUTTON_COLORS}, {"FF3B30", "D92326", "74DB58", "330D0B"})


if __name__ == "__main__":
    unittest.main()
