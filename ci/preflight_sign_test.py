#!/usr/bin/env python3
"""Tests of the signing preflight on profiles and identities made here with
openssl: a self-signed stand-in for the distribution certificate, and
profiles signed with it the way Apple signs real ones (CMS)."""

import base64
import datetime
import pathlib
import plistlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import patch  # noqa: E402
import preflight_sign  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEAM = "ABCDE12345"
BUNDLE = patch.load_env(ROOT / "config/app.env")["PLUMA_BUNDLE_ID"]
NOW = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None, microsecond=0)
DEVICES = ["00008110-000A1B2C3D4E5F60", "00008120-0011223344556677"]
PASSWORD = "correct horse"


def run(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def make_identity(d, name, cn, team=TEAM, days=365):
    key, cert = d / f"{name}.key", d / f"{name}.pem"
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", str(days),
        "-subj", f"/CN={cn}/OU={team}/O=Pluma Test/C=US")
    p12 = run("pkcs12", "-export", "-inkey", str(key), "-in", str(cert), "-passout", f"pass:{PASSWORD}")
    der = run("x509", "-in", str(cert), "-outform", "DER")
    return key, cert, p12, der


def profile_plist(suffix, cert_der, **over):
    ent = {
        "application-identifier": f"{TEAM}.{BUNDLE}{suffix}",
        "com.apple.developer.team-identifier": TEAM,
        "com.apple.security.application-groups": [f"group.{BUNDLE}"],
        "get-task-allow": False,
        "keychain-access-groups": [f"{TEAM}.*", "com.apple.token"],
    }
    if suffix == "":
        ent["aps-environment"] = "production"
    ent.update(over.pop("entitlements", {}))
    p = {
        "AppIDName": f"Pluma{suffix}",
        "ApplicationIdentifierPrefix": [TEAM],
        "CreationDate": NOW - datetime.timedelta(days=10),
        "Platform": ["iOS"],
        "DeveloperCertificates": [cert_der],
        "Entitlements": ent,
        "ExpirationDate": NOW + datetime.timedelta(days=355),
        "Name": f"Pluma{suffix} Ad Hoc",
        "ProvisionedDevices": list(DEVICES),
        "TeamIdentifier": [TEAM],
        "TeamName": "Pluma Test",
        "TimeToLive": 365,
        "UUID": "00000000-0000-0000-0000-000000000000",
        "Version": 1,
    }
    p.update(over)
    return {k: v for k, v in p.items() if v is not None}


class PreflightTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        d = pathlib.Path(cls.dir.name)
        cls.key, cls.cert, cls.p12, cls.cert_der = make_identity(d, "dist", f"Apple Distribution: Pluma Test ({TEAM})")
        cls.good = {secret: cls.sign(profile_plist(suffix, cls.cert_der)) for suffix, _, secret in patch.TARGETS}

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    @classmethod
    def sign(cls, plist):
        return run("smime", "-sign", "-signer", str(cls.cert), "-inkey", str(cls.key), "-nodetach", "-binary",
                   "-outform", "der", data=plistlib.dumps(plist))

    def check(self, profiles=None, p12=None, password=PASSWORD):
        return preflight_sign.check(profiles or self.good, p12 or self.p12, password, TEAM, BUNDLE, NOW, 14)

    def with_profile(self, secret, plist):
        profiles = dict(self.good)
        profiles[secret] = self.sign(plist)
        return profiles

    def assert_error(self, errors, *parts):
        self.assertTrue(any(all(p in e for p in parts) for e in errors), f"no error with {parts} in {errors}")

    def test_good(self):
        report, errors = self.check()
        self.assertEqual(errors, [])
        self.assertIn(f"certificate: Apple Distribution: Pluma Test ({TEAM})", report[0])
        self.assertEqual(len(report), 1 + len(patch.TARGETS))
        self.assertIn(f"profile Intents: {TEAM}.{BUNDLE}.SiriIntents, 'Pluma.SiriIntents Ad Hoc', 2 devices", report[6])

    def test_the_certificate_is_parsed(self):
        cert = preflight_sign.Certificate(self.cert_der)
        self.assertEqual((cert.subject["OU"], cert.subject["O"]), (TEAM, "Pluma Test"))
        self.assertGreater(cert.not_after, NOW)

    def test_profile_problems(self):
        cases = (
            ("MAIN", profile_plist("", self.cert_der, ExpirationDate=NOW - datetime.timedelta(days=1)), ("expired",)),
            ("SHARE", profile_plist(".Share", self.cert_der, ExpirationDate=NOW + datetime.timedelta(days=5)),
             ("expires on", "renew")),
            ("WIDGET", profile_plist(".Share", self.cert_der), (f"is for {TEAM}.{BUNDLE}.Share", ".Widget")),
            ("MAIN", profile_plist("", self.cert_der, TeamIdentifier=["ZYXWV98765"]), ("of team",)),
            ("NOTIFICATION_SERVICE", profile_plist(".NotificationService", self.cert_der,
                                                   entitlements={"get-task-allow": True}), ("not an ad hoc",)),
            ("NOTIFICATION_CONTENT", profile_plist(".NotificationContent", self.cert_der, ProvisionedDevices=None),
             ("not an ad hoc",)),
            ("SIRI_INTENTS", profile_plist(".SiriIntents", self.cert_der, ProvisionsAllDevices=True), ("not an ad hoc",)),
            ("BROADCAST_UPLOAD", profile_plist(".BroadcastUpload", self.cert_der,
                                               entitlements={"com.apple.security.application-groups": []}),
             (f"lacks the App Group group.{BUNDLE}",)),
            ("MAIN", profile_plist("", self.cert_der, entitlements={"aps-environment": "development"}),
             ("PLUMA_PROFILE_MAIN", "'production'")),
            ("MAIN", profile_plist("", self.cert_der, Platform=["tvOS"]), ("not iOS",)),
            ("SHARE", profile_plist(".Share", b"another certificate"), ("PLUMA_PROFILE_SHARE", "does not hold the certificate")),
            ("WIDGET", profile_plist(".Widget", self.cert_der, ProvisionedDevices=DEVICES[:1]),
             ("profile Widget", "misses 1")),
        )
        for secret, plist, parts in cases:
            with self.subTest(secret=secret, parts=parts):
                _, errors = self.check(self.with_profile(secret, plist))
                self.assert_error(errors, *parts)

    def test_not_a_profile(self):
        profiles = dict(self.good, SHARE=b"\x30\x03\x02\x01\x00")
        _, errors = self.check(profiles)
        self.assert_error(errors, "PLUMA_PROFILE_SHARE")

    def test_identity_problems(self):
        d = pathlib.Path(self.dir.name)
        _, _, dev_p12, _ = make_identity(d, "dev", f"Apple Development: Pluma Test ({TEAM})")
        _, _, other_team, _ = make_identity(d, "other", "Apple Distribution: Someone (ZYXWV98765)", team="ZYXWV98765")
        _, _, short, _ = make_identity(d, "short", f"Apple Distribution: Pluma Test ({TEAM})", days=3)
        for p12, password, parts in (
            (self.p12, "wrong", ("does not open",)),
            (dev_p12, PASSWORD, ("not a distribution certificate",)),
            (other_team, PASSWORD, ("of team ZYXWV98765",)),
            (short, PASSWORD, ("certificate expires",)),
        ):
            with self.subTest(parts=parts):
                _, errors = self.check(p12=p12, password=password)
                self.assert_error(errors, preflight_sign.P12_B64, *parts)

    def test_main_reads_the_environment(self):
        env = {preflight_sign.P12_B64: base64.b64encode(self.p12).decode(), preflight_sign.P12_PASSWORD: PASSWORD}
        for _, _, secret in patch.TARGETS:
            env[preflight_sign.PROFILE_PREFIX + secret] = base64.encodebytes(self.good[secret]).decode()
        args = ["--app", str(ROOT / "config/app.env"), "--team-id", TEAM, "--min-days", "0"]
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(preflight_sign.main(args + ["--out-dir", out], env=env), 0)
            names = sorted(p.name for p in pathlib.Path(out, "profiles").iterdir())
            self.assertEqual(names, sorted(f"{name}.mobileprovision" for _, name, _ in patch.TARGETS))
            self.assertEqual(pathlib.Path(out, "identity.p12").read_bytes(), self.p12)
        missing = dict(env)
        del missing[preflight_sign.PROFILE_PREFIX + "WIDGET"]
        missing[preflight_sign.P12_B64] = "not base64!"
        self.assertEqual(preflight_sign.main(args, env=missing), 1)


if __name__ == "__main__":
    unittest.main()
