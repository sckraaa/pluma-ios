#!/usr/bin/env python3
"""Checks the signing material of the ad hoc IPA before anything is built.

A profile that has expired, belongs to another team or App ID, lacks the
App Group, push or a device, or does not hold the distribution certificate
stops the release here, seconds into the run, instead of at the end of an
hour of compilation. The certificate must be a distribution one of the team,
valid, and the key in the .p12 must be its key.

The material comes from the environment (the secrets of the "release"
environment, README):
  PLUMA_DIST_P12_B64        the distribution certificate with its key (.p12),
                            base64;
  PLUMA_DIST_P12_PASSWORD   the password of the .p12;
  PLUMA_PROFILE_<TARGET>    the ad hoc profile of each target, base64; TARGET
                            is MAIN, SHARE, ... (TARGETS of ci/patch.py).
With --out-dir it is written where Make.py and ci/keychain.sh read it:
<dir>/profiles/<name>.mobileprovision and <dir>/identity.p12.

Prints no secret: names, dates and counts only. Needs the openssl command
(OpenSSL or LibreSSL).
"""

import argparse
import base64
import binascii
import datetime
import os
import pathlib
import plistlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import patch  # noqa: E402

P12_B64 = "PLUMA_DIST_P12_B64"
P12_PASSWORD = "PLUMA_DIST_P12_PASSWORD"
PROFILE_PREFIX = "PLUMA_PROFILE_"

DISTRIBUTION_NAMES = ("Apple Distribution: ", "iPhone Distribution: ")


class CheckError(Exception):
    pass


def openssl(args, data, env=None):
    r = subprocess.run(["openssl", *args], input=data, capture_output=True, env=env)
    if r.returncode != 0:
        lines = r.stderr.decode("utf-8", "replace").strip().splitlines()
        raise CheckError(f"openssl {args[0]}: {lines[0] if lines else 'failed'}")
    return r.stdout


# --- certificates ------------------------------------------------------------


def _tlv(data, pos):
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length


def _children(data, start, end):
    pos = start
    while pos < end:
        tag, vs, ve = _tlv(data, pos)
        yield tag, vs, ve, pos
        pos = ve


def _time(tag, raw):
    s = raw.decode("ascii")
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
    return datetime.datetime.strptime(s, fmt)


NAME_OIDS = {b"\x55\x04\x03": "CN", b"\x55\x04\x0b": "OU", b"\x55\x04\x0a": "O"}


class Certificate:
    """The fields of an X.509 certificate the checks need, from its DER."""

    def __init__(self, der):
        try:
            tag, s, e = _tlv(der, 0)
            _, ts, te, _ = next(_children(der, s, e))
            items = list(_children(der, ts, te))
            if items[0][0] == 0xA0:  # version
                items = items[1:]
            _, _, _, validity, subject, spki = items[:6]
            times = list(_children(der, validity[1], validity[2]))
            self.not_after = _time(times[1][0], der[times[1][1]:times[1][2]])
            self.subject = {}
            for _, ss, se, _ in _children(der, subject[1], subject[2]):
                for _, as_, ae, _ in _children(der, ss, se):
                    (_, os_, oe, _), (_, vs, ve, _) = list(_children(der, as_, ae))[:2]
                    key = NAME_OIDS.get(der[os_:oe])
                    if key:
                        self.subject[key] = der[vs:ve].decode("utf-8", "replace")
            self.spki = der[spki[3]:spki[2]]
        except (IndexError, ValueError, StopIteration):
            raise CheckError("the certificate does not parse")
        self.der = der
        self.name = self.subject.get("CN", "?")


def pem_blocks(text, kind):
    return re.findall(rf"-----BEGIN {kind}-----.*?-----END {kind}-----\n?", text, re.S)


def load_identity(p12, password):
    """The certificate of the .p12 and whether its key is the certificate's."""
    env = dict(os.environ, PLUMA_P12_PASS=password)

    def pkcs12(*args):
        base = ["pkcs12", "-passin", "env:PLUMA_P12_PASS", *args]
        try:
            return openssl(base, p12, env)
        except CheckError:
            # OpenSSL 3 reads the RC2 of older Keychain exports only with
            # its legacy provider; LibreSSL has no such option.
            try:
                return openssl(base + ["-legacy"], p12, env)
            except CheckError:
                raise CheckError("the .p12 does not open with PLUMA_DIST_P12_PASSWORD")

    certs = pem_blocks(pkcs12("-nokeys", "-clcerts").decode(), "CERTIFICATE")
    if len(certs) != 1:
        raise CheckError(f"the .p12 holds {len(certs)} certificates of its own, expected 1")
    cert = Certificate(openssl(["x509", "-outform", "DER"], certs[0].encode()))
    key = pkcs12("-nocerts", "-nodes")
    try:
        public = openssl(["pkey", "-pubout", "-outform", "DER"], key)
    finally:
        del key
    return cert, public == cert.spki


# --- profiles ----------------------------------------------------------------


def decode_profile(der):
    """The property list inside a provisioning profile (a CMS signed message;
    the signature is Apple's and is not checked here, as Make.py does not)."""
    try:
        return plistlib.loads(openssl(["smime", "-inform", "der", "-verify", "-noverify"], der))
    except plistlib.InvalidFileException:
        raise CheckError("not a provisioning profile")


def check(profiles, p12, password, team, bundle, now, min_days):
    """Checks the material; returns (report lines, errors)."""
    report, errors = [], []
    horizon = now + datetime.timedelta(days=min_days)

    cert = None
    try:
        cert, key_matches = load_identity(p12, password)
    except CheckError as e:
        errors.append(f"{P12_B64}: {e}")
    if cert:
        report.append(f"certificate: {cert.name}, valid until {cert.not_after:%Y-%m-%d}")
        if not cert.name.startswith(DISTRIBUTION_NAMES):
            errors.append(f"{P12_B64}: {cert.name!r} is not a distribution certificate (Apple Distribution)")
        if cert.subject.get("OU") != team:
            errors.append(f"{P12_B64}: the certificate is of team {cert.subject.get('OU')}, PLUMA_TEAM_ID is {team}")
        if cert.not_after <= horizon:
            errors.append(f"{P12_B64}: the certificate expires on {cert.not_after:%Y-%m-%d}; renew it")
        if not key_matches:
            errors.append(f"{P12_B64}: the key in the .p12 is not the certificate's")

    devices = {}
    for suffix, name, secret in patch.TARGETS:
        var = PROFILE_PREFIX + secret
        app_id = f"{team}.{bundle}{suffix}"
        try:
            p = decode_profile(profiles[secret])
        except CheckError as e:
            errors.append(f"{var}: {e}")
            continue
        ent = p.get("Entitlements", {})
        problems = []
        if ent.get("application-identifier") != app_id:
            problems.append(f"is for {ent.get('application-identifier')}, expected {app_id}")
        if p.get("TeamIdentifier") != [team] or ent.get("com.apple.developer.team-identifier") != team:
            problems.append(f"is of team {p.get('TeamIdentifier')}, PLUMA_TEAM_ID is {team}")
        expires = p.get("ExpirationDate")
        if not isinstance(expires, datetime.datetime):
            problems.append("has no expiration date")
        elif expires <= now:
            problems.append(f"expired on {expires:%Y-%m-%d}")
        elif expires <= horizon:
            problems.append(f"expires on {expires:%Y-%m-%d}, in less than {min_days} days; renew it")
        udids = p.get("ProvisionedDevices") or []
        if not udids or p.get("ProvisionsAllDevices") or ent.get("get-task-allow") is not False:
            problems.append("is not an ad hoc profile (devices listed, no debugging)")
        if "iOS" not in p.get("Platform", []):
            problems.append(f"is for {p.get('Platform')}, not iOS")
        group = f"group.{bundle}"
        if group not in ent.get("com.apple.security.application-groups", []):
            problems.append(f"lacks the App Group {group}")
        if suffix == "" and ent.get("aps-environment") != "production":
            problems.append(f"has push {ent.get('aps-environment')!r}, an ad hoc build needs 'production'")
        if cert and cert.der not in p.get("DeveloperCertificates", []):
            problems.append(f"does not hold the certificate {cert.name!r}")
        for problem in problems:
            errors.append(f"{var}: the profile {p.get('Name')!r} {problem}")
        devices[name] = set(udids)
        until = f"{expires:%Y-%m-%d}" if isinstance(expires, datetime.datetime) else "?"
        report.append(f"profile {name}: {ent.get('application-identifier')}, {p.get('Name')!r}, "
                      f"{len(udids)} devices, until {until}")

    # A device missing from any profile cannot install the app at all.
    if devices and len({frozenset(d) for d in devices.values()}) > 1:
        main = devices.get("Telegram", set())
        for name, d in devices.items():
            if d != main:
                errors.append(f"the profile {name} lists {len(d - main)} devices the app's profile does not "
                              f"and misses {len(main - d)} of its devices; register the same devices in all")
    return report, errors


def read_secret(env, var, errors):
    value = env.get(var, "")
    if not value.strip():
        errors.append(f"{var} is not set")
        return None
    try:
        return base64.b64decode("".join(value.split()), validate=True)
    except binascii.Error:
        errors.append(f"{var} is not base64")
        return None


def main(argv=None, env=None):
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--app", required=True, help="config/app.env")
    ap.add_argument("--team-id", required=True)
    ap.add_argument("--out-dir", help="where to write the profiles and the .p12 for the build")
    ap.add_argument("--min-days", type=int, default=14, help="the certificate and profiles must stay valid this long")
    a = ap.parse_args(argv)

    errors = []
    bundle = patch.load_env(a.app)["PLUMA_BUNDLE_ID"]
    if not re.fullmatch(r"[A-Z0-9]{10}", a.team_id or ""):
        errors.append(f"PLUMA_TEAM_ID {a.team_id!r} is not an Apple Team ID")
    p12 = read_secret(env, P12_B64, errors)
    password = env.get(P12_PASSWORD)
    if password is None:
        errors.append(f"{P12_PASSWORD} is not set")
    profiles = {secret: read_secret(env, PROFILE_PREFIX + secret, errors) for _, _, secret in patch.TARGETS}
    report = []
    if not errors:
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        report, errors = check(profiles, p12, password, a.team_id, bundle, now, a.min_days)
    for line in report:
        print(f"preflight: {line}")
    if errors:
        prefix = "::error::" if env.get("GITHUB_ACTIONS") else "preflight: "
        for e in errors:
            print(prefix + e, file=sys.stderr)
        print(f"preflight: {len(errors)} problems with the signing material (README, Signing)", file=sys.stderr)
        return 1
    if a.out_dir:
        out = pathlib.Path(a.out_dir)
        (out / "profiles").mkdir(parents=True, exist_ok=True)
        for _, name, secret in patch.TARGETS:
            (out / "profiles" / f"{name}.mobileprovision").write_bytes(profiles[secret])
        identity = out / "identity.p12"
        identity.touch(mode=0o600)
        identity.write_bytes(p12)
    print(f"preflight: the signing material of {bundle} (team {a.team_id}) is good")
    return 0


if __name__ == "__main__":
    sys.exit(main())
