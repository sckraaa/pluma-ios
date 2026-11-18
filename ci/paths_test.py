#!/usr/bin/env python3
"""The choice of a path to the server by probes (task 113): the contract of
the probe, the pure rules on this machine's compilers, and the patch on the
pinned upstream."""
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import patch  # noqa: E402
from patch_test import RecordingTree, config, upstream_files  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
NETWORK, ACCOUNT = patch.NETWORK, patch.ACCOUNT

PROBE_LINE = "pluma.probe nonce:int128 down:int pad:bytes = pluma.Probe"
PROBE_DATA_LINE = "pluma.probeData nonce:int128 seq:int total:int server_ms:long pad:bytes = pluma.ProbeData"

# pluma_probe of the brief's section 7: the defaults and the ranges of the
# server (bff, appconfig/probe.go), (key, default, min, max, ratio).
SERVER_FIELDS = (
    ("gate_down", 65536, 16384, 524288, False),
    ("rank_down", 196608, 16384, 524288, False),
    ("up", 20480, 0, 65536, False),
    ("stall_ms", 1500, 300, 10000, False),
    ("deadline_ms", 6000, 1000, 30000, False),
    ("suspect_ms", 4000, 1000, 30000, False),
    ("reprobe_s", 21600, 600, 604800, False),
    ("rank_min_interval_s", 1800, 60, 86400, False),
    ("min_dwell_s", 600, 0, 86400, False),
    ("switch_ratio", 0.7, 0.05, 0.95, True),
    ("switch_ratio_now", 0.25, 0.05, 0.95, True),
    ("edge_probe_if_direct_ms", 1500, 100, 60000, False),
    ("bad_ttl_s", 86400, 60, 604800, False),
    ("failed_ttl_s", 300, 10, 86400, False),
    ("race_stagger_ms", 800, 0, 10000, False),
    ("confirm_s", 60, 10, 3600, False),
)

NONCE = bytes(range(16))
OTHER_NONCE = bytes(range(16, 32))
DIRECT, E1, E2 = "direct", "wss://e1.example.org/apiws", "wss://e2.example.org/apiws"


def tl_bytes(data):
    head = bytes([len(data)]) if len(data) < 254 else bytes([254]) + len(data).to_bytes(3, "little")
    out = head + data
    return out + b"\0" * (-len(out) % 4)


def unencrypted(body, msg_id=0x6553_0000_0000_0001):
    return b"\0" * 8 + struct.pack("<qI", msg_id, len(body)) + body


def probe_request(nonce, down, pad, msg_id):
    """pluma.probe as the contract lays it out."""
    return unencrypted(struct.pack("<I", 0x5c316d30) + nonce + struct.pack("<i", down) + tl_bytes(pad), msg_id)


def probe_data(nonce, seq, total, pad_length, server_ms=1_763_000_000_000):
    """pluma.probeData as the gateway makes it (handshake.ProbeData)."""
    body = struct.pack("<I", 0x6ab3780b) + nonce + struct.pack("<iiq", seq, total, server_ms) + tl_bytes(b"\x5a" * pad_length)
    return unencrypted(body)


def answer(nonce, down):
    """The whole answer to down bytes: 16 KiB a message, the rest in the last."""
    down = min(max(down, 16384), 524288)
    total = -(-down // 16384)
    return [probe_data(nonce, i, total, 16384 if i < total - 1 else down - 16384 * (total - 1)) for i in range(total)]


def res_pq(nonce):
    body = struct.pack("<I", 0x05162463) + nonce + bytes(16) + tl_bytes(bytes(8)) + struct.pack("<II", 0x1cb5c415, 1) + bytes(8)
    return unencrypted(body)


class PathContractTest(unittest.TestCase):
    """The contract of the probe and the settings, as the sources hold them."""

    def test_constructors(self):
        # The constructors are the CRC32 of the TL lines, as the gateway takes
        # them; the same rule gives req_pq_multi its 0xbe7e8ef1.
        self.assertEqual(zlib.crc32(b"req_pq_multi nonce:int128 = ResPQ"), 0xbe7e8ef1)
        self.assertEqual(zlib.crc32(PROBE_LINE.encode()), 0x5c316d30)
        self.assertEqual(zlib.crc32(PROBE_DATA_LINE.encode()), 0x6ab3780b)
        for line in patch.PATH_CONTRACT_LINES:
            self.assertIn(line, patch.PATH_LOGIC_M_SOURCE)

    def test_reference_layout(self):
        # The vectors of the brief's contract, for the native checks below.
        request = probe_request(NONCE, 65536, b"", 0)
        self.assertEqual(request[20:].hex(), "306d315c000102030405060708090a0b0c0d0e0f0000010000000000")
        big = probe_request(NONCE, 65536, b"\0" * 20480, 0)
        self.assertEqual(big[20:48].hex()[-16:], "00000100fe005000")
        # 4 + 16 + 4 + the pad as TL bytes (4 + 20480), as the gateway parses it.
        self.assertEqual(struct.unpack("<I", big[16:20])[0], 20508)
        chunk = probe_data(NONCE, 0, 4, 16384)
        self.assertEqual((len(chunk), struct.unpack("<I", chunk[16:20])[0]), (16444, 16424))

    def test_settings(self):
        # The defaults agree in MtProtoKit, in TelegramCore and on the server;
        # the ranges of TelegramCore are the server's.
        built_in = patch.path_built_in_values(patch.PATH_LOGIC_M_SOURCE)
        for key, default, low, high, ratio in SERVER_FIELDS:
            self.assertEqual(float(built_in[key]), float(default), key)
            self.assertIn(f'Field(key: "{key}", builtIn: {built_in[key]}, min: {low}, max: {high}, ratio: {"true" if ratio else "false"})',
                          patch.PATH_PROBE_SWIFT_SOURCE)
        self.assertEqual(patch.PATH_PROBE_SWIFT_SOURCE.count("Field(key: "), len(SERVER_FIELDS))
        self.assertIn('if let data = appConfiguration.data, let value = data["pluma_probe"] as? [String: Any], ', patch.PATH_PATHS_SWIFT_SOURCE)

    def test_privacy(self):
        # The fingerprint of the network and its key never reach the log or the
        # server; the memory keeps the hash only.
        for source in (patch.EDGE_ROUTE_M_SOURCE, patch.PATH_PROBE_M_SOURCE, patch.PATH_LOGIC_M_SOURCE):
            for line in source.splitlines():
                if "MTLog(" in line:
                    self.assertNotRegex(line, r"_fingerprint|fingerprint|_key\b|\bkey\b|nonce|pad", line)
        self.assertNotRegex(patch.PATH_PATHS_SWIFT_SOURCE, r"\bprint\(|NSLog\(|Logger\.")
        self.assertIn("NSString *key = MTPathNetworkKey(_settings.country, _fingerprint);", patch.EDGE_ROUTE_M_SOURCE)
        # No probes through a proxy of the user's: the race is upstream's search
        # then, and the measurements go through a context without one.
        self.assertIn("context.apiEnvironment.socksProxySettings != nil || addressList.count == 0) {\n        return nil;", patch.EDGE_ROUTE_M_SOURCE)
        self.assertEqual(patch.EDGE_ROUTE_M_SOURCE.count("socksProxySettings == nil"), 2)

    def test_extensions_read_only(self):
        # Extensions and supplementary accounts read the memory, never write it or
        # measure; the app is the one that writes.
        self.assertIn("readOnly: supplementary || isAppExtension)", patch.PATH_NETWORK)
        route = patch.EDGE_ROUTE_M_SOURCE
        self.assertIn("    if (!_writable) {\n        return nil;\n    }\n", route)
        self.assertIn("    if (!_writable || _unsupported || _key == nil) {\n", route)
        self.assertEqual(route.count("writeToFile:"), 1)


def compilers():
    return sys.platform == "darwin" and shutil.which("xcrun") is not None


def run_tool(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise AssertionError(f"{args[0:3]}: {result.stdout}{result.stderr}")
    return result.stdout


@unittest.skipUnless(compilers(), "the pure rules are checked with the compilers of macOS")
class PathLogicTest(unittest.TestCase):
    """MTPathLogic.m, built with a harness that answers JSON cases."""

    HARNESS = r'''#import <Foundation/Foundation.h>
#import <math.h>

#import "MTPathLogic.h"

// The checks of MTPathLogic: a JSON list of cases in, a JSON list of answers out.

static NSData *Hex(NSString *hex) {
    NSMutableData *data = [[NSMutableData alloc] init];
    for (NSUInteger i = 0; i + 1 < hex.length; i += 2) {
        unsigned value = 0;
        [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&value];
        uint8_t byte = (uint8_t)value;
        [data appendBytes:&byte length:1];
    }
    return data;
}

static NSString *ToHex(NSData *data) {
    NSMutableString *hex = [[NSMutableString alloc] init];
    const uint8_t *bytes = data.bytes;
    for (NSUInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return hex;
}

static id Number(double value) {
    return isinf(value) || isnan(value) ? (id)[NSNull null] : @(value);
}

static id Run(NSArray *c, MTPathMemory *memory) {
    NSString *op = c[0];
    if ([op isEqualToString:@"message"]) {
        return ToHex(MTPathProbeMessage(Hex(c[1]).bytes, [c[2] intValue], Hex(c[3]), [c[4] longLongValue]));
    }
    if ([op isEqualToString:@"parse"]) {
        int32_t seq = -1, total = -1, padLength = -1;
        int rc = MTPathProbeDataParse(Hex(c[1]), Hex(c[2]).bytes, &seq, &total, &padLength);
        return @[@(rc), @(seq), @(total), @(padLength)];
    }
    if ([op isEqualToString:@"respq"]) {
        return @(MTPathIsResPQ(Hex(c[1]), Hex(c[2]).bytes));
    }
    if ([op isEqualToString:@"clamp"]) {
        return @[@(MTPathProbeClampedDown([c[1] intValue])), @(MTPathProbeTotal([c[1] intValue]))];
    }
    if ([op isEqualToString:@"tracker"]) {
        MTPathProbeTracker *tracker = [[MTPathProbeTracker alloc] initWithNonce:Hex(c[1]).bytes down:[c[2] intValue] stall:[c[3] doubleValue] deadline:[c[4] doubleValue] connectLimit:[c[5] doubleValue] startedAt:0.0];
        NSMutableArray *steps = [[NSMutableArray alloc] init];
        for (NSArray *event in c[6]) {
            NSString *kind = event[0];
            double t = [event[1] doubleValue];
            if ([kind isEqualToString:@"sent"]) {
                [tracker requestSentAt:t];
            } else if ([kind isEqualToString:@"written"]) {
                [tracker probeWrittenAt:t];
            } else if ([kind isEqualToString:@"bytes"]) {
                [tracker bytesAt:t];
            } else if ([kind isEqualToString:@"message"]) {
                [tracker message:Hex(event[2]) at:t];
            } else if ([kind isEqualToString:@"closed"]) {
                [tracker closedAt:t];
            } else if ([kind isEqualToString:@"check"]) {
                [tracker checkAt:t];
            }
            [steps addObject:@[@(tracker.finished), @(tracker.needsProbe)]];
        }
        return @{@"steps": steps, @"finished": @(tracker.finished), @"outcome": @(tracker.outcome), @"rtt": Number(tracker.rttMs), @"bps": Number(tracker.bytesPerSecond), @"received": @(tracker.receivedBytes), @"score": Number([tracker scoreMs])};
    }
    if ([op isEqualToString:@"score"]) {
        return Number(MTPathScoreMs([c[1] doubleValue], [c[2] doubleValue]));
    }
    if ([op isEqualToString:@"key"]) {
        return MTPathNetworkKey(c[1], c[2]);
    }
    if ([op isEqualToString:@"order"]) {
        return MTPathOrder(c[1], [c[2] boolValue]);
    }
    if ([op isEqualToString:@"tiers"]) {
        return MTPathRaceTiers(c[1], c[2] == [NSNull null] ? nil : c[2], [c[3] boolValue], [NSSet setWithArray:c[4]]);
    }
    if ([op isEqualToString:@"participants"]) {
        return MTPathRankParticipants(c[1], c[2] == [NSNull null] ? nil : c[2], [c[3] boolValue], [c[4] boolValue], c[5] == [NSNull null] ? NAN : [c[5] doubleValue], [c[6] doubleValue]);
    }
    if ([op isEqualToString:@"best"]) {
        NSString *best = MTPathBestOf(c[1], c[2]);
        return best != nil ? best : [NSNull null];
    }
    if ([op isEqualToString:@"decide"]) {
        MTPathSettings *settings = [[MTPathSettings alloc] initWithValues:c[8] country:@""];
        double current = c[1] == [NSNull null] ? INFINITY : [c[1] doubleValue];
        return @(MTPathDecideSwitch(current, [c[2] boolValue], [c[3] doubleValue], [c[4] boolValue], [c[5] doubleValue], [c[6] boolValue], [c[7] doubleValue], settings));
    }
    if ([op isEqualToString:@"settings"]) {
        MTPathSettings *s = [[MTPathSettings alloc] initWithValues:c[1] country:c[2]];
        return @[@(s.gateDown), @(s.rankDown), @(s.up), @(s.stall), @(s.deadline), @(s.suspect), @(s.reprobe), @(s.rankMinInterval), @(s.minDwell), @(s.switchRatio), @(s.switchRatioNow), @(s.edgeProbeIfDirectMs), @(s.badTtl), @(s.failedTtl), @(s.raceStagger), @(s.confirm), s.country];
    }
    if ([op isEqualToString:@"record"]) {
        [memory recordPath:c[1] key:c[2] outcome:[c[3] intValue] scoreMs:c[4] == [NSNull null] ? INFINITY : [c[4] doubleValue] rank:[c[5] boolValue] now:[c[6] doubleValue] badTtl:[c[7] doubleValue] failedTtl:[c[8] doubleValue]];
        return [NSNull null];
    }
    if ([op isEqualToString:@"setBest"]) {
        [memory setBest:c[1] forKey:c[2] now:[c[3] doubleValue]];
        return [NSNull null];
    }
    if ([op isEqualToString:@"bestFor"]) {
        NSString *best = [memory bestForKey:c[1] now:[c[2] doubleValue]];
        return best != nil ? best : [NSNull null];
    }
    if ([op isEqualToString:@"excluded"]) {
        return [[[memory excludedForKey:c[1] now:[c[2] doubleValue]] allObjects] sortedArrayUsingSelector:@selector(compare:)];
    }
    if ([op isEqualToString:@"scoreOf"]) {
        return Number([memory scoreOfPath:c[1] key:c[2]]);
    }
    if ([op isEqualToString:@"passed"]) {
        return @([memory passedPath:c[1] key:c[2]]);
    }
    if ([op isEqualToString:@"effective"]) {
        return Number([memory effectiveScore:[c[1] doubleValue] path:c[2] key:c[3]]);
    }
    if ([op isEqualToString:@"switched"]) {
        [memory setSwitchedForKey:c[1] now:[c[2] doubleValue]];
        return @[@([memory lastSwitchForKey:c[1]]), @([memory lastRankForKey:c[1]])];
    }
    if ([op isEqualToString:@"ranked"]) {
        [memory setRankedForKey:c[1] now:[c[2] doubleValue]];
        return @[@([memory lastSwitchForKey:c[1]]), @([memory lastRankForKey:c[1]])];
    }
    if ([op isEqualToString:@"dump"]) {
        return [memory dictionary];
    }
    return [NSString stringWithFormat:@"unknown case %@", op];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            return 2;
        }
        NSData *input = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]];
        NSArray *cases = [NSJSONSerialization JSONObjectWithData:input options:0 error:nil];
        NSMutableArray *answers = [[NSMutableArray alloc] init];
        MTPathMemory *memory = [[MTPathMemory alloc] initWithDictionary:nil];
        for (NSArray *c in cases) {
            if ([c[0] isEqualToString:@"load"]) {
                memory = [[MTPathMemory alloc] initWithDictionary:c[1] == [NSNull null] ? nil : c[1]];
                [answers addObject:[NSNull null]];
                continue;
            }
            [answers addObject:Run(c, memory)];
        }
        NSData *output = [NSJSONSerialization dataWithJSONObject:answers options:0 error:nil];
        fwrite(output.bytes, 1, output.length, stdout);
    }
    return 0;
}
'''

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        d = pathlib.Path(cls.dir.name)
        (d / "MTPathLogic.h").write_text(patch.PATH_LOGIC_H_SOURCE)
        (d / "MTPathLogic.m").write_text(patch.PATH_LOGIC_M_SOURCE)
        (d / "harness.m").write_text(cls.HARNESS)
        cls.binary = d / "harness"
        run_tool(["xcrun", "clang", "-fobjc-arc", "-Wall", "-Werror", "-framework", "Foundation", "-I", str(d),
                  "-o", str(cls.binary), str(d / "harness.m"), str(d / "MTPathLogic.m")])

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def ask(self, *cases):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(list(cases), f)
        try:
            return json.loads(run_tool([str(self.binary), f.name]))
        finally:
            os.unlink(f.name)

    def test_request(self):
        [empty, big, odd] = self.ask(["message", NONCE.hex(), 65536, "", 0],
                                     ["message", NONCE.hex(), 196608, "ab" * 20480, 0x6553_0000_0000_0004],
                                     ["message", NONCE.hex(), 16384, "cd" * 253, 8])
        self.assertEqual(bytes.fromhex(empty), probe_request(NONCE, 65536, b"", 0))
        self.assertEqual(bytes.fromhex(big), probe_request(NONCE, 196608, b"\xab" * 20480, 0x6553_0000_0000_0004))
        self.assertEqual(bytes.fromhex(odd), probe_request(NONCE, 16384, b"\xcd" * 253, 8))

    def test_answer(self):
        chunks = answer(NONCE, 65536 + 100)
        cases = [["parse", c.hex(), NONCE.hex()] for c in chunks]
        self.assertEqual(self.ask(*cases), [[1, 0, 5, 16384], [1, 1, 5, 16384], [1, 2, 5, 16384], [1, 3, 5, 16384], [1, 4, 5, 100]])
        good = chunks[0]
        padded = good + b"\0" * 12  # the padding of padded intermediate is not the object's
        longer = good[:16] + struct.pack("<I", 16428) + good[20:] + b"\0" * 4  # a byte inside the object too many
        short = good[:-4]
        other = res_pq(NONCE)
        self.assertEqual(self.ask(["parse", padded.hex(), NONCE.hex()], ["parse", good.hex(), OTHER_NONCE.hex()],
                                  ["parse", longer.hex(), NONCE.hex()], ["parse", short.hex(), NONCE.hex()],
                                  ["parse", other.hex(), NONCE.hex()])[:5],
                         [[1, 0, 5, 16384], [-1, -1, -1, -1], [-1, -1, -1, -1], [-1, -1, -1, -1], [0, -1, -1, -1]])
        self.assertEqual(self.ask(["respq", res_pq(NONCE).hex(), NONCE.hex()], ["respq", res_pq(OTHER_NONCE).hex(), NONCE.hex()],
                                  ["respq", res_pq(NONCE)[:80].hex(), NONCE.hex()]), [True, False, False])
        self.assertEqual(self.ask(["clamp", 1], ["clamp", 16385], ["clamp", 65536], ["clamp", 1 << 30]),
                         [[16384, 1], [16385, 2], [65536, 4], [524288, 32]])

    def tracker(self, events, down=65536, stall=1.5, deadline=6.0, connect=5.0, nonce=NONCE):
        cooked = []
        for e in events:
            if e[0] == "message":
                cooked.append(["message", e[1], e[2].hex()])
            else:
                cooked.append(list(e))
        [result] = self.ask(["tracker", nonce.hex(), down, stall, deadline, connect, cooked])
        return result

    def opening(self):
        return [("sent", 0.0), ("bytes", 0.1), ("message", 0.1, res_pq(NONCE)), ("written", 0.11)]

    def test_ok(self):
        chunks = answer(NONCE, 65536)
        events = self.opening() + [("bytes", 0.3 + i * 0.1) for i in range(1)]
        events += [("message", 0.3 + i * 0.1, c) for i, c in enumerate(chunks)]
        r = self.tracker(events)
        self.assertEqual((r["finished"], r["outcome"], r["received"]), (True, 0, 65536))
        self.assertAlmostEqual(r["rtt"], 100.0, places=6)
        # The bytes after the first message over the time to the last one.
        self.assertAlmostEqual(r["bps"], 3 * 16444 / 0.3, places=3)
        self.assertAlmostEqual(r["score"], 100.0 + 262144 / (3 * 16444 / 0.3) * 1000.0, places=3)
        # res_pq asks for the probe; nothing else does.
        self.assertEqual([s[1] for s in r["steps"]], [False, False, True, False, False, False, False, False, False])

    def test_frozen(self):
        chunks = answer(NONCE, 65536)
        # The answer stops after its first 16 KiB: 1.5 s of silence after the last byte.
        events = self.opening() + [("bytes", 0.3), ("message", 0.3, chunks[0]), ("check", 1.79)]
        self.assertFalse(self.tracker(events)["finished"])
        r = self.tracker(events + [("check", 1.81)])
        self.assertEqual((r["outcome"], r["received"]), (2, 16384))
        # A path that freezes on the upload answers not a byte: the stall counts from
        # the write of the probe plus the round trip.
        events = self.opening() + [("check", 1.70)]
        self.assertFalse(self.tracker(events)["finished"])
        self.assertEqual(self.tracker(events + [("check", 1.72)])["outcome"], 2)

    def test_slow(self):
        chunks = answer(NONCE, 65536)
        # The bytes never stop for 1.5 s, but not everything is there by the deadline.
        events = self.opening() + [("bytes", 1.0), ("bytes", 2.0), ("message", 2.0, chunks[0]), ("bytes", 3.0), ("bytes", 4.0),
                                   ("message", 4.0, chunks[1]), ("bytes", 5.0), ("bytes", 5.9), ("check", 6.10)]
        self.assertFalse(self.tracker(events)["finished"])
        r = self.tracker(events + [("check", 6.11)])
        self.assertEqual((r["outcome"], r["received"]), (1, 32768))
        self.assertAlmostEqual(r["bps"], 16444 / 2.0, places=3)

    def test_unsupported_and_failed(self):
        # A close after res_pq with not a byte of the answer: a gateway without
        # probes; the path is not judged.
        self.assertEqual(self.tracker(self.opening() + [("closed", 0.2)])["outcome"], 4)
        chunks = answer(NONCE, 65536)
        # A close after a part of the answer, before res_pq, or no res_pq in time.
        self.assertEqual(self.tracker(self.opening() + [("bytes", 0.3), ("message", 0.3, chunks[0]), ("closed", 0.4)])["outcome"], 3)
        self.assertEqual(self.tracker([("sent", 0.0), ("closed", 0.2)])["outcome"], 3)
        r = self.tracker([("sent", 0.0), ("check", 4.99)])
        self.assertFalse(r["finished"])
        self.assertEqual(self.tracker([("sent", 0.0), ("check", 5.0)])["outcome"], 3)
        # Wrong answers: another nonce, a seq out of order, another total, another
        # size, a message other than res_pq first, one before the probe is written.
        wrong = (answer(OTHER_NONCE, 65536)[0], chunks[1], answer(NONCE, 131072)[0], probe_data(NONCE, 0, 4, 100))
        for message in wrong:
            r = self.tracker(self.opening() + [("message", 0.3, message)])
            self.assertEqual((r["finished"], r["outcome"]), (True, 3), message[:40].hex())
        self.assertEqual(self.tracker([("sent", 0.0), ("message", 0.1, chunks[0])])["outcome"], 3)
        self.assertEqual(self.tracker([("sent", 0.0), ("message", 0.1, res_pq(NONCE)), ("message", 0.2, chunks[0])])["outcome"], 3)

    def test_score_and_key(self):
        a, b, c, d, e, f = self.ask(["score", 100, 262144], ["score", -1, 1000], ["score", 50, 0],
                                    ["key", "RU", "wifi|en0|192.168.1.1:0"], ["key", "DE", "wifi|en0|192.168.1.1:0"],
                                    ["key", "RU", "wifi|en0|192.168.1.1:0"])
        self.assertEqual((a, b, c), (1100.0, None, None))
        self.assertRegex(d, "^[0-9a-f]{32}$")
        self.assertNotEqual(d, e)
        self.assertEqual(d, f)
        self.assertNotIn("192.168", d)

    def test_order_and_tiers(self):
        paths = [DIRECT, E1, E2]
        answers = self.ask(
            ["order", paths, False], ["order", paths, True],
            # No memory: the first group of pluma_edge (the direct path, or the edges in Russia).
            ["tiers", paths, None, False, []], ["tiers", paths, None, True, []],
            # The remembered best path alone first.
            ["tiers", paths, E2, False, []],
            # An excluded path last; a remembered one that is excluded is no memory.
            ["tiers", paths, None, False, [DIRECT]], ["tiers", paths, E2, False, [E2]],
            ["tiers", [DIRECT], None, True, []])
        self.assertEqual(answers, [
            [DIRECT, E1, E2], [E1, E2, DIRECT],
            [[DIRECT], [E1, E2]], [[E1, E2], [DIRECT]],
            [[E2], [DIRECT, E1]],
            [[E1, E2], [DIRECT]], [[DIRECT], [E1], [E2]],
            [[DIRECT]]])

    def test_participants_and_best(self):
        paths = [DIRECT, E1, E2]
        answers = self.ask(
            # A good direct path outside Russia: the direct path and the one in use.
            ["participants", paths, E1, False, True, 800, 1500],
            ["participants", paths, None, False, True, 800, 1500],
            # The direct path is slow, failed or unknown, or the edges go first: all.
            ["participants", paths, None, False, True, 2000, 1500],
            ["participants", paths, None, False, False, None, 1500],
            ["participants", paths, DIRECT, True, True, 100, 1500],
            ["best", {DIRECT: 1000, E1: 900}, paths], ["best", {DIRECT: 2000, E1: 900}, paths],
            ["best", {DIRECT: 900, E1: 1100}, [E1, E2, DIRECT]], ["best", {}, paths],
            ["best", {E2: 500}, paths])
        self.assertEqual(answers, [[DIRECT, E1], [DIRECT], paths, paths, paths, DIRECT, E1, E1, None, E2])

    def test_decide(self):
        s = {}
        # (current, its pass, candidate, previous win, since the switch, transfer, waited)
        cases = [
            (None, False, 3000, False, 0, True, 0),     # the current path failed: at once
            (1000, True, 800, False, 3600, False, 0),   # 0.8: stay
            (1000, True, 500, False, 3600, False, 0),   # 0.5 once: measure again
            (1000, True, 500, True, 3600, False, 0),    # 0.5 twice: switch
            (1000, True, 500, True, 100, False, 0),     # within min_dwell_s
            (1000, True, 200, False, 3600, False, 0),   # 0.2 once: switch
            (1000, True, 200, False, 3600, True, 30),   # a transfer: wait
            (1000, True, 200, False, 3600, True, 120),  # at most two minutes
        ]
        answers = self.ask(*[["decide", c, p, n, w, t, x, y, s] for c, p, n, w, t, x, y in cases])
        self.assertEqual(answers, [2, 0, 1, 2, 3, 2, 4, 2])
        # The server's ratios and dwell.
        self.assertEqual(self.ask(["decide", 1000, True, 500, False, 3600, False, 0, {"switch_ratio_now": 0.6}],
                                  ["decide", 1000, True, 500, True, 30, False, 0, {"min_dwell_s": 0}]), [2, 2])

    def test_settings(self):
        [built_in, server] = self.ask(["settings", {}, ""], ["settings", {"gate_down": 32768, "stall_ms": 2000, "race_stagger_ms": 0}, "RU"])
        self.assertEqual(built_in, [65536, 196608, 20480, 1.5, 6.0, 4.0, 21600, 1800, 600, 0.7, 0.25, 1500, 86400, 300, 0.8, 60, ""])
        self.assertEqual((server[0], server[3], server[14], server[16]), (32768, 2.0, 0.0, "RU"))

    def test_memory(self):
        k, other = "k" * 32, "o" * 32
        day = 86400.0
        answers = self.ask(
            ["load", None],
            ["record", E1, k, 2, None, False, 1000, day, 300],      # frozen: out for a day
            ["record", DIRECT, k, 3, None, False, 1000, day, 300],  # failed: out for 5 min
            ["record", E2, k, 0, 900, False, 1000, day, 300],
            ["excluded", k, 1001], ["excluded", k, 1301], ["excluded", k, 1000 + day + 1],
            ["passed", E2, k], ["passed", E1, k], ["scoreOf", E2, k], ["scoreOf", E1, k],
            # A pass of a gate keeps a frozen path out; a pass of a measurement lets it in.
            ["record", E1, k, 0, 700, False, 2000, day, 300], ["excluded", k, 2001],
            ["record", E1, k, 1, 700, True, 2001, day, 300], ["excluded", k, 2002],
            # Two of the last four not ok: the score counts twice.
            ["effective", 700, E1, k], ["effective", 900, E2, k],
            ["record", E2, k, 0, 900, True, 3000, day, 300], ["record", E2, k, 0, 900, True, 3001, day, 300],
            ["record", E2, k, 0, 900, True, 3002, day, 300], ["effective", 900, E2, k],
            # An unsupported answer is not a result.
            ["record", DIRECT, k, 4, None, True, 3003, day, 300], ["passed", DIRECT, k],
            ["setBest", E2, k, 3004], ["bestFor", k, 3004 + 7 * day], ["bestFor", k, 3005 + 7 * day], ["bestFor", other, 3004],
            ["switched", k, 3006], ["ranked", k, 3007])
        self.assertEqual(answers[1:4], [None, None, None])
        self.assertEqual(answers[4:7], [[DIRECT, E1], [E1], []])
        self.assertEqual(answers[7:11], [True, False, 900, None])
        self.assertEqual(answers[12], [E1])
        self.assertEqual(answers[14], [])
        self.assertEqual(answers[15:17], [1400, 900])
        self.assertEqual(answers[20], 900)
        self.assertEqual(answers[22], False)
        self.assertEqual(answers[24:27], [E2, None, None])
        self.assertEqual(answers[27:29], [[3006, 0], [3006, 3007]])

    def test_memory_file(self):
        k = "k" * 32
        # What the file holds comes back as it was; a damaged file is read as far as it
        # goes, and the rest is dropped.
        [_, _, _, dump, _, best, score, dump2] = self.ask(
            ["load", None], ["record", E1, k, 0, 800, True, 10, 86400, 300], ["setBest", E1, k, 11], ["dump"],
            ["load", {"v": 1, "networks": {k: {"t": 11, "best": E1, "paths": {E1: {"score": 800, "outcome": 0, "at": 10, "history": 0, "count": 1, "bad": 0, "failed": 0}}},
                                         "bad": "x", "worse": {"paths": [1, 2]}}}],
            ["bestFor", k, 12], ["scoreOf", E1, k], ["dump"])
        self.assertEqual(dump["v"], 1)
        self.assertEqual(dump["networks"][k]["best"], E1)
        self.assertEqual((best, score), (E1, 800))
        self.assertEqual(sorted(dump2["networks"]), [k, "worse"])
        self.assertEqual(dump2["networks"]["worse"]["paths"], {})
        # At most 16 networks, the least recently written goes.
        cases = [["load", None]] + [["setBest", DIRECT, f"{i:032x}", 100 + i] for i in range(17)] + [["dump"]]
        networks = self.ask(*cases)[-1]["networks"]
        self.assertEqual(len(networks), 16)
        self.assertNotIn(f"{0:032x}", networks)
        self.assertIn(f"{16:032x}", networks)


@unittest.skipUnless(compilers(), "the pure rules are checked with the compilers of macOS")
class PathConfigurationTest(unittest.TestCase):
    """pluma_probe as PlumaProbe.swift reads it."""

    MAIN = r'''import Foundation

// The checks of PlumaProbe.swift: a JSON list of cases in, a JSON list of answers out.
let input = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
guard let cases = try JSONSerialization.jsonObject(with: input) as? [[Any]] else {
    exit(2)
}
var answers: [Any] = []
for c in cases {
    switch c[0] as? String {
    case "probe":
        if let value = c[1] as? [String: Any], let configuration = PlumaProbeConfiguration(value: value) {
            answers.append(["country": configuration.country, "values": configuration.values])
        } else {
            answers.append(NSNull())
        }
    case "builtIn":
        answers.append(["country": PlumaProbeConfiguration.builtIn.country, "values": PlumaProbeConfiguration.builtIn.values])
    case "country":
        answers.append(plumaProbeCountryIsValid(c[1] as? String ?? "?"))
    case "fingerprint":
        answers.append(plumaNetworkFingerprint(kind: c[1] as? String ?? "", interface: c[2] as? String ?? "", gateways: c[3] as? [String] ?? []))
    default:
        answers.append("unknown case")
    }
}
FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: answers))
'''

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        d = pathlib.Path(cls.dir.name)
        (d / "PlumaProbe.swift").write_text(patch.PATH_PROBE_SWIFT_SOURCE)
        (d / "main.swift").write_text(cls.MAIN)
        cls.binary = d / "harness"
        run_tool(["xcrun", "swiftc", "-swift-version", "5", "-warnings-as-errors", "-o", str(cls.binary),
                  str(d / "PlumaProbe.swift"), str(d / "main.swift")])

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def ask(self, *cases):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(list(cases), f)
        try:
            return json.loads(run_tool([str(self.binary), f.name]))
        finally:
            os.unlink(f.name)

    def server_value(self, **over):
        value = {"v": 1, "country": "RU"}
        value.update({key: default for key, default, _, _, _ in SERVER_FIELDS})
        value.update(over)
        return value

    def test_values(self):
        [built_in, full, partial] = self.ask(["builtIn"], ["probe", self.server_value(gate_down=32768, switch_ratio=0.5)],
                                             ["probe", {"v": 1, "country": ""}])
        defaults = {key: float(default) for key, default, _, _, _ in SERVER_FIELDS}
        self.assertEqual(built_in, {"country": "", "values": defaults})
        self.assertEqual(full["country"], "RU")
        self.assertEqual(full["values"], dict(defaults, gate_down=32768.0, switch_ratio=0.5))
        self.assertEqual(partial, {"country": "", "values": defaults})

    def test_rejects(self):
        cases = [self.server_value(v=2), self.server_value(country="ru"), self.server_value(country="RUS"),
                 self.server_value(country=7), {"country": "RU"}]
        for key, _, low, high, ratio in SERVER_FIELDS:
            cases.append(self.server_value(**{key: high * 2 + 1}))
            if low > 0:
                cases.append(self.server_value(**{key: low / 2}))
            if not ratio:
                cases.append(self.server_value(**{key: low + 0.5}))
            cases.append(self.server_value(**{key: "1"}))
        cases.append(self.server_value(stall_ms=6000, deadline_ms=6000))
        cases.append(self.server_value(switch_ratio=0.5, switch_ratio_now=0.5))
        answers = self.ask(*[["probe", c] for c in cases])
        for c, a in zip(cases, answers):
            self.assertIsNone(a, c)
        # The edges of the ranges are in.
        # (Not where the other field of a pair would be crossed: a deadline at 1 s is
        # below the stall of 1.5 s, a switch_ratio of 0.05 below switch_ratio_now.)
        edges = [self.server_value(**{key: low}) for key, _, low, _, _ in SERVER_FIELDS if key not in ("deadline_ms", "switch_ratio")]
        edges += [self.server_value(**{key: high}) for key, _, _, high, _ in SERVER_FIELDS if key not in ("stall_ms", "switch_ratio_now")]
        for c, a in zip(edges, self.ask(*[["probe", c] for c in edges])):
            self.assertIsNotNone(a, c)

    def test_fingerprint(self):
        self.assertEqual(self.ask(["fingerprint", "wifi", "en0", ["192.168.1.1:0", "10.0.0.1:0"]], ["fingerprint", "cellular", "pdp_ip0", []],
                                  ["country", ""], ["country", "DE"], ["country", "De"], ["country", "DEU"]),
                         ["wifi|en0|10.0.0.1:0,192.168.1.1:0", "cellular|pdp_ip0|", True, True, False, False])


@unittest.skipIf(not os.environ.get("CI") and upstream_files() is None,
                 "no checkout of the pinned upstream (ci/fetch-upstream.sh sparse)")
class PathsTest(unittest.TestCase):
    """The paths (task 113) on the commit upstream.env pins."""

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

    def damaged(self, rel, old, new):
        """The patched tree with old replaced by new in rel: verify must stop."""
        self.tearDown()
        tree, c = self.run_patch()
        text = tree.read(rel)
        self.assertEqual(text.count(old), 1, (rel, old[:60]))
        tree.write(rel, text.replace(old, new))
        with self.assertRaises(patch.PatchError) as e:
            patch.verify(tree, c)
        self.assertIn(pathlib.PurePath(rel).name, str(e.exception))

    def test_paths(self):
        tree, _ = self.run_patch()
        for rel, text in patch.path_files():
            self.assertEqual(tree.read(rel), text)
            self.assertNotIn(rel, self.files)
        for rel, _, new in patch.PATH_EDITS:
            self.assertEqual(tree.read(rel).count(new), 1, rel)
        net = tree.read(NETWORK)
        self.assertIn('            context.attachPathSelection(storagePath: (basePath as NSString).deletingLastPathComponent + "/pluma-paths.json", '
                      "readOnly: supplementary || isAppExtension)\n", net)
        # After the seed with the edges, before anything connects.
        self.assertLess(net.index("plumaEdge.addresses))"), net.index("context.attachPathSelection("))
        self.assertLess(net.index("context.attachPathSelection("), net.index("let network = Network(queue: queue"))
        account = tree.read(ACCOUNT)
        self.assertIn("            return updateAppConfigurationOnce(postbox: postbox, network: network)\n", account)
        # The search for an address goes through the race before upstream's rounds.
        discover = tree.read(patch.EDGE_DISCOVER_M)
        self.assertLess(discover.index("MTSignal *pathSignal = "), discover.index("NSMutableArray *bestTcp4Signals"))

    def test_no_paths(self):
        tree, c = self.run_patch(edge_urls="")
        for rel, _ in patch.path_files():
            self.assertFalse((self.root / rel).exists(), rel)
        for rel, _, new in patch.PATH_EDITS:
            self.assertNotIn(new, tree.read(rel))
        tree.write(patch.PATH_LOGIC_M, patch.PATH_LOGIC_M_SOURCE)
        with self.assertRaisesRegex(patch.PatchError, "MTPathLogic.m: a file of the paths"):
            patch.verify(tree, c)

    def test_file_already_there(self):
        for rel, _ in patch.path_files():
            with self.subTest(rel=rel):
                self.tearDown()
                self.written.add(rel)
                (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
                (self.root / rel).write_text("")
                with self.assertRaisesRegex(patch.PatchError, "already exists"):
                    self.run_patch()

    def test_upstream_changed(self):
        # The text of an edit on upstream's own lines changed: the patch stops with
        # the file's name.
        for i, (rel, old, _) in enumerate(patch.PATH_EDITS):
            text = self.files[rel].decode("utf-8")
            if text.count(old) != 1:
                continue  # an edit on what the patch itself wrote before (Network.swift, Account.swift)
            with self.subTest(edit=i, rel=rel):
                self.tearDown()
                end = len(old.rstrip()) - 1
                self.written.add(rel)
                (self.root / rel).write_text(text.replace(old, old[:end] + "#" + old[end:]), encoding="utf-8")
                with self.assertRaises(patch.PatchError) as e:
                    self.run_patch()
                self.assertIn(pathlib.PurePath(rel).name, str(e.exception))

    def test_paths_are_verified(self):
        for i, (rel, old, new) in enumerate(patch.PATH_EDITS):
            with self.subTest(edit=i, rel=rel):
                self.damaged(rel, new, old)
        for rel, _ in patch.path_files():
            with self.subTest(file=rel):
                self.tearDown()
                tree, c = self.run_patch()
                tree.write(rel, tree.read(rel) + "\n")
                with self.assertRaises(patch.PatchError) as e:
                    patch.verify(tree, c)
                self.assertIn(pathlib.PurePath(rel).name, str(e.exception))
        with self.subTest("a probe elsewhere"):
            self.damaged(patch.EDGE_TRANSPORT_M, "- (void)reset\n{\n",
                         "- (void)reset\n{\n    [MTPathProbe probeWithContext:_context datacenterId:1 address:nil down:0 up:0 stall:0 deadline:0];\n")
        with self.subTest("silence unwatched"):
            self.damaged(patch.EDGE_TRANSPORT_M, "plumaWatchesSilence = true", "plumaWatchesSilence = false")
        with self.subTest("a second race"):
            self.damaged(patch.EDGE_DISCOVER_M, "    if (pathSignal != nil) {\n",
                         "    pathSignal = [[MTEdgeRoute shared] discoverSchemeWithContext:context datacenterId:datacenterId addressList:bestAddressList "
                         "alternatePorts:alternatePorts media:media];\n    if (pathSignal != nil) {\n")
        with self.subTest("another constructor"):
            self.damaged(patch.PATH_LOGIC_M, "= 0x5c316d30;", "= 0x5c316d31;")
        with self.subTest("defaults apart"):
            self.damaged(patch.PATH_PROBE_SWIFT, 'Field(key: "stall_ms", builtIn: 1500,', 'Field(key: "stall_ms", builtIn: 1000,')

    @unittest.skipUnless(compilers(), "compiled with the compilers of macOS")
    def test_compiles(self):
        # What the build compiles with -Werror, for the oldest systems of the app.
        self.run_patch()
        mt = self.root / "submodules/MtProtoKit"
        headers = self.root / patch.MT_DEPENDENCY_HEADERS
        sources = [patch.PATH_LOGIC_M, patch.PATH_PROBE_M, patch.EDGE_ROUTE_M, patch.EDGE_CONTEXT_M, patch.EDGE_CONNECTION_M,
                   patch.EDGE_TRANSPORT_M, patch.EDGE_DISCOVER_M]
        for sdk, target in (("iphoneos", "arm64-apple-ios15.0"), ("macosx", "arm64-apple-macos10.13")):
            for rel in sources:
                with self.subTest(sdk=sdk, rel=rel):
                    run_tool(["xcrun", "--sdk", sdk, "clang", "-fsyntax-only", "-fobjc-arc", "-fmodules", "-Wall", "-Werror",
                              "-target", target, "-I", str(mt / "PublicHeaders"), "-I", str(mt / "Sources"), "-I", str(headers),
                              str(self.root / rel)])


if __name__ == "__main__":
    unittest.main()
