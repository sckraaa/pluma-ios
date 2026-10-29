# Pluma for iOS

Builds of the official Telegram iOS app ([TelegramMessenger/Telegram-iOS](https://github.com/TelegramMessenger/Telegram-iOS)) for a [Pluma](https://github.com/sckraaa/pluma) server, a self-hosted Telegram-compatible server: Telegram-iOS patched for Pluma. This project is not affiliated with Telegram.

The repository holds no copy of the app's code. CI fetches the upstream release pinned in [`upstream.env`](upstream.env) (tag `release-12.9.2`, MTProto layer 228), patches it with [`ci/patch.py`](ci/patch.py) and builds it with Telegram-iOS's own `Make.py` (Bazel). Every edit must match the upstream source exactly. If an update moves any of the edited places, the build fails; it never quietly produces a client that talks to Telegram.

## What the patch changes

- **Datacenter.** MtProtoKit gets a single datacenter, DC 1: the Pluma server (IPv4 address, optional IPv6 address, port). It is used for both the production and the test backend. A fresh install starts on it, and it is the only datacenter the client makes keys for ahead.
- **Server key.** The server's RSA key replaces Telegram's production and test keys; MtProtoKit picks the key by the fingerprint the server announces. Telegram's key for its backup address records is replaced too, so no key of Telegram's is left in the client.
- **Backup addresses.** The client does not look up backup addresses: no DNS-over-HTTPS queries at Google for Telegram's records, no CloudKit records. The library call returns nothing as well. Proxy host names resolve through the system resolver, not through Google's DNS-over-HTTPS.
- **Calls.** No extra TCP reflector of Telegram's is added to calls of the 12.0.0 protocol.
- **App identity.** It goes into the build configuration of `Make.py` (`--configurationPath`), which the patch writes from [`config/app.env`](config/app.env):
  - the bundle ID is `chat.pluma.app`, the extensions are `chat.pluma.app.<name>`, the App Group is `group.chat.pluma.app`;
  - Pluma's `api_id` (10002) and `api_hash`, and the Team ID that signs the app;
  - a public build, as from the App Store: no internal debug features, no App Center, no in-app purchases;
  - no iCloud and no Siri, which need capabilities of their own.

  The name under the icon and in the share sheet is "Pluma". The app registers the `plm://` scheme instead of Telegram's `tg://` ([Branding](#branding)). These are edits of `Telegram/BUILD`.
- **Branding.** Pluma's icons, logos, name, link scheme and colours instead of Telegram's: see [Branding](#branding).
- **Build flags.** The upstream `.bazelrc` imports `pluma.bazelrc`, which [`ci/build.sh`](ci/build.sh) writes: the cache locations, and no provisioning profiles for a simulator build.

After the edits, the result is checked again. MtProtoKit, TelegramCore and TelegramVoip may hold no address in Telegram's published ranges, and their only RSA keys must be the server's. The check also covers the layer (`currentLayer()` is 228), the versions of `versions.json`, and the `Make.py` options and targets the build relies on.

What the patch leaves, and why:
- **Links** to `t.me`, `telegram.org` and `fragment.com` in the interface: share links, the terms, the privacy policy. There are about 120 of them in the code and 54 in the strings, and each opens only when tapped. The rebranding leaves URLs as they are.
- **The reflector benchmark** of TelegramUI's `AppDelegate` measures a call server of Telegram's. It runs only in internal builds or behind a hidden debug switch; this is a public build.
- **Connection probing.** MtProtoKit pings `google.com` or `8.8.8.8` (ICMP) when a proxy the user set up stops answering.
- **Translation and app icons.** Translation through Google, and app icons from the App Store in "Open in…", load only when the user asks.

## Branding

The app looks like Pluma, not like Telegram. The brand kit of the server repository (task 017: the logo and the palette "graphite and sage") is the source; the patch applies it:

- **Icons and logos.** [`brand/render.sh`](brand/render.sh) renders the images from the kit's SVGs ([`brand/pluma-icon-square.svg`](brand/pluma-icon-square.svg), [`brand/pluma-mark.svg`](brand/pluma-mark.svg), [`brand/pluma-mark-mono.svg`](brand/pluma-mark-mono.svg)) into [`brand/ios`](brand/ios), each under the upstream path of the file it replaces. The patch checks each upstream file by its SHA-256 and copies Pluma's over it:
  - the app icon (Icon Composer, `Telegram.icon`): the mark on white, a light mark on graphite in the dark appearance, and the tinted and clear ones iOS 26 derives;
  - the alternate icon `BlueIcon`, which the app counts as its default one. The other alternate icons are Telegram's: the bundle no longer carries them, and the icon picker shows Pluma's only;
  - the home screen quick action, the context menu item, the call screen title and CallKit;
  - the QR code logos and their animations ([`brand/tgs.py`](brand/tgs.py) writes the mark as a still Lottie);
  - the first page of the intro (the mark on a white disc, no paper plane); the pages "Powerful" and "Cloud-Based" are sage instead of blue.
- **Name.** "Telegram" becomes "Pluma" wherever the user reads it: the built-in English strings (556 entries, feature names included, such as "Pluma Premium"; string keys, URLs and user names stay), the permission prompts in every language (in Arabic, Persian and Korean script too, and the name under the icon in Arabic and Korean), the Photos album, CallKit, the locked widget, the label of the app's entry in address book contacts.
- **Link scheme.** The app registers `plm://`, not `tg://`, which stays with Telegram installed on the same phone. The links it makes use `plm://`, the QR code of a sign-in on another device among them; its scanner takes `plm://` codes only, so a sign-in by QR code works between Pluma clients. `tg://` links inside the app (messages, bots) still open in it.
- **Colours.** Day Classic and Night, the themes of a fresh install, take the palette: sage accents (`#5B7A5E` light, `#9DBB9F` dark), sage links, bubbles, time and checks, a white or graphite chat background instead of Telegram's pattern. The first accent the theme settings offer is sage. The other built-in themes ("Day", "Night Tinted") and the other accents stay as they are.
- **Settings.** The support section ("Ask a Question", the FAQ, "Pluma Features") leads only to Telegram's services and is gone.

Every edit is exact, as the rest of the patch: the counts of the pinned commit are part of it (the strings, the colours, the links), and an upstream update that moves any of them stops the patch.

To change an image, edit the SVG and re-render; this needs rsvg-convert (librsvg), ImageMagick 7 and Python 3, and writes the same bytes on a re-run:

```sh
brand/render.sh                      # brand/ios
python3 -m unittest discover -s ci -p '*_test.py'
```

A new or renamed file in `brand/ios` needs its entry in `BRAND_REPLACED` or `BRAND_ADDED` of [`ci/patch.py`](ci/patch.py); the tests compare the two.

## Configuration

Set these in the repository's *Settings → Secrets and variables → Actions → Variables*:

| Variable | |
|---|---|
| `PLUMA_SERVER_IPV4` | The server's IPv4 address. MtProtoKit takes an address, not a host name. |
| `PLUMA_SERVER_PORT` | The port of the server's MTProto gateway (gnetway). |
| `PLUMA_SERVER_IPV6` | Optional. The server's IPv6 address. |
| `PLUMA_RSA_PUBLIC_KEY` | The server key as a PKCS#1 PEM: `openssl rsa -in server_pkcs1.key -RSAPublicKey_out` |
| `PLUMA_TEAM_ID` | The Apple Team ID (10 characters, *Membership details* in the Apple Developer account). Setting it turns on signed builds. |
| `PLUMA_AGE_RECIPIENT` | The owner's [age](https://age-encryption.org) public key (`age1...`); see [Signing](#signing). |
| `PLUMA_BAZEL_CACHE_GB` | Optional. The size the Bazel disk cache is trimmed to before it is saved, in GB; 12 by default (a full simulator cache is about 9 GB, about 3 GB compressed in the Actions cache). |

None of these values is a secret: every IPA carries them. The server variables have the same names as in `pluma-android`.

- **No `PLUMA_TEAM_ID`.** CI builds only the simulator app for the development server.
- **`PLUMA_TEAM_ID` set.** The check job also patches for the server variables, and a push to `main` builds the signed IPA. Missing server variables fail the check job within seconds.

## Development build (simulator)

Every run builds the simulator app for the development server of [`config/dev`](config/dev): `127.0.0.1:10443` with the development key. The iOS Simulator shares the Mac's network, so it reaches a server stack that runs on the same Mac. The app is built for arm64 simulators (a Mac with Apple Silicon), in the `Make.py` configuration `PLUMA_SIM_CONFIGURATION` of `config/app.env` (`debug_sim_arm64`). It is not code signed, carries no secret, and stays plain in the `simulator` artifact of the run for seven days.

1. In the server repository, start the stack with the development key and the gateway on port 10443, and allow a phone number:
   ```sh
   E2E_SERVER_KEY=~/pluma-dev-secrets/server_pkcs1.key E2E_GATEWAY_PORT=10443 test/e2e/run.sh up
   test/e2e/run.sh admin allowlist add +79990000001
   ```
2. Install the app on a booted simulator (Xcode 26) and start it:
   ```sh
   gh run download <run id> -R sckraaa/pluma-ios -n simulator
   unzip pluma-ios-*-simulator.zip
   xcrun simctl boot "iPhone 17"      # or any iPhone simulator
   xcrun simctl install booted Pluma.app
   xcrun simctl launch booted chat.pluma.app
   ```
3. Sign in with the number. Get the code with `test/e2e/run.sh admin login-code +79990000001`.
4. Take the stack down with `test/e2e/run.sh down`.

## Signing

The IPA is signed inside the build, with ad hoc profiles: it installs on the registered devices only, up to 100 iPhones per membership year. The `preflight-sign` job checks the signing material first, in the protected `release` environment, and a bad certificate or profile fails it within a minute. It requires the following:
- the certificate is an Apple Distribution certificate of the team, valid for at least 14 more days, and the key in the `.p12` is its key;
- there is one ad hoc profile for each of the seven App IDs below, of the team, valid for at least 14 more days, and holding that certificate;
- every profile has the App Group, and the app's profile has push (`aps-environment` = `production`);
- all profiles list the same devices.

The `build-ipa` job checks again on its runner, puts the identity into a temporary keychain and builds.

### In the Apple Developer account

In *Certificates, Identifiers & Profiles*:

1. **App Group.** *Identifiers → App Groups*: `group.chat.pluma.app`.
2. **App IDs.** *Identifiers → App IDs*, explicit, one for each target:

   | App ID | Capabilities | Secret of its profile |
   |---|---|---|
   | `chat.pluma.app` | App Groups (`group.chat.pluma.app`), Push Notifications | `PLUMA_PROFILE_MAIN` |
   | `chat.pluma.app.Share` | App Groups | `PLUMA_PROFILE_SHARE` |
   | `chat.pluma.app.NotificationService` | App Groups | `PLUMA_PROFILE_NOTIFICATION_SERVICE` |
   | `chat.pluma.app.NotificationContent` | App Groups | `PLUMA_PROFILE_NOTIFICATION_CONTENT` |
   | `chat.pluma.app.Widget` | App Groups | `PLUMA_PROFILE_WIDGET` |
   | `chat.pluma.app.SiriIntents` | App Groups | `PLUMA_PROFILE_SIRI_INTENTS` |
   | `chat.pluma.app.BroadcastUpload` | App Groups | `PLUMA_PROFILE_BROADCAST_UPLOAD` |

   No other capability is needed: the build asks for no iCloud, Siri, Associated Domains, Sign in with Apple, Apple Pay or CarPlay. The notification service extension reads the account keys from the App Group to decrypt pushes.
3. **Certificate.** *Certificates → Apple Distribution*. Install it on a Mac, then export it with its private key from Keychain Access as `pluma-distribution.p12`, with a password.
4. **Devices.** *Devices*: register the UDID of every iPhone that will run the app.
5. **Profiles.** *Profiles → Ad Hoc*: one profile for each App ID of step 2, each with the certificate of step 3 and all the devices of step 4. After adding a device, regenerate all seven and replace the secrets.

The APNs key of task 009 stays on the server and is not part of the build.

### In GitHub

1. Create the age key once and back it up off-line. The key of `pluma-android` works too.
   ```sh
   age-keygen -o pluma-ipa.agekey        # prints the public key, age1...
   gh variable set PLUMA_AGE_RECIPIENT -R sckraaa/pluma-ios --body age1...
   ```
2. Create the environment in *Settings → Environments → New environment*, named `release`:
   - *Required reviewers*: yourself;
   - *Deployment branches and tags*: `main` only.
3. Add the secrets to the environment:
   ```sh
   base64 -i pluma-distribution.p12 | gh secret set PLUMA_DIST_P12_B64 -R sckraaa/pluma-ios --env release
   gh secret set PLUMA_DIST_P12_PASSWORD -R sckraaa/pluma-ios --env release
   profile() { base64 -i "$2" | gh secret set "PLUMA_PROFILE_$1" -R sckraaa/pluma-ios --env release; }
   profile MAIN Pluma_Ad_Hoc.mobileprovision                 # the file names are whatever you saved
   profile SHARE Pluma_Share_Ad_Hoc.mobileprovision
   profile NOTIFICATION_SERVICE Pluma_NotificationService_Ad_Hoc.mobileprovision
   profile NOTIFICATION_CONTENT Pluma_NotificationContent_Ad_Hoc.mobileprovision
   profile WIDGET Pluma_Widget_Ad_Hoc.mobileprovision
   profile SIRI_INTENTS Pluma_SiriIntents_Ad_Hoc.mobileprovision
   profile BROADCAST_UPLOAD Pluma_BroadcastUpload_Ad_Hoc.mobileprovision
   ```
4. Set the server variables and, last, `PLUMA_TEAM_ID` ([Configuration](#configuration)).

A release waits for your approval twice: for `preflight-sign`, and a minute later for `build-ipa`. The IPA is the `pluma-ios` artifact of the run, kept for 30 days:

```sh
gh run download <run id> -R sckraaa/pluma-ios -n pluma-ios
for f in pluma-ios-*.ipa.age; do age -d -i pluma-ipa.agekey -o "${f%.age}" "$f"; done
shasum -a 256 -c pluma-ios-*.ipa.sha256
```

Install it with Apple Configurator or Finder on a registered device. Publishing to the server for installation over the air is a later step.

A signing failure after a good preflight (say, a keychain problem) is fixed with *Re-run failed jobs*. The compiled code is in the cache, so the build mostly repeats the signing.

## When it builds

| Trigger | Simulator app | Signed IPA |
|---|---|---|
| Push to `main` | yes, artifact `simulator` (7 days) | yes, if `PLUMA_TEAM_ID` is set |
| Manual run (*Actions → ios → Run workflow*) | yes | yes, if `PLUMA_TEAM_ID` is set and *ipa* is ticked |
| Pull request | yes, no artifact | no |
| Weekly canary | the pinned upstream on a fresh runner image | no |

The jobs run on GitHub's `macos-26` runners with Xcode 26.2 selected explicitly, the version `versions.json` asks for. The setup removes the image's other Xcode versions when the disk is short, and downloads the Metal toolchain when it is missing.

The Bazel disk cache and Bazel's downloads are kept in the GitHub Actions cache, one entry for the simulator app and one for the IPA:
- the entry is saved even when a build fails, so a re-run continues from where it stopped;
- before saving, the disk cache is trimmed to 12 GB (`PLUMA_BAZEL_CACHE_GB`), least recently used entries first;
- older entries of each kind are deleted after the run, so the two kinds fit in the repository's 10 GB together;
- a build takes only the entry of the same patch, configuration and upstream (`upstream.env`, `config/`, `ci/patch.py`), to continue after a failure. A change of any of them builds from an empty cache: on 2026-10-29 a build that started from the cache of the previous patch kept the old code of a module the patch had changed (`AvatarNode`, Saved Messages colours), and a cold build had the new one.

A cold build, and so any change of the patch, takes about an hour. A repeat build without changes takes minutes. An edit of TelegramCore or MtProtoKit, which most of the app depends on, compiles nearly everything again.

Since the repository is public, set *Settings → Actions → General → Fork pull request workflows* to require approval for all outside collaborators.

## Local build

The checks need Python 3, openssl and git, on any system:

```sh
ci/fetch-upstream.sh sparse          # ./upstream, only the files the patch reads
python3 -m unittest discover -s ci -p '*_test.py'
ci/configure.sh dev
```

A build needs a Mac with Xcode 26.2 and several tens of GB free:

```sh
ci/fetch-upstream.sh full            # ./upstream with all submodules
ci/configure.sh dev                  # the development server; set SERVER_IPV4, SERVER_PORT, RSA_PUBLIC_KEY, TEAM_ID and use server for another
ci/build.sh sim                      # out/pluma-ios-<version>-1-simulator.zip
```

## Updating the upstream

1. Change `upstream.env`: the tag and its commit, the version, the layer, and the Xcode and Bazel versions of its `versions.json`. The layer must be one the server speaks.
2. Run `ci/fetch-upstream.sh sparse` and the tests.
3. Push. Where the upstream moved something, `ci/patch.py` names the file and the text it expected.

## License

Telegram publishes the app under the GNU GPL v2 or later ([telegram.org/apps](https://telegram.org/apps)). The scripts of this repository are under the GPL v2 as well ([LICENSE](LICENSE)). A build is GPL software too: its source is the pinned upstream commit together with this repository's patch.
