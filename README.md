# Pluma for iOS

Builds of the official Telegram iOS app ([TelegramMessenger/Telegram-iOS](https://github.com/TelegramMessenger/Telegram-iOS)) for a [Pluma](https://github.com/sckraaa/pluma) server, a self-hosted Telegram-compatible server: Telegram-iOS patched for Pluma. This project is not affiliated with Telegram.

The repository holds no copy of the app's code. CI fetches the upstream release pinned in [`upstream.env`](upstream.env) (tag `release-13.2`, MTProto layer 233), patches it with [`ci/patch.py`](ci/patch.py) and builds it with Telegram-iOS's own `Make.py` (Bazel). Every edit must match the upstream source exactly. If an update moves any of the edited places, the build fails; it never quietly produces a client that talks to Telegram.

## What the patch changes

- **Datacenter.** MtProtoKit gets a single datacenter, DC 1: the Pluma server (IPv4 address, optional IPv6 address, port). It is used for both the production and the test backend. A fresh install starts on it, and it is the only datacenter the client makes keys for ahead.
- **Server key.** The server's RSA key replaces Telegram's production and test keys; MtProtoKit picks the key by the fingerprint the server announces. Telegram's key for its backup address records is replaced too, so no key of Telegram's is left in the client.
- **Backup addresses.** The client does not look up backup addresses: no DNS-over-HTTPS queries at Google for Telegram's records, no CloudKit records. The library call returns nothing as well. Proxy host names resolve through the system resolver, not through Google's DNS-over-HTTPS.
- **App identity.** It goes into the build configuration of `Make.py` (`--configurationPath`), which the patch writes from [`config/app.env`](config/app.env):
  - the bundle ID is `chat.pluma.app`, the extensions are `chat.pluma.app.<name>`, the App Group is `group.chat.pluma.app`;
  - Pluma's `api_id` (10002) and `api_hash`, and the Team ID that signs the app;
  - a public build, as from the App Store: no internal debug features, no App Center, no in-app purchases;
  - no iCloud and no Siri, which need capabilities of their own.

  The name under the icon and in the share sheet is "Pluma". The app registers the `plm://` scheme instead of Telegram's `tg://` ([Branding](#branding)). These are edits of `Telegram/BUILD`.
- **Branding.** Pluma's icons, logos, name, link scheme and colours instead of Telegram's: see [Branding](#branding).
- **Birthdays.** The notice at the top of the chat list about contacts whose birthday is today offers to gift them Premium, which Pluma does not sell. It shows whenever Telegram's app shows it (the birthdays come from the server's `contacts.getBirthdays`), but:
  - its second line says "Send Message" (`ContactList.Context.SendMessage`) instead of "Gift them Pluma Premium.";
  - a tap opens the chat with the contact; with several contacts, it lists them in an action sheet, as the live location panel above the chat list lists its chats, and opens the chat of the one chosen. The list is in the order of their names, the same on every launch (the notice's own order may change);
  - its close button dismisses it as before (`help.dismissSuggestion` with `BIRTHDAY_CONTACTS_TODAY`), but without the toast that sends the user to Settings to gift Premium: with Premium purchases blocked (`premium_purchase_blocked`) and no Stars, Settings offer no gifts.
  - the birthday row of the contact's profile, two taps away, offers a gift (by a tap and by its gift icon) only while Premium can be bought, as the chat already does.
- **Read date.** The context menu of an outgoing message in a private chat shows when it was read, as the Android app does. Telegram's app shows it to a user without Premium only where Premium is sold, so with `premium_purchase_blocked` the row was gone. Where the peer hides it, the row says "Read" without the badge that opens Premium's privacy screen.
- **Tags of Saved Messages.** Every user tags messages in Saved Messages, filters the chat by a tag and names the tags, as a Premium user does in Telegram's app, which offers Premium instead. One flag of the chat's state, `canUseSavedTags` (true), takes the place of `isPremium` at the gates of tags only: a tap on a tag, its context menu, the bar of tags in a message's context menu, the panel of tags over the chat and when it shows. A custom emoji tag still needs Premium, as a custom emoji reaction does in other chats, and so does everything else Premium unlocks.
- **Reactions on a message.** Telegram's app lets a user without Premium put one reaction on a message, whatever the server's `reactions_user_max_default` says. Pluma's app takes the server's limit for everybody, and in Saved Messages, where reactions are tags, the Premium one (`reactions_user_max_premium`); Pluma's server sends 3 for both. The toast that more reactions need Premium shows only while Premium is sold.
- **Video quality.** The app re-encodes a video before sending at a fixed bitrate per quality. The user chooses the quality as in Telegram's app, and the default is still the server's `video_upload_maxbitrate` (with Pluma's server, 720p on mobile data and 1080p on Wi-Fi). Every quality is sent at a higher bitrate than Telegram's, with better sound, in both preset tables (`TGMediaVideoConverter.m`, `MediaEditorValues.swift`):

  | quality | Telegram: video, sound | Pluma: video, sound |
  |---|---|---|
  | 240p | 0.4 Mbit/s, 32 kbit/s mono | 0.8 Mbit/s, 64 kbit/s stereo |
  | 360p | 0.7 Mbit/s, 32 kbit/s mono | 1.5 Mbit/s, 64 kbit/s stereo |
  | 480p | 1.6 Mbit/s, 64 kbit/s stereo | 2.5 Mbit/s, 128 kbit/s stereo |
  | 720p | 3.0 Mbit/s, 64 kbit/s stereo | 5.0 Mbit/s, 128 kbit/s stereo |
  | 1080p | 6.6 Mbit/s, 64 kbit/s stereo | 12 Mbit/s, 128 kbit/s stereo |
  | a video sent as a GIF | 0.9 Mbit/s | 1.8 Mbit/s |
  | round video | 1.2 Mbit/s, 64 kbit/s | 2.0 Mbit/s, 96 kbit/s |

  A round video is recorded at 2 Mbit/s instead of 1 or 1.2, by the legacy recorder (`CameraOutput.swift`) as by the new camera's (`VideoRecorder.swift`); a GIF file becomes an mp4 at 1 Mbit/s instead of 0.5 (`TGGifConverter.m`). No video is scaled up: an edited video with no quality chosen takes the default quality only up to its own size, as an unedited one already does. Upstream fits such a video into the default's size, so a trimmed 720p video with a 1080p default went out as 1080p.
- **App Store requirements.** What App Store Connect warns about on upload (its notes on build 20):
  - the Info.plist names the purpose of background location (`NSLocationAlwaysAndWhenInUseUsageDescription`, ITMS-90683), in English the text every language's `InfoPlist.strings` already translates;
  - no Apple font in the bundle (ITMS-91198, refused from 1 October 2027): SF Camera, the face of the camera's controls, is gone, and the camera uses the system font of the same weight, as it already does when the font cannot be loaded (the legacy camera of the attachment menu is given the same fallback, without which it crashed);
  - Siri gets an example phrase for each of the five system intents of the Intents extension in each of the app's 19 languages (ITMS-90626), naming Pluma, and in the fallback vocabulary (`Base.lproj`), whichever language a device has; upstream's name Telegram.
- **App update** (task 054 of the server repository). A build installed from the site (its profile lists devices, as an ad hoc profile does) ends its `app_version` with `adhoc`, so the server offers it updates; the update screen opens the page the server gives (the site's install page) instead of the App Store, which has no Pluma page. TestFlight builds are left to TestFlight.

  The app asks the server (`help.getAppUpdate`) at start, every hour instead of every 12 hours, and each time it comes to the foreground (task 095 of the server repository), so a new release reaches it within about an hour. The hour counts while the app is suspended, so a check due then runs within seconds of its return. A release the operator makes mandatory (`can_not_skip`) shows the screen upstream already gives it: no Skip button and no swipe that closes it, above the passcode screen; the check fails when an update gives that screen a way out. When the server's answer changes, say the release is withdrawn, made mandatory or replaced by a newer one, the screen shown goes away and the new answer's screen, if any, takes its place; upstream kept the old one until the app restarted. The same answer again changes nothing, so a skipped update is not offered again until the app restarts or the answer changes.
- **Login code screens** (task 076 of the server repository). Pluma sends no SMS; the code screen says where the code went, by the type the server answers:
  - in the person's other Pluma session (`auth.sentCodeTypeApp`): upstream's screen, with "Didn't get the code?" instead of "Get the code via SMS";
  - in the person's Telegram (`auth.sentCodeTypeFragmentSms`, otherwise unused in Pluma): Fragment's layout with the title "Check Telegram", the text naming the phone and the big button "Open Telegram", which opens the chat with the account that wrote the code in the Telegram app; the sticker and the accent of the other code screens instead of Fragment's; "Didn't get the code?" over the button;
  - nowhere, the code did not reach Telegram (`auth.sentCodeTypeSms`): the same layout, "Code didn't reach Telegram", how to let Telegram find the person by number, the button "Open Telegram settings" (`tg://settings/phone_privacy`), and "Send again in 0:30", then "Send again", which tries Telegram anew.
- **No AI message editor** (task 079 of the server repository). Pluma runs no language model, so nothing offers the AI editor (rewrite, proofread, style and translate a typed message: `messages.composeMessageWithAI`, `messages.composeRichMessageWithAI`, `aicompose.*`). The AI button of the chat's text field never shows, though the field keeps its expand button, which upstream ties to the same flag; the attachment caption and the legacy media caption never enable theirs; the rich text editor makes its AI button but never adds it, and its action bar takes the room. The check fails when upstream adds another place that enables or adds one.

  Each button shows only when the Telegram app is installed (`canOpenURL`; `tg` is among `LSApplicationQueriesSchemes`). The app's `openUrl` lets these two `tg://` links through to Telegram and drops any other one, as upstream does. With nothing more to send, "Didn't get the code?" says to ask the administrator, in the login and in the change of the phone number: no mail to Telegram's `sms@telegram.org`, no `auth.reportMissingCode`.

  Every answer to "Send again" or "Didn't get the code?" restarts the countdown of the screen it leads to, also when the server answers the same screen with the same data (upstream keeps the screen as it was, and the link stays active). The link sends one request at a time: while the answer is awaited it is dimmed and does nothing. An expired code (`PHONE_CODE_EXPIRED`) goes back to the phone number, as at sign in; `SEND_CODE_UNAVAILABLE` says to ask the administrator; after `FLOOD_WAIT` upstream's "Too many attempts" shows and the link waits the screen's countdown, or 60 s on a screen without one (TelegramCore keeps no seconds of `FLOOD_WAIT`).

  The long text of a code that did not reach Telegram fits on small phones: upstream drops the sticker of any code screen whose content does not fit with the keyboard up, and what still does not fit (on the smaller phones, such as the iPhone SE or mini) is the text, which then scrolls between the title and the code; the code field, the link and the button stay in view. Under the code field there is room for the error line. The Telegram app is checked again when the app becomes active in the login; the change of the phone number checks it when its code screen opens.

  The texts are the patch's own (`Pluma.Login.*`, in English); other languages come with the server's language pack.
- **Transcription of voice and round messages.** The server transcribes them for everybody (`messages.transcribeAudio`; every user has Premium, ADR 0041 of the server repository), so the button shows as for a Premium user of Telegram's app; the patch leaves it as upstream has it. A view-once voice or round message gets no button: the server refuses to transcribe one, and upstream already keeps it out (`ChatMessageInteractiveFileNode.swift`, `ChatMessageInteractiveInstantVideoNode.swift`). The check fails when an update drops or moves those gates, or sets the button anywhere outside them (`TRANSCRIBE_VIEW_ONCE_GATES`, `TRANSCRIBE_BUTTON_SETTERS`).
- **Service account** (task 080 of the server repository). The server's support account goes out with the `support` flag and no status. Where a last seen goes it reads "service account", not Telegram's "support": the text of upstream's `Bot.GenericSupportStatus` changes, the key stays, and two rows upstream has no line for a support account in show the same one: the row of a contact, instead of "last seen a long time ago" (`ContactsPeerItem.swift`), and the row of the settings' lists, such as the blocked users and the exceptions of a privacy rule, instead of "offline" (`ItemListPeerItem.swift`). English is bundled; other languages come with the server's language pack, which writes the same key in Pluma's words.
- **Group calls** (task 094 of the server repository, its ADR 0060). Every group call is end-to-end encrypted, the call of a group or a channel included: it keeps the interface and the rights of a chat's call and takes the cryptography of Telegram's conferences, which upstream gives conferences only. The server refuses a join without a key.
  - Each group call gets an end-to-end key (`PresentationCallManager.swift`); a call this client schedules gets its end-to-end context once the server has made the call. tgcalls encrypts every frame (it follows the encryption callback, not the conference flag, so a chat's call keeps its three video layers); a call without a context gets a dead one rather than none, and the screen always goes out of the app's own engine, never the broadcast extension's, which has no encryption.
  - The emoji of the key show in every group call, as in a conference.
  - A group call is joined as oneself only: no channel to join as is offered (`cachedGroupCallDisplayAsAvailablePeers` returns none), the block of the join is the account's own, and `reconnect(as:)` goes to nobody else.
  - The call rejoins with a new key by the self-healing rule of the server's ADR 0060 §5: a failure of the end-to-end state (a block that does not apply, a state that cannot be made from the last block), sub-chain 0 behind the server's `next_offset` with no block applied for over 12 s, `GROUPCALL_FORBIDDEN` on a write to the chain, or 15 s in which frames come, the chain is current and nothing from anyone was decrypted. tdesktop rejoins on a failure; upstream leaves the call. The rejoins of 5 minutes wait 0, 2 and 5 s, each plus up to 1 s; after 3 the call is left with a notice (`Pluma.GroupCall.EncryptionFailed`, in English; other languages come with the server's language pack). A rejoin of the transport keeps its key and is none of these.
  - Every 5 s, from 5 s after a join, the client reports the state of its encryption to the SFU over the call's data channel, next to tgcalls' `ReceiverVideoConstraints`: `PlumaE2EStatus` v1 of the server's ADR 0060 §5, its fields and no others. `seq` (1 after each join), `height` (sub-chain 0 as tde2e applied it, -1 with no state), `lastBlock` (the first 8 bytes of the SHA-256 of that block as the server keeps it, `""` with no state), `offset0` and `offset1` (the next blocks it polls for), `error` (the code of the tde2e error that made its call fail, 0 for none), `sendEpochs` (what it encrypts with), and since the last report `decryptEpochs`, `unknownEpochs` (at most 15 and 8), `encrypted`, `encryptFailed` and, per sender with frames, by user id, at most 100 (`senders`: `user`, `ok`, `unknownEpoch`, `tooOld`, `duplicate`, `failed`, `lastOkMs`, -1 when nothing was ever decrypted). Hashes are 16 hex digits; a report stays within 16 KiB, losing the senders decrypted longest ago first. No key, nonce, emoji or byte of a frame. TdCall counts (`TdBinding.mm`), the end-to-end context makes the report, and tgcalls takes it only while the channel is open, so a report that cannot go is not made and its counters go with the next; tgcalls sends nothing but a status report. The reference engine of Debug Settings sends none.
  - RTMP streams and live stories are gone: no "Stream with…" in the call menu of a group's or a channel's profile, no stream key in a stream's menu, no live mode in the story camera.
  - The server does not record a call, so nothing offers to start a recording: neither the call's menu nor a stream's.
- **Call colours.** The call screens take the sage palette (owner's decision of 2026-11-12, variant A). The background of the 1:1 call has Pluma's three four-point sets for connecting, connected and a weak signal in place of Telegram's (`CallBackgroundLayer.swift`); the group call screens, the call bar and a chat's panel of its call take the colours of the same meaning, Telegram's blues and purples the connecting set, its greens the connected set, its reds, pinks and oranges the weak set, its accents the palette's accents for a dark theme. The buttons that end, decline or leave a call keep Telegram's red and the button that answers one its green (owner's decision of 2026-11-13): End of the 1:1 call (`ContentOverlayButton.swift`), End, Decline and Accept of the incoming call screen and its legacy one (`CallControllerButton.swift`, `LegacyCallControllerButton.swift`), Leave of a group call (`VideoChatActionButtonComponent.swift`). The check fails when a colour of the call screens' sources is neither Pluma's nor one of upstream's greys, or when a button colour of Telegram's shows anywhere but its button (`CALL_COLORS`, `CALL_GREYS`, `CALL_BUTTON_COLORS`).
- **Build flags.** The upstream `.bazelrc` imports `pluma.bazelrc`, which [`ci/build.sh`](ci/build.sh) writes: the cache locations, and no provisioning profiles for a simulator build.

After the edits, the result is checked again. MtProtoKit, TelegramCore and TelegramVoip may hold no address in Telegram's published ranges, and their only RSA keys must be the server's. The check also covers the layer (`currentLayer()` is 233), the versions of `versions.json`, and the `Make.py` options and targets the build relies on.

What the patch leaves, and why:
- **Sections of 13.x the server does not offer.** The wallet (`wallet_available`), the news feed (`news_feed_enabled`) and Agent mode (`agent_bot_ids`) stay off without the server's app configuration key; the patch stops if one of those gates (or the default of the MTProto engine: MtProtoKit, with the Rust engine behind Debug Settings) changes.
- **Links** to `telegram.org` and `fragment.com` in the interface: the terms, the privacy policy, Telegram's own features. Each opens only when tapped. The rebranding leaves them as they are, except the links to Telegram's desktop and web clients in Settings → Devices and in its QR scanner ([Branding](#branding)). Links of `t.me` the app makes are `pluma.chat`'s, except those of Telegram's own features ([Branding](#branding), pluma.chat links).
- **The reflector benchmark** of TelegramUI's `AppDelegate` measures a call server of Telegram's. It runs only in internal builds or behind a hidden debug switch; this is a public build.
- **Connection probing.** MtProtoKit pings `google.com` or `8.8.8.8` (ICMP) when a proxy the user set up stops answering.
- **Translation and app icons.** Translation through Google, and app icons from the App Store in "Open in…", load only when the user asks.

## Branding

The app looks like Pluma, not like Telegram. The brand kit of the server repository (task 017: the logo and the palette "graphite and sage") is the source; the patch applies it:

- **Icons and logos.** [`brand/render.sh`](brand/render.sh) renders the images from the kit's SVGs ([`brand/pluma-icon-square.svg`](brand/pluma-icon-square.svg), [`brand/pluma-mark.svg`](brand/pluma-mark.svg), [`brand/pluma-mark-mono.svg`](brand/pluma-mark-mono.svg), [`brand/pluma-wordmark.svg`](brand/pluma-wordmark.svg)) into [`brand/ios`](brand/ios), each under the upstream path of the file it replaces. The patch checks each upstream file by its SHA-256 and copies Pluma's over it. Pluma's own files (the layers of the app icon, the intro's wordmark and the animation of its mark) go where the patch adds them, and the patch refuses one that upstream already has:
  - the app icon (Icon Composer, `Telegram.icon`): the mark on white, a light mark on graphite in the dark appearance, and the tinted and clear ones iOS 26 derives;
  - the alternate icon `BlueIcon`, which the app counts as its default one. The other alternate icons are Telegram's: the bundle no longer carries them, and the icon picker shows Pluma's only;
  - the home screen quick action, the context menu item, the call screen title and CallKit;
  - the QR code logos and their animations ([`brand/tgs.py`](brand/tgs.py) writes the mark as a still Lottie);
  - the laptop animation of Settings → Devices (`Devices.tgs`): Telegram's own animation in the palette, with the mark, centred on the disc, in place of the plane on the lid and in the QR code. It is not drawn from the SVGs: `render.sh` copies [`brand/pluma-devices.tgs`](brand/pluma-devices.tgs) as it is;
  - the first page of the intro: the mark writes itself above the wordmark "pluma", its title, as on Pluma's site, with no disc and no paper plane. The wordmark is in the colour of the intro's text at 90%.
    - [`brand/mark_write.py`](brand/mark_write.py) writes the animation, `pluma_mark_write.json`, from the kit's mark, with the motion of the site's `writeMark`: the ring drawn in 1.05 s on twos with the feathers riding the nib, then one breath of the feathers. The mark is at rest from 2.12 s; with Reduce Motion it shows finished at once.
    - The screen that hosts the intro plays it with the app's own Lottie player (rlottie) whenever the first page appears: at the start, and when the user comes back to the page or to the intro. Light themes show the kit's ink; dark themes show the ink of the app icon's dark appearance, by colour replacement. The mark shows while the first page is current, fades with the scroll, and comes in and goes as the old disc did. When the user comes back to the page, it writes itself once the scroll lets it show.
    - The pages are one group between the status bar and the start button: the mark 128 pt high, the wordmark's glyphs 32 pt under it, the group at 44% of the free space (`PlumaIntroMarkHeight`, `PlumaIntroMarkGap` and `PlumaIntroGroupBias` in `ci/patch.py`). The free space starts where the app's own screens start under the status bar, by the app's own metrics of the device (Display's `DeviceMetrics`), not by UIKit's safe area: 54 pt on an iPhone 16 Pro, for example, or the height of UIKit's status bar if that is taller. The start button keeps upstream's place, and the pictures of the other pages end where the mark ends.
    - The textures of Telegram's sphere and plane are transparent. The intro fills the sphere's texture with its background colour, so on that page its OpenGL animation draws a square of the background colour over the next page's speedometer and hides it. When the page changes, the square fades in or out over the speedometer, with the old sphere's timing (0.24 s in, 0.3 s out), and the mark fades in or out with it: the mark and the speedometer cross-fade. The patch pins the upstream lines this relies on (`INTRO_SPHERE_MASK`). The pages "Powerful" and "Cloud-Based" are sage instead of blue. Upstream does not start that animation in the arm64 simulator build (Apple Silicon; `loadGL` in `RMIntroViewController.m`, with no reason given); the patch starts it there as on devices, so the simulator, where the intro is checked, shows what a device shows.
- **Name.** "Telegram" becomes "Pluma" wherever the user reads it, except where the login code screens mean the Telegram app: the built-in English strings (585 entries, feature names included, such as "Pluma Premium"; string keys, URLs and user names stay), the permission prompts in every language (in Arabic, Persian and Korean script too, and the name under the icon in Arabic and Korean), the Photos album, the locked widget, the label of the app's entry in address book contacts.
- **Link scheme.** The app registers `plm://`, not `tg://`, which stays with Telegram installed on the same phone, nor `ton://` and `tc://` of 13.x (the wallet, which the server does not offer). The links it makes use `plm://`, the QR code of a sign-in on another device among them; its scanner takes `plm://` codes only, so a sign-in by QR code works between Pluma clients. `tg://` links inside the app (messages, bots) still open in it.
- **Client links.** In the header of Settings → Devices ("Link Pluma Desktop or Pluma Web by scanning a QR code"), "Pluma Desktop" opens Pluma's site https://pluma.chat/ and "Pluma Web" its web client https://web.pluma.chat/, as in the Android client, instead of getdesktop.telegram.org and web.telegram.org (`CLIENT_LINKS` in `ci/patch.py`). The QR scanner opened from that screen does the same under its viewfinder, and its text reads "Go to pluma.chat or web.pluma.chat to get the QR code" (`AuthSessions.AddDevice.ScanInstallInfo`, `CLIENT_TEXTS`; English is the only language the app bundles). The header's text names no site, so its string stays. "Learn More" under the sessions, which the app shows only when the server enables the QR login camera (`qr_login_camera`), still opens telegram.org/apps.
- **pluma.chat links** (task 026 of the server repository). pluma.chat is to Pluma what t.me is to Telegram (the server's invite links and `me_url_prefix` are pluma.chat's):
  - The app opens links of `pluma.chat` itself, as those of `t.me`, `telegram.me` and `telegram.dog`, which stay its own as upstream: the parsers of `UrlHandling`, the check of `OpenUrl`, concealed links without a warning, the QR scanner of a profile and the story camera, a pasted bot or sticker set link, the "View Message" of a message link's preview, the slug of a shared folder's link (`LINK_HOSTS` in `ci/patch.py`). Only the host itself: a subdomain of `t.me` is read as a username, one of `pluma.chat` (web.pluma.chat) stays a site (`URL_SUBDOMAIN`).
  - Every link the app makes is `https://pluma.chat/…` instead of `https://t.me/…`, and every prefix it shows before a name is `pluma.chat/`: profiles, channels and groups (share, copy, QR codes, the admin log), messages, sticker and emoji sets, themes, wallpapers, languages, proxies, phone number links, story albums, gift collections, games, voice chats (`SHARE_LINKS`). So are the English texts that show such a link (`STRINGS_LINKS`).
  - `t.me` stays in the links of Telegram's own features (gift codes, collectible gifts, auctions, text styles, Stars, Cocoon, Premium's limits), in links made only to be opened in the app, in the address of a username the app writes into device contacts and reads back (contacts already written stay readable) and in the old watch extension, which no target builds (`SHARE_KEEP`). The check after the edits counts every `t.me` literal of the app's code: one that is neither replaced nor kept stops the patch, so a new link upstream adds is found.
  - Universal links: the app's entitlements list `applinks:pluma.chat` (`ASSOCIATED_DOMAINS` in `ci/patch.py`; upstream gives associated domains only to Telegram's own bundle ids), so a pluma.chat link opened in another app opens Pluma. The App ID has the Associated Domains capability, and `ci/preflight_sign.py` refuses a main profile without it. The site's `/.well-known/apple-app-site-association` leaves its own pages out, so they stay in Safari.
- **Colours.** Day Classic and Night, the themes of a fresh install, take the palette: sage accents (`#5B7A5E` light, `#9DBB9F` dark), sage links, bubbles, time and checks, a white or graphite chat background instead of Telegram's pattern. The first accent the theme settings offer is sage. The other built-in themes ("Day", "Night Tinted") and the other accents stay as they are.
  - People's identity colours, the seven Telegram picks by the id of a user or chat for letter avatars, names in groups, replies and link previews, and offers for chat folder tags, stay Telegram's, except blue and cyan, in every theme: blue is the palette's sage (avatars `#7FA082` to `#5B7A5E`, names `#4F6E52`, in dark themes `#9DBB9F`), and cyan a teal without Telegram's blue (avatars `#5BCBC4` to `#2C9C98`, names `#1F8A80`, in dark themes `#53CCC6`, the teal of Telegram's Android app at night: this app's one cyan, `#309EBA`, which it shows in dark themes too, leans to blue). The app has one name colour for light and dark themes; these two get one of their own for dark themes, and so does blue where the app falls back on it for a colour it has no value for. The tables are in `ci/patch.py` (`TELEGRAM_IDENTITY`, `IDENTITY_COLOURS`): the app's own, the copies in its notification, widget and Siri extensions and in the reactions of a live stream, and the colours TelegramCore takes for the server's.
  - The places that take the blue one as a plain blue are sage too: the default name colour (theme previews), the "Contacts" and "Read" categories of a chat folder, the "Contacts" category of business message recipients, Saved Messages in a profile's menu. Upstream draws that last one in the blue of the Saved Messages avatar; here it is the identity sage (`#7FA082` to `#5B7A5E`), and the avatar the palette's (`#9DBB9F` to `#5B7A5E`).
  - Colours 7 and above are the server's (`help.getPeerColors`) and stay as it sends them. When the server lists colours 0 to 6 with values, names, bars and tags take the server's values, while letter avatars keep these; listed without values, or not served, names take these too. A server that serves the list must change its hash whenever these colours change here: the app keeps the list it got, these colours baked in for the ones listed without values, and replaces it only when the server's hash changes.
  - Once users or channels can have colours of their own, two things differ from Telegram. A colour the app has no value for (any above 6 while the server does not serve the list) falls back on blue's name colour, but `AvatarNode` picks the letter avatar of one above 13 by the hue of that colour, and sage's hue is green's, so that avatar is green. The quote of a channel in the text input asks for the light name colour in every theme, as upstream does, so blue's is `#4F6E52` in dark themes too.
  - The icons of Settings → Devices are not identity colours in this app: iPhone, iPad, Mac and Windows take the blue of the icons of Settings (`#0079FF`, Saved Messages among them), the session screen the same blue, and Safari and iOS are images. Whether they turn sage too is not decided yet; for now they stay as they are.
- **Settings.** The support section ("Ask a Question", the FAQ, "Pluma Features") leads only to Telegram's services and is gone.

Every edit is exact, as the rest of the patch: the counts of the pinned commit are part of it (the strings, the colours, the links), and an upstream update that moves any of them stops the patch.

To change an image, edit the SVG (or replace `brand/pluma-devices.tgs`) and re-render; this needs rsvg-convert (librsvg), ImageMagick 7 and Python 3, and writes the same bytes on a re-run:

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
| `PLUMA_ASC_APP_ID` | Optional. The Apple ID of the app record in App Store Connect (digits), for uploads to [TestFlight](#testflight). |
| `PLUMA_INSTALL_URL` | Optional. The site whose install service re-signs the ad hoc IPA for iPhones that install Pluma from it; `https://pluma.chat` by default. See [Installing from the site](#installing-from-the-site). |
| `PLUMA_BAZEL_CACHE_GB` | Optional. The size the Bazel disk cache is trimmed to before it is saved, in GB; 12 by default (a full simulator cache is about 9 GB, about 3 GB compressed in the Actions cache). |

None of these values is a secret: every IPA carries them. The server variables have the same names as in `pluma-android`.

- **No `PLUMA_TEAM_ID`.** CI builds only the simulator app for the development server.
- **`PLUMA_TEAM_ID` set.** The check job also patches for the server variables, and a push to `main` builds the signed IPA. Missing server variables fail the check job within seconds.

## Development build (simulator)

Every run builds the simulator app for the development server of [`config/dev`](config/dev): `127.0.0.1:10443` with the development key. The iOS Simulator shares the Mac's network, so it reaches a server stack that runs on the same Mac. The app is built for arm64 simulators (a Mac with Apple Silicon), in the `Make.py` configuration `PLUMA_SIM_CONFIGURATION` of `config/app.env` (`debug_sim_arm64`). It is not code signed, carries no secret, and stays plain in the `simulator` artifact of the run for seven days. The intro's OpenGL animations, the pictures of its pages, show there as on a device: upstream does not start their view in an arm64 simulator build, and the patch does.

1. In the server repository, start the stack with the development key and the gateway on port 10443, and allow a phone number:
   ```sh
   E2E_SERVER_KEY=~/pluma-dev-secrets/server_pkcs1.key E2E_GATEWAY_PORT=10443 test/e2e/run.sh up
   test/e2e/run.sh admin allowlist add +79990000001
   ```
2. Install the app on a booted simulator (Xcode 27) and start it:
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

The IPA is signed inside the build, with ad hoc profiles: it installs on the registered devices only, up to 100 iPhones per membership year. The `build-ipa` job checks the signing material first, in the protected `release` environment, and a bad certificate or profile fails it within a minute. It requires the following:
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

A release waits for your approval once, for `build-ipa`. The IPA is the `pluma-ios` artifact of the run, kept for 30 days:

```sh
gh run download <run id> -R sckraaa/pluma-ios -n pluma-ios
for f in pluma-ios-*.ipa.age; do age -d -i pluma-ipa.agekey -o "${f%.age}" "$f"; done
shasum -a 256 -c pluma-ios-*.ipa.sha256
```

Install it with Apple Configurator or Finder on a registered device, or from the site (below).

A signing failure after a good preflight (say, a keychain problem) is fixed with *Re-run failed jobs*. The compiled code is in the cache, so the build mostly repeats the signing.

### Installing from the site

The signed ad hoc IPA also goes to the server's install service (`ci/install-upload.sh`, before the IPA is encrypted): with it go the version, the build number and, for the app and each extension, the bundle ID and the entitlements it was signed with. The service registers every iPhone that asks on the site, issues the ad hoc profiles anew for the team's devices and re-signs this IPA with them, so a new iPhone needs no new build (server repository: `docs/ops/ios-install.md`). It authenticates with the secret `IOSINSTALL_UPLOAD_TOKEN` of the environment `release`, which the server's `put-secrets.sh` sets; without it the step passes and says the service is not set up.

### TestFlight

After the ad hoc IPA, every push to `main` (and a manual run of `main` with *testflight* ticked) builds the same app signed with App Store profiles and uploads it to App Store Connect, where it becomes a TestFlight build. Testers install it with the TestFlight app on any iPhone; it needs no registered devices. The certificate is the same Apple Distribution certificate; only the profiles differ, so the build reads the compiled code from the ad hoc IPA's Bazel cache and saves no cache of its own. The build number is the run number, which App Store Connect needs to grow from build to build.

The `preflight-testflight` job checks first, in the `release` environment, and fails within a minute when something is wrong. It requires the following:
- the certificate as for the ad hoc IPA;
- there is one App Store profile for each of the seven App IDs, of the team, valid for at least 14 more days, holding that certificate and listing no devices;
- every profile has the App Group, and the app's profile has push (`aps-environment` = `production`);
- the API key, its issuer and `PLUMA_ASC_APP_ID` are set, and the key is a private key.

The `build-testflight` job checks again on its runner, builds, uploads with `xcrun altool --upload-package` and an App Store Connect API key (`ci/testflight.sh`), and keeps the IPA encrypted as the `pluma-ios-appstore` artifact of the run for 30 days, also when the upload fails. The app declares no non-exempt encryption (`ITSAppUsesNonExemptEncryption` in upstream's `Telegram/BUILD`), so a build does not wait for the export compliance question.

Set it up once, after [the ad hoc IPA](#in-the-apple-developer-account):

1. **App record.** In App Store Connect, *Apps → + → New App*: platform iOS, the name, the primary language, the bundle ID `chat.pluma.app` and any SKU, such as `pluma-ios`. *App Information → Apple ID* of the new app is the variable `PLUMA_ASC_APP_ID`.
2. **Profiles.** In *Certificates, Identifiers & Profiles → Profiles*: one profile of the App Store distribution type for each App ID of the table above, each with the Apple Distribution certificate. They list no devices and need no regenerating when a device is added.
3. **API key.** In App Store Connect, *Users and Access → Integrations → App Store Connect API → Team Keys*: generate a key with the *App Manager* role. The page shows its key ID and the issuer ID; the `.p8` file downloads only once.
4. **Secrets and the variable.**
   ```sh
   asprofile() { base64 -i "$2" | gh secret set "PLUMA_APPSTORE_PROFILE_$1" -R sckraaa/pluma-ios --env release; }
   asprofile MAIN Pluma_App_Store.mobileprovision            # the file names are whatever you saved
   asprofile SHARE Pluma_Share_App_Store.mobileprovision
   asprofile NOTIFICATION_SERVICE Pluma_NotificationService_App_Store.mobileprovision
   asprofile NOTIFICATION_CONTENT Pluma_NotificationContent_App_Store.mobileprovision
   asprofile WIDGET Pluma_Widget_App_Store.mobileprovision
   asprofile SIRI_INTENTS Pluma_SiriIntents_App_Store.mobileprovision
   asprofile BROADCAST_UPLOAD Pluma_BroadcastUpload_App_Store.mobileprovision
   gh secret set PLUMA_ASC_KEY_ID -R sckraaa/pluma-ios --env release          # asks for the value
   gh secret set PLUMA_ASC_ISSUER_ID -R sckraaa/pluma-ios --env release
   base64 -i AuthKey_<key ID>.p8 | gh secret set PLUMA_ASC_KEY_P8_B64 -R sckraaa/pluma-ios --env release
   gh variable set PLUMA_ASC_APP_ID -R sckraaa/pluma-ios --body <Apple ID of the app>
   ```
   Keep the `.p8` off-line afterwards, or revoke the key and make a new one when it is lost.

To release, run *Actions → ios → Run workflow* on `main` with *testflight* ticked (untick *ipa* when the ad hoc IPA is not wanted), or:

```sh
gh workflow run ios -R sckraaa/pluma-ios --ref main -f testflight=true -f ipa=false
```

The run waits for your approval of `preflight-testflight` and `build-testflight`. The build appears in App Store Connect under *TestFlight* once Apple has processed it:
- **internal testers**, up to 100 members of the team in App Store Connect, get it without review;
- **external testers**, invited by email or through a public link, get it after Beta App Review; the first build needs a beta app description and review information, and builds added to an external group go to review automatically.

To fetch the uploaded IPA:

```sh
gh run download <run id> -R sckraaa/pluma-ios -n pluma-ios-appstore
for f in pluma-ios-*.ipa.age; do age -d -i pluma-ipa.agekey -o "${f%.age}" "$f"; done
shasum -a 256 -c pluma-ios-*.ipa.sha256
```

An upload that fails after a good build (say, a network error) is repeated with *Re-run failed jobs*: the run number stays, and App Store Connect accepts it as long as the first attempt did not get through.

## Releases

After `build-ipa` hands the IPA to the install service, `ci/release-upload.sh` records the build with the server's releases service: the apps installed from the site then show the update screen, which leads to the install page. The notes are [`release/notes.en.txt`](release/notes.en.txt) and [`release/notes.ru.txt`](release/notes.ru.txt); change them with the change they describe.

- `RELEASES_UPLOAD_TOKEN`, a secret of the `release` environment: `teamgramd/deploy/releases/put-token.sh` of the server repository sets it. Without it `build-ipa` fails at its start.
- `PLUMA_RELEASES_URL`, a repository variable, defaults to `https://pluma.chat`.

A bad release: `pluma-admin release withdraw ios <build>` on the server stops the update screens (`docs/ops/releases.md` of the server repository), but the install page keeps serving the IPA it was given. To take it back, run the workflow with `ipa` on the last good commit, or release the fix as the next build. The workflow needs both tokens, `RELEASES_UPLOAD_TOKEN` and `IOSINSTALL_UPLOAD_TOKEN`: a build is offered to the apps only together with the IPA the install page serves.

## When it builds

| Trigger | Simulator app | Signed IPA | TestFlight |
|---|---|---|---|
| Push to `main` | yes, artifact `simulator` (7 days) | yes, if `PLUMA_TEAM_ID` is set | no |
| Manual run (*Actions → ios → Run workflow*) | yes | yes, if `PLUMA_TEAM_ID` is set and *ipa* is ticked | on `main`, if `PLUMA_TEAM_ID` is set and *testflight* is ticked |
| Pull request | yes, no artifact | no | no |
| Weekly canary | the pinned upstream on a fresh runner image | no | no |

The jobs run on GitHub's `xcode-27` runners (macOS 27, a public preview of GitHub's) with Xcode 27.1 selected explicitly, the version `versions.json` asks for; the label is a hosted one that actionlint does not know yet (`.github/actionlint.yaml`). The setup removes the image's other Xcode versions when the disk is short, and downloads the Metal toolchain when it is missing.

The Bazel disk cache and Bazel's downloads are kept in the GitHub Actions cache, one entry for the simulator app and one for the IPA (the TestFlight build reads the IPA's and saves none):
- the entry is saved even when a build fails, so a re-run continues from where it stopped;
- before saving, the disk cache is trimmed to 12 GB (`PLUMA_BAZEL_CACHE_GB`), least recently used entries first;
- a pull request saves its own entry (not one of a fork or Dependabot), so its next push finds what the last one compiled; it reads its own entries and those of `main`, and `cache-cleanup` deletes them when it closes;
- older entries of each kind on a branch are deleted after the run. The repository's cache limit is 40 GB (*Settings → Actions → General*; above 10 GB it is paid, ADR 0010 of the server repository).

A cold build takes about an hour. A repeat build without changes takes minutes. An edit of TelegramCore or MtProtoKit, which most of the app depends on, compiles nearly everything again.

Since the repository is public, set *Settings → Actions → General → Fork pull request workflows* to require approval for all outside collaborators.

### Reference build of Telegram

*Actions → reference → Run workflow* builds the same Telegram-iOS release without the patch, with Telegram's own configuration from upstream (`build-system/appstore-configuration.json`), for the simulator: the official client on Telegram's servers, to compare Pluma with (`ci/build-reference.sh`). The App Store app runs on devices only, and Telegram publishes no simulator build. The artifact `telegram-reference-simulator` (7 days) holds `Telegram.app` (`ph.telegra.Telegraph`), which installs next to Pluma: unzip it and run `xcrun simctl install booted Telegram.app`. The job reads the Bazel cache of the Pluma simulator build and saves none.

## Local build

The checks need Python 3, openssl and git, on any system:

```sh
ci/fetch-upstream.sh sparse          # ./upstream, only the files the patch reads
python3 -m unittest discover -s ci -p '*_test.py'
ci/configure.sh dev
```

A build needs a Mac with macOS 27, Xcode 27.1 and several tens of GB free; Bazel 9.2.0 is what `Make.py` downloads, and Rust 1.98.1, the crates of its two Rust engines and more come with the build:

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
