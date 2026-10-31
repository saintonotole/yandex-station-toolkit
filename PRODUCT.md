# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Station owners rooting their own Yandex Station. They start with a stock speaker, on their own LAN, and are not comfortable with OS package managers, console tools, or GitHub. The app has to carry every step for them, from first ADB access through to a secured device.

## Product Purpose

Take a station from stock to rooted-and-secured from one desktop window, without the owner touching a shell, a package manager, or GitHub.

The flow has two stages:

1. **Bootstrap (get ADB/root).** During the official onboarding, the PC acts as the station's network endpoint: a local DNS server points the Yandex sync hosts at the PC, and a local HTTPS endpoint the station trusts answers its sync with ADB remote-activation turned on, which opens port 5555. When a model needs it, the same endpoint serves a firmware downgrade to a version that honors that injection. Borrowed from lite-kit (MIT).
2. **Secure (keep it).** Once ADB is open: find the speaker, turn OTA updates off, install key-only SSH, and keep ADB across reboots.

Installing further packages (yse, YAM, BetterYAM) is a later, secondary job. Day-to-day controls — resource widgets and reboot — are extras, and they stay only while they are cheap to implement and maintain. The Glagol player and its Yandex account sign-in were cut in October 2026: they leaned on undocumented Yandex endpoints for no core benefit.

## Positioning

A GUI that takes a station the whole way from stock to "ADB open, OTA off, SSH installed," for an owner who does not work in a terminal. lite-kit does the bootstrap step but is a set of shell/PowerShell scripts; the official Yandex app does none of it.

## Safety

This is for the owner's own devices on their own network only. A factory reset unbinds the account, and a failed firmware step can brick the speaker. The UI must carry that warning where the bootstrap and firmware actions live, not bury it.

## Operating Context

The app is a desktop window (Wails) on Windows, Linux, and macOS — all three are supported targets. The smallest screen it must fit and stay operable on is a Steam Deck, 1280×800. That size is the layout floor.

The speaker is on the same local network. The bootstrap ritual is: point the router's DNS at the PC, factory-reset the speaker (power on, hold pause ~7–10 s), add it in the «Дом с Алисой» app and join it to the Wi-Fi, then watch for ADB to open. Afterwards the owner restores the router's DNS to automatic.

Running the local DNS server needs port 53, and override mode adds ports 80 and 443. The app asks the OS for elevation only when a bind actually fails, using the native GUI prompt: UAC on Windows, pkexec/polkit on Linux, the system administrator prompt on macOS. Elevation is visible in the UI while the server runs and is released on stop.

## Capabilities and Constraints

Bootstrap workflow:

- A dedicated control starts and stops the local DNS server.
- The DNS server has two modes:
  - **Pass-through** — a plain forwarding resolver. Nothing is redirected and no local HTTPS endpoint runs. The station onboards normally, and the router's DNS can stay pointed at the PC.
  - **Override** — redirects the Yandex sync hosts to the PC and injects the ADB activation into the station's sync; serves a firmware file locally when the station's version differs from the one the exploit needs.
- Firmware for each station model detected on the LAN is downloaded locally: the official Yandex CDN first, the lite-kit mirror as the last-resort fallback (see Confirmed bootstrap decisions below).

Secure workflow:

- Find the station on the LAN, or connect by IP.
- Disable OTA, with a way to see status and restore it.
- Install SSH.
- Preserve network ADB, including across reboot.

A host counts as a Yandex Station only when Yandex mDNS data or glagol is present. An open ADB port alone is not enough.

Reach the device by the least invasive channel that already works: network ADB, then one passwordless root SSH attempt, then the system SSH agent only when that setting is on. adb is never embedded in the app. If it is missing, ask before downloading the official platform-tools.

Secondary: install, remove, start, and autostart yse, YAM, and BetterYAM.

Not goals: local playback, resource readouts, the journal, nicknames, and color. They remain only while they stay cheap.

Confirmed bootstrap decisions:

- Pass-through is a plain forwarding resolver with no redirect; override is the only mode that redirects and injects.
- Firmware bytes come from the official Yandex CDN first; the lite-kit mirror is the last-resort source. Verified finding: Yandex's check_updates only ever offers the latest build for a platform, so the download URL of an older vulnerable version is discovered from the mirror's metadata.json, which records Yandex's own CDN URLs. All four registered target artifacts are confirmed live on the official Yandex CDN with matching CRCs: Lite `0.369.1.46…297` (67 MB, crc32 371630625), Mini `1.305.4.16…20250721`, Mini 2 `0.369.1.46…299` (67 MB, crc32 1524631406), Midi `0.369.1.46…160` (173 MB, crc32 3103154577). The Mini 2 and Midi versions come from the Marker284/yandex-station-extended wiki's verified-versions table (checked on a real Mini 2, YNDX-00020, including the post-2026-10-21 rollback path).
- Elevation is requested only when a port bind fails, through the OS-native GUI prompt, and shown in the UI.
- The eQuasar/eMudhra certificates the station trusts are bundled under `payloads/`, with the own-devices-only and bricking warning carried in the UI.

## Product Principles

- Carry every step: the owner never opens a shell, a package manager, or GitHub.
- Least invasive channel first: existing network ADB, then one passwordless root SSH attempt, then the SSH agent only when enabled; downloads only as a last resort, with consent.
- Official sources first: Yandex CDN firmware, official platform-tools, official model imagery; third-party mirrors only as verified fallbacks.
- Honest states over comforting ones: unknown platforms answer hasUpdate:false, widgets keep the last reading rather than blinking fake data, and the factory-reset/bricking risks are warned where the actions live.
- Keystrokes, session output, and token-like values are never logged.

## Brand Commitments

The product name is Yandex Station ToolKit. The interface the owner uses is the one committed earlier in this project: the structure of dimap/yandex-station-web, with discovery and provisioning placed inside it. The shipped UI copy is Russian; the journal, commits, and pull requests are English. The dimap/yandex-station-web (MIT) and lite-kit (MIT) attributions stay in the README. `adb` is always written lowercase.

## Evidence on Hand

- `README.md` — what the app does today, and the wiki step it replaces.
- The Wails app and `frontend/` — the current interface.
- `payloads/` — versioned runtime payloads (Dropbear, OTA script, yse).
- lite-kit (`krevetkqqq/lite-kit`, MIT) — the reference for the bootstrap step: DNS redirect, sync injection, firmware downgrade. Its own field reports cover Лайт 1, Мини, Миди and Мини 2; treat those as lite-kit's claims, not this app's tested results.
- The Marker284/yandex-station-extended wiki is the current source for verified vulnerable versions (fresh snapshot in `.tmp/yse-repo` during work; it is documentation, not a dependency). Its own-server compatibility table now marks Лайт 1, Мини 1, Мини 2 and Миди ✅; the registry follows it.

No user research, testimonials, or marketing site exist. Do not invent them. Pages on hackalice.me are external documentation, not source.
