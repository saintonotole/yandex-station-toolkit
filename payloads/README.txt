These runtime payloads are versioned in the standalone repository and embedded
into the station-tool binary by //go:embed in embeds.go:

- dropbearmulti: device-side static ARMv7 hard-float musl binary that is both
  dropbear and dropbearkey (installed as symlinks). Rebuild it from the
  signed upstream release with scripts/build-dropbear.sh.
- yandex-noupdate.sh: device-side OTA control script.
- equasar-fullchain.pem, equasar-key.pem: the certificate chain Yandex
  Stations trust for quasar.yandex.net during onboarding, as published in the
  eQuasar/lite-kit projects. Used only by the local bootstrap endpoint, for
  the owner's own devices on their own network.
- equasar-sync-template.json: the local fallback sync answer (secrets
  stripped by the app before use) from krevetkqqq/lite-kit (MIT).

adb is not embedded. The app uses adb from PATH, or offers to download the
official Android SDK Platform-Tools from Google into its config directory.

The "test" job in .github/workflows/build.yml verifies these files before
every build.
