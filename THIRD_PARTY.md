# Third-party components

The application source is licensed under `LICENSE`. Bundled runtime payloads
and image assets retain their own licenses and terms:

- Dropbear (`payloads/dropbearmulti`): Dropbear SSH, MIT-style license,
  built from the signed upstream release by `scripts/build-dropbear.sh`.
  <https://matt.ucc.asn.au/dropbear/dropbear.html>
  zlib 1.3.2 is statically linked into that binary for SSH compression,
  under the zlib license. <https://zlib.net/>
- Android Debug Bridge is not bundled. When it is missing from PATH, the app
  downloads Android SDK Platform-Tools (Apache License 2.0) from Google at
  the user's request.
  <https://developer.android.com/tools/releases/platform-tools>
- Yandex Station device images (`frontend/icons/official-*.png`): official
  Yandex Alice help assets, used to identify supported hardware.
  <https://alice.yandex.ru/support/ru/station/identify>
- YAM and BetterYAM are downloaded from their respective GitHub releases at
  install time; they are not bundled in this repository.

The device-side scripts in `payloads/` are distributed with the toolkit
because they are required for an offline, reproducible build.
