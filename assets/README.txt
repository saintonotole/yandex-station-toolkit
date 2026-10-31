Application binary assets, one home for every platform icon. All files
here are committed static assets (the one-time python renderers that
produced them are gone from the repo).

- assets/icon.png: small Alisa PNG for in-app use (favicon/header).
- assets/windows/: Windows icon resources.
  - icon.ico: multi-size app icon, 16–256 px.
  - app.rc, app.manifest: resource script and manifest. The window icon
    must sit at resource ID 3 — see scripts/make_syso.go.
- assets/darwin/: macOS .app bundle assets.
  - AppIcon.icns: bundle icon.
  - Info.plist.template: filled with {{VERSION}} by scripts/build-macos-app.sh.

resource_windows_amd64.syso (repo root, gitignored) is generated at
build time by scripts/build.sh and the CI windows job from icon.ico +
app.manifest via scripts/make_syso.go. It sits in the repo root because
the Go toolchain links .syso files only from the main package directory;
a bare `go build .` on a fresh clone builds without icon and manifest
until build.sh (or make_syso.go) has run once.

Device model icons for the UI are not binary assets; they live under
frontend/icons/ and ship inside the embedded frontend.
