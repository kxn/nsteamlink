# Changelog

[简体中文](CHANGELOG.md)

## [0.3.0] - 2026-10-15

Previous stable release: **v0.2.1**. This release: **v0.3.0**. Target branch: `main`; tagged source: [`v0.3.0`](https://github.com/kxn/nsteamlink/tree/v0.3.0).

### Highlights

- **In-app updates**: Switch checks for the latest stable release in the background at startup and offers installation on the home page, at most once per launch. “Update check” in X Options defaults to On; disabling it takes effect on the next launch. Failed checks are silently skipped.
- **Download verification**: only use certificate-verified HTTPS for this repository's stable releases. Check the download size and SHA-256 before replacing an NRO; if replacing a file fails, attempt to restore its old copy. Update the launched file and any existing HOME shortcut target, then ask the user to exit and relaunch.
- **Simpler releases**: remove the standalone NSP build and its key configuration, which never produced a published release asset. Releases contain the NRO; its “Add to HOME Menu” feature remains available without user-supplied packaging keys.

### Commits by type

- **Feature**: `0a93607`, startup checks, update settings, verified downloads, and update UI ([PR #41](https://github.com/kxn/nsteamlink/pull/41)).
- **Build and cleanup**: `6df4b21`, `8b45610`, remove standalone NSP packaging and code used only by that path ([PR #42](https://github.com/kxn/nsteamlink/pull/42)).
- **Documentation**: `4c0e8c0`, `68fd88d`, record NRO release and in-app update decisions and evidence limits.

### Thanks

Thank you to **Simone Caronni ([@scaronni](https://github.com/scaronni))** for PRs #41 / #42: implementing in-app updates, simplifying packaging, and adding automated tests and validation records. Thank you to **Sven** for providing an original-model Nintendo Switch for development and device testing, and to the authors and maintainers of IHSlib, FFmpeg, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

### Validation and evidence scope

Reviewed both PRs' updater, UI, thread cleanup, and packaging changes. Desktop suites with diagnostics ON/OFF passed all 56 tests each, along with release tooling tests; upstream desktop and Switch CI passed after the merges. The tag workflow also verifies the version, release diagnostic exclusion, NRO structure, build provenance, and attachment checksums before publication.

The contributor recorded a host-side test that connected to GitHub, downloaded v0.2.1, and verified its checksum. The full check/download/replace/relaunch flow on Switch, network interruption, insufficient SD space, and the hbmenu return lifecycle still require device validation. Desktop tests and cross builds do not prove those device behaviors.

### Download and update

v0.2.1 and earlier have no in-app updater: download the `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.3.0) for this upgrade. If a HOME shortcut is installed, replace its fixed target at `sdmc:/switch/nsteamlink/nsteamlink.nro`. Starting with v0.3.0, in-app updates are available when launched from the SD card; netloader launches skip update checks. Release builds exclude advanced diagnostics and include `SHA256SUMS`, `build_identity.json`, and the SDK package list.

[Full changelog: v0.2.1 → v0.3.0](https://github.com/kxn/nsteamlink/compare/v0.2.1...v0.3.0)

## [0.2.1] - 2026-10-11

Previous stable release: **v0.2.0**. This release: **v0.2.1**. Target branch: `main`; tagged source: [`v0.2.1`](https://github.com/kxn/nsteamlink/tree/v0.2.1).

### Highlights

- Fix pairing with modern Steam: support the PIN-masked X25519 key exchange and persist the negotiated key for each computer, so pairing can be reused after restarting the app. Migration from v2/v3 profiles retains existing identity and pairing data. The initial pairing code and the connection security PIN remain separate concepts.
- Improve LAN discovery: also send discovery requests to local IPv4 subnet broadcast addresses, addressing the recorded Switch/Linux Steam host case where global broadcast alone received no response.
- Fix the app exiting when opening “Add PC manually” on Switch: raise the deko per-frame quad limit from 4096 to 8192 and report limit exhaustion in diagnostic builds.
- Integrate upstream IHSlib updates: flush pending data and wait for a keyframe after decoder-reported frame loss; report actual platform and decoder capabilities supplied by the app, omitting unverified Switch OS type and form factor.

### Commits by type

**Fixes**

- `4a7973d`: persist each host's negotiated pairing key and retain keys missing from UI snapshots ([PR #36](https://github.com/kxn/nsteamlink/pull/36)).
- `63075fc`: increase deko quad capacity to prevent the manual PC page from exiting ([PR #37](https://github.com/kxn/nsteamlink/pull/37), [Issue #35](https://github.com/kxn/nsteamlink/issues/35)).
- `1f55e51`: integrate upstream decoder recovery and supply platform streaming capabilities from the app ([Issue #38](https://github.com/kxn/nsteamlink/issues/38)).

**Build and dependencies**

- `689ecd8`, `d09e63f`: update IHSlib for pairing key exchange and subnet broadcast discovery.
- `552c839`: consolidate IHSlib fork maintenance on one branch and pin the dependency commit.

**Documentation**

- `2c85f49`, `7861d68`: document official-client key exchange and source/device evidence for Switch pairing and host discovery.

### Thanks

- Thank you to **Simone Caronni ([@scaronni](https://github.com/scaronni))** for PRs #36 / #37 and the related IHSlib work: pairing key exchange, per-host key persistence, subnet discovery, and the manual PC page fix, with Switch/Linux Steam host validation evidence.
- Thank you to **[@akiriroll](https://github.com/akiriroll)** for reporting discovery failure and the manual PC page exit in Issue #35, including the device environment and reproduction details.
- Thank you to **Mariotaku ([@mariotaku](https://github.com/mariotaku))** and **[@skwizzy222](https://github.com/skwizzy222)** for the upstream decoder-loss recovery work and original idea integrated in this release ([IHSlib commit 6721ecc](https://github.com/mariotaku/ihslib/commit/6721ecc1a31ed2a39af5a84a0df43158816b0dc6)).
- Thank you to **Sven** for providing an original-model Nintendo Switch for development and device testing, and to the authors and maintainers of IHSlib, FFmpeg, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

### Validation and evidence scope

PR #36 records device results for discovering a Linux Steam host from Switch, pairing successfully, and streaming again after restarting the app without re-pairing. Integration commit `1f55e51` passed desktop tests with diagnostics ON/OFF (55 each), Switch release/diagnostic builds, and release tooling checks. The tag workflow repeats desktop tests, Switch builds, release diagnostic-exclusion checks, and artifact structure/provenance validation before publication.

The effects of the new capability fields and decoder recovery across different Steam hosts, real network loss, and NVDEC errors still require device validation. These builds and tests do not establish device proof for those cases or the hbmenu return lifecycle.

### Download and update

Download the `.nro` attachment from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.2.1). If you already installed a HOME shortcut, update its fixed target at `sdmc:/switch/nsteamlink/nsteamlink.nro`. The release NRO excludes advanced diagnostics and includes on-device HOME shortcut installation; a standalone `.nsp` is provided only when packaging keys are configured for the release build. Use `SHA256SUMS`, `build_identity.json`, and the SDK package list to verify artifacts and build provenance.

[Full changelog: v0.2.0 → v0.2.1](https://github.com/kxn/nsteamlink/compare/v0.2.0...v0.2.1)
