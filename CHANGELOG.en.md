# Changelog

[简体中文](CHANGELOG.md)

## [0.5.1] - 2026-10-20

Previous stable release: **v0.5.0**. This release: **v0.5.1**. Target branch: `main`; tagged source: [`v0.5.1`](https://github.com/kxn/nsteamlink/tree/v0.5.1).

### Highlights

- **Streaming recovery and shutdown**: improve video-loss feedback, keyframe recovery, decoder queues, and frame ownership. Preserve the final eligible receive batch during shutdown and treat normal close-time cancellation separately from submission failures.
- **Discovery and retries**: use bounded socket recreation when every discovery broadcast destination fails. Correct the order of receive batches, discovery sends, and launch retries while preserving host identity and the current request. Full discovery rounds and fast retries follow the verified official deadlines and sequence rules.
- **Authorization and credentials**: improve automatic authorization within the original launch request, credential-save attempts before confirmation, and key storage under the selected Steam identity. Pairing authorization codes and connection security codes remain separate.
- **Ordinary release build**: explicitly disable application and SDK diagnostics. The published NRO excludes the debug UDP endpoint, nxlink/file logging, HID history capture, advanced diagnostic overlays, fault injection, and test probes. Publication gates inspect actual objects, ELF/NRO consistency, and the attachment allowlist. Tag workflows retain diagnostic exclusion tests without uploading diagnostic packages.

### Commits by type

- **Recovery and lifecycle fixes**: `3be848b`, UDP receive boundaries; `07ed493`, close-time submission cancellation; `a94d163` and `c5a7cfb`, decoder stop batches and final frame assembly.
- **Discovery fixes**: `8fad3ca` and `9f193c8`, receive recovery and failed-startup cleanup; `6c7a02d` and `e1274b5`, broadcast recreation and discovery rounds; `fe5bc32`, `e46cf75`, and `9de506c`, operation, callback, and joint retry ordering ([PR #87](https://github.com/kxn/nsteamlink/pull/87)).
- **Authorization and release checks**: `a3000a4`, `eeeb684`, `b51680d`, and `03bf16e`, authorization and credential lifetimes; `55fcf98`, SDK diagnostic exclusion and artifact gates.
- **Validation and references**: original-instruction comparisons, audio gap/stop cases, cross-group and cross-channel FEC, capacity boundaries, and isolated Switch probes. Research and test fixtures are excluded from the ordinary NRO.

### Validation and evidence scope

The verified `9de506c` / IHSlib `bfb7100` passed 239 ordinary desktop tests, 245 diagnostic tests, nine related ASan/UBSan/leak checks, and two full CI runs. Switch checks covered diagnostic exclusion in 45 product translation units, SDK objects, and the final NRO, with 15 contamination cases and nine probe artifact/call-path faults rejected. The tag workflow rebuilds the final release commit and repeats these checks.

Real Steam→Switch sessions verified FEC reconstruction after one missing data shard and recovery after an entire group was erased beyond its repair capacity: an actual recovery request was sent, a later keyframe was received and submitted, and playback continued for 30 seconds. Loss-to-keyframe-submission was about 40 milliseconds in this controlled LAN run, with zero submission errors ([device evidence](https://github.com/kxn/nsteamlink/issues/69#issuecomment-6281073775)). This is not a latency guarantee for other networks or proof of the original intermittent-stall/Steam Big Picture flicker cause. Network switching, complete session disconnection, and Internet connectivity remain separate work.

### Download and update

Download the ordinary `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.5.1), or use the in-app updater. Existing HOME shortcuts continue to target `sdmc:/switch/nsteamlink/nsteamlink.nro`. Attachments contain only the ordinary NRO, source identity, diagnostic exclusion report, SDK package list, license text, and `SHA256SUMS`.

Thanks to users providing playtesting and device-test feedback, **Sven** for the original-model Switch, **Simone Caronni ([@scaronni](https://github.com/scaronni))**, and the authors and maintainers of IHSlib, FFmpeg, Opus, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

[Full changelog: v0.5.0 → v0.5.1](https://github.com/kxn/nsteamlink/compare/v0.5.0...v0.5.1)

## [0.5.0] - 2026-10-19

Previous stable release: **v0.4.0**. This release: **v0.5.0**. Target branch: `main`; tagged source: [`v0.5.0`](https://github.com/kxn/nsteamlink/tree/v0.5.0).

### Highlights

- **1080p streaming**: choose Auto, 720p, or 1080p. Auto requests 720p in handheld mode and 1080p when docked at connection time. Handheld mode also supports manually selected 1080p, decoded at full resolution and scaled to the internal screen. Docked presentation preserves native 1080p detail.
- **Settings categories**: X on the home screen opens Settings directly, with Video & audio, Network, Host management, and Application. Quality, resolution, bitrate, and language entries show the saved value. Sound, error correction, and update checks use consistent graphical switches. Only entries that navigate to another page show arrows.
- **Simpler streaming menu**: Streaming offers only Resume game, End game and disconnect, and Disconnect. Settings are available from the home screen. Confirmations distinguish closing the host game from disconnecting while leaving it running.
- **Interface cleanup**: consolidate host terminology, remove repeated timing explanations, and revise Chinese/English layouts, return focus, and controller/touch behavior for disabled actions.

### Commits by type

- **Features**: `3560194`, selectable resolution, automatic docked negotiation, and native 1080p presentation ([PR #60](https://github.com/kxn/nsteamlink/pull/60), [Issue #12](https://github.com/kxn/nsteamlink/issues/12)); `719deef`, settings categories and streaming menu reorganization.
- **Fixes**: `be19b8a`, resolution navigation and drawer layout; `1e74f71`, nxlink argument ordering for device probes.
- **Development tests**: `1e4e13c`, an isolated forced-1080p test build. The published application defaults to automatic resolution.

### Validation and evidence scope

All 173 local regression tests ultimately passed, along with the ordinary Switch build and release diagnostic exclusion check. Chinese and English menus were inspected using actual rendering. All 12 Switch hardware-decode/native-1080p pixel cases passed, with clean test resources and no heap growth; the maintainer reported successful handheld playtesting of forced-1080p streaming.

A physical dock was unavailable, so HDMI output and physical dock hotplug remain untested. These results do not establish sustained 1080p60 performance or a complete latency baseline. The tag workflow repeats desktop diagnostics ON/OFF tests, ordinary and diagnostic Switch builds, and checks the version, NRO structure, source identity, and attachment checksums before publishing.

### Download and update

Download the ordinary `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.5.0), or use the existing in-app updater. An installed HOME shortcut targets `sdmc:/switch/nsteamlink/nsteamlink.nro`. Resolution is under **Settings → Video & audio → Resolution**; automatic update checks are under **Settings → Application**. Netloader launches skip update checks.

Attachments contain the ordinary NRO, `SHA256SUMS`, `build_identity.json`, the SDK package list, and license text. Forced-1080p test packages and standalone NSPs are not published.

Thanks to users for the 1080p request and menu feedback, Sven for the original-model Switch, and the authors and maintainers of IHSlib, FFmpeg, Opus, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

[Full changelog: v0.4.0 → v0.5.0](https://github.com/kxn/nsteamlink/compare/v0.4.0...v0.5.0)

## [0.4.0] - 2026-10-19

Previous stable release: **v0.3.0**. This release: **v0.4.0**. Target branch: `main`; tagged source: [`v0.4.0`](https://github.com/kxn/nsteamlink/tree/v0.4.0). Runtime code is unchanged from the tested `d05abab` candidate, with IHSlib pinned to `afed70e`; the release commit only updates the version and bilingual notes.

### Highlights

- **Media recovery and transport**: adjust video loss feedback, keyframe recovery, decoder resets, frame presentation timing, and reliable transport acknowledgements, retransmission, and receive windows against verified official-client paths. Integrate FEC reception and the saved FEC setting.
- **Audio playback**: adjust Opus loss recovery, jitter buffering, raw audio playback, and player startup/shutdown, with revised ownership of media data and playback devices.
- **Connection tests and settings**: integrate first-time and manual network tests, saved results, recommended presets, and complete client configuration persistence. Distinguish transport, authentication, and media connection waits; remove automatic disconnects based on a fixed video-stall timeout.
- **Switch capabilities**: report the actual backend's 720p60 / H.264 support and omit unverified maximum decode bitrates. Album applet mode can install the HOME shortcut through a confirmation screen with activity and elapsed-time feedback; streaming still requires full application mode.
- **Protocol references**: add Steam Link Anywhere / SDR client policies, protocol schemas, and reproducible offline audits. This research does not itself provide a complete, usable Internet streaming backend.

### Commits by type

- **Features**: `1a49cca`, HOME shortcut installation in applet mode ([Issue #44](https://github.com/kxn/nsteamlink/issues/44)); `c4de796`, `2512fb1`, `d6fab25`, FEC reception, connection lifecycle, and complete configuration persistence.
- **Fixes and integration**: `7c3b220`, `a3fe641`, `d095563`, keyframes, content modes, and encrypted fragments; `1e8e542`, `87e6c4f`, audio recovery and buffering; `59eebda`, `697f9b9`, `40dd5b3`, network tests, connection waits, and retired sessions. See [PR #53](https://github.com/kxn/nsteamlink/pull/53) for the full integration.
- **Research and documentation**: [PR #50](https://github.com/kxn/nsteamlink/pull/50), Anywhere / SDR policies and schemas; [PR #53](https://github.com/kxn/nsteamlink/pull/53), official media, transport, settings, and network-test comparisons.

### Validation and evidence scope

The maintainer tested the `d05abab` main-branch candidate on a real Switch and reported that it worked well. Main-branch CI passed 170 desktop tests each with diagnostics ON/OFF, plus ordinary and diagnostic Switch builds. The tag workflow repeats these checks and verifies the version, release diagnostic exclusion, NRO structure, build provenance, and attachment checksums before publishing.

Offline original-instruction replays and controlled-peer tests prove only the corresponding inputs and boundaries. FEC activation with real Steam, long-term behavior across networks and hosts, hardware errors, and the hbmenu return lifecycle need further validation. This does not establish that the previously reported intermittent stalls or Steam Big Picture flickering are fully resolved. Unmerged changes on the continuing reverse-engineering branch are excluded; remaining protocol differences are tracked in [Issue #52](https://github.com/kxn/nsteamlink/issues/52).

### Thanks

Thank you to users who provided playtest feedback and issue reports, **Sven** for the original-model Nintendo Switch, **Simone Caronni ([@scaronni](https://github.com/scaronni))**, and the authors and maintainers of IHSlib, FFmpeg, Opus, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

### Download and update

Download the `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.4.0). Starting with v0.3.0, SD-card launches support in-app updates; netloader launches skip update checks. An installed HOME shortcut targets `sdmc:/switch/nsteamlink/nsteamlink.nro`. Release builds exclude advanced diagnostics and include `SHA256SUMS`, `build_identity.json`, and the SDK package list. Only the NRO is published, with no standalone NSP or test tools.

[Full changelog: v0.3.0 → v0.4.0](https://github.com/kxn/nsteamlink/compare/v0.3.0...v0.4.0)

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
