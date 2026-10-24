# Changelog

[简体中文](CHANGELOG.md)

## [0.7.2] - 2026-10-24

Previous stable release: **v0.7.1**. Target: `main`; source: [`v0.7.2`](https://github.com/kxn/nsteamlink/tree/v0.7.2).

### Highlights

- Fix doubled settings values such as quality, resolution and language selections.
- Rename the pairing entry to “Show pairing code”. Disable it with “Cloud unavailable” until the cloud session is ready; hide its arrow and dim its surface and text. Restore it on connection. Manual address entry stays available.
- Add “Skip this version” to the update dialog. Select it using the touchscreen, then confirm with A; B cancels without saving. The selected version stays hidden across restarts, while later versions can still prompt.

### Validation and scope

Checked actual Chinese and English renders. Regression coverage includes cloud availability, disabled activation, ignored-version persistence across restart, later-version prompts and failed file-replacement recovery. No new hardware testing was performed for this release. The unresolved Internet connectivity report in #93 is not claimed fixed.

### Commits by type

- UI fixes: `1a94f48` remove doubled settings text; `e36771f` gate pairing-code entry on cloud availability; `054cf01` hide disabled arrows and strengthen disabled styling.
- Updater: `ad40898` allow opting out of a specific release notification.
- Release: version and bilingual release notes.

Thanks to [@jiaruisme](https://github.com/jiaruisme) for reporting [#93](https://github.com/kxn/nsteamlink/issues/93).

[Full changelog: v0.7.1 → v0.7.2](https://github.com/kxn/nsteamlink/compare/v0.7.1...v0.7.2)

## [0.7.1] - 2026-10-23

Previous stable release: **v0.7.0**. Target: `main`; source: [`v0.7.1`](https://github.com/kxn/nsteamlink/tree/v0.7.1).

### Highlights

- Short-press Capture during streaming to send **Steam Guide**. Enabled by default; choose Capture or Off under **Settings → Application → Steam Guide key**. Off preserves system screenshots; screenshots also remain available outside streaming.
- Preserve the previous toggle when loading settings. Gate Guide on input readiness, focus and session lifetime, and send its press/release through the existing controller path without changing ordinary button or gyro mappings.
- Exclude Capture self-tests, HOME capability probes, virtual-controller injection and their diagnostic entry points from the ordinary package. HOME remains a Switch system button.

### Validation and known limits

Regression coverage includes settings persistence, input-readiness gates, Guide press/release and cleanup. Offline Switch tests verified Capture notification ownership, two virtual Capture notifications and resource cleanup; these do not establish physical-button or host-overlay behavior. A user previously observed a physical first press taking a screenshot before subsequent presses worked. Its cause remains unconfirmed; this release does not claim to fix that first-press behavior.

### Commits by type

- Input/settings: `5c0d283` Capture mapping and opt-out; `27a4b3b` Application settings placement and bounded diagnostics.
- Tests/documentation: `11f00d6` system-button and Guide protocol references; `23cf2c3` observe HOME without clearing the shared event; `a29a7ac` record hardware evidence and validation limits.
- Release: version, bilingual notes and button-diagnostic exclusion checks. Adaptive-quality research remains on the research branch.

Download the ordinary NRO from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.7.1), or use the in-app updater. Existing pairing data is retained.

[Full changelog: v0.7.0 → v0.7.1](https://github.com/kxn/nsteamlink/compare/v0.7.0...v0.7.1)

## [0.7.0] - 2026-10-23

Previous stable release: **v0.6.0**. Target: `main`; source: [`v0.7.0`](https://github.com/kxn/nsteamlink/tree/v0.7.0).

### Highlights

- Add account-free cloud pairing, host discovery and Internet streaming, with automatic direct/Valve SDR routing. The Add host page offers manual address and pairing-code flows; host status distinguishes LAN, Internet, offline and unpaired devices.
- Query multiple public DNS providers and rotate HTTPS candidates across subnets. Start on the first answer and allow at most three concurrent directory/CM TLS candidates while retaining certificate verification. This compatibility policy addresses observed reachable-IP/unreachable-HTTPS paths; it cannot guarantee reachability on every network.
- Separate signaling preparation from the media connection deadline, explicitly hand off IHS/SDK ownership, and fix discovery responsiveness, reply forwarding, auxiliary Switch UDP buffers and end-game completion. Preparation has a bounded 90-second budget; media retains its own connection deadlines.
- Share in-flight DNS work with independent cancellation, manage HTTP lifetime and joined workers, and recover Switch cache replacement. Retain v0.6.0 gyro support.
- Exclude diagnostic HTTP/UDP endpoints, nxlink/persistent logging, fault injection and probes from ordinary packages, with object and ELF/NRO publication gates.

### Validation and limits

The user confirmed hotspot discovery, streaming, controller input and timely shutdown. Saved `d6dcce4` logs identify **Valve SDR relay** routing, about 2.9 seconds of signaling preparation before IHS admission, acknowledged controller reports and about 2.9 seconds to complete end-game/disconnect. This validates that hotspot SDR session, not every NAT type or network. Retransmission and video recovery remain visible; experience still depends on network quality. Tag CI reruns diagnostic ON/OFF desktop tests, Switch builds and diagnostic-exclusion counterexamples.

### Commits by type

- Internet functionality and UI: pairing, discovery, SNS/SDR, status and integration commits in [PR #54](https://github.com/kxn/nsteamlink/pull/54).
- Connection/recovery: `d294b91` reply forwarding; `6e427e9`/`7a30734` DNS fanout; `5d28638`/`16cd183`/`4eb9804` discovery and auxiliary sockets; `ebe0cde` initialization ownership; `d6dcce4` LAN startup when HTTPS initialization fails.
- Mainline integration: `8bddbd0` retains both gyro and Internet support.

Download the ordinary NRO from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.7.0), or use the in-app updater. Pairing data is retained. Diagnostic packages are not published.

[Full changelog: v0.6.0 → v0.7.0](https://github.com/kxn/nsteamlink/compare/v0.6.0...v0.7.0)

## [0.6.0] - 2026-10-23

Previous stable release: **v0.5.1**. This release: **v0.6.0**. Target branch: `main`; tagged source: [`v0.6.0`](https://github.com/kxn/nsteamlink/tree/v0.6.0).

### Highlights

- **Switch gyro input**: forward libnx motion samples to Steam Input. Configure gyro as a mouse in Steam's desktop controller layout to move the pointer by rotating the Switch. A user has verified this on hardware.
- **Complete the host sensor protocol**: advertise motion capability and include normal-sensor freshness and timestamps in Generic RAW V3 reports. Identical angular velocities at different sample times are still reported. Button, stick, or acceleration-only changes do not replay an already submitted gyro sample, while pending samples are preserved.
- **Reduce device trial and error**: add offline execution of a pinned Steam Host DLL and full/delta fixtures from the production C packer. Remove experimental switches that confused normal and left sensor slots, and correct the earlier reverse-engineering conclusions.

### Commits by type

- **Feature**: `d13ff0c`, Switch motion sampling, unit conversion, and HID injection.
- **Fix**: `b6421a2`, the complete RAW V3 sensor contract, event merging, capability declaration, and host verification; IHSlib pinned to `0bc7087`.
- **Tests**: `0dd07e5`, isolated motion probes and an axis viewer; `b6421a2`, production C reports checked against original host instructions. Test tools are excluded from the ordinary NRO.
- **Documentation**: record the user's desktop mouse result, update Chinese and English usage instructions, and explicitly retract the earlier claim that remote Generic rejects 0x400.

### Validation and evidence scope

Eight related desktop regression tests passed, and the fixed Switch build succeeded. Offline original-DLL checks cover full/delta decoding, invalid CRC rejection, normal sensor slot selection, enable/capability gates, and isolated quaternion integration and gyro-source consumption.

The user confirmed that gyro controls the mouse after changing Steam's desktop controller layout. **In-game behavior and compatibility have not yet been verified** and depend on each game's Steam Input layout. This result does not establish support for every controller configuration or calibration accuracy. The cause of input loss in earlier experimental builds remains undetermined.

The tag workflow rebuilds the release commit, runs desktop diagnostics ON/OFF tests, builds ordinary and diagnostic Switch configurations, and checks diagnostic exclusion counterexamples and artifact identity. Publication follows successful checks.

### Download and update

Download the ordinary `.nro` from [this release](https://github.com/kxn/nsteamlink/releases/tag/v0.6.0), or use the in-app updater. Existing HOME shortcuts continue to use `sdmc:/switch/nsteamlink/nsteamlink.nro` and do not need reinstalling.
Attachments contain the ordinary NRO, source identity, diagnostic exclusion report, SDK package list, license text, and `SHA256SUMS`; diagnostic builds and motion probes are not published.

Thanks to users providing playtesting and gyro feedback, **Sven** for the original-model Switch, **Simone Caronni ([@scaronni](https://github.com/scaronni))**, and the authors and maintainers of IHSlib, FFmpeg, Opus, SDL, libnx, devkitPro, deko3d, and nx-hbloader.

[Full changelog: v0.5.1 → v0.6.0](https://github.com/kxn/nsteamlink/compare/v0.5.1...v0.6.0)

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
