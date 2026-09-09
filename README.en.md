<p align="center">
  <img src="assets/branding/icon.jpg" alt="NSteamLink" width="112" height="112">
</p>

# NSteamLink

**Play your PC's Steam games on your Switch.**

NSteamLink is a Steam Remote Play client for Nintendo Switch homebrew.
Your PC runs the game; your Switch receives video and audio and sends your controls back.
Pick up your Joy-Con, choose a PC, and return to your last game.

[Download](https://github.com/kxn/nsteamlink/releases/latest) · [简体中文](README.md) · [Report an issue](https://github.com/kxn/nsteamlink/issues)

## Features

- **Pair once, connect again** — background PC discovery, with pairing and recent games saved per PC.
- **Launch recent games** — browse game artwork and select a card to request game launch and streaming.
- **Handheld navigation** — use sticks, the D-pad or touch, with smooth horizontal card scrolling.
- **Full-screen play** — Joy-Con rumble and an on-demand menu that stays out of the way.
- **End games remotely** — disconnect while leaving the game running, or ask the PC to quit it.
- **Make it yours** — English and Chinese, picture preferences and UI sounds.
- **Launch from HOME** — add a shortcut from the app's options.

## Get started

You need a homebrew-capable Switch and a PC with **Steam Remote Play** enabled.
Connect both devices to the same local network. Keep the PC on with Steam running.

1. Download the `.nro` file from [Releases](https://github.com/kxn/nsteamlink/releases/latest).
2. Save it as `switch/nsteamlink/nsteamlink.nro` on your SD card.
3. **Hold R while launching a game** to enter full-memory hbmenu, then open NSteamLink.
4. Select your PC, enter the pairing code shown on your Switch into Steam on the PC, and follow the prompts.

**Album applet mode is not supported.** The app will explain how to launch with enough memory and let you return with B.

Use **Y to open Steam** on your first visit. Games played during streaming appear in your recent games for direct launch next time.

## Controls

| Action | Control |
|---|---|
| Select a game | Left/right on a stick or D-pad; swipe cards on the touchscreen |
| Switch PCs | L / R, with hints shown when multiple PCs are available |
| Launch the selected game / confirm | A |
| Open Steam | Y |
| Options | X |
| Back / exit | B |
| Open the streaming menu | Hold **− and + together for 0.8 seconds** |

The home screen and menus also support touch. **Disconnect** leaves the PC game running.
**End game** asks the PC to quit the game and end the session.

## Add a HOME Menu shortcut

Open **X Options → Add to HOME Menu** and confirm. No key file needs to be supplied manually.
Your CFW must support homebrew application installation and launch.

The shortcut opens `switch/nsteamlink/nsteamlink.nro` on your SD card. Keep that file in place.
To update, replace it with the new NRO; you do not need to install the shortcut again.

## Help and development

[Report an issue](https://github.com/kxn/nsteamlink/issues) with the version shown at the top right,
steps to reproduce, and a screenshot or error message.

For implementation details and source builds, see the [technical and development guide](docs/TECHNICAL.md) (Chinese).

## Credits and license

Built with open-source projects including IHSlib, FFmpeg, SDL, libnx, devkitPro and nx-hbloader.
NSteamLink is distributed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html); third-party components retain their own licenses.

This is an unofficial community client and is not affiliated with Valve or Nintendo.
