# AGENTS.md

## Evidence Discipline

- Treat user-provided real-device observations, screenshots, logs, and exact console text as primary evidence.
- Do not override a user-observed Switch screen state with PC-side tool behavior. For example, `nxlink` exiting normally is not evidence that the Switch returned to hbmenu.
- Before changing protocol flow, read the relevant project docs and source references first. Record which file or log supports the conclusion.
- Separate statements into:
  - Evidence: directly observed logs, screenshots, source lines, command output, or documented behavior.
  - Conclusion: what the evidence proves.
  - Hypothesis: plausible but unproven explanations that still need validation.
- Do not present hypotheses as conclusions. Mark them as `hypothesis` or `待验证`.
- If a prior conclusion is contradicted by new evidence, explicitly retract it in docs before building on it.
- For Switch testing, do not use TCP port probes against netloader port `28280`; use `nxlink` directly because empty TCP connections can consume netloader's receive attempt.
- This project's Switch debug unit is `10.10.10.77`; hbmenu netloader listens on port `28280`. Do not infer another Switch IP from ARP/neighbour tables unless the user explicitly says the IP changed.
- Keep Steam authentication semantics aligned with `docs/STEAM_REMOTE_PLAY_AUTH.md`: do not collapse pairing PIN / authorization code and connect/security PIN into one concept, and do not change protocol flow without a source/log-backed evidence note.
- Current tasks and status live in GitHub Issues on the private repo `kxn/nsteamlink` (with milestones). `docs/M2_STATUS.md` / `docs/M3_STATUS.md` / `docs/M4_STATUS.md` are frozen archives: never take tasks or "未处理事项" from them without cross-checking Issues first.

## Switch Homebrew Runtime Discipline

- Treat returning to hbmenu as returning to a loader ABI, not as proof that the process state was fully reset.
- Before any Switch NRO returns from `main()`, it must satisfy the Homebrew ABI cleanup rule: no leaked handles, no dirty memory-state assumptions, and no leftover background threads.
- Do not use `pthread_detach()` or fire-and-forget threads in Switch NRO code unless a decision record proves they terminate before returning to hbmenu. Prefer joinable threads and explicit `stop -> join -> destroy`.
- Cleanup order for Switch probe/client code must be evidence-backed and logged. Stop/join app-owned threads before destroying their dependencies; stop/join IHS session/client workers before `IHS_Quit()` / `socketExit()`; release SDL/Mesa resources before returning to hbmenu.
- Runtime diagnostics must never sit on the rendering, input, or local-exit hot path. nxlink/stdout logging must be non-blocking or bounded; high-rate IHS/session logs must be rate-limited before testing interactive streaming.
- After changes touching threads, applet lifecycle, SDL/Mesa, sockets, or NRO exit, one successful run is weaker evidence than two consecutive launches. Do not automatically require repeated hbmenu/netloader testing for routine work; when a second launch materially reduces lifecycle risk, explain the evidence value and ask before spending the user's time.
- `nxlink` exiting normally is never sufficient evidence that the Switch screen returned to hbmenu. If the user declines hbmenu/second-launch testing, record PC-side cleanup as partial evidence and leave lifecycle safety as lower-confidence instead of forcing another manual test.

## Known Project Pitfalls

- `gamesRunning=0` in Steam discovery logs means Steam was discovered but no game was running. It is not evidence that UDP broadcast failed.
- Steam Remote Play has separate pairing authorization code and connect/security PIN semantics. Re-read `docs/STEAM_REMOTE_PLAY_AUTH.md` before changing auth UI or protocol flow.
- The Switch test unit is normally in full application mode when the user says it is. Do not re-litigate applet mode unless a new observation directly points there.
- SDL2/Mesa work should follow the upstream/devkitPro example lifecycle unless a decision record documents why this project must diverge.
- HID/input diagnostics can create control-channel retransmission log floods. If frames or local `+` freeze only after pressing controls, check log backpressure and main-loop drain behavior before changing protocol semantics.
- A returned first launch is not enough for high-confidence loader lifecycle proof. Do not run or request repeated hbmenu return tests by default; only do so for lifecycle-risk changes after explaining why it matters or when a new failure points there.
