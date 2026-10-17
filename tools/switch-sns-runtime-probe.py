#!/usr/bin/env python3
"""Run a private fixture around the full Switch client, using its normal UI.

Automatically isolates LAN discovery in the fixture process, starts streaming
from cloud discovery, checks actual presentation/audio queue and synthetic SDL
input/ACK, then disconnects and exits. Does not prove physical sound or buttons.
The user only prepares hbmenu netloader. Identity and readback use the existing
private RomFS/AES-GCM delivery path. Never publish the private NRO.
"""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('sns_private', Path(__file__).with_name('switch-sns-network-probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

if __name__ == '__main__':
    probe.main(runtime=True)
