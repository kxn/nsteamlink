#!/usr/bin/env python3
"""Opt-in Switch IHS media test; requests a Steam desktop stream.

The network-only tool and NRO retain their separate mode whitelist. This tool
builds another private NRO, receives 30 encoded frames without decoding or saving
them, and joins IHS workers before destroying SNS and returning the profile.
Loss mode waits for 30 frames before dropping the primary, and requires 30 fresh
frames after switching POP plus the network fixture's five-second E2E hold.
loss-warm waits 15 seconds before injection; it keeps the same recovery criteria.
"""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('sns_private', Path(__file__).with_name('switch-sns-network-probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

if __name__ == '__main__':
    probe.main(media=True)
