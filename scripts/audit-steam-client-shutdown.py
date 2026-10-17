#!/usr/bin/env python3
"""Execute original Socket -> client queue -> transport retirement -> Stopping.

Pinned Android instructions run CRC RX, real reliable windows, control crypto /
owned queue / dispatcher, full config99 parsing, Connection Disconnect/Update,
client OnStreamDisconnected, OnThink and HandleStreamStopping. AES/HMAC
primitives, locks/refcounts, transport wait/read/write, StreamTransport Update,
decoder/input destructor bodies and network-stats Stop/result/save are adapters.
Streaming/Starting terminal bodies are adapted here; their prior audits remain
separate. Original default OnStreamUpdate and player OnStreamStopped execute.
No real Steam authentication, decoder device, whole stats scoring, producer lock
interleaving or Switch lifecycle equivalence is claimed. Stats hooks are source
only; native app notices are explicitly distinct outside the stopping boundary.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


network = module("network", "audit-steam-network-cycle.py")
handoff = module("handoff", "audit-steam-control-handoff.py")
c = network.cycle.config


class Shutdown(network.Network):
    init_handoff = handoff.Handoff.init_handoff
    decrypt = handoff.Handoff.decrypt
    mac = handoff.Handoff.mac
    packet_value = handoff.Handoff.packet_value
    construct_frame = handoff.Handoff.construct_frame
    observe_handoff = handoff.Handoff.observe_handoff

    def __init__(self, binary, phase, mask, crc):
        super().__init__(binary, crc)
        self.init_handoff(phase)
        self.call(self.symbols["_ZN17CUtlQueueBaseImplC2Ej"], c.CLIENT + 816, 8)
        self.actions = []
        self.source_stats = []
        self.mask = mask
        self.config_events = []
        self.wq(c.CLIENT + 264, self.alloc(4096))
        vt = self.alloc(4096)
        self.wq(c.CLIENT, vt)
        self.wq(vt + 48, 0x7ACFA8)
        self.wq(vt + 56, 0x7B0790)
        self.wq(vt + 64, c.STOP + 0x410)
        self.wq(self.connection + 368, c.CLIENT)
        self.wq(c.VTABLE + 104, c.STOP + 0x414)
        for bit, offset in enumerate((32, 40, 24)):
            if mask & (1 << bit):
                obj, ovt = self.alloc(4096), self.alloc(4096)
                self.wq(obj, ovt)
                self.wq(ovt + 8, c.STOP + 0x420 + bit * 4)
                self.wq(ovt + 24, 0x7B0790)
                self.wq(ovt + 32, 0x7B0790)
                self.wq(c.CLIENT + offset, obj)
            else:
                self.wq(c.CLIENT + offset, 0)
        self.b(c.CLIENT + 625, 3 if mask & 1 else 0)
        self.b(c.CLIENT + 626, 4 if mask & 2 else 0)
        self.callbacks.update(
            {
                0xC0E0B0: self.process_network,
                0xC0E0C0: lambda: self.ret(),
                0xC0E030: lambda: self.jump(0x7FB724),
                0xC11320: lambda: self.ret(12),
                0xC0E0E0: lambda: self.stage("starting"),
                0xC0E0F0: lambda: self.stage("streaming"),
                0xC0E040: self.stopping,
                0xC0B8E0: self.decoder_stop,
                0xC0C270: lambda: self.stats_hook("stop"),
                0xC0C280: lambda: self.ret(3),
                0xC0E070: lambda: self.stats_hook("save"),
                c.STOP + 0x410: self.closed,
                c.STOP + 0x414: self.player_stopped,
                c.STOP + 0x420: lambda: self.destroy("audio"),
                c.STOP + 0x424: lambda: self.destroy("video"),
                c.STOP + 0x428: lambda: self.destroy("input"),
            }
        )

    def notify(self):
        self.actions.append("config_notify")
        self.config_events.append(("notify", self.freeze(self.r(1)), bool(self.r(2))))
        self.ret()

    def save_config(self):
        self.actions.append("config_save")
        self.config_events.append(("save", self.freeze(c.CLIENT + 456), None))
        self.ret()

    def handler(self, tag, name=None):
        if tag not in (9, 106):
            self.actions.append(f"control_{tag}")
        return handoff.Handoff.handler(self, tag, name)

    def process_network(self):
        self.u.reg_write(c.X0, self.sock)
        self.jump(0x7FECD4)

    def closed(self):
        self.actions.append("transport_closed")
        self.u.reg_write(c.X0, c.CLIENT)
        self.jump(0x7B00D0)

    def stage(self, name):
        self.actions.append(name)
        self.ret()

    def stopping(self):
        self.actions.append("stopping")
        self.jump(0x7A7238)

    def decoder_stop(self):
        name = "audio" if self.r(0) == self.q(c.CLIENT + 32) else "video"
        self.actions.append(name + "_stop")
        self.ret()

    def destroy(self, name):
        self.actions.append(name + "_destroy")
        self.ret()

    def player_stopped(self):
        self.actions.append("player_stopped")
        self.jump(0x7B76E4)

    def stats_hook(self, name):
        self.source_stats.append(name)
        self.ret()

    def snapshot(self):
        h = self.observe_handoff()
        return dict(
            client=h["state"],
            transport=self.i(self.connection + 16),
            queue=h["queue"],
            events=h["events"],
            config=h["client_config"],
            sequence=h["receive_sequence"],
            actions=list(self.actions),
            audio=bool(self.q(c.CLIENT + 32)),
            video=bool(self.q(c.CLIENT + 40)),
            audio_id=self.u.mem_read(c.CLIENT + 625, 1)[0],
            video_id=self.u.mem_read(c.CLIENT + 626, 1)[0],
            local=self.u.mem_read(self.connection + 12, 1)[0],
            peer=self.u.mem_read(self.connection + 13, 1)[0],
            wires=list(self.wires),
            config_events=[
                dict(
                    kind=k,
                    wire=self.serialize(p).hex(),
                    **({"local_only": b} if b is not None else {}),
                )
                for k, p, b in self.config_events
            ],
        )


def schedules(binary):
    schema = c.descriptor_pb2.FileDescriptorProto.FromString(
        binary[0x3E5474 : 0x3E5474 + 21560]
    )
    pool = c.descriptor_pool.DescriptorPool()
    pool.Add(schema)
    Message = c.message_factory.GetMessageClass(
        pool.FindMessageTypeByName("CSetStreamingClientConfig")
    )
    bodies = [
        Message(
            config=dict(enable_unreliable_fec=True, desired_bitrate_kbps=12345)
        ).SerializeToString(),
        Message(
            config=dict(enable_unreliable_fec=False, desired_bitrate_kbps=23456)
        ).SerializeToString(),
    ]
    cases = []
    for crc in (False, True):
        for count in (1, 2):
            for mask in range(8):
                for action in ("timeout", "peer", "retire"):
                    controls = [
                        network.cycle.packet(
                            n,
                            kind=5,
                            channel=1,
                            payload=handoff.ciphertext(99, b, sequence=n),
                        )
                        for n, b in enumerate(bodies[:count])
                    ]
                    cases.append(
                        dict(
                            name=f"{action}_mask{mask}_count{count}_crc{int(crc)}",
                            mask=mask,
                            phase=6,
                            crc=crc,
                            action=action,
                            controls=controls,
                            bodies=[b.hex() for b in bodies[:count]],
                        )
                    )
    return cases


def audit(binary):
    assert hashlib.sha256(binary).hexdigest() == c.SHA
    cases = []
    for inp in schedules(binary):
        r = Shutdown(binary, inp["phase"], inp["mask"], inp["crc"])
        r.phase = "drain"
        r.wi(r.connection + 52, 1000000)
        r.wi(r.connection + 56, 1000000)
        # Preload through the real Socket/reliable/client delivery, then leave
        # the owned queue pending for OnThink's network closing/retirement step.
        r.now = 1000000
        r.prepare(inp["controls"], inp["crc"])
        r.ready = True
        r.eof_cost = 0
        wait = r.call(0x7FEB7C, r.sock)
        r.call(0x7FEB90, r.sock, wait)
        r.call(0x7FECD4, r.sock)
        before = r.snapshot()
        r.actions.clear()
        r.wires.clear()
        r.events.clear()
        r.wi(r.connection + 52, 1000000)
        r.now = 1000000 + 15 * 65536
        r.prepare(
            [network.cycle.packet(0, kind=9, channel=0, payload="00")]
            if inp["action"] == "peer"
            else [],
            inp["crc"],
        )
        r.ready = inp["action"] == "peer"
        r.eof_cost = 0
        observed = []
        source_stats = []
        for n in range(2):
            if n:
                r.now += 200
                r.prepare([], inp["crc"])
                r.ready = False
            r.actions.clear()
            r.wires.clear()
            r.events.clear()
            r.source_stats.clear()
            r.config_events.clear()
            if not n and inp["action"] == "retire":
                r.call(0x7FB724, r.connection)
            wait = r.call(0x7FEB7C, r.sock)
            r.call(0x7FEB90, r.sock, wait)
            r.call(0x7A5FF8, c.CLIENT)
            observed.append(r.snapshot())
            source_stats.append(list(r.source_stats))
        assert not r.asserts, r.asserts
        stopping = observed[0 if inp["action"] in ("peer", "retire") else 1]
        expected = ["transport_closed"]
        if inp["action"] in ("peer", "retire"):
            expected += [
                a
                for _ in inp["controls"]
                for a in ("control_99", "config_notify", "config_save")
            ]
        expected += ["stopping"]
        if inp["mask"] & 1:
            expected += ["audio_stop", "audio_destroy"]
        if inp["mask"] & 2:
            expected += ["video_stop", "video_destroy"]
        expected += ["player_stopped"]
        if inp["mask"] & 4:
            expected += ["input_destroy"]
        assert stopping["actions"] == expected, (inp["name"], stopping["actions"])
        assert stopping["client"] == 0 and stopping["transport"] == 3
        assert len(before["queue"]) == len(inp["controls"]) and not stopping["queue"]
        assert source_stats[0 if inp["action"] in ("peer", "retire") else 1] == [
            "stop",
            "save",
        ]
        cases.append(
            dict(input=inp, before=before, observed=observed, source_stats=source_stats)
        )
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--refresh-reference", action="store_true")
    a = p.parse_args()
    report = dict(
        binary_sha256=c.SHA, scope=__doc__, cases=audit(a.binary.read_bytes())
    )
    ref = ROOT / "scripts/fixtures/steam-client-shutdown-reference.json"
    if a.refresh_reference:
        if ref.exists():
            assert (
                json.loads(ref.read_text())["cases"]
                == report["cases"][: len(json.loads(ref.read_text())["cases"])]
            )
        ref.write_text(json.dumps(report, indent=2) + "\n")
    else:
        assert json.loads(ref.read_text()) == report
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Official client shutdown:", len(report["cases"]), "cases")


if __name__ == "__main__":
    main()
