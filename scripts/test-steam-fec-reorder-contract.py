#!/usr/bin/env python3
"""Run real UDP comparisons and reject corrupted observation transcripts.

Counterexamples execute a transcript adapter that exits normally, not a mutant
decoder/official client. They prove comparison checks, not mutation coverage of
production code. --native-report reuses a separately captured actual Native run.
"""
import argparse
from copy import deepcopy
import gzip
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

if not __debug__:
    raise RuntimeError("This audit requires Python assertions; -O is not supported")

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "fec_reorder_check", ROOT / "scripts/check-steam-fec-reorder-process.py"
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def checked(receiver, case, bank):
    result = check.verify(receiver, case, bank)
    # This declared 5Hz schedule never applies FIFO byte pressure. Compare
    # every actual SDK input identity too; visible-picture selection remains
    # a distinct platform boundary, with every observed pixel checked above.
    native_ids = [r["id"] for r in result["native"]["load"]["sdk"]]
    source_ids = [r["id"] for r in case["process"]["pictures"]]
    assert native_ids == source_ids, (
        case["name"],
        "SDK identity",
        native_ids,
        source_ids,
    )
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--native-report", type=Path)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    source = json.loads(
        gzip.decompress(
            (
                ROOT
                / "scripts/fixtures/steam-client-fec-reorder-process-reference.json.gz"
            ).read_bytes()
        )
    )
    check.metadata(source)
    bank = source["fec_encoder"]
    results, rejected = [], []
    with tempfile.TemporaryDirectory(prefix="fec-reorder-transcripts-") as td:
        directory = Path(td)
        data, adapter = directory / "report.json", directory / "adapter"
        adapter.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\nprint(Path({str(data)!r}).read_text())\n"
        )
        adapter.chmod(0o700)
        if a.native_report:
            captured = json.loads(a.native_report.read_text())
            assert [c["name"] for c in captured] == [c["name"] for c in source["cases"]]
        else:
            captured = None
        for index, case in enumerate(source["cases"]):
            if captured is not None:
                data.write_text(json.dumps(captured[index]["native"]))
            result = checked(
                adapter if captured is not None else a.receiver, case, bank
            )
            results.append(result)
            print(
                json.dumps({k: v for k, v in result.items() if k != "native"}),
                flush=True,
            )
        chosen = next(
            i
            for i, c in enumerate(source["cases"])
            if c["profile"] == "late_old" and not c["crc"]
        )
        case, baseline = source["cases"][chosen], results[chosen]["native"]

        def rejects(label, mutate):
            bad = deepcopy(baseline)
            mutate(bad)
            data.write_text(json.dumps(bad))
            try:
                checked(adapter, case, bank)
            except AssertionError:
                rejected.append(label)
            else:
                raise RuntimeError("Comparison accepted counterexample: " + label)

        rejects(
            "unexpected complete frame", lambda r: r["load"]["rx_ids"].insert(1, 101)
        )
        rejects(
            "unaccounted datagram", lambda r: r["fec_admitted"][1].update(packets=0)
        )
        rejects("missing unique shard", lambda r: r["fec_admitted"][1].update(unique=0))
        rejects("peer receive loss", lambda r: r["peer_socket"].update(drops=1))
        rejects(
            "recovery source frame",
            lambda r: r["load"]["recovery_inputs"][0].update(id=103),
        )
        rejects("missing recovery retry", lambda r: r.update(recovery_calls=1))
        rejects("SDK bytes", lambda r: r["load"]["sdk"][0].update(sha256="0" * 64))
        rejects(
            "decoded pixels", lambda r: r["load"]["pictures"][-1].update(md5="0" * 32)
        )

        def skip_sdk(r):
            fid = r["load"]["sdk"].pop(1)["id"]
            r["video"]["submits"] -= 1
            r["load"]["pictures"] = [p for p in r["load"]["pictures"] if p["id"] != fid]

        rejects("SDK frame skipped despite valid remaining pixels", skip_sdk)
        for label, mutate in (
            (
                "source strict key reset",
                lambda c: next(e for e in c["process"]["gap_states"] if e["id"] == 106)[
                    "after"
                ].update(strict=1),
            ),
            (
                "source request provenance",
                lambda c: c["process"]["gap_sends"][0].update(input_id=103),
            ),
            (
                "source decoded pixels",
                lambda c: c["process"]["pictures"][-1].update(md5="0" * 32),
            ),
        ):
            bad = deepcopy(case)
            mutate(bad)
            try:
                check.verify_source(bad)
            except AssertionError:
                rejected.append(label)
            else:
                raise RuntimeError("Source comparison accepted: " + label)
    report = dict(
        scope=__doc__,
        native_replayed=bool(a.native_report),
        cases=results,
        transcript_counterexamples=rejected,
    )
    if a.output:
        a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"PASS:10 official-client/Native schedules and {len(rejected)} transcript counterexamples"
    )


if __name__ == "__main__":
    main()
