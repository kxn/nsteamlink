#!/usr/bin/env python3
"""Stage pinned VCL assets and a diagnostics-only pipeline size experiment.

The product source is never edited. The generated copy changes one local size
guard for a separate capability executable, never a Steam policy or SDK limit.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pipeline", required=True, type=Path)
    p.add_argument("--fixtures", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((args.fixtures / "manifest.json").read_text())
    rows, initializers = [], []
    assert len(manifest["cases"]) == 2
    for row in manifest["cases"]:
        name = row["name"]
        assert name in ("pcm720", "pcm1080")
        archive = (args.fixtures / (name + ".h264.gz")).read_bytes()
        assert sha(archive) == row["archive_sha256"]
        raw = gzip.decompress(archive)
        assert sha(raw) == row["fixture_sha256"] and len(raw) == sum(row["sizes"])
        # Verify actual Annex B boundaries, including absence of filler NAL12.
        starts = [n for n in range(len(raw) - 4) if raw[n : n + 4] == b"\0\0\0\1"]
        assert (
            [raw[n + 4] & 31 for n in starts] == row["nal_types"] == [9, 7, 8, 5, 9, 1]
        )
        assert starts[4] == row["sizes"][0]
        assert starts[4] - starts[3] - 4 == row["vcl_bytes"]
        (args.output / (name + ".h264")).write_bytes(raw)
        initializers.append(
            '{"%s",%u,%u,%u,%u,%u,"%s","%s"}'
            % (
                name,
                row["width"],
                row["height"],
                row["sizes"][0],
                row["sizes"][1],
                row["vcl_bytes"],
                row["fixture_sha256"],
                row["visible_yuv_md5"],
            )
        )
        rows.append(row)
    header = (
        "static const vcl_spec vcl_specs[] = {\n" + ",\n".join(initializers) + "\n};\n"
    )
    (args.output / "vcl_fixture_metadata.h").write_text(header)
    source = args.pipeline.read_text()
    needle = "#define MAX_PACKET   (2u * 1024u * 1024u)"
    assert source.count(needle) == 1 and source.count("MAX_PACKET") == 3
    copy = (
        '#if !NSL_DIAGNOSTICS\n#error "VCL capability copy requires diagnostics"\n#endif\n'
        + source.replace(needle, "#define MAX_PACKET   (4u * 1024u * 1024u)")
        + "\nconst unsigned nsl_vcl_probe_limit_bytes = MAX_PACKET;\n"
    )
    (args.output / "video_pipeline_capability.c").write_text(copy)
    report = dict(
        scope=__doc__,
        production_limit=2097152,
        capability_limit=4194304,
        source_sha256=sha(source.encode()),
        copy_sha256=sha(copy.encode()),
        script_sha256=sha(Path(__file__).read_bytes()),
        cases=rows,
    )
    (args.output / "vcl_probe_manifest.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
