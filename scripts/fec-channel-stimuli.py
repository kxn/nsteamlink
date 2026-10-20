"""Declared opaque input schedules and payload/RS evidence assertions.

Not a replacement receiver or product audio/video role assignment. Actual client
channel state, coding and delivery are captured separately by the Source audit.
"""


def schedules(bank):
    result = []
    for crc in (False, True):
        for swapped in (False, True):
            a, b = (4, 3) if swapped else (3, 4)
            plans = {
                "same_group": [
                    (a, 1, 0),
                    (b, 1, 0),
                    (a, 1, 3),
                    (b, 1, 3),
                    (b, 1, 4),
                    (a, 1, 4),
                ],
                "other_newer": [
                    (a, 1, 0),
                    *[(b, g, i) for g in (2, 3) for i in (0, 1, 2)],
                    (a, 1, 3),
                    (a, 1, 4),
                ],
                "other_rollback": [
                    (a, 1, 0),
                    (b, 1, 0),
                    (b, 2, 0),
                    (a, 1, 3),
                    (a, 1, 4),
                    (b, 1, 3),
                    (b, 1, 4),
                    (b, 1, 0),
                    *[(b, 2, i) for i in (0, 1, 2)],
                ],
            }
            for profile, rows in plans.items():
                actions = []
                for n, (ch, group, index) in enumerate(rows):
                    w = bytes.fromhex(bank[int(ch == b)]["wires"][index])
                    actions.append(
                        [
                            "W",
                            1000000 + n,
                            11,
                            ch,
                            group,
                            0,
                            index,
                            900000 + n,
                            w[13:].hex(),
                        ]
                    )
                result.append(
                    dict(
                        name=f"{profile}_swap{int(swapped)}_crc{int(crc)}",
                        crc=crc,
                        profile=profile,
                        a=a,
                        b=b,
                        actions=actions,
                    )
                )
        # Ordinary input on the SAME channel is deliberately inserted while
        # its FEC group lacks two data shards. U drives the real window poll.
        actions = [
            [
                "W",
                1000000,
                11,
                3,
                1,
                0,
                0,
                900000,
                bytes.fromhex(bank[0]["wires"][0])[13:].hex(),
            ],
            ["W", 1000001, 3, 3, 0, 0, 0, 900001, "06aabb"],
            ["U", 1000002, 3],
        ]
        for ch, index in ((4, 0), (4, 1), (4, 2), (3, 3), (3, 4)):
            n = len(actions)
            w = bytes.fromhex(bank[int(ch == 4)]["wires"][index])
            actions.append(
                ["W", 1000000 + n, 11, ch, 1, 0, index, 900000 + n, w[13:].hex()]
            )
        result.append(
            dict(
                name=f"ordinary_during_crc{int(crc)}",
                crc=crc,
                profile="ordinary_during",
                a=3,
                b=4,
                actions=actions,
            )
        )
    return result


def verify(case, bank):
    a, b = case["input"]["a"], case["input"]["b"]
    profile = case["input"]["profile"]
    if profile == "same_group":
        expected = [(b, 1, bank[1]["body"]), (a, 1, bank[0]["body"])]
        rs = [a, b]
    elif profile == "other_newer":
        expected = [
            (b, 2, bank[1]["body"]),
            (b, 3, bank[1]["body"]),
            (a, 1, bank[0]["body"]),
        ]
        rs = [a]
    elif profile == "other_rollback":
        expected = [
            (a, 1, bank[0]["body"]),
            (b, 1, bank[1]["body"]),
            (b, 2, bank[1]["body"]),
        ]
        rs = [a, b]
    else:
        assert profile == "ordinary_during"
        expected = [(a, 0, "06aabb"), (b, 1, bank[1]["body"]), (a, 1, bank[0]["body"])]
        rs = [a]
    assert [
        (d["channel"], d["group"], d["body"]) for d in case["deliveries"]
    ] == expected, case["input"]["name"]
    assert sorted(v["channel"] for v in case["rs"]) == sorted(rs), case["rs"]
    assert case["channels_distinct"] and not case["source_assertions"]
    # Every recorded Source body must be attributed to its actual input step.
    bodies = [
        (n, body)
        for n, state in enumerate(case["observed"])
        for body in state["delivered"]
    ]
    assert bodies == [(d["action"], d["body"]) for d in case["deliveries"]]
