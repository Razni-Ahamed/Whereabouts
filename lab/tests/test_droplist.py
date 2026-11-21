from __future__ import annotations

import json

from wlab import droplist


def test_adds_lab_entries_to_the_real_list(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "drop_v4.json").write_text('{"cidr":"1.10.16.0/20","sblid":"SBL1","rir":"apnic"}\n{"type":"metadata"}', encoding="utf-8")
    labels = [
        {"type": "known_bad", "addresses": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"]},
        {"type": "known_bad", "addresses": ["93.184.215.14"]},
        {"type": "renamed_binary"},
    ]
    added = droplist.build(labels, real, tmp_path / "out")
    assert added == 2
    v4 = (tmp_path / "out" / "drop_v4.json").read_text(encoding="utf-8").splitlines()
    assert v4[0].startswith('{"cidr":"1.10.16.0/20"')
    assert json.loads(v4[-1]) == {"cidr": "93.184.215.14/32", "sblid": "SBL-LAB", "rir": "lab"}
    v6 = (tmp_path / "out" / "drop_v6.json").read_text(encoding="utf-8")
    assert "/128" in v6 and "SBL-LAB" in v6


def test_without_the_real_list_only_lab_entries(tmp_path):
    added = droplist.build([{"type": "known_bad", "addresses": ["192.0.2.1"]}], None, tmp_path)
    assert added == 1
    assert (tmp_path / "drop_v4.json").read_text(encoding="utf-8").count("\n") == 1
