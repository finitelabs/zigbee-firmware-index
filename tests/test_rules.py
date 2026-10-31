import pytest

from firmware_index import rules
from firmware_index.sources import Candidate


def cand(**kw):
    base = dict(
        source="community",
        priority=3,
        url="https://example.test/images/Vendor/a.ota",
        manufacturer=0x1234,
        image_type=0x0001,
        version=0x20,
        file_name="a.ota",
        model_id="M1",
    )
    return Candidate(**{**base, **kw})


def test_every_match_key_must_hold():
    r = rules.Rule(
        id="r",
        action=rules.HOLD,
        match={
            "manufacturerCode": 0x1234,
            "imageType": 1,
            "fileVersion": {"min": 0x10, "max": 0x30},
            "modelId": "M1",
            "url": "*/Vendor/*",
            "source": "community",
        },
    )
    assert r.matches(cand(), None, None)
    assert not r.matches(cand(version=0x31), None, None)
    assert not r.matches(cand(model_id="M2"), None, None)
    assert not r.matches(cand(url="https://example.test/other/a.ota"), None, None)


def test_sha512_matches_our_file_or_the_upstream_one():
    r = rules.Rule(id="r", action=rules.DROP, match={"sha512": "up"})
    assert r.matches(cand(), "ours", "up")
    assert not r.matches(cand(), "ours", None)


def test_a_drop_beats_a_hold_and_set_rules_add_up():
    rs = [
        rules.Rule(id="hold", action=rules.HOLD, match={"imageType": 1}),
        rules.Rule(id="drop", action=rules.DROP, match={"modelId": "M1"}),
        rules.Rule(id="set1", action=rules.SET, match={}, set={"modelId": "M9"}),
        rules.Rule(id="set2", action=rules.SET, match={}, set={"hardwareVersionMin": 1}),
        rules.Rule(id="off", action=rules.DROP, match={}, enabled=False),
    ]
    out = rules.apply(rs, cand(), "s", None)
    assert out.action == rules.DROP
    assert out.applied == ["hold", "drop", "set1", "set2"]
    assert out.fields == {"modelId": "M9", "hardwareVersionMin": 1}


def test_a_rule_names_only_known_actions_and_fields():
    with pytest.raises(ValueError, match="unknown action"):
        rules.Rule(id="r", action="delete", match={})
    with pytest.raises(ValueError, match="cannot set url"):
        rules.Rule(id="r", action=rules.SET, match={}, set={"url": "x"})
    with pytest.raises(ValueError, match="unknown match key"):
        rules.Rule(id="r", action=rules.HOLD, match={"colour": 1}).matches(cand(), None, None)
