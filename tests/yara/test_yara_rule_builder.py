import yara

from yaralyzer.yara.yara_rule_builder import build_yara_rule, yara_rule_string

TEST_BYTES = b"I'm a real producer but you're just a piano man, Scotty Storch"

EXPECTED_RULE_STRING = """
rule Just_A_Piano_Man {
    meta:
        author = "The Yaralyzer"
    strings:
        $hilton_producer = /Scott.*Storch/
    condition:
        $hilton_producer
}
"""


def test_yara_rule_string():
    rule_string = yara_rule_string('Scott.*Storch', 'Just_A_Piano_Man', 'hilton_producer')
    assert rule_string == EXPECTED_RULE_STRING


def test_build_yara_rule():
    try:
        rule = build_yara_rule('Scott.*Storch', 'Just_A_Piano_Man', 'hilton_producer')
    except:
        assert False, f"Failed to compile rule"

    matches = []
    rule.match(data=TEST_BYTES, callback=lambda match: matches.append(match))
    assert len(matches) == 1
    assert matches[0]['strings'] == [(49, '$hilton_producer', b'Scotty Storch')]
