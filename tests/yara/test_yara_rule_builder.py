import yara

from yaralyzer.yara.yara_rule_builder import REGEX, build_yara_rule, yara_rule_string

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

BUILD_RULE_KWARGS = {
    'pattern': 'Scott.*Storch',
    'pattern_type': REGEX,
    'rule_name': 'Just_A_Piano_Man',
    'pattern_label': 'hilton_producer',
}


def test_yara_rule_string():
    rule_string = yara_rule_string(**BUILD_RULE_KWARGS)
    assert rule_string == EXPECTED_RULE_STRING


def test_yara_rule_modifier():
    rule_string = yara_rule_string(modifier='wide', **BUILD_RULE_KWARGS)
    print(rule_string)
    assert rule_string == EXPECTED_RULE_STRING.replace('Storch/', 'Storch/ wide')


def test_build_yara_rule():
    try:
        rule = build_yara_rule(**BUILD_RULE_KWARGS)
    except:
        assert False, f"Failed to compile rule"

    matches = []
    rule.match(data=TEST_BYTES, callback=lambda match: matches.append(match))
    assert len(matches) == 1
    assert matches[0]['strings'] == [(49, '$hilton_producer', b'Scotty Storch')]
