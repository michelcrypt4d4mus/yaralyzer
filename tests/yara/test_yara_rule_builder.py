import yara

from yaralyzer.yara.yara_rule_builder import HEX, PATTERN, REGEX, build_yara_rule, yara_rule_string

TEST_BYTES = b"I'm a real producer but you're just a piano man, Scotty Storch"
HEX_STRING = 'A1 B2 C3'

EXPECTED_RULE = """
rule Just_A_Piano_Man {
    meta:
        author = "The Yaralyzer"
    strings:
        $hilton_producer = /Scott.*Storch/
    condition:
        $hilton_producer
}
"""

REGEX_RULE_KWARGS = {
    'pattern': 'Scott.*Storch',
    'pattern_type': REGEX,
    'rule_name': 'Just_A_Piano_Man',
    'pattern_label': 'hilton_producer',
}


def test_yara_rule_string():
    rule_string = yara_rule_string(**REGEX_RULE_KWARGS)
    assert rule_string == EXPECTED_RULE


def test_yara_rule_modifier():
    rule_string = yara_rule_string(modifier='wide', **REGEX_RULE_KWARGS)
    print(rule_string)
    assert rule_string == EXPECTED_RULE.replace('Storch/', 'Storch/ wide')


def test_build_yara_rule():
    try:
        rule = build_yara_rule(**REGEX_RULE_KWARGS)
    except:
        assert False, f"Failed to compile rule"

    matches = []
    rule.match(data=TEST_BYTES, callback=lambda match: matches.append(match))
    assert len(matches) == 1
    assert matches[0]['strings'] == [(49, '$hilton_producer', b'Scotty Storch')]


def test_yara_hex_rule(binary_file_path):
    rule_kwargs = REGEX_RULE_KWARGS.copy()
    rule_kwargs.update({'pattern_type': HEX, PATTERN: HEX_STRING})
    rule_string = yara_rule_string(**rule_kwargs)
    expected_rule = EXPECTED_RULE.replace(f"/{REGEX_RULE_KWARGS[PATTERN]}/", f"{{{HEX_STRING}}}")
    assert rule_string == expected_rule
