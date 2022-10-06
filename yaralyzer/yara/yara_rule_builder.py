"""
Builds bare bones YARA rules to match strings and regex patterns. Example rule string:

rule Just_A_Piano_Man {
    meta:
        author           = "Tim"
	strings:
		$hilton_producer = /Scott.*Storch/
	condition:
		$hilton_producer
}

"""
from typing import Optional, Type

import yara

from yaralyzer.config import YARALYZE
from yaralyzer.util.logging import log

HEX = 'hex'
REGEX = 'regex'
RULE = 'rule'
PATTERN = 'pattern'
YARA_REGEX_MODIFIERS = ['nocase', 'ascii', 'wide', 'fullword']

RULE_TEMPLATE = """
rule {rule_name} {{
    meta:
        author = "The Yaralyzer"
    strings:
        ${pattern_label} = {pattern}
    condition:
        ${pattern_label}
}}
"""

BYTES_RULE_TEMPLATE = """
rule {rule_name} {{
    meta:
        author = "The Yaralyzer"
    strings:
        ${pattern_label} = {{ {bytes_pattern} }}
    condition:
        ${pattern_label}
}}
"""


def yara_rule_string(
        pattern: str,
        pattern_type: str = REGEX,
        rule_name: str = YARALYZE,
        pattern_label: Optional[str] = PATTERN,
        modifier: Optional[str] = None
    ) -> str:
    """Build a YARA rule string for a given pattern"""
    if not (modifier is None or modifier in YARA_REGEX_MODIFIERS):
        raise TypeError(f"Modifier '{modifier}' is not one of {YARA_REGEX_MODIFIERS}")

    if pattern_type == REGEX:
        pattern = f"/{pattern}/"
    elif pattern_type == HEX:
        pattern = f"{{{pattern}}}"

    if modifier:
        pattern += f" {modifier}"

    rule = RULE_TEMPLATE.format(
        rule_name=rule_name,
        pattern_label=pattern_label,
        pattern=pattern,
        modifier='' if modifier is None else f" {modifier}")

    log.debug(f"Built YARA rule: \n{rule}")
    return rule


def build_yara_rule(
        pattern: str,
        pattern_type: str = REGEX,
        rule_name: str = YARALYZE,
        pattern_label: Optional[str] = PATTERN,
        modifier: Optional[str] = None
    ) -> yara.Rule:
    """Build a compiled YARA rule"""
    rule_string = yara_rule_string(pattern, pattern_type, rule_name, pattern_label, modifier)
    return yara.compile(source=rule_string)
