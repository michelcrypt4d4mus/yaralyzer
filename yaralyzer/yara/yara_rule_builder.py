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

from yaralyzer.util.logging import log

YARA_REGEX_MODIFIERS = ['nocase', 'ascii', 'wide', 'fullword']

RULE_TEMPLATE = """
rule {rule_name} {{
    meta:
        author = "The Yaralyzer"
    strings:
        ${string_label} = /{pattern}/{modifier}
    condition:
        ${string_label}
}}
"""


def yara_rule_string(
        pattern: str,
        rule_name: str,
        string_label: Optional[str] = 'pattern',
        modifier: Optional[str] = None
    ) -> str:
    """Build a YARA rule string for a given pattern"""
    if not (modifier is None or modifier in YARA_REGEX_MODIFIERS):
        raise TypeError(f"Modifier '{modifier}' is not one of {YARA_REGEX_MODIFIERS}")

    rule = RULE_TEMPLATE.format(
        rule_name=rule_name,
        string_label=string_label,
        pattern=pattern,
        modifier='' if modifier is None else f" {modifier}")

    log.debug(f"Built YARA rule: \n{rule}")
    return rule


def build_yara_rule(
        pattern: str,
        rule_name: str,
        string_label: Optional[str] = 'pattern',
        modifier: Optional[str] = None
    ) -> yara.Rule:
    """Build a compiled YARA rule"""
    return yara.compile(source=yara_rule_string(pattern, rule_name, string_label, modifier))
