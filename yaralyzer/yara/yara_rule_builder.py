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
from typing import Optional

import yara

from yaralyzer.util.logging import log

RULE_TEMPLATE = """
rule {rule_name} {{
    meta:
        author = "The Yaralyzer"
    strings:
        ${string_label} = /{pattern}/
    condition:
        ${string_label}
}}
"""


def yara_rule_string(pattern: str, rule_name: str, string_label: Optional[str] = 'pattern'):
    rule = RULE_TEMPLATE.format(rule_name=rule_name, string_label=string_label, pattern=pattern)
    log.debug(f"Built YARA rule: \n{rule}")
    return rule


def build_yara_rule(pattern: str, rule_name: str, string_label: Optional[str] = 'pattern'):
    return yara.compile(source=yara_rule_string(pattern, rule_name, string_label))
