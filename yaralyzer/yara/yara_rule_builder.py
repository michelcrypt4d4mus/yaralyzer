"""
Builds bare bones YARA rules to match strings and regex patterns.

Example rule string:

```
rule Just_A_Piano_Man {
    meta:
        author           = "Tim"
    strings:
        $hilton_producer = /Scott.*Storch/
    condition:
        $hilton_producer
}
```
"""
import re
from typing import Literal, Optional

import yara

from yaralyzer.util.constants import YARALYZE
from yaralyzer.util.logging import log

PatternType = Literal['hex', 'regex']
HEX = 'hex'
REGEX = 'regex'
PATTERN_TYPES: list[PatternType] = ['hex', 'regex']

YaraModifierType = Literal['ascii', 'fullword', 'nocase', 'wide']
YARA_REGEX_MODIFIERS = ['ascii', 'fullword', 'nocase', 'wide']

PATTERN = 'pattern'
RULE = 'rule'
UNDERSCORE = '_'

SAFE_LABEL_REPLACEMENTS = {
    '/': 'frontslash',
    '\\': 'backslash',
    "'": 'singlequote',
    '"': 'doublequote',
    '`': 'backtick',
    '-': UNDERSCORE,
    ' ': UNDERSCORE,
}

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
    pattern_type: PatternType = REGEX,
    rule_name: str = YARALYZE,
    pattern_label: Optional[str] = PATTERN,
    modifier: Optional[YaraModifierType] = None
) -> str:
    """
    Build a YARA rule string for a given `pattern`.

    Args:
        pattern (str): The string or regex pattern to match.
        pattern_type (str): Either `"regex"` or `"hex"`. Default is `"regex"`.
        rule_name (str): The name of the YARA rule. Default is `"YARALYZE"`.
        pattern_label (Optional[str]): The label for the pattern in the YARA rule. Default is `"pattern"`.
        modifier (Optional[str]): Optional regex modifier (e.g. 'fullword', 'nocase', 'ascii', 'wide').
            Only valid if `pattern_type` is `"regex"`.

    Returns:
        str: The constructed YARA rule as a string.
    """
    if not (modifier is None or modifier in YARA_REGEX_MODIFIERS):
        raise TypeError(f"Modifier '{modifier}' is not one of {YARA_REGEX_MODIFIERS}")

    if pattern_type == REGEX:
        pattern = f"/{pattern}/"
    elif pattern_type == HEX:
        pattern = f"{{{pattern}}}"
    else:
        raise ValueError(f"pattern_type must be either '{REGEX}' or '{HEX}'")

    if modifier:
        pattern += f" {modifier}"

    rule = RULE_TEMPLATE.format(
        rule_name=rule_name,
        pattern_label=pattern_label,
        pattern=pattern,
        modifier='' if modifier is None else f" {modifier}"
    )

    log.debug(f"Built YARA rule: \n{rule}")
    return rule


def build_yara_rule(
    pattern: str,
    pattern_type: PatternType = REGEX,
    rule_name: str = YARALYZE,
    pattern_label: Optional[str] = PATTERN,
    modifier: Optional[YaraModifierType] = None
) -> yara.Rule:
    """
    Build a compiled `yara.Rule` object.

    Args:
        pattern (str): The string or regex pattern to match.
        pattern_type (str): Either `"regex"` or `"hex"`. Default is `"regex"`.
        rule_name (str): The name of the YARA rule. Default is `"YARALYZE"`.
        pattern_label (Optional[str]): The label for the pattern in the YARA rule. Default is `"pattern"`.
        modifier (Optional[str]): Optional regex modifier (e.g. 'nocase', 'ascii', 'wide', 'fullword').
            Only valid if `pattern_type` is `"regex"`.

    Returns:
        yara.Rule: Compiled YARA rule object.
    """
    rule_string = yara_rule_string(pattern, pattern_type, rule_name, pattern_label, modifier)
    return yara.compile(source=rule_string)


def safe_label(_label: str) -> str:
    """
    YARA rule and pattern names can only contain alphanumeric chars.

    Args:
        _label (str): The label to sanitize.

    Returns:
        str: A sanitized label safe for use in YARA rules.
    """
    label = _label

    for char, replacement in SAFE_LABEL_REPLACEMENTS.items():
        if replacement != UNDERSCORE:
            label = label.replace(char, f"__{replacement.upper()}__")
        else:
            label = label.replace(char, replacement)

    if re.match('^\\d', label):
        label = '_' + label

    if not re.match('\\w+', label):
        msg = f"'{label}' is invalid: YARA labels must be alphanumeric/underscore and cannot start with a number"
        raise ValueError(msg)

    log.debug(f"Built safe label {label} from {_label}")
    return label
