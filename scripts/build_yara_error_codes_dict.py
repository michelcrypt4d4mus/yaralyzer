#!/usr/bin/env python
"""
Script to turn the official list of error codes into a python dict string, theoretically
to update YARA_ERROR_CODES in case the list ever changes.
"""
import requests

from yaralyzer.yara.error import YARA_ERRORS_RAW_URL

ERROR_LINE_PFX = '#define ERROR_'


response = requests.get(YARA_ERRORS_RAW_URL)
error_codes = {}
print('YARA_ERROR_CODES = {')

for line in response.text.split('\n'):
    if not line.startswith(ERROR_LINE_PFX):
        continue

    error_name, error_code = line.removeprefix(ERROR_LINE_PFX).split()
    error_code = int(error_code)
    error_codes[error_code] = error_name
    print(f"    {error_code}: '{error_name}',")

print('}')
