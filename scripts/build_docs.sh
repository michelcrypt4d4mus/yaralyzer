#!/bin/bash
# Script to build and serve documentation using mkdocs and lazydocs.
# GitHub Pages site: https://michelcrypt4d4mus.github.io/yaralyzer/
# Some docs on docstrings: https://www.geeksforgeeks.org/python/python-docstrings/

YARALYZER_PKG="yaralyzer"


# Manually validate docstrings because lazydocs --validate doesn't correctly read pyproject.toml options
#pydocstyle

# Generate documnentation markdown files using lazydocs
# TODO: the --ignored-modules doesn't actually ignore the modules, it just doesn't error out if they fail
lazydocs --output-path docs/api \
         --overview-file="README.md" \
         --src-base-url="https://github.com/michelcrypt4d4mus/$YARALYZER_PKG/blob/main/" \
         --ignored-modules="dict_helper,list_helper,helpers.dict_helper,helpers.list_helper,yaralyzer.helpers.dict_helper,yaralyzer.helpers.list_helper" \
         "$YARALYZER_PKG" \
         "$YARALYZER_PKG/decoding" \
         "$YARALYZER_PKG/encoding_detection" \
         "$YARALYZER_PKG/output" \
         "$YARALYZER_PKG/util" \
         "$YARALYZER_PKG/yara"
         # "$YARALYZER_PKG/helpers" \ Ignoring helpers module for now bc it has a lot of cruft and ignoring doesn't seem to work

mkdocs build
# mkdocs serve
mkdocs gh-deploy --force
