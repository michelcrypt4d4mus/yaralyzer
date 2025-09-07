#!/bin/bash
# Script to build and serve documentation using mkdocs and lazydocs.
# Mildly out of date tutorial: https://sorokin.engineer/posts/en/github-pages-lazydocs-mkdocs.html
# Some docs on docstrings: https://www.geeksforgeeks.org/python/python-docstrings/

YARALYZER_PKG="yaralyzer"


# Manually validate docstrings because lazydocs --validate doesn't correctly read pyproject.toml options
pydocstyle

# Generate documnentation markdown files using lazydocs
lazydocs --output-path docs/api \
         --overview-file="README.md" \
         --src-base-url="https://github.com/michelcrypt4d4mus/$YARALYZER_PKG/blob/main/" \
         "$YARALYZER_PKG" \
         "$YARALYZER_PKG/decoding" \
         "$YARALYZER_PKG/encoding_detection" \
         "$YARALYZER_PKG/helpers/bytes_helper" \
         "$YARALYZER_PKG/helpers/rich_text_helper" \
         "$YARALYZER_PKG/output" \
         "$YARALYZER_PKG/util" \
         "$YARALYZER_PKG/yara"

mkdocs build
# mkdocs serve
mkdocs gh-deploy
