#!/bin/bash
# Script to build and serve documentation using mkdocs and lazydocs.
# Mildly out of date tutorial: https://sorokin.engineer/posts/en/github-pages-lazydocs-mkdocs.html
# Some docs on docstrings: https://www.geeksforgeeks.org/python/python-docstrings/

YARALYZER_PKG="yaralyzer"


# Generate documnentation markdown files using lazydocs
lazydocs --output-path docs/api \
         --overview-file="README.md" \
         --src-base-url="https://github.com/michelcrypt4d4mus/$YARALYZER_PKG/blob/main/" \
         "$YARALYZER_PKG"

mkdocs build
# mkdocs serve
# mkdocs gh-deploy
