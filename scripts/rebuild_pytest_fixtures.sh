#!/bin/bash

rm tests/fixtures/rendered/*
PYTEST_REBUILD_FIXTURES=True pytest -k yaralyze_with -vv "$@"
