#!/bin/bash

PYTEST_REBUILD_FIXTURES=True pytest -k yaralyze_with -vv "$@"
