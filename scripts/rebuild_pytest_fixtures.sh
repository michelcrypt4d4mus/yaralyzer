#!/bin/bash

FIXTURES_DIR=./tests/fixtures/rendered

if [ $# -eq 0 ]; then
    echo -e "\nDeleting existing fixtures rendered fixtures from $FIXTURES_DIR..."
    rm "$FIXTURES_DIR/*.txt"
fi

PYTEST_REBUILD_FIXTURES=True pytest -vv # "$@"
