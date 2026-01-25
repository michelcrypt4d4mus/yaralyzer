#!/bin/bash

rm tests/fixtures/rendered/*
PYTEST_REBUILD_FIXTURES=True pytest -vv # "$@"
