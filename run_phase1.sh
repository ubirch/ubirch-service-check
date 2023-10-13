#!/usr/bin/env bash

cd /build/ ; tar cf - . | (cd /app ; tar xf -)
cd /app
source ./venv/bin/activate
python service-check-v2.py
