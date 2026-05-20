#!/bin/sh
# SmartFuzz backend entrypoint.
# The Dockerfile already installs Chromium at build time, but re-running
# `playwright install` is idempotent and harmless — useful as a fallback for
# non-Docker hosts (e.g. Render's native Python runtime).
playwright install chromium --with-deps
python app.py
