#!/bin/bash
set -e

echo "Stopping kairo processes..."
pkill -f kairo-server || true
pkill -f "next dev" || true
echo "Done."
