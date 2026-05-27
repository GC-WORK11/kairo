#!/bin/bash
set -e

echo "Starting kairo local stack..."

echo "Starting kairo-server..."
cargo run -p kairo-server &
SERVER_PID=$!

sleep 3

echo "Starting kairo-web dev server..."
cd apps/web && bun run dev &
WEB_PID=$!

sleep 5

echo ""
echo "Local stack is running:"
echo "  Server:  http://127.0.0.1:8080"
echo "  Web:     http://localhost:3000"
echo ""
echo "To stop: pkill -f kairo-server; pkill -f \"next dev\""
