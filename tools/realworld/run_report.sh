#!/usr/bin/env sh
# Run the MemoryGraph testing report on this computer (no internet needed).
#   ./run_report.sh --check
#   ./run_report.sh --dump /cases/case1.lime --os linux
#   ./run_report.sh --simulate
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/../.."
export QT_QPA_PLATFORM=offscreen
export PYTHONIOENCODING=utf-8
if [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"; else PY=python3; fi
exec "$PY" "$HERE/run_report.py" "$@"
