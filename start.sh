#!/bin/bash
set -e

echo "=== SentinelScan Startup ==="
echo "[startup] Checking Python..."
python --version

echo "[startup] Testing app import..."
python -c "
import sys, os
sys.path.insert(0, os.path.abspath('backend'))
from backend import create_app
app = create_app()
print('[startup] App imported OK, routes:', len(list(app.url_map.iter_rules())))
" 2>&1

echo "[startup] Starting gunicorn..."
exec gunicorn --bind 0.0.0.0:7860 --workers 1 --timeout 300 \
  --access-logfile - --error-logfile - \
  app:app
