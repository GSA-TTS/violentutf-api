#!/bin/bash
# Test script to verify all dependencies in a clean environment
# This simulates what GitHub CI does

set -e  # Exit on error

echo "================================================"
echo "Testing Dependencies in Clean Environment"
echo "================================================"

# Create temporary virtual environment
TEMP_ENV=$(mktemp -d)
echo "Creating clean virtual environment in: $TEMP_ENV"

python3 -m venv "$TEMP_ENV/venv"
# shellcheck source=/dev/null
source "$TEMP_ENV/venv/bin/activate"

echo ""
echo "Installing dependencies from requirements.txt..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo ""
echo "Testing critical imports..."
python3 -c "
import sys
failed = []

# Most critical imports that failed in CI
critical_imports = [
    'from prometheus_client import make_asgi_app',
    'from app.main import create_application',
    'from apscheduler.triggers.cron import CronTrigger',
    'import matplotlib.pyplot as plt',
    'from reportlab.lib import colors',
    'from PIL import Image',
]

for imp in critical_imports:
    try:
        if 'from app.' in imp:
            print(f'⏭️  Skipping app import: {imp}')
        else:
            exec(imp)
            print(f'✅ {imp}')
    except ImportError as e:
        print(f'❌ {imp}: {e}')
        failed.append(imp)

if failed:
    print(f'\n❌ {len(failed)} imports failed!')
    sys.exit(1)
else:
    print('\n✅ All critical imports successful!')
"

echo ""
echo "Running contract test to verify app can be imported..."
cd "$(dirname "$0")"
python3 -c "
try:
    from app.main import create_application
    print('✅ App imports successfully!')
except ImportError as e:
    print(f'❌ App import failed: {e}')
    import sys
    sys.exit(1)
"

# Cleanup
deactivate
rm -rf "$TEMP_ENV"

echo ""
echo "================================================"
echo "✅ All dependency checks passed!"
echo "================================================"
