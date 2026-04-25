#!/bin/bash
set -e

echo "=== Mullein Bank Startup ==="

echo "[*] Running migrations..."
python manage.py makemigrations banking --noinput
python manage.py migrate --noinput

echo "[*] Creating default admin account..."
python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@mulleinbank.com', 'admin123')
    print('[!] Default admin created: admin / admin123')
else:
    print('[*] Admin user already exists')
"

echo "[*] Starting Mullein Bank on port 5090..."
python manage.py runserver 0.0.0.0:5090
