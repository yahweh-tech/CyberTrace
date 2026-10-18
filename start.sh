#!/usr/bin/env bash
# Exit on error
set -o errexit

# Run database migrations
python manage.py migrate

# Auto-create superuser if it doesn't exist
python init_admin.py

# Start Gunicorn WSGI server
exec gunicorn project.wsgi:application
