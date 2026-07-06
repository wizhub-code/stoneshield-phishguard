#!/bin/bash
echo "Starting on PORT: $PORT"
exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
