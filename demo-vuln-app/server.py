"""Standalone entry point for running the NSAT vulnerable demo server."""

import os
import sys

# Ensure demo-vuln-app directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.api.handlers import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
