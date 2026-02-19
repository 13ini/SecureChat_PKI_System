# ------
# IMPORTS
# ------
from flask import Flask
import sqlite3
import hashlib
import secrets
import json
import os
from datetime import datetime, timedelta, timezone

# ------
# APP & CONFIG
# ------
app = Flask(__name__)
app.secret_key = "dev-key-temp"

@app.route("/")
def index():
    return "SecureChat Starting..."

if __name__ == "__main__":
    app.run(debug=True)