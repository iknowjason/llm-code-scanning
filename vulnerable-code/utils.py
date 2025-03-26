import os
import re
import sqlite3
import json
import requests
import subprocess
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# Hard-coded credentials
DB_USERNAME = "db_user"
DB_PASSWORD = "password123"  # Hard-coded password vulnerability

# Hard-coded encryption key
ENCRYPTION_KEY = b'super_secret_key_12345678901234'  # Static encryption key vulnerability

def load_config(config_file):
    """
    Load configuration from a file
    
    Vulnerability: Path traversal in config_file parameter
    """
    with open(config_file, 'r') as f:
        config = json.load(f)
    return config

def execute_query(query, params=None):
    """
    Execute a SQL query
    
    Vulnerability: SQL injection if params is None
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    if params:
        cursor.execute(query, params)
    else:
        # SQL Injection vulnerability if query contains user input
        cursor.execute(query)
    
    result = cursor.fetchall()
    conn.close()
    return result

def validate_username(username):
    """
    Validate username
    
    Vulnerability: Improper
