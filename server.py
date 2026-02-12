"""
RC Tank License Server
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, g

ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'changeme_rc_tank_2026')
DB_PATH = os.environ.get('DB_PATH', 'licenses.db')

app = Flask(__name__)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()


def init_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute('''CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT UNIQUE NOT NULL,
        machine_id TEXT DEFAULT '',
        email TEXT DEFAULT '',
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        activated_at REAL DEFAULT 0,
        revoked INTEGER DEFAULT 0,
        notes TEXT DEFAULT ''
    )''')
    db.commit()
    db.close()


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('X-Admin-Secret', '')
        if not hmac.compare_digest(auth, ADMIN_SECRET):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


def generate_key():
    raw = secrets.token_hex(8).upper()
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"


@app.route('/api/activate', methods=['POST'])
def activate():
    data = request.get_json(force=True)
    key = data.get('license_key', '').strip()
    machine = data.get('machine_id', '').strip()
    if not key or not machine:
        return jsonify({'valid': False, 'message': 'Missing key or machine ID'}), 400
    db = get_db()
    row = db.execute('SELECT * FROM licenses WHERE license_key = ?', (key,)).fetchone()
    if not row:
        return jsonify({'valid': False, 'message': 'Invalid license key'}), 404
    if row['revoked']:
        return jsonify({'valid': False, 'message': 'License has been revoked'}), 403
    now = time.time()
    if row['expires_at'] < now:
        return jsonify({'valid': False, 'message': 'License has expired'}), 403
    if row['machine_id'] and row['machine_id'] != machine:
        return jsonify({'valid': False, 'message': 'License is already activated on another machine'}), 403
    db.execute('UPDATE licenses SET machine_id = ?, activated_at = ? WHERE license_key = ?', (machine, now, key))
    db.commit()
    days_left = max(0, (row['expires_at'] - now) / 86400)
    expires_str = datetime.fromtimestamp(row['expires_at'], tz=timezone.utc).strftime('%Y-%m-%d')
    return jsonify({'valid': True, 'activated': True, 'message': 'License activated', 'days_left': int(days_left), 'expires': expires_str})


@app.route('/api/validate', methods=['POST'])
def validate():
    data = request.get_json(force=True)
    key = data.get('license_key', '').strip()
    machine = data.get('machine_id', '').strip()
    if not key or not machine:
        return jsonify({'valid': False, 'message': 'Missing key or machine ID'}), 400
    db = get_db()
    row = db.execute('SELECT * FROM licenses WHERE license_key = ?', (key,)).fetchone()
    if not row:
        return jsonify({'valid': False, 'message': 'Invalid license key'}), 404
    if row['revoked']:
        return jsonify({'valid': False, 'message': 'License revoked'}), 403
    now = time.time()
    if row['expires_at'] < now:
        return jsonify({'valid': False, 'message': 'License expired'}), 403
    if row['machine_id'] != machine:
        return jsonify({'valid': False, 'message': 'License not activated for this machine'}), 403
    days_left = max(0, (row['expires_at'] - now) / 86400)
    expires_str = datetime.fromtimestamp(row['expires_at'], tz=timezone.utc).strftime('%Y-%m-%d')
    return jsonify({'valid': True, 'message': 'License valid', 'days_left': int(days_left), 'expires': expires_str})


@app.route('/api/admin/generate', methods=['POST'])
@require_admin
def admin_generate():
    data = request.get_json(force=True)
    count = min(data.get('count', 1), 50)
    days = data.get('days', 30)
    email = data.get('email', '')
    notes = data.get('notes', '')
    db = get_db()
    now = time.time()
    expires = now + days * 86400
    keys = []
    for _ in range(count):
        key = generate_key()
        db.execute('INSERT INTO licenses (license_key, email, created_at, expires_at, notes) VALUES (?, ?, ?, ?, ?)', (key, email, now, expires, notes))
        keys.append(key)
    db.commit()
    expires_str = datetime.fromtimestamp(expires, tz=timezone.utc).strftime('%Y-%m-%d')
    return jsonify({'keys': keys, 'days': days, 'expires': expires_str, 'count': count})


@app.route('/api/admin/revoke', methods=['POST'])
@require_admin
def admin_revoke():
    data = request.get_json(force=True)
    key = data.get('license_key', '')
    db = get_db()
    cur = db.execute('UPDATE licenses SET revoked = 1 WHERE license_key = ?', (key,))
    db.commit()
    if cur.rowcount:
        return jsonify({'success': True, 'message': 'License revoked'})
    return jsonify({'success': False, 'message': 'Key not found'}), 404


@app.route('/api/admin/renew', methods=['POST'])
@require_admin
def admin_renew():
    data = request.get_json(force=True)
    key = data.get('license_key', '')
    days = data.get('days', 30)
    db = get_db()
    row = db.execute('SELECT * FROM licenses WHERE license_key = ?', (key,)).fetchone()
    if not row:
        return jsonify({'success': False, 'message': 'Key not found'}), 404
    base = max(time.time(), row['expires_at'])
    new_expires = base + days * 86400
    db.execute('UPDATE licenses SET expires_at = ?, revoked = 0 WHERE license_key = ?', (new_expires, key))
    db.commit()
    expires_str = datetime.fromtimestamp(new_expires, tz=timezone.utc).strftime('%Y-%m-%d')
    return jsonify({'success': True, 'expires': expires_str})


@app.route('/api/admin/unbind', methods=['POST'])
@require_admin
def admin_unbind():
    data = request.get_json(force=True)
    key = data.get('license_key', '')
    db = get_db()
    cur = db.execute("UPDATE licenses SET machine_id = '', activated_at = 0 WHERE license_key = ?", (key,))
    db.commit()
    if cur.rowcount:
        return jsonify({'success': True, 'message': 'Machine binding removed'})
    return jsonify({'success': False, 'message': 'Key not found'}), 404


@app.route('/api/admin/list', methods=['GET'])
@require_admin
def admin_list():
    db = get_db()
    rows = db.execute('SELECT * FROM licenses ORDER BY created_at DESC').fetchall()
    licenses = []
    now = time.time()
    for r in rows:
        licenses.append({
            'license_key': r['license_key'],
            'machine_id': r['machine_id'] or '',
            'email': r['email'] or '',
            'created': datetime.fromtimestamp(r['created_at'], tz=timezone.utc).strftime('%Y-%m-%d %H:%M'),
            'expires': datetime.fromtimestamp(r['expires_at'], tz=timezone.utc).strftime('%Y-%m-%d'),
            'days_left': max(0, int((r['expires_at'] - now) / 86400)),
            'activated': bool(r['activated_at']),
            'revoked': bool(r['revoked']),
            'notes': r['notes'] or '',
        })
    return jsonify({'licenses': licenses, 'total': len(licenses)})


@app.route('/')
def health():
    return jsonify({'service': 'RC Tank License Server', 'status': 'running', 'version': '1.0'})


init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
