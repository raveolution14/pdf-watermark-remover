#!/usr/bin/env python3
"""
RPP Chihuahua – Consulta de Folio Real / Nombre de Propietario
Google OAuth · Stripe subscriptions (MXN) · Anti-sharing session
"""

import io, threading, webbrowser, os, uuid, time, sqlite3, functools, json
from collections import defaultdict
from datetime import datetime, timedelta
try:
    import anthropic as _anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

from flask import (Flask, request, send_file, render_template_string,
                   jsonify, session, redirect, url_for, Response)
from werkzeug.middleware.proxy_fix import ProxyFix
from playwright.sync_api import sync_playwright
from authlib.integrations.flask_client import OAuth
import stripe as _stripe

from main import remove_watermarks

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# ── Config ────────────────────────────────────────────────────────────────────
RPP_URL     = "https://srppn.chihuahua.gob.mx/rpp/RppApp/"
RPP_USER    = "CEMVCHIH"
RPP_PASS    = "Cemv2026$1"
ADMIN_EMAIL = "fjhdezg@gmail.com"

app.config.update(
    SECRET_KEY              = os.environ.get('FLASK_SECRET_KEY', 'rpp-dev-secret-CHANGE-ME'),
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'Lax',
    SESSION_COOKIE_SECURE   = True,
    SESSION_COOKIE_NAME     = 'rpp_sess',
)

GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
GOOGLE_ANALYTICS_ID  = os.environ.get('GOOGLE_ANALYTICS_ID', '')

_stripe.api_key       = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PUB_KEY        = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
STRIPE_PRICE = {
    'basico':              os.environ.get('STRIPE_PRICE_BASICO', ''),
    'pro':                 os.environ.get('STRIPE_PRICE_PRO', ''),
    'empresarial':         os.environ.get('STRIPE_PRICE_EMPRESARIAL', ''),
    'basico_annual':       os.environ.get('STRIPE_PRICE_BASICO_ANNUAL', ''),
    'pro_annual':          os.environ.get('STRIPE_PRICE_PRO_ANNUAL', ''),
    'empresarial_annual':  os.environ.get('STRIPE_PRICE_EMPRESARIAL_ANNUAL', ''),
    'extra':               os.environ.get('STRIPE_PRICE_EXTRA', ''),
    'single':              os.environ.get('STRIPE_PRICE_SINGLE', ''),
    'pack5':               os.environ.get('STRIPE_PRICE_PACK5', ''),
    'pack10':              os.environ.get('STRIPE_PRICE_PACK10', ''),
    'corporativo':              os.environ.get('STRIPE_PRICE_CORPORATIVO', ''),
    'corporativo_pro':          os.environ.get('STRIPE_PRICE_CORPORATIVO_PRO', ''),
    'corporativo_annual':       os.environ.get('STRIPE_PRICE_CORPORATIVO_ANNUAL', ''),
    'corporativo_pro_annual':   os.environ.get('STRIPE_PRICE_CORPORATIVO_PRO_ANNUAL', ''),
}
PACK_CONFIG = {
    'pack5':  {'qty': 5,  'price_mxn': 500,  'label': '5 descargas — $500 MXN', 'save': 'Ahorra $150'},
    'pack10': {'qty': 10, 'price_mxn': 900,  'label': '10 descargas — $900 MXN', 'save': 'Ahorra $400'},
}
PLAN_LIMITS = {'basico': 5, 'pro': 10, 'empresarial': 20, 'corporativo': 100, 'corporativo_pro': 500}

# Notion integration
NOTION_API_KEY    = os.environ.get('NOTION_API_KEY', '')
NOTION_DB_ID      = os.environ.get('NOTION_DB_ID', 'd2c69675c50b419f8ad7c7d86ce52cbd')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
PLAN_PRICES = {'basico': 500, 'pro': 1000, 'empresarial': 2000, 'corporativo': 5000, 'corporativo_pro': 8000}
PLAN_LABELS = {'basico': 'Básico', 'pro': 'Pro', 'empresarial': 'Empresarial', 'corporativo': 'Corporativo', 'corporativo_pro': 'Corporativo Pro'}

DB_PATH = os.environ.get('DB_PATH', '/opt/rpp/rpp.db')

# ── Rate Limiter ─────────────────────────────────────────────────────────────
_rate_buckets = defaultdict(list)  # key -> [timestamps]
_rate_lock = threading.Lock()

def _rate_limited(key, max_requests, window_seconds):
    """Return True if rate limit exceeded."""
    now = time.time()
    cutoff = now - window_seconds
    with _rate_lock:
        _rate_buckets[key] = [t for t in _rate_buckets[key] if t > cutoff]
        if len(_rate_buckets[key]) >= max_requests:
            return True
        _rate_buckets[key].append(now)
        return False

def check_search_rate(u):
    """Check search rate limits. Returns error response or None."""
    uid = u['id']
    ip = request.remote_addr or '0.0.0.0'
    # Per-user: 10 searches per minute
    if _rate_limited(f'search_user_{uid}', 10, 60):
        _audit(uid, 'rate_limit', 'search', ip)
        return jsonify({'error': 'Demasiadas búsquedas. Espera un momento.'}), 429
    # Per-IP: 20 searches per minute
    if _rate_limited(f'search_ip_{ip}', 20, 60):
        _audit(uid, 'rate_limit', 'search_ip', ip)
        return jsonify({'error': 'Demasiadas solicitudes desde tu red. Espera un momento.'}), 429
    return None

def check_webhook_rate():
    """Rate limit Stripe webhooks: 60/min."""
    ip = request.remote_addr or '0.0.0.0'
    if _rate_limited(f'webhook_{ip}', 60, 60):
        return True
    return False

def check_api_rate(key, limit=30, window=60):
    """Generic API rate limit check."""
    if _rate_limited(key, limit, window):
        return jsonify({'error': 'Demasiadas solicitudes. Espera un momento.'}), 429
    return None

# ── Database ──────────────────────────────────────────────────────────────────
def _db():
    c = sqlite3.connect(DB_PATH, timeout=20, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

# One-time DB init: WAL mode + schema
with sqlite3.connect(DB_PATH, timeout=20) as _c:
    _c.execute("PRAGMA journal_mode=WAL")
    _c.execute("PRAGMA busy_timeout=10000")

# Migrate: add new columns if missing
with sqlite3.connect(DB_PATH, timeout=20) as _c:
    _cols = [r[1] for r in _c.execute("PRAGMA table_info(users)").fetchall()]
    if 'trial_ends' not in _cols:
        _c.execute("ALTER TABLE users ADD COLUMN trial_ends TEXT")
    if 'referral_code' not in _cols:
        _c.execute("ALTER TABLE users ADD COLUMN referral_code TEXT")
    if 'renewal_reminder_sent' not in _cols:
        _c.execute("ALTER TABLE users ADD COLUMN renewal_reminder_sent TEXT")
    if 'password_hash' not in _cols:
        _c.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    if 'billing_interval' not in _cols:
        _c.execute("ALTER TABLE users ADD COLUMN billing_interval TEXT DEFAULT 'month'")
    if 'annual_reminder_sent' not in _cols:
        _c.execute("ALTER TABLE users ADD COLUMN annual_reminder_sent TEXT")

with sqlite3.connect(DB_PATH, timeout=20) as _c:
    _dcols = [r[1] for r in _c.execute("PRAGMA table_info(downloads)").fetchall()]
    if 'nombre' not in _dcols:
        _c.execute("ALTER TABLE downloads ADD COLUMN nombre TEXT")

with _db() as _c:
    _c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        google_id          TEXT UNIQUE NOT NULL,
        email              TEXT UNIQUE NOT NULL,
        name               TEXT,
        picture            TEXT,
        role               TEXT DEFAULT 'user',
        plan               TEXT,
        stripe_customer_id TEXT,
        stripe_sub_id      TEXT,
        sub_status         TEXT,
        downloads_used     INTEGER DEFAULT 0,
        period_start       TEXT,
        session_token      TEXT,
        trial_ends         TEXT,
        referral_code      TEXT,
        created_at         TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS downloads (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        folio_real TEXT,
        ts         TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS extra_credits (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id        INTEGER NOT NULL,
        payment_intent TEXT,
        used           INTEGER DEFAULT 0,
        ts             TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS single_purchases (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id        INTEGER NOT NULL,
        folio_real     TEXT,
        payment_intent TEXT,
        amount         INTEGER DEFAULT 13000,
        ts             TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS download_packs (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id        INTEGER NOT NULL,
        pack_type      TEXT NOT NULL,
        credits_total  INTEGER NOT NULL,
        credits_used   INTEGER DEFAULT 0,
        payment_intent TEXT,
        ts             TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS referral_codes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL UNIQUE,
        code        TEXT UNIQUE NOT NULL,
        ts          TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS referral_uses (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        code            TEXT NOT NULL,
        referred_user_id INTEGER NOT NULL UNIQUE,
        bonus_given      INTEGER DEFAULT 0,
        ts              TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS folio_alerts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        folio_real TEXT NOT NULL,
        last_hash  TEXT,
        active     INTEGER DEFAULT 1,
        ts         TEXT DEFAULT (datetime('now')),
        UNIQUE(user_id, folio_real)
    );
    CREATE TABLE IF NOT EXISTS abandoned_carts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        folio_real TEXT,
        emailed    INTEGER DEFAULT 0,
        ts         TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL,
        token      TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        used       INTEGER DEFAULT 0,
        ts         TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS corporate_members (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id     INTEGER NOT NULL,
        invite_email TEXT NOT NULL,
        member_id    INTEGER DEFAULT NULL,
        joined_at    TEXT,
        active       INTEGER DEFAULT 1,
        ts           TEXT DEFAULT (datetime('now')),
        UNIQUE(owner_id, invite_email)
    );
    CREATE TABLE IF NOT EXISTS analytics_events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event      TEXT NOT NULL,
        user_id    INTEGER,
        plan       TEXT,
        meta       TEXT,
        ts         TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        action     TEXT NOT NULL,
        detail     TEXT,
        ip         TEXT,
        ts         TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS rpp_metrics (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event      TEXT NOT NULL,
        folio      TEXT,
        duration_ms INTEGER,
        success    INTEGER DEFAULT 1,
        error_msg  TEXT,
        ts         TEXT DEFAULT (datetime('now'))
    );
    """)

# ── Automatic DB Backups ─────────────────────────────────────────────────────
import glob as _glob_mod

def _do_db_backup():
    backup_dir = os.path.join(os.path.dirname(DB_PATH), 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    ts  = datetime.utcnow().strftime('%Y%m%d')
    dst = os.path.join(backup_dir, f'rpp_{ts}.db')
    if not os.path.exists(dst):
        src = sqlite3.connect(DB_PATH, timeout=20)
        bak = sqlite3.connect(dst, timeout=20)
        src.backup(bak)
        src.close(); bak.close()
        # Keep only 30 most recent backups
        files = sorted(_glob_mod.glob(os.path.join(backup_dir, 'rpp_*.db')))
        for old in files[:-30]:
            try: os.remove(old)
            except Exception: pass
        print(f'[BACKUP] Saved {dst}', flush=True)

def _backup_loop():
    time.sleep(10)  # wait for app startup
    while True:
        try:
            _do_db_backup()
        except Exception as e:
            print(f'[BACKUP] Error: {e}', flush=True)
        try:
            _send_annual_renewal_reminders()
        except Exception as e:
            print(f'[REMINDER] Error: {e}', flush=True)
        try:
            _cleanup_disk_cache()
        except Exception as e:
            print(f'[CACHE] Cleanup error: {e}', flush=True)
        time.sleep(86400)  # 24 hours

threading.Thread(target=_backup_loop, daemon=True).start()

# ── RPP Service Status Checker ────────────────────────────────────────────────
_rpp_status = {'ok': True, 'response_ms': 0, 'checked_at': '', 'message': ''}

def _check_rpp_status():
    import urllib.request as _ur
    try:
        t0 = time.time()
        req = _ur.Request('https://srppn.chihuahua.gob.mx/rpp/RppApp/', method='GET')
        req.add_header('User-Agent', 'Mozilla/5.0')
        with _ur.urlopen(req, timeout=10) as r:
            ms = int((time.time() - t0) * 1000)
        _rpp_status.update({'ok': True, 'response_ms': ms,
                            'checked_at': datetime.utcnow().isoformat()[:19],
                            'message': ''})
    except Exception as e:
        _rpp_status.update({'ok': False, 'response_ms': 0,
                            'checked_at': datetime.utcnow().isoformat()[:19],
                            'message': str(e)[:80]})

_alert_state = {'consecutive_errors': 0, 'alerted': False, 'recovered': False}

def _send_rpp_alert(down=True):
    """Send admin alert when RPP goes down or recovers."""
    try:
        subject = '🔴 RPP Chihuahua caído — Consulta RPP' if down else '🟢 RPP Chihuahua recuperado'
        body = f"""
        <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:1.5rem">
          <h2 style="color:{'#ef4444' if down else '#4ade80'}">{subject}</h2>
          <p>{'El servicio RPP Chihuahua no responde. Las consultas están fallando.' if down else 'El servicio RPP Chihuahua volvió a responder correctamente.'}</p>
          <p style="color:#888;font-size:.85rem">Detectado: {datetime.utcnow().isoformat()[:19]} UTC</p>
        </div>"""
        threading.Thread(target=_smtp_send, args=(ADMIN_EMAIL, subject, body), daemon=True).start()
        print(f'[ALERT] RPP {"down" if down else "up"} — alert sent to {ADMIN_EMAIL}', flush=True)
    except Exception as e:
        print(f'[ALERT] Failed to send alert: {e}', flush=True)

def _status_loop():
    time.sleep(15)
    while True:
        try:
            _check_rpp_status()
            if _rpp_status['ok']:
                if _alert_state['alerted'] and not _alert_state['recovered']:
                    _alert_state['recovered'] = True
                    _alert_state['alerted']   = False
                    _alert_state['consecutive_errors'] = 0
                    _send_rpp_alert(down=False)
            else:
                _alert_state['consecutive_errors'] += 1
                _alert_state['recovered'] = False
                # Alert after 2 consecutive failures (~10 min)
                if _alert_state['consecutive_errors'] >= 2 and not _alert_state['alerted']:
                    _alert_state['alerted'] = True
                    _send_rpp_alert(down=True)
        except Exception:
            pass
        time.sleep(300)  # every 5 min

threading.Thread(target=_status_loop, daemon=True).start()

# ── Analytics helper ──────────────────────────────────────────────────────────
def _audit(user_id, action, detail='', ip=''):
    """Write to audit_log table."""
    try:
        with _db() as c:
            c.execute('INSERT INTO audit_log(user_id,action,detail,ip) VALUES(?,?,?,?)',
                      (user_id, action, detail or None, ip or None))
    except Exception:
        pass

def _rpp_metric(event, folio='', duration_ms=0, success=True, error_msg=''):
    """Track RPP call performance metrics."""
    try:
        with _db() as c:
            c.execute('INSERT INTO rpp_metrics(event,folio,duration_ms,success,error_msg) VALUES(?,?,?,?,?)',
                      (event, folio or None, duration_ms, 1 if success else 0, error_msg[:200] if error_msg else None))
    except Exception:
        pass

def _track(event, uid, plan, meta=''):
    try:
        with _db() as c:
            c.execute('INSERT INTO analytics_events(event,user_id,plan,meta) VALUES(?,?,?,?)',
                      (event, uid, plan, meta or None))
    except Exception:
        pass

def _send_annual_renewal_reminders():
    """Send annual plan renewal warning emails at 30, 7 and 1 day before renewal."""
    now = datetime.utcnow()
    with _db() as c:
        rows = c.execute(
            """SELECT id, email, name, plan, period_start, annual_reminder_sent
               FROM users
               WHERE sub_status='active' AND billing_interval='year'
                 AND period_start IS NOT NULL""").fetchall()
    for r in rows:
        try:
            ps       = datetime.fromisoformat(r['period_start'])
            renewal  = ps.replace(year=ps.year + 1)
            days_left = (renewal - now).days
            sent_flags = (r['annual_reminder_sent'] or '').split(',')
            # Determine which threshold to send
            threshold = None
            if days_left <= 1 and '1' not in sent_flags:
                threshold = 1
            elif days_left <= 7 and '7' not in sent_flags:
                threshold = 7
            elif days_left <= 30 and '30' not in sent_flags:
                threshold = 30
            if threshold is None:
                continue
            plan_label  = PLAN_LABELS.get(r['plan'], r['plan'] or 'Tu plan')
            renewal_str = renewal.strftime('%d de %B de %Y')
            urgency     = 'mañana' if threshold == 1 else f'en {threshold} días'
            body = f"""
            <div style="font-family:sans-serif;max-width:520px;margin:auto;background:#0d0d14;
                        color:#dde0e8;padding:2rem;border-radius:12px">
              <h2 style="background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;
                         -webkit-text-fill-color:transparent">Renovación de tu plan anual</h2>
              <p style="color:#aaa;margin:.5rem 0 1.5rem">Hola {r['name'] or r['email']},</p>
              <p>Tu plan <strong style="color:#c084fc">{plan_label} Anual</strong> se renueva
                 <strong style="color:#f59e0b">{urgency}</strong> ({renewal_str}).</p>
              <p style="margin-top:1rem;color:#888;font-size:.85rem">
                Si no deseas renovar, cancela tu suscripción en Stripe antes de esa fecha para evitar el cargo.
              </p>
              <div style="margin-top:1.5rem;padding:1rem;background:#1a1a2e;border-radius:8px;font-size:.85rem">
                <div style="display:flex;justify-content:space-between;margin-bottom:.5rem">
                  <span style="color:#666">Plan</span>
                  <span style="color:#dde0e8;font-weight:600">{plan_label}</span>
                </div>
                <div style="display:flex;justify-content:space-between">
                  <span style="color:#666">Fecha de renovación</span>
                  <span style="color:#f59e0b;font-weight:600">{renewal_str}</span>
                </div>
              </div>
            </div>"""
            ok = _smtp_send(r['email'], f'Renovación de tu plan anual — {urgency.capitalize()}', body)
            if ok:
                new_flags = ','.join(sent_flags + [str(threshold)]).strip(',')
                with _db() as c:
                    c.execute('UPDATE users SET annual_reminder_sent=? WHERE id=?',
                              (new_flags, r['id']))
                print(f'[REMINDER] Annual {threshold}d → {r["email"]}', flush=True)
        except Exception as e:
            print(f'[REMINDER] {r["email"]}: {e}', flush=True)

# ── Notion auto-sync helper ───────────────────────────────────────────────────
import urllib.request, urllib.error

def _notion_sync_user(user_row):
    """Sync a single user to Notion database. Runs in background thread."""
    if not NOTION_API_KEY:
        return
    try:
        headers = {
            'Authorization': f'Bearer {NOTION_API_KEY}',
            'Notion-Version': '2022-06-28',
            'Content-Type': 'application/json',
        }
        # Search for existing page by email
        search_body = json.dumps({
            "filter": {"property": "Email", "email": {"equals": user_row['email']}},
        }).encode()
        req = urllib.request.Request(
            f'https://api.notion.com/v1/databases/{NOTION_DB_ID}/query',
            data=search_body, headers=headers, method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.loads(resp.read())['results']

        # Build properties
        props = {
            "Nombre": {"title": [{"text": {"content": user_row.get('name') or user_row['email']}}]},
            "Email": {"email": user_row['email']},
            "Descargas Usadas": {"number": user_row.get('downloads_used', 0)},
            "Último Sync": {"date": {"start": datetime.utcnow().isoformat()[:19]}},
        }
        plan = user_row.get('plan')
        if plan and plan in ('basico', 'pro', 'empresarial', 'corporativo', 'corporativo_pro', 'admin'):
            props["Plan"] = {"select": {"name": plan}}
        sub = user_row.get('sub_status')
        if sub and sub in ('active', 'canceled', 'past_due'):
            props["Estado Suscripción"] = {"select": {"name": sub}}
        else:
            props["Estado Suscripción"] = {"select": {"name": "none"}}
        if user_row.get('stripe_sub_id'):
            props["Stripe Sub ID"] = {"rich_text": [{"text": {"content": user_row['stripe_sub_id']}}]}
        if user_row.get('created_at'):
            props["Fecha Registro"] = {"date": {"start": user_row['created_at'][:10]}}

        if results:
            # Update existing page
            page_id = results[0]['id']
            body = json.dumps({"properties": props}).encode()
            req = urllib.request.Request(
                f'https://api.notion.com/v1/pages/{page_id}',
                data=body, headers=headers, method='PATCH'
            )
        else:
            # Create new page
            body = json.dumps({
                "parent": {"database_id": NOTION_DB_ID},
                "properties": props,
            }).encode()
            req = urllib.request.Request(
                'https://api.notion.com/v1/pages',
                data=body, headers=headers, method='POST'
            )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f'[Notion sync error] {e}')

def notion_sync_user_async(user_row):
    """Fire-and-forget Notion sync."""
    threading.Thread(target=_notion_sync_user, args=(dict(user_row),), daemon=True).start()

# ── OAuth ─────────────────────────────────────────────────────────────────────
oauth = OAuth(app)
_google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# ── Auth helpers ──────────────────────────────────────────────────────────────
def current_user():
    uid = session.get('uid')
    tok = session.get('tok')
    if not uid or not tok:
        return None
    with _db() as c:
        u = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not u or u['session_token'] != tok:
        return None
    d = dict(u)
    # Compute trial status
    d['in_trial'] = False
    if d.get('trial_ends') and d.get('sub_status') != 'active' and d['role'] != 'admin':
        try:
            d['in_trial'] = datetime.fromisoformat(d['trial_ends']) > datetime.utcnow()
        except (ValueError, TypeError):
            pass
    return d

def login_required(f):
    @functools.wraps(f)
    def wrap(*a, **kw):
        if not current_user():
            session['next'] = request.url
            return redirect(url_for('login_page'))
        return f(*a, **kw)
    return wrap

def sub_required(f):
    """JSON-API: require logged-in + active subscription or trial (admin bypasses)."""
    @functools.wraps(f)
    def wrap(*a, **kw):
        u = current_user()
        if not u:
            return jsonify({'error': 'No autenticado', 'goto': '/login'}), 401
        if u['role'] == 'admin' or u.get('sub_status') == 'active' or u.get('in_trial'):
            return f(*a, **kw)
        # Allow corporate team members
        owner_id = get_corporate_owner_id(u['id'])
        if owner_id:
            with _db() as c:
                owner = c.execute('SELECT sub_status FROM users WHERE id=?', (owner_id,)).fetchone()
            if owner and owner['sub_status'] == 'active':
                return f(*a, **kw)
        return jsonify({'error': 'Se requiere suscripción activa', 'goto': '/pricing'}), 402
    return wrap

def _reset_period_if_due(uid):
    with _db() as c:
        u = c.execute('SELECT period_start FROM users WHERE id=?', (uid,)).fetchone()
        if u and u['period_start']:
            ps = datetime.fromisoformat(u['period_start'])
            if datetime.utcnow() >= ps + timedelta(days=30):
                c.execute('UPDATE users SET downloads_used=0, period_start=? WHERE id=?',
                          (datetime.utcnow().isoformat(), uid))

def _get_pack_credits(c, user_id):
    """Get total available pack credits for a user."""
    rows = c.execute(
        'SELECT SUM(credits_total - credits_used) as avail FROM download_packs WHERE user_id=? AND credits_used < credits_total',
        (user_id,)).fetchone()
    return (rows['avail'] or 0) if rows else 0

def _use_pack_credit(c, user_id):
    """Consume one pack credit. Returns True if successful."""
    row = c.execute(
        'SELECT id FROM download_packs WHERE user_id=? AND credits_used < credits_total ORDER BY ts LIMIT 1',
        (user_id,)).fetchone()
    if row:
        c.execute('UPDATE download_packs SET credits_used=credits_used+1 WHERE id=?', (row['id'],))
        return True
    return False

# ── Corporate team helpers ────────────────────────────────────────────────────
def get_corporate_owner_id(user_id):
    """Return owner_id if this user is an active corporate member, else None."""
    with _db() as c:
        row = c.execute(
            'SELECT owner_id FROM corporate_members WHERE member_id=? AND active=1',
            (user_id,)).fetchone()
    return row['owner_id'] if row else None

def get_team_member_ids(owner_id):
    """Return list of member_ids (excluding Nones) for a corporate owner."""
    with _db() as c:
        rows = c.execute(
            'SELECT member_id FROM corporate_members WHERE owner_id=? AND active=1 AND member_id IS NOT NULL',
            (owner_id,)).fetchall()
    return [r['member_id'] for r in rows]

def get_team_downloads_used(owner_id, period_start):
    """Count total downloads by owner + all active members since period_start."""
    member_ids = get_team_member_ids(owner_id)
    ids = [owner_id] + member_ids
    placeholders = ','.join('?' * len(ids))
    with _db() as c:
        count = c.execute(
            f'SELECT COUNT(*) FROM downloads WHERE user_id IN ({placeholders}) AND ts >= ?',
            ids + [period_start or '1970-01-01']).fetchone()[0]
    return count

def link_corporate_member(email, user_id):
    """If email is invited to a corporate account, link this user_id."""
    with _db() as c:
        c.execute(
            'UPDATE corporate_members SET member_id=?, joined_at=? WHERE invite_email=? AND member_id IS NULL AND active=1',
            (user_id, datetime.utcnow().isoformat(), email.lower()))


def get_dl_info(user):
    """Returns {'left': int, 'use_extra': bool, 'use_pack': bool, 'limit': int, 'used': int, 'pack_credits': int}"""
    if user['role'] == 'admin':
        return {'left': 99999, 'use_extra': False, 'use_pack': False, 'limit': 99999, 'used': 0, 'pack_credits': 0}
    # Corporate member: use owner's plan and aggregate team quota
    owner_id = get_corporate_owner_id(user['id'])
    if owner_id:
        with _db() as c:
            owner = c.execute('SELECT * FROM users WHERE id=?', (owner_id,)).fetchone()
        if owner and owner['sub_status'] == 'active':
            limit        = PLAN_LIMITS.get(owner['plan'] or '', 0)
            period_start = owner['period_start'] or datetime.utcnow().isoformat()
            used         = get_team_downloads_used(owner_id, period_start)
            left         = max(0, limit - used)
            return {'left': left, 'use_extra': False, 'use_pack': False,
                    'limit': limit, 'used': used, 'pack_credits': 0, 'is_team_member': True}
    _reset_period_if_due(user['id'])
    with _db() as c:
        u = c.execute('SELECT downloads_used, plan FROM users WHERE id=?',
                      (user['id'],)).fetchone()
        limit = PLAN_LIMITS.get(u['plan'] or '', 0)
        if limit == 0 and user.get('in_trial'):
            limit = 1  # Trial gets 1 free download
        used  = u['downloads_used'] or 0
        left  = limit - used
        pack_credits = _get_pack_credits(c, user['id'])
        if left > 0:
            return {'left': left + pack_credits, 'use_extra': False, 'use_pack': False,
                    'limit': limit, 'used': used, 'pack_credits': pack_credits}
        extras = c.execute(
            'SELECT COUNT(*) as n FROM extra_credits WHERE user_id=? AND used=0',
            (user['id'],)).fetchone()['n']
        if pack_credits > 0:
            return {'left': pack_credits + extras, 'use_extra': False, 'use_pack': True,
                    'limit': limit, 'used': used, 'pack_credits': pack_credits}
        return {'left': extras, 'use_extra': extras > 0, 'use_pack': False,
                'limit': limit, 'used': used, 'pack_credits': 0}

def send_welcome_email(to_email, name, plan):
    """Send welcome email on new subscription. Requires SMTP_* env vars."""
    import smtplib, ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    host  = os.environ.get('SMTP_HOST', '')
    port  = int(os.environ.get('SMTP_PORT', 587))
    user  = os.environ.get('SMTP_USER', '')
    pwd   = os.environ.get('SMTP_PASS', '')
    frm   = os.environ.get('SMTP_FROM', user)
    if not host or not user:
        return  # SMTP not configured, skip silently
    plan_label  = PLAN_LABELS.get(plan, plan or 'Básico')
    plan_limit  = PLAN_LIMITS.get(plan, 0)
    plan_price  = PLAN_PRICES.get(plan, 0)
    subject = f'¡Bienvenido a Consulta RPP — Plan {plan_label}!'
    body_html = f"""
<div style="font-family:sans-serif;max-width:520px;margin:auto;background:#0d0d14;color:#dde0e8;padding:2rem;border-radius:12px">
  <h2 style="background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent">
    ¡Bienvenido, {name}!
  </h2>
  <p style="color:#aaa;margin:.5rem 0 1.5rem">Tu suscripción al <strong style="color:#c084fc">Plan {plan_label}</strong> está activa.</p>
  <table style="width:100%;border-collapse:collapse;font-size:.875rem">
    <tr><td style="color:#666;padding:.4rem 0;border-bottom:1px solid #1e1e2e">Plan</td>
        <td style="color:#dde0e8;font-weight:600;text-align:right">{plan_label}</td></tr>
    <tr><td style="color:#666;padding:.4rem 0;border-bottom:1px solid #1e1e2e">Descargas/mes</td>
        <td style="color:#4ade80;font-weight:600;text-align:right">{plan_limit}</td></tr>
    <tr><td style="color:#666;padding:.4rem 0">Costo mensual</td>
        <td style="color:#dde0e8;font-weight:600;text-align:right">${plan_price:,} MXN</td></tr>
  </table>
  <a href="https://consulta-rpp.javisnes.com" style="display:block;margin-top:1.5rem;text-align:center;
     background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;padding:.7rem 1.5rem;
     border-radius:8px;text-decoration:none;font-weight:600">Ir al buscador →</a>
  <p style="color:#333;font-size:.75rem;margin-top:1.5rem;text-align:center">
    Consulta RPP Chihuahua · Si tienes dudas responde a este correo.
  </p>
</div>"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = frm
    msg['To']      = to_email
    msg.attach(MIMEText(body_html, 'html'))
    try:
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ctx) as s:
                s.login(user, pwd)
                s.sendmail(frm, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(host, port) as s:
                s.ehlo(); s.starttls(context=ctx); s.ehlo()
                s.login(user, pwd)
                s.sendmail(frm, [to_email], msg.as_string())
    except Exception as e:
        print(f'[EMAIL] Failed to send to {to_email}: {e}', flush=True)


def send_receipt_email(to_email, name, folio, amount=130):
    """Send receipt email for single download purchase."""
    import smtplib, ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    host  = os.environ.get('SMTP_HOST', '')
    port  = int(os.environ.get('SMTP_PORT', 587))
    user  = os.environ.get('SMTP_USER', '')
    pwd   = os.environ.get('SMTP_PASS', '')
    frm   = os.environ.get('SMTP_FROM', user)
    if not host or not user:
        return
    subject = f'Recibo — Descarga Folio {folio} · Consulta RPP'
    body_html = f"""
<div style="font-family:sans-serif;max-width:520px;margin:auto;background:#0d0d14;color:#dde0e8;padding:2rem;border-radius:12px">
  <h2 style="background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent">
    Recibo de compra
  </h2>
  <p style="color:#aaa;margin:.5rem 0 1.5rem">Hola {name}, tu descarga ha sido procesada.</p>
  <table style="width:100%;border-collapse:collapse;font-size:.875rem">
    <tr><td style="color:#666;padding:.4rem 0;border-bottom:1px solid #1e1e2e">Concepto</td>
        <td style="color:#dde0e8;font-weight:600;text-align:right">Descarga de escritura</td></tr>
    <tr><td style="color:#666;padding:.4rem 0;border-bottom:1px solid #1e1e2e">Folio Real</td>
        <td style="color:#c084fc;font-weight:600;text-align:right">{folio}</td></tr>
    <tr><td style="color:#666;padding:.4rem 0;border-bottom:1px solid #1e1e2e">Monto</td>
        <td style="color:#4ade80;font-weight:600;text-align:right">${amount} MXN</td></tr>
    <tr><td style="color:#666;padding:.4rem 0">Fecha</td>
        <td style="color:#dde0e8;font-weight:600;text-align:right">{datetime.utcnow().strftime('%d/%m/%Y %H:%M')} UTC</td></tr>
  </table>
  <a href="https://consulta-rpp.javisnes.com" style="display:block;margin-top:1.5rem;text-align:center;
     background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;padding:.7rem 1.5rem;
     border-radius:8px;text-decoration:none;font-weight:600">Ir al buscador →</a>
  <p style="color:#333;font-size:.75rem;margin-top:1.5rem;text-align:center">
    Consulta RPP Chihuahua · Si tienes dudas responde a este correo.
  </p>
</div>"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = frm
    msg['To']      = to_email
    msg.attach(MIMEText(body_html, 'html'))
    try:
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ctx) as s:
                s.login(user, pwd)
                s.sendmail(frm, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(host, port) as s:
                s.ehlo(); s.starttls(context=ctx); s.ehlo()
                s.login(user, pwd)
                s.sendmail(frm, [to_email], msg.as_string())
    except Exception as e:
        print(f'[EMAIL] Receipt failed for {to_email}: {e}', flush=True)


def send_pack_email(to_email, name, pack_type, credits):
    """Send receipt for pack purchase."""
    import smtplib, ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    host = os.environ.get('SMTP_HOST', '')
    port = int(os.environ.get('SMTP_PORT', 587))
    user = os.environ.get('SMTP_USER', '')
    pwd  = os.environ.get('SMTP_PASS', '')
    frm  = os.environ.get('SMTP_FROM', user)
    if not host or not user:
        return
    price = PACK_CONFIG.get(pack_type, {}).get('price_mxn', 0)
    subject = f'Recibo — Paquete de {credits} descargas · Consulta RPP'
    body_html = f"""
<div style="font-family:sans-serif;max-width:520px;margin:auto;background:#0d0d14;color:#dde0e8;padding:2rem;border-radius:12px">
  <h2 style="background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent">
    Paquete activado
  </h2>
  <p style="color:#aaa;margin:.5rem 0 1.5rem">Hola {name}, tu paquete de descargas ha sido activado.</p>
  <table style="width:100%;border-collapse:collapse;font-size:.875rem">
    <tr><td style="color:#666;padding:.4rem 0;border-bottom:1px solid #1e1e2e">Paquete</td>
        <td style="color:#c084fc;font-weight:600;text-align:right">{credits} descargas</td></tr>
    <tr><td style="color:#666;padding:.4rem 0;border-bottom:1px solid #1e1e2e">Monto</td>
        <td style="color:#4ade80;font-weight:600;text-align:right">${price} MXN</td></tr>
    <tr><td style="color:#666;padding:.4rem 0">Fecha</td>
        <td style="color:#dde0e8;font-weight:600;text-align:right">{datetime.utcnow().strftime('%d/%m/%Y %H:%M')} UTC</td></tr>
  </table>
  <p style="color:#aaa;font-size:.875rem;margin-top:1rem">Las descargas no expiran. Úsalas cuando quieras.</p>
  <a href="https://consulta-rpp.javisnes.com" style="display:block;margin-top:1.5rem;text-align:center;
     background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;padding:.7rem 1.5rem;
     border-radius:8px;text-decoration:none;font-weight:600">Ir al buscador →</a>
</div>"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = frm
    msg['To']      = to_email
    msg.attach(MIMEText(body_html, 'html'))
    try:
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ctx) as s:
                s.login(user, pwd)
                s.sendmail(frm, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(host, port) as s:
                s.ehlo(); s.starttls(context=ctx); s.ehlo()
                s.login(user, pwd)
                s.sendmail(frm, [to_email], msg.as_string())
    except Exception as e:
        print(f'[EMAIL] Pack receipt failed for {to_email}: {e}', flush=True)


# ── Shared SMTP helper ────────────────────────────────────────────────────────
def _smtp_send(to_email, subject, body_html):
    import smtplib, ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    host = os.environ.get('SMTP_HOST', '')
    port = int(os.environ.get('SMTP_PORT', 587))
    user = os.environ.get('SMTP_USER', '')
    pwd  = os.environ.get('SMTP_PASS', '')
    frm  = os.environ.get('SMTP_FROM', user)
    if not host or not user:
        return False
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = frm
    msg['To']      = to_email
    msg.attach(MIMEText(body_html, 'html'))
    try:
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ctx) as s:
                s.login(user, pwd); s.sendmail(frm, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(host, port) as s:
                s.ehlo(); s.starttls(context=ctx); s.ehlo()
                s.login(user, pwd); s.sendmail(frm, [to_email], msg.as_string())
        return True
    except Exception as e:
        print(f'[EMAIL] {subject[:30]} -> {to_email}: {e}', flush=True)
        return False

_EMAIL_WRAP = ('font-family:sans-serif;max-width:520px;margin:auto;'
               'background:#0d0d14;color:#dde0e8;padding:2rem;border-radius:12px')
_EMAIL_BTN  = ('display:block;margin-top:1.5rem;text-align:center;'
               'background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;'
               'padding:.7rem 1.5rem;border-radius:8px;text-decoration:none;font-weight:600')

def _notify_new_user(name, email, uid, method, ip='', ref_code=''):
    """Send admin notification email when a new user registers."""
    now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    subject = f'🆕 Nuevo usuario — {name} ({email})'
    row = lambda lbl, val, color='#dde0e8': (
        f'<tr style="border-bottom:1px solid #1e1e2e">'
        f'<td style="padding:.55rem .75rem;color:#666;width:38%;font-size:.85rem">{lbl}</td>'
        f'<td style="padding:.55rem .75rem;color:{color};font-size:.875rem"><strong>{val}</strong></td></tr>'
    )
    body = f"""
    <div style="{_EMAIL_WRAP}">
      <h2 style="margin:0 0 .25rem;background:linear-gradient(120deg,#8b9cf4,#c084fc);
                 -webkit-background-clip:text;-webkit-text-fill-color:transparent">
        🆕 Nuevo usuario registrado
      </h2>
      <p style="color:#555;font-size:.8rem;margin-bottom:1.5rem">{now_str}</p>
      <table style="width:100%;border-collapse:collapse">
        {row('Nombre', name)}
        {row('Email', email, '#8b9cf4')}
        {row('ID de usuario', f'#{uid}', '#c084fc')}
        {row('Método de registro', method, '#facc15')}
        {row('IP', ip or '—', '#555')}
        {row('Referido por', ref_code or '—', '#4ade80')}
      </table>
      <a href="https://consulta-rpp.javisnes.com/admin" style="{_EMAIL_BTN}">
        Ver en Admin Panel →
      </a>
    </div>"""
    threading.Thread(target=_smtp_send, args=(ADMIN_EMAIL, subject, body), daemon=True).start()
_BASE_URL   = 'https://consulta-rpp.javisnes.com'

def send_folio_alert_email(to_email, name, folio):
    """Folio watched by user has changed in RPP."""
    html = f"""<div style="{_EMAIL_WRAP}">
  <h2 style="color:#c084fc">📋 Cambio detectado en folio {folio}</h2>
  <p style="color:#aaa;margin:.5rem 0 1rem">Hola {name or 'usuario'}, el folio <strong style="color:#c084fc">{folio}</strong> que tienes en seguimiento ha cambiado en el RPP Chihuahua.</p>
  <a href="{_BASE_URL}/?auto_folio={folio}" style="{_EMAIL_BTN}">Ver documento actualizado →</a>
  <p style="color:#555;font-size:.8rem;margin-top:1.5rem">Para cancelar esta alerta entra a tu cuenta → Mi cuenta.</p>
</div>"""
    return _smtp_send(to_email, f'📋 Cambio detectado en folio {folio} — Consulta RPP', html)

def send_renewal_reminder_email(to_email, name, plan_label, renewal_date):
    """Plan renews in 3 days."""
    html = f"""<div style="{_EMAIL_WRAP}">
  <h2 style="color:#8b9cf4">🔄 Tu plan {plan_label} se renueva el {renewal_date}</h2>
  <p style="color:#aaa;margin:.5rem 0 1rem">Hola {name or 'usuario'}, tu suscripción se renovará automáticamente en 3 días (<strong style="color:#c084fc">{renewal_date}</strong>).</p>
  <p style="color:#aaa">Si deseas cambiar o cancelar tu plan, hazlo antes de esa fecha desde el portal.</p>
  <a href="{_BASE_URL}/portal" style="{_EMAIL_BTN}">Gestionar mi suscripción →</a>
</div>"""
    return _smtp_send(to_email, f'🔄 Tu plan se renueva el {renewal_date} — Consulta RPP', html)

def send_trial_expiry_email(to_email, name, days_left):
    """Trial ends in 1-2 days."""
    btn = _EMAIL_BTN.replace('#8b9cf4,#c084fc', '#f59e0b,#ef4444')
    html = f"""<div style="{_EMAIL_WRAP}">
  <h2 style="color:#f59e0b">⏱️ Tu prueba gratuita termina en {days_left} día(s)</h2>
  <p style="color:#aaa;margin:.5rem 0 1rem">Hola {name or 'usuario'}, tu acceso de prueba vence pronto.</p>
  <p style="color:#aaa">Suscríbete ahora para no perder búsqueda por nombre y lote, vista previa de documentos y todas las funciones Pro.</p>
  <a href="{_BASE_URL}/pricing" style="{btn}">Suscribirme antes que expire →</a>
</div>"""
    return _smtp_send(to_email, f'⏱️ Tu prueba gratuita termina en {days_left} día(s) — Consulta RPP', html)

def send_payment_failed_email(to_email, name, plan_label):
    """Stripe payment failed."""
    btn = _EMAIL_BTN.replace('#8b9cf4,#c084fc', '#ef4444,#b91c1c')
    html = f"""<div style="{_EMAIL_WRAP}">
  <h2 style="color:#f87171">⚠️ Problema con el pago de tu plan {plan_label}</h2>
  <p style="color:#aaa;margin:.5rem 0 1rem">Hola {name or 'usuario'}, no pudimos procesar el cobro de tu suscripción.</p>
  <p style="color:#aaa">Actualiza tu método de pago para continuar sin interrupciones.</p>
  <a href="{_BASE_URL}/portal" style="{btn}">Actualizar método de pago →</a>
</div>"""
    return _smtp_send(to_email, '⚠️ Pago fallido — Consulta RPP', html)

def send_low_downloads_email(to_email, name, left):
    """Only 1 download remaining."""
    html = f"""<div style="{_EMAIL_WRAP}">
  <h2 style="color:#f59e0b">📉 Solo te queda {left} descarga este mes</h2>
  <p style="color:#aaa;margin:.5rem 0 1rem">Hola {name or 'usuario'}, casi agotaste las descargas de tu plan para este período.</p>
  <p style="color:#aaa">Compra un paquete de descargas extra o mejora tu plan.</p>
  <a href="{_BASE_URL}/pricing" style="{_EMAIL_BTN}">Comprar más descargas →</a>
</div>"""
    return _smtp_send(to_email, '📉 Solo te queda 1 descarga este mes — Consulta RPP', html)


# ── Cron functions ────────────────────────────────────────────────────────────
def check_folio_alerts():
    """Fetch each watched folio, compare hash, email if changed. Called by cron."""
    import hashlib
    with _db() as c:
        alerts = c.execute("""
            SELECT fa.id, fa.folio_real, fa.last_hash, u.email, u.name
            FROM folio_alerts fa JOIN users u ON fa.user_id = u.id
            WHERE fa.active = 1 AND u.sub_status = 'active'
            ORDER BY fa.ts
        """).fetchall()
    notified = 0
    for alert in alerts:
        try:
            pdf_bytes = fetch_pdf_for_folio(alert['folio_real'])
            new_hash  = hashlib.md5(pdf_bytes).hexdigest()
            old_hash  = alert['last_hash']
            with _db() as c:
                c.execute('UPDATE folio_alerts SET last_hash=? WHERE id=?',
                          (new_hash, alert['id']))
            if old_hash and new_hash != old_hash:
                send_folio_alert_email(alert['email'], alert['name'], alert['folio_real'])
                notified += 1
                print(f'[ALERT] Folio {alert["folio_real"]} changed → {alert["email"]}', flush=True)
        except Exception as e:
            print(f'[ALERT] Error folio {alert["folio_real"]}: {e}', flush=True)
    return notified

def send_renewal_reminders():
    """Email users 3 days before their plan renews. Called daily by cron."""
    now          = datetime.utcnow()
    window_start = (now - timedelta(days=27)).isoformat()
    window_end   = (now - timedelta(days=26)).isoformat()
    sent = 0
    with _db() as c:
        rows = c.execute("""
            SELECT id, email, name, plan, period_start
            FROM users
            WHERE sub_status='active' AND period_start IS NOT NULL
              AND period_start <= ? AND period_start > ?
              AND (renewal_reminder_sent IS NULL OR renewal_reminder_sent < ?)
        """, (window_start, window_end, window_start)).fetchall()
        for r in rows:
            plan_label   = PLAN_LABELS.get(r['plan'], r['plan'] or 'Tu plan')
            renewal_dt   = datetime.fromisoformat(r['period_start']) + timedelta(days=30)
            renewal_str  = renewal_dt.strftime('%d/%m/%Y')
            if send_renewal_reminder_email(r['email'], r['name'], plan_label, renewal_str):
                c.execute('UPDATE users SET renewal_reminder_sent=? WHERE id=?',
                          (now.isoformat(), r['id']))
                sent += 1
    return sent

def send_trial_expiry_reminders():
    """Email trial users 2 days before trial ends. Called daily by cron."""
    now          = datetime.utcnow()
    window_start = (now + timedelta(days=1)).isoformat()
    window_end   = (now + timedelta(days=3)).isoformat()
    sent = 0
    with _db() as c:
        rows = c.execute("""
            SELECT id, email, name, trial_ends
            FROM users
            WHERE trial_ends IS NOT NULL AND trial_ends > ? AND trial_ends <= ?
              AND (sub_status IS NULL OR sub_status != 'active')
        """, (window_start, window_end)).fetchall()
        for r in rows:
            try:
                days_left = max(1, (datetime.fromisoformat(r['trial_ends']) - now).days)
                if send_trial_expiry_email(r['email'], r['name'], days_left):
                    sent += 1
            except Exception as e:
                print(f'[TRIAL REMINDER] {r["email"]}: {e}', flush=True)
    return sent


def record_dl(user_id, folio, use_extra, use_pack=False, nombre=None):
    with _db() as c:
        if use_pack:
            _use_pack_credit(c, user_id)
        elif use_extra:
            row = c.execute(
                'SELECT id FROM extra_credits WHERE user_id=? AND used=0 ORDER BY ts LIMIT 1',
                (user_id,)).fetchone()
            if row:
                c.execute('UPDATE extra_credits SET used=1 WHERE id=?', (row['id'],))
        else:
            c.execute('UPDATE users SET downloads_used=downloads_used+1 WHERE id=?', (user_id,))
            c.execute("""UPDATE users SET period_start=COALESCE(period_start,?)
                         WHERE id=? AND period_start IS NULL""",
                      (datetime.utcnow().isoformat(), user_id))
        c.execute('INSERT INTO downloads(user_id,folio_real,nombre) VALUES(?,?,?)',
                  (user_id, str(folio), nombre or None))

# ── HTML: Annual Subscriber Dashboard ────────────────────────────────────────

def render_dashboard(u, dl, history, monthly_counts, annual_used, annual_quota, selected_year, selected_month):
    plan_label  = PLAN_LABELS.get(u['plan'], u['plan'] or '—')
    billing_txt = 'Anual' if u.get('billing_interval') == 'year' else 'Mensual'
    period_start = u.get('period_start', '')
    next_renewal = '—'
    if period_start:
        try:
            dt = datetime.fromisoformat(period_start)
            dt = dt.replace(year=dt.year + 1)
            next_renewal = dt.strftime('%d %b %Y')
        except Exception:
            pass

    annual_left  = max(0, annual_quota - annual_used)
    annual_pct   = min(100, int(annual_used / annual_quota * 100)) if annual_quota > 0 else 0
    bar_color    = '#4ade80' if annual_pct < 70 else ('#f59e0b' if annual_pct < 90 else '#f87171')

    # Monthly breakdown table rows
    months_es = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic']
    monthly_rows = ''
    for m in range(1, 13):
        cnt = monthly_counts.get(str(m).zfill(2), 0)
        bar_w = int(cnt / max(monthly_counts.values(), default=1) * 100) if monthly_counts else 0
        monthly_rows += f'''<tr>
          <td style="color:#777;width:2.5rem">{months_es[m-1]}</td>
          <td><div style="background:#1a1a2a;border-radius:4px;height:10px;overflow:hidden">
            <div style="height:100%;background:#8b9cf4;width:{bar_w}%"></div></div></td>
          <td style="text-align:right;color:#dde0e8;font-weight:600;width:2.5rem">{cnt}</td>
        </tr>'''

    # History rows
    hist_rows = ''
    for r in history:
        ts = (r.get('ts') or '')
        fecha = ts[:10] if ts else '—'
        hora  = ts[11:16] if len(ts) > 11 else '—'
        folio = r.get('folio_real') or '—'
        nom   = r.get('nombre') or '—'
        hist_rows += f'<tr><td style="color:#555;font-size:.77rem">{fecha}</td><td style="color:#555;font-size:.77rem">{hora}</td><td style="color:#8b9cf4;font-family:monospace">{folio}</td><td style="color:#aaa;font-size:.82rem">{nom}</td></tr>'
    if not hist_rows:
        hist_rows = '<tr><td colspan="4" style="color:#333;text-align:center;padding:1.5rem">Sin descargas en el periodo seleccionado</td></tr>'

    # Year options
    import datetime as _dt
    cur_year = _dt.datetime.utcnow().year
    year_opts = ''.join(f'<option value="{y}" {"selected" if y==selected_year else ""}>{y}</option>'
                        for y in range(cur_year - 2, cur_year + 1))
    month_opts = '<option value="0" ' + ('selected' if selected_month==0 else '') + '>Todos los meses</option>'
    for i in range(1, 13):
        month_opts += f'<option value="{i}" {"selected" if i==selected_month else ""}>{months_es[i-1]}</option>'

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Panel de Control – Consulta RPP</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#0d0d14;color:#dde0e8;min-height:100vh;padding:2rem 1rem}}
    .wrap{{max-width:900px;margin:0 auto}}
    h1{{font-size:1.5rem;font-weight:700;background:linear-gradient(120deg,#8b9cf4,#c084fc);
        -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.25rem}}
    .sub{{color:#444;font-size:.8rem;margin-bottom:1.8rem}}
    /* hero counter */
    .hero{{background:#0f0f1e;border:1.5px solid #2a2a4a;border-radius:16px;padding:1.8rem 2rem;
           margin-bottom:1.5rem;text-align:center;position:relative;overflow:hidden}}
    .hero::before{{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 50% -20%,rgba(139,156,244,.12),transparent 70%);pointer-events:none}}
    .hero-num{{font-size:5rem;font-weight:900;line-height:1;color:{bar_color};
               text-shadow:0 0 40px {bar_color}55;margin-bottom:.3rem}}
    .hero-lbl{{font-size:1rem;color:#666;font-weight:500}}
    .hero-sub{{font-size:.8rem;color:#333;margin-top:.5rem}}
    .bar-wrap{{background:#1a1a2a;border-radius:99px;height:6px;margin:.9rem auto;max-width:320px}}
    .bar-fill{{height:100%;border-radius:99px;background:{bar_color};width:{annual_pct}%}}
    /* stat cards */
    .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem;margin-bottom:1.5rem}}
    .card{{background:#13131f;border:1.5px solid #1e1e2e;border-radius:12px;padding:1rem 1.1rem}}
    .card-val{{font-size:1.5rem;font-weight:800}}
    .card-lbl{{font-size:.7rem;color:#444;text-transform:uppercase;letter-spacing:.05em;margin-top:.1rem}}
    /* sections */
    .section{{background:#13131f;border:1.5px solid #1e1e2e;border-radius:12px;
              padding:1.2rem 1.4rem;margin-bottom:1.2rem}}
    .section-title{{font-weight:700;font-size:.9375rem;margin-bottom:1rem;display:flex;
                    align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem}}
    /* filters */
    .filters{{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}}
    select{{background:#0a0a12;border:1px solid #2a2a3a;border-radius:7px;color:#dde0e8;
            padding:.4rem .65rem;font-size:.85rem;cursor:pointer}}
    .btn-filter{{padding:.4rem .9rem;background:linear-gradient(135deg,#8b9cf4,#c084fc);
                 color:#fff;border:none;border-radius:7px;font-weight:600;font-size:.82rem;cursor:pointer}}
    .btn-report{{padding:.4rem .9rem;background:#1a2a1a;border:1px solid #2a4a2a;color:#4ade80;
                 border-radius:7px;font-weight:600;font-size:.82rem;cursor:pointer;text-decoration:none;display:inline-block}}
    .btn-report:hover{{background:#1d3a1d}}
    /* tables */
    table{{width:100%;border-collapse:collapse;font-size:.875rem}}
    th{{color:#333;font-weight:600;padding:.4rem .5rem;text-align:left;
        border-bottom:1px solid #1e1e2e;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em}}
    td{{padding:.5rem .5rem;border-bottom:1px solid #0f0f18;vertical-align:middle}}
    tr:last-child td{{border-bottom:none}}
    .back{{color:#444;font-size:.875rem;text-decoration:none;display:inline-block;margin-bottom:1.2rem}}
    .back:hover{{color:#8b9cf4}}
    .badge{{display:inline-block;padding:.15rem .55rem;border-radius:20px;font-size:.68rem;
            font-weight:700;background:#1d1d35;color:#8b9cf4;border:1px solid #2a2a5a;margin-left:.4rem}}
    .badge-annual{{background:#1a2a1a;color:#4ade80;border-color:#2a4a2a}}
  </style>
</head>
<body>
<div class="wrap">
  <a href="/" class="back">← Volver al buscador</a>
  <h1>Panel de Control <span class="badge">{plan_label}</span><span class="badge badge-annual">{billing_txt}</span></h1>
  <p class="sub">Próxima renovación: {next_renewal} &nbsp;·&nbsp; Periodo desde: {(period_start or '')[:10]}</p>

  <!-- HERO COUNTER -->
  <div class="hero">
    <div class="hero-num">{annual_left}</div>
    <div class="hero-lbl">descargas disponibles este año</div>
    <div class="bar-wrap"><div class="bar-fill"></div></div>
    <div class="hero-sub">{annual_used} usadas · {annual_quota} cuota anual total</div>
  </div>

  <!-- STAT CARDS -->
  <div class="cards">
    <div class="card">
      <div class="card-val" style="color:#8b9cf4">{annual_used}</div>
      <div class="card-lbl">Usadas este año</div>
    </div>
    <div class="card">
      <div class="card-val" style="color:#c084fc">{annual_quota}</div>
      <div class="card-lbl">Cuota anual</div>
    </div>
    <div class="card">
      <div class="card-val" style="color:#4ade80">{max(0, annual_quota - annual_used)}</div>
      <div class="card-lbl">Disponibles</div>
    </div>
    <div class="card">
      <div class="card-val" style="color:#f59e0b">{sum(monthly_counts.values())}</div>
      <div class="card-lbl">Descargas {selected_year}</div>
    </div>
  </div>

  <!-- MONTHLY BREAKDOWN -->
  <div class="section">
    <div class="section-title">
      Actividad mensual — {selected_year}
      <form method="get" style="display:inline">
        <div class="filters">
          <select name="year" onchange="this.form.submit()">{year_opts}</select>
        </div>
      </form>
    </div>
    <table><tbody>{monthly_rows}</tbody></table>
  </div>

  <!-- HISTORY + REPORT -->
  <div class="section">
    <div class="section-title">
      Historial de descargas
      <div class="filters">
        <form method="get" style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap">
          <input type="hidden" name="year" value="{selected_year}">
          <select name="month" onchange="this.form.submit()">{month_opts}</select>
          {'<a class="btn-report" href="/dashboard/report?year=' + str(selected_year) + '&month=' + str(selected_month) + '">&#11123; Descargar reporte CSV</a>' if selected_month > 0 else '<a class="btn-report" href="/dashboard/report?year=' + str(selected_year) + '">&#11123; Reporte anual CSV</a>'}
        </form>
      </div>
    </div>
    <table>
      <thead><tr><th>Fecha</th><th>Hora</th><th>Folio Real</th><th>Propietario</th></tr></thead>
      <tbody>{hist_rows}</tbody>
    </table>
  </div>
</div>
</body></html>"""


# ── HTML: Login ───────────────────────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Iniciar sesión – Consulta RPP</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#09090f;color:#e2e4ed;min-height:100vh;display:flex;
         align-items:center;justify-content:center;padding:1rem}
    .card{width:100%;max-width:400px;background:#0f0f18;border:1px solid #1e1e2e;
          border-radius:14px;padding:2.2rem 2rem}
    .logo{font-size:1.3rem;font-weight:700;text-align:center;letter-spacing:-.025em;
          background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;
          -webkit-text-fill-color:transparent;margin-bottom:.2rem}
    .sub{color:#4b5268;font-size:.8rem;text-align:center;margin-bottom:1.5rem}
    /* Google block */
    .google-wrap{position:relative;margin-bottom:.5rem}
    .rec-badge{position:absolute;top:-10px;left:50%;transform:translateX(-50%);
               background:linear-gradient(135deg,#4ade80,#22c55e);color:#000;
               font-size:.63rem;font-weight:800;padding:.18rem .65rem;border-radius:20px;
               white-space:nowrap;letter-spacing:.04em;z-index:1}
    .google-btn{display:flex;align-items:center;justify-content:center;gap:.75rem;width:100%;
                padding:.75rem 1rem;background:#fff;color:#1a1a2a;border:2px solid #4ade80;
                border-radius:10px;font-size:.9375rem;font-weight:700;cursor:pointer;
                text-decoration:none;transition:box-shadow .2s}
    .google-btn:hover{box-shadow:0 0 0 3px rgba(74,222,128,.25)}
    .google-btn svg{width:18px;height:18px;flex-shrink:0}
    .google-hint{text-align:center;font-size:.72rem;color:#3a4a3a;margin-top:.4rem}
    /* divider */
    .divider{display:flex;align-items:center;gap:.75rem;margin:1.2rem 0;font-size:.75rem;color:#2a2a3a}
    .divider::before,.divider::after{content:'';flex:1;border-top:1px solid #1e1e2e}
    /* email form */
    .form-group{margin-bottom:.8rem}
    label{display:block;font-size:.78rem;color:#666;margin-bottom:.28rem}
    input[type=text],input[type=email],input[type=password]{
      width:100%;background:#0a0a12;border:1px solid #1e1e2e;border-radius:8px;
      padding:.55rem .75rem;color:#e2e4ed;font-size:.9rem;outline:none;transition:border .2s}
    input:focus{border-color:#6366f1}
    .captcha-row{display:flex;gap:.5rem;align-items:flex-end}
    .captcha-q{flex:1}
    .captcha-q input{width:100%}
    .captcha-refresh{background:#1a1a2a;border:1px solid #2a2a3a;border-radius:8px;
                     color:#8b9cf4;padding:.55rem .65rem;cursor:pointer;font-size:.85rem;
                     white-space:nowrap;line-height:1}
    .captcha-err{font-size:.72rem;color:#f87171;margin-top:.25rem;display:none}
    .btn-main{width:100%;padding:.65rem;background:linear-gradient(135deg,#8b9cf4,#c084fc);
              color:#fff;border:none;border-radius:8px;font-weight:700;font-size:.95rem;
              cursor:pointer;margin-top:.2rem;transition:opacity .2s}
    .btn-main:hover{opacity:.88}
    .err{background:#200a0a;border:1px solid #4a1010;color:#f87171;border-radius:7px;
         padding:.55rem .75rem;font-size:.8rem;margin-top:.6rem;display:none}
    .msg{margin-top:.8rem;padding:.55rem .75rem;border-radius:6px;font-size:.8rem}
    .msg.info{background:#0d1a2e;border:1px solid #1e3a5f;color:#7bb3f0}
    .msg.warn{background:#1a0a0a;border:1px solid #3f1515;color:#f87171}
    .note{margin-top:1.1rem;font-size:.72rem;color:#232333;text-align:center;line-height:1.5}
    .toggle-mode{font-size:.8rem;color:#555;text-align:center;margin-top:.85rem}
    .toggle-mode a{color:#8b9cf4;text-decoration:none;cursor:pointer}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">Consulta RPP</div>
  <p class="sub">Registro Público de la Propiedad · Chihuahua</p>

  <!-- Google — método recomendado -->
  <div class="google-wrap">
    <div class="rec-badge">⭐ Recomendado · más rápido</div>
    <a href="/auth/google" class="google-btn">
      <svg viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
      Continuar con Google
    </a>
    <p class="google-hint">Un clic · sin contraseña · acceso inmediato</p>
  </div>

  <div class="divider">o continúa con correo electrónico</div>

  <!-- Magic Link form -->
  <div id="magic-form">
    <div class="form-group">
      <label>Correo electrónico</label>
      <input type="email" id="inp-email" placeholder="correo@ejemplo.com" autocomplete="email"
             onkeydown="if(event.key==='Enter')sendMagicLink()">
    </div>
    <button class="btn-main" id="btn-magic" onclick="sendMagicLink()">
      ✉ Enviar link de acceso
    </button>
    <div class="err" id="magic-err"></div>
  </div>

  <!-- Success state -->
  <div id="magic-sent" style="display:none;text-align:center;padding:1rem 0">
    <div style="font-size:2.5rem;margin-bottom:.5rem">📩</div>
    <p style="font-size:1rem;font-weight:600;color:#4ade80;margin-bottom:.5rem">¡Link enviado!</p>
    <p style="font-size:.85rem;color:#888;margin-bottom:1rem">Revisa tu bandeja de entrada y haz clic en el botón para entrar. El link es válido por 15 minutos.</p>
    <p style="font-size:.75rem;color:#555">¿No llegó? Revisa spam o <a href="#" onclick="document.getElementById('magic-sent').style.display='none';document.getElementById('magic-form').style.display='';return false" style="color:#8b9cf4">intenta de nuevo</a></p>
  </div>

  __MSG__
  <p class="note">Al continuar aceptas los <a href="/terminos" style="color:#444;text-decoration:underline">términos de uso</a>.</p>
</div>
<script>
async function sendMagicLink(){
  const btn = document.getElementById('btn-magic');
  const err = document.getElementById('magic-err');
  err.style.display = 'none';
  const email = document.getElementById('inp-email').value.trim();
  if(!email){err.textContent='Ingresa tu correo electrónico';err.style.display='';return;}
  btn.disabled=true; btn.textContent='Enviando...';
  try{
    const res = await fetch('/auth/magic-link',{method:'POST',credentials:'same-origin',
                             headers:{'Content-Type':'application/json'},
                             body:JSON.stringify({email})});
    const d = await res.json();
    if(d.ok){
      document.getElementById('magic-form').style.display='none';
      document.getElementById('magic-sent').style.display='';
      return;
    }
    err.textContent = d.error || 'Error al enviar';
    err.style.display = '';
  }catch(e){
    err.textContent='Error de conexión. Intenta de nuevo.';
    err.style.display='';
  }
  btn.disabled=false; btn.textContent='✉ Enviar link de acceso';
}
</script>
</body></html>"""

# ── HTML: Pricing ─────────────────────────────────────────────────────────────
ANNUAL_PRICES = {
    'basico':          5000,
    'pro':             10000,
    'empresarial':     20000,
    'corporativo':     50000,
    'corporativo_pro': 80000,
}
ANNUAL_QUOTAS = {
    'basico':          60,
    'pro':             120,
    'empresarial':     240,
    'corporativo':     1200,
    'corporativo_pro': 6000,
}
MAX_TEAM_MEMBERS = {
    'basico':          2,
    'pro':             2,
    'empresarial':     2,
    'corporativo':     10,
    'corporativo_pro': 50,
}

def _has_team_access(u):
    """Check if user has team features. Corporativo always; others only annual."""
    plan = u.get('plan') or ''
    if plan not in MAX_TEAM_MEMBERS or u.get('sub_status') != 'active':
        return False
    if plan in ('corporativo', 'corporativo_pro'):
        return True
    return u.get('billing_interval') == 'year'

def render_pricing(user=None):
    cur  = user.get('plan') if user and user.get('role') != 'admin' else None
    stat = user.get('sub_status') if user else None

    def card(key, color, features, popular=False):
        label       = PLAN_LABELS[key]
        mo_price    = PLAN_PRICES[key]
        ann_price   = ANNUAL_PRICES[key]
        ann_mo      = ann_price // 12  # effective monthly
        savings     = mo_price * 12 - ann_price
        is_cur      = (cur == key and stat == 'active')
        badge       = '<div class="popular">MÁS POPULAR</div>' if popular else ''
        btn_txt     = 'Plan actual' if is_cur else 'Suscribirse'
        btn_dis     = 'disabled' if is_cur else ''
        onclick_mo  = '' if is_cur else f"subscribe('{key}')"
        onclick_ann = '' if is_cur else f"subscribe('{key}_annual')"
        feats       = ''.join(f'<li>{f}</li>' for f in features)
        return f"""
        <div class="plan-card{'  current' if is_cur else ''}" data-key="{key}">
          {badge}
          <div class="plan-name" style="color:{color}">{label}</div>
          <div class="price-monthly">
            <div class="plan-price">${mo_price:,} <span>MXN/mes</span></div>
          </div>
          <div class="price-annual" style="display:none">
            <div class="plan-price">${ann_price:,} <span>MXN/año</span></div>
            <div class="ann-equiv">${ann_mo:,} MXN/mes · <span style="color:#4ade80">Ahorras ${savings:,}</span></div>
          </div>
          <ul class="plan-feats">{feats}</ul>
          <button class="plan-btn btn-monthly" style="background:{color}" {btn_dis} onclick="{onclick_mo}">{btn_txt}</button>
          <button class="plan-btn btn-annual" style="background:{color};display:none" {btn_dis} onclick="{onclick_ann}">{btn_txt}</button>
        </div>"""

    basico_card = card('basico', '#8b9cf4', [
        'Consultas ilimitadas',
        '5 descargas de escrituras/mes',
        'Sin marca de agua',
        'Buscar por folio real',
        'Buscar por nombre de propietario',
        '👥 Hasta 2 miembros de equipo <small style="color:#facc15">(anual)</small>',
        '📊 Dashboard de equipo <small style="color:#facc15">(anual)</small>',
    ])
    pro_card = card('pro', '#c084fc', [
        'Consultas ilimitadas',
        '10 descargas de escrituras/mes',
        'Sin marca de agua',
        'Buscar por folio real y nombre',
        'Vista previa del documento',
        'Soporte WhatsApp',
        '👥 Hasta 2 miembros de equipo <small style="color:#facc15">(anual)</small>',
        '📊 Dashboard de equipo <small style="color:#facc15">(anual)</small>',
    ], popular=True)
    emp_card = card('empresarial', '#f472b6', [
        'Consultas ilimitadas',
        '20 descargas de escrituras/mes',
        'Sin marca de agua',
        'Buscar por folio, nombre y lote',
        'Vista previa del documento',
        'Alertas de cambios en folio',
        'Soporte WhatsApp prioritario',
        '👥 Hasta 2 miembros de equipo <small style="color:#facc15">(anual)</small>',
        '📊 Dashboard de equipo <small style="color:#facc15">(anual)</small>',
    ])

    def corp_card(key, color, badge_text, features, note=''):
        label    = PLAN_LABELS[key]
        mo_price = PLAN_PRICES[key]
        ann_price= ANNUAL_PRICES[key]
        ann_mo   = ann_price // 12
        savings  = mo_price * 12 - ann_price
        is_cur   = (cur == key and stat == 'active')
        btn_txt  = 'Plan actual' if is_cur else 'Suscribirse'
        btn_dis  = 'disabled' if is_cur else ''
        onclick_mo  = '' if is_cur else f"subscribe('{key}')"
        onclick_ann = '' if is_cur else f"subscribe('{key}_annual')"
        feats    = ''.join(f'<li>{f}</li>' for f in features)
        note_html= f'<p style="font-size:.75rem;color:#666;margin-top:.5rem">{note}</p>' if note else ''
        return f"""
        <div class="plan-card{'  current' if is_cur else ''}" data-key="{key}"
             style="border-color:{color}33;position:relative">
          <div style="position:absolute;top:-11px;left:50%;transform:translateX(-50%);
                      background:{color};color:#000;font-size:.65rem;font-weight:700;
                      padding:.2rem .8rem;border-radius:20px;white-space:nowrap">{badge_text}</div>
          <div class="plan-name" style="color:{color}">{label}</div>
          <div class="price-monthly">
            <div class="plan-price">${mo_price:,} <span>MXN/mes</span></div>
          </div>
          <div class="price-annual" style="display:none">
            <div class="plan-price">${ann_price:,} <span>MXN/año</span></div>
            <div class="ann-equiv">${ann_mo:,} MXN/mes · <span style="color:#4ade80">Ahorras ${savings:,}</span></div>
          </div>
          <ul class="plan-feats">{feats}</ul>
          {note_html}
          <button class="plan-btn btn-monthly" style="background:{color};color:#000" {btn_dis} onclick="{onclick_mo}">{btn_txt}</button>
          <button class="plan-btn btn-annual" style="background:{color};color:#000;display:none" {btn_dis} onclick="{onclick_ann}">{btn_txt}</button>
        </div>"""

    corp_card_html = corp_card('corporativo', '#facc15', 'PARA INMOBILIARIAS', [
        'Hasta 10 asesores con acceso',
        '100 descargas de escrituras/mes (1,200/año)',
        'Sin marca de agua',
        'Buscar por folio, nombre, lote y clave catastral',
        'Vista previa + Alertas de folio para toda la cartera',
        'Dashboard corporativo — descargas por asesor',
        'Reportes consolidados mensuales',
        'Soporte WhatsApp prioritario (respuesta garantizada)',
    ], note='* Asesores adicionales: $300 MXN/mes c/u.')

    corp_pro_card_html = corp_card('corporativo_pro', '#f97316', 'ALTO VOLUMEN', [
        'Usuarios ilimitados — sin costo adicional',
        '500 descargas/mes (uso interno exclusivo)',
        'Sin marca de agua',
        'Buscar por folio, nombre, lote y clave catastral',
        'Vista previa + Alertas de folio para toda la cartera',
        'Dashboard corporativo — descargas por asesor',
        'Reportes consolidados mensuales',
        'Soporte directo — tiempo de respuesta garantizado',
        'Prioridad máxima en resolución de incidencias',
        'Posibilidad de funciones personalizadas a la medida',
    ])

    portal_btn = ''
    if cur and stat == 'active' and user.get('stripe_customer_id'):
        portal_btn = '<a href="/portal" class="portal-link">Gestionar suscripción / cancelar</a>'

    extra_section = f"""
    <div class="extra-box">
      <div class="extra-title">Paquetes de descargas</div>
      <p class="extra-desc">Compra un paquete y úsalas cuando quieras. No expiran.</p>
      <div style="display:flex;gap:.8rem;justify-content:center;flex-wrap:wrap;margin-bottom:.8rem">
        <button class="plan-btn" style="background:linear-gradient(135deg,#4ade80,#22c55e);width:auto;padding:.6rem 1.4rem;position:relative"
                onclick="buyPack('pack5')">5 descargas — $500 MXN
          <span style="position:absolute;top:-8px;right:-8px;background:#f472b6;color:#fff;font-size:.6rem;padding:.15rem .4rem;border-radius:10px;font-weight:700">Ahorra $150</span>
        </button>
        <button class="plan-btn" style="background:linear-gradient(135deg,#8b9cf4,#c084fc);width:auto;padding:.6rem 1.4rem;position:relative"
                onclick="buyPack('pack10')">10 descargas — $900 MXN
          <span style="position:absolute;top:-8px;right:-8px;background:#f472b6;color:#fff;font-size:.6rem;padding:.15rem .4rem;border-radius:10px;font-weight:700">Ahorra $400</span>
        </button>
      </div>
      <p class="extra-desc" style="margin-top:.5rem">O compra una sola: <strong style="color:#c084fc">$130 MXN</strong></p>
      <button class="plan-btn" style="background:#555;width:auto;padding:.5rem 1.2rem;font-size:.875rem"
              onclick="buyExtra()">&#43; 1 descarga — $130 MXN</button>
    </div>"""

    pub_key  = STRIPE_PUB_KEY
    user_js  = json.dumps({'plan': cur, 'sub_status': stat})

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Planes – Consulta RPP</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#0d0d14;color:#dde0e8;min-height:100vh;padding:2rem 1rem}}
    .wrap{{max-width:860px;margin:0 auto}}
    h1{{font-size:1.6rem;font-weight:700;background:linear-gradient(120deg,#8b9cf4,#c084fc);
        -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.3rem}}
    .sub{{color:#555;font-size:.875rem;margin-bottom:1.5rem}}
    /* TOGGLE */
    .billing-toggle{{display:flex;align-items:center;justify-content:center;gap:.75rem;
                     margin-bottom:2rem}}
    .toggle-label{{font-size:.875rem;color:#777;cursor:pointer;transition:color .2s}}
    .toggle-label.active{{color:#dde0e8;font-weight:600}}
    .toggle-track{{width:46px;height:24px;background:#2a2a3a;border-radius:12px;
                   cursor:pointer;position:relative;transition:background .2s}}
    .toggle-track.annual{{background:linear-gradient(135deg,#8b9cf4,#c084fc)}}
    .toggle-thumb{{position:absolute;top:3px;left:3px;width:18px;height:18px;
                   background:#fff;border-radius:50%;transition:transform .2s}}
    .toggle-track.annual .toggle-thumb{{transform:translateX(22px)}}
    .save-badge{{background:linear-gradient(135deg,#4ade80,#22c55e);color:#000;
                 font-size:.68rem;font-weight:700;padding:.15rem .5rem;
                 border-radius:10px;white-space:nowrap}}
    /* CARDS */
    .plans{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin-bottom:1.5rem}}
    .plan-card{{background:#13131f;border:1.5px solid #2a2a3a;border-radius:14px;
                padding:1.5rem 1.2rem;position:relative;display:flex;flex-direction:column;gap:.75rem}}
    .plan-card.current{{border-color:#8b9cf4;box-shadow:0 0 0 1px #8b9cf4}}
    .popular{{position:absolute;top:-11px;left:50%;transform:translateX(-50%);
              background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;
              font-size:.68rem;font-weight:700;padding:.2rem .7rem;border-radius:20px;
              white-space:nowrap;letter-spacing:.05em}}
    .plan-name{{font-size:1.125rem;font-weight:700}}
    .plan-price{{font-size:1.9rem;font-weight:800;color:#fff}}
    .plan-price span{{font-size:.875rem;color:#555;font-weight:400}}
    .ann-equiv{{font-size:.8125rem;color:#888;margin-top:.2rem}}
    .plan-feats{{list-style:none;display:flex;flex-direction:column;gap:.4rem;flex:1}}
    .plan-feats li{{font-size:.875rem;color:#aaa;padding-left:1rem;position:relative}}
    .plan-feats li::before{{content:"✓";position:absolute;left:0;color:#4ade80}}
    .plan-btn{{width:100%;padding:.65rem;border:none;border-radius:8px;color:#fff;
               font-weight:700;font-size:1rem;cursor:pointer;transition:opacity .2s;margin-top:auto}}
    .plan-btn:hover{{opacity:.85}}
    .plan-btn:disabled{{opacity:.4;cursor:not-allowed}}
    /* REST */
    .extra-box{{background:#13131f;border:1.5px solid #2a2a3a;border-radius:12px;
                padding:1.2rem 1.5rem;text-align:center;margin-bottom:1.5rem}}
    .extra-title{{font-weight:700;margin-bottom:.3rem}}
    .extra-desc{{font-size:.875rem;color:#555;margin-bottom:.9rem}}
    .portal-link{{display:block;text-align:center;color:#555;font-size:.875rem;
                  text-decoration:none;margin-bottom:1.5rem}}
    .portal-link:hover{{color:#8b9cf4}}
    .cmp-table{{width:100%;border-collapse:collapse;margin-bottom:1.5rem;font-size:.875rem}}
    .cmp-table th{{padding:.65rem .8rem;font-weight:700;text-align:center;border-bottom:1px solid #2a2a3a}}
    .cmp-table th:first-child{{text-align:left;color:#666}}
    .cmp-table td{{padding:.6rem .8rem;border-bottom:1px solid #1a1a2a;text-align:center;color:#aaa}}
    .cmp-table td:first-child{{text-align:left;color:#ccc;font-size:.875rem}}
    .cmp-table tr:last-child td{{border-bottom:none}}
    .cmp-table .yes{{color:#4ade80;font-size:1rem}}
    .cmp-table .no{{color:#374151;font-size:1rem}}
    .cmp-table .val{{color:#e9d5ff;font-weight:600}}
    .cmp-section{{background:#13131f;border:1.5px solid #2a2a3a;border-radius:12px;padding:1.2rem 1.5rem;margin-bottom:1.5rem}}
    .cmp-section h3{{font-size:1rem;color:#555;font-weight:600;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.05em}}
    .back{{color:#555;font-size:.875rem;text-decoration:none}}
    .back:hover{{color:#8b9cf4}}
    .toast{{position:fixed;bottom:1.5rem;right:1.5rem;padding:.7rem 1.1rem;
            border-radius:8px;font-size:.875rem;font-weight:600;display:none;z-index:99}}
    .toast.err{{background:#200f0f;border:1px solid #5c1d1d;color:#f87171}}
  </style>
</head>
<body>
<div class="wrap">
  <h1>Elige tu plan</h1>
  <p class="sub">Consultas ilimitadas incluidas en todos los planes · Descargas sin marca de agua</p>

  <!-- BILLING TOGGLE -->
  <div class="billing-toggle">
    <span class="toggle-label active" id="lbl-monthly" onclick="setBilling('monthly')">Mensual</span>
    <div class="toggle-track" id="billing-track" onclick="toggleBilling()">
      <div class="toggle-thumb"></div>
    </div>
    <span class="toggle-label" id="lbl-annual" onclick="setBilling('annual')">Anual</span>
    <span class="save-badge">2 meses gratis</span>
  </div>

  <div class="free-card" style="background:#13131f;border:1.5px solid #2a2a3a;border-radius:12px;padding:1.2rem 1.5rem;text-align:center;margin-bottom:1.5rem">
    <div style="font-weight:700;font-size:1.125rem;color:#4ade80">Gratis</div>
    <div style="font-size:1.9rem;font-weight:800;color:#fff;margin:.3rem 0">$0 <span style="font-size:.875rem;color:#555;font-weight:400">MXN/mes</span></div>
    <p style="font-size:.875rem;color:#aaa;margin-bottom:.6rem">Busca por folio real y descarga escrituras individuales a <strong style="color:#c084fc">$130 MXN</strong> cada una. Sin suscripción.</p>
    <a href="/" style="display:inline-block;padding:.5rem 1.4rem;background:#1d1d35;color:#8b9cf4;border:1px solid #3a3a5a;border-radius:8px;text-decoration:none;font-weight:600;font-size:.875rem">Ir al buscador →</a>
  </div>

  <div class="plans">
    {basico_card}
    {pro_card}
    {emp_card}
  </div>

  <div style="margin:2rem 0 1rem;text-align:center">
    <div style="display:inline-block;background:linear-gradient(135deg,#facc15,#f97316);
                -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                font-size:1.2rem;font-weight:800;letter-spacing:.03em">
      ✦ Planes Corporativos — Exclusivo para Inmobiliarias ✦
    </div>
    <p style="color:#555;font-size:.8rem;margin-top:.3rem">Acceso multi-usuario · Factura unificada · Soporte prioritario</p>
  </div>
  <div class="plans" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr))">
    {corp_card_html}
    {corp_pro_card_html}
  </div>

  <div class="cmp-section">
    <h3>Comparativa de planes</h3>
    <table class="cmp-table">
      <thead>
        <tr>
          <th></th>
          <th style="color:#8b9cf4">Básico</th>
          <th style="color:#c084fc">Pro</th>
          <th style="color:#f472b6">Empresarial</th>
          <th style="color:#facc15">Corporativo</th>
          <th style="color:#f97316">Corp. Pro</th>
        </tr>
      </thead>
      <tbody>
        <tr><td>Precio mensual</td><td class="val">$500</td><td class="val">$1,000</td><td class="val">$2,000</td><td class="val">$5,000</td><td class="val">$8,000</td></tr>
        <tr><td>Precio anual (2 meses gratis)</td><td class="val">$5,000</td><td class="val">$10,000</td><td class="val">$20,000</td><td class="val">$50,000</td><td class="val">$80,000</td></tr>
        <tr><td>Descargas incluidas</td><td class="val">5/mes</td><td class="val">10/mes</td><td class="val">20/mes</td><td class="val">100/mes</td><td class="val">500/mes</td></tr>
        <tr><td>Usuarios incluidos</td><td class="val">Hasta 3 <small style="color:#facc15">anual</small></td><td class="val">Hasta 3 <small style="color:#facc15">anual</small></td><td class="val">Hasta 3 <small style="color:#facc15">anual</small></td><td class="val">Hasta 11</td><td class="val">Ilimitados</td></tr>
        <tr><td>Buscar por folio y nombre</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
        <tr><td>Buscar por lote</td><td class="no">✗</td><td class="no">✗</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
        <tr><td>Buscar por clave catastral</td><td class="no">✗</td><td class="no">✗</td><td class="no">✗</td><td class="yes">✓</td><td class="yes">✓</td></tr>
        <tr><td>Vista previa del documento</td><td class="no">✗</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
        <tr><td>Alertas de cambios en folio</td><td class="no">✗</td><td class="no">✗</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
        <tr><td>Dashboard de equipo</td><td class="yes">✓ <small style="color:#facc15">anual</small></td><td class="yes">✓ <small style="color:#facc15">anual</small></td><td class="yes">✓ <small style="color:#facc15">anual</small></td><td class="yes">✓</td><td class="yes">✓</td></tr>
        <tr><td>Miembros de equipo</td><td class="val">Hasta 2 <small style="color:#facc15">anual</small></td><td class="val">Hasta 2 <small style="color:#facc15">anual</small></td><td class="val">Hasta 2 <small style="color:#facc15">anual</small></td><td class="val">Hasta 10</td><td class="val">Hasta 50</td></tr>
        <tr><td>Soporte WhatsApp</td><td class="no">✗</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
        <tr><td>Soporte prioritario</td><td class="no">✗</td><td class="no">✗</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
        <tr><td>Funciones personalizadas</td><td class="no">✗</td><td class="no">✗</td><td class="no">✗</td><td class="no">✗</td><td class="yes">✓</td></tr>
        <tr><td>Paquetes adicionales</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
      </tbody>
    </table>
  </div>

  {extra_section}
  {portal_btn}
  <a href="/" class="back">← Volver al buscador</a>
</div>
<div class="toast err" id="toast"></div>
<script>
const PUB_KEY = {json.dumps(pub_key)};
const USER    = {user_js};
let _billing  = 'monthly';

function setBilling(mode) {{
  _billing = mode;
  const isAnnual = mode === 'annual';
  document.getElementById('billing-track').classList.toggle('annual', isAnnual);
  document.getElementById('lbl-monthly').classList.toggle('active', !isAnnual);
  document.getElementById('lbl-annual').classList.toggle('active', isAnnual);
  document.querySelectorAll('.price-monthly').forEach(el => el.style.display = isAnnual ? 'none' : '');
  document.querySelectorAll('.price-annual').forEach(el => el.style.display = isAnnual ? '' : 'none');
  document.querySelectorAll('.btn-monthly').forEach(el => el.style.display = isAnnual ? 'none' : '');
  document.querySelectorAll('.btn-annual').forEach(el => el.style.display = isAnnual ? '' : 'none');
}}

function toggleBilling() {{
  setBilling(_billing === 'monthly' ? 'annual' : 'monthly');
}}

async function subscribe(plan) {{
  if (!PUB_KEY) {{ showToast('Stripe no configurado aún'); return; }}
  try {{
    const res = await fetch('/create-checkout/' + plan, {{method:'POST',headers:{{'Content-Type':'application/json'}},redirect:'manual'}});
    if (res.type === 'opaqueredirect' || res.status === 0 || res.status === 302 || res.status === 401) {{ window.location = '/login'; return; }}
    const d   = await res.json();
    if (d.url) {{ window.location = d.url; }}
    else       {{ showToast(d.error || 'Error al crear sesión de pago'); }}
  }} catch(e) {{ window.location = '/login'; }}
}}

async function buyPack(pack) {{
  if (!PUB_KEY) {{ showToast('Stripe no configurado aún'); return; }}
  try {{
    const res = await fetch('/create-checkout/' + pack, {{method:'POST',headers:{{'Content-Type':'application/json'}},redirect:'manual'}});
    if (res.type === 'opaqueredirect' || res.status === 0 || res.status === 302 || res.status === 401) {{ window.location = '/login'; return; }}
    const d   = await res.json();
    if (d.url) {{ window.location = d.url; }}
    else       {{ showToast(d.error || 'Error al crear sesión de pago'); }}
  }} catch(e) {{ window.location = '/login'; }}
}}

async function buyExtra() {{
  if (!PUB_KEY) {{ showToast('Stripe no configurado aún'); return; }}
  if (!USER.plan || USER.sub_status !== 'active') {{
    showToast('Necesitas una suscripción activa para comprar descargas extra');
    return;
  }}
  try {{
    const res = await fetch('/create-checkout/extra', {{method:'POST',headers:{{'Content-Type':'application/json'}}}});
    const d   = await res.json();
    if (d.url) {{ window.location = d.url; }}
    else       {{ showToast(d.error || 'Error al crear sesión de pago'); }}
  }} catch(e) {{ showToast('Error de red'); }}
}}

function showToast(msg) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 4000);
}}
</script>
</body></html>"""

# ── HTML: Admin ───────────────────────────────────────────────────────────────
def _calc_next_renewal(period_start, billing_interval):
    if not period_start:
        return '—'
    try:
        dt = datetime.fromisoformat(period_start)
        if billing_interval == 'year':
            dt = dt.replace(year=dt.year + 1)
        elif dt.month == 12:
            dt = dt.replace(year=dt.year + 1, month=1)
        else:
            dt = dt.replace(month=dt.month + 1)
        return dt.strftime('%Y-%m-%d')
    except Exception:
        return '—'


def render_admin(users_rows, metrics=None):
    rows = ''
    for u in users_rows:
        plan_txt = PLAN_LABELS.get(u['plan'], u['plan'] or '') if u['plan'] else ''
        if u['role'] == 'admin':
            plan_txt = 'Admin'
        billing   = u.get('billing_interval') or 'month'
        billing_badge = ('<span style="font-size:.65rem;color:#facc15;margin-left:.3rem">Anual</span>'
                         if billing == 'year' else '')
        status_color  = '#4ade80' if u['sub_status'] == 'active' else '#555'
        renewal       = _calc_next_renewal(u.get('period_start'), billing)
        period_start  = (u.get('period_start') or '')[:10]
        safe_name = (u['name'] or u['email']).replace("'", "\\'").replace('"', '\\"')
        team_owner = u.get('_team_owner', '')
        team_owner_id = u.get('_team_owner_id')
        team_cell = (f'<span style="font-size:.7rem;color:#c084fc;cursor:pointer" title="Ver dueño" '
                     f'onclick="openDetail({team_owner_id})">👥 {team_owner}</span>'
                     if team_owner else '')
        rows += f"""<tr class="user-row" data-uid="{u['id']}" data-name="{safe_name}" data-email="{u['email']}" data-plan="{u['plan'] or ''}" data-status="{u['sub_status'] or ''}">
          <td>{u['id']}</td>
          <td style="max-width:130px;overflow:hidden;text-overflow:ellipsis;cursor:pointer" onclick="openDetail({u['id']})">{u['name'] or ''}</td>
          <td style="font-size:.75rem;color:#aaa;cursor:pointer" onclick="openDetail({u['id']})">{u['email']}</td>
          <td id="plan-{u['id']}">{plan_txt}{billing_badge}</td>
          <td id="status-{u['id']}" style="color:{status_color}">{u['sub_status'] or ''}</td>
          <td style="font-size:.75rem;color:#777">{period_start or ''}</td>
          <td style="font-size:.75rem;color:#facc15">{renewal}</td>
          <td style="text-align:center">{u['downloads_used'] or 0}</td>
          <td style="font-size:.75rem;color:#555">{(u['created_at'] or '')[:10]}</td>
          <td style="font-size:.72rem">{team_cell}</td>
          <td style="white-space:nowrap"><button class="plan-btn-sm" onclick="openGrantModal({u['id']}, '{safe_name}', '{u['plan'] or ''}', '{u['sub_status'] or ''}', '{billing}')">✏️</button>"""
        if u['role'] != 'admin':
            rows += f""" <button class="plan-btn-sm" style="color:#4ade80;border-color:#4ade80" onclick="openCreditsModal({u['id']}, '{safe_name}')">🎁</button>"""
            rows += f""" <button class="plan-btn-sm" style="color:#f87171;border-color:#f87171" onclick="deleteUser({u['id']}, '{safe_name}')">🗑️</button>"""
        rows += """</td></tr>"""

    m = metrics or {}
    total_users      = m.get('total_users', len(users_rows))
    active_subs      = m.get('active_subs', 0)
    total_dl         = m.get('total_downloads', 0)
    dl_month         = m.get('downloads_this_month', 0)
    mrr_estimate     = m.get('mrr', 0)
    trial_users      = m.get('trial_users', 0)
    canceled         = m.get('canceled', 0)
    conversion       = m.get('conversion_rate', 0)
    onetime_rev      = m.get('onetime_rev_month', 0)
    total_revenue    = m.get('total_revenue', 0)
    # downloads per day chart (last 14 days)
    dl_chart_data = json.dumps(m.get('dl_per_day', []))
    churn_list    = json.dumps(m.get('churn_alerts', []))

    return f"""<!DOCTYPE html>
<html lang="es"><head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Admin - RPP</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#0d0d14;color:#dde0e8;padding:1.5rem 1rem}}
    h1{{font-size:1.4rem;font-weight:700;margin-bottom:.8rem;
        background:linear-gradient(120deg,#8b9cf4,#c084fc);
        -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
    .metrics{{display:flex;flex-wrap:wrap;gap:.6rem;margin-bottom:1.2rem}}
    .mcard{{background:#13131f;border:1px solid #1e1e2e;border-radius:10px;
            padding:.7rem 1rem;min-width:120px;flex:1}}
    .mval{{font-size:1.2rem;font-weight:700;margin-bottom:.15rem}}
    .mlbl{{font-size:.7rem;color:#555;text-transform:uppercase;letter-spacing:.04em}}
    /* Tabs */
    .tabs{{display:flex;gap:.5rem;margin-bottom:1rem;border-bottom:1px solid #1e1e2e;padding-bottom:.5rem}}
    .tab{{padding:.4rem 1rem;background:none;border:1px solid #2a2a3a;border-radius:8px;
          color:#666;cursor:pointer;font-size:.8125rem;font-weight:600;transition:all .2s}}
    .tab.active{{background:#1d1d35;color:#8b9cf4;border-color:#8b9cf4}}
    .tab:hover{{border-color:#8b9cf4;color:#aaa}}
    .tab-content{{display:none}}.tab-content.active{{display:block}}
    /* Table */
    table{{width:100%;border-collapse:collapse;font-size:.8125rem}}
    th{{background:#13131f;color:#666;font-weight:600;padding:.45rem .6rem;
        text-align:left;border-bottom:1px solid #1e1e2e;white-space:nowrap;position:sticky;top:0}}
    td{{padding:.45rem .6rem;border-bottom:1px solid #1a1a2a;color:#ccc}}
    tr:hover td{{background:#13131f}}
    .back{{color:#555;font-size:.875rem;text-decoration:none;display:inline-block;margin-bottom:.8rem}}
    .back:hover{{color:#8b9cf4}}
    /* Search */
    .search-bar{{display:flex;gap:.6rem;align-items:center;margin-bottom:.8rem;flex-wrap:wrap}}
    .search-bar input{{background:#0d0d14;border:1px solid #2a2a3a;border-radius:8px;
                        padding:.45rem .8rem;color:#dde0e8;font-size:.8125rem;width:240px}}
    .search-bar select{{background:#0d0d14;border:1px solid #2a2a3a;border-radius:8px;
                         padding:.45rem .6rem;color:#dde0e8;font-size:.8125rem}}
    .abtn{{padding:.35rem .7rem;background:#1d1d35;color:#8b9cf4;border:1px solid #3a3a5a;
           border-radius:7px;cursor:pointer;font-size:.75rem;font-weight:600;white-space:nowrap}}
    .abtn:hover{{border-color:#8b9cf4}}
    .abtn.green{{color:#4ade80;border-color:#22543d}}
    .abtn.orange{{color:#f59e0b;border-color:#78350f}}
    .abtn.pink{{color:#f472b6;border-color:#831843}}
    /* Plan buttons */
    .plan-btn-sm{{background:#1d1d35;color:#8b9cf4;border:1px solid #3a3a5a;border-radius:6px;
                  padding:.2rem .5rem;font-size:.7rem;cursor:pointer;white-space:nowrap}}
    .plan-btn-sm:hover{{border-color:#8b9cf4}}
    /* Modal */
    .modal-bg{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;
               align-items:center;justify-content:center}}
    .modal-bg.open{{display:flex}}
    .modal-box{{background:#13131f;border:1.5px solid #2a2a3a;border-radius:14px;
                padding:1.5rem;width:100%;max-width:420px;max-height:90vh;overflow-y:auto}}
    .modal-box h3{{font-size:1.05rem;font-weight:700;margin-bottom:.8rem;
                   background:linear-gradient(120deg,#8b9cf4,#c084fc);
                   -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
    .modal-box label{{font-size:.8125rem;color:#888;display:block;margin-bottom:.25rem}}
    .modal-box select,.modal-box input,.modal-box textarea{{width:100%;background:#0d0d14;color:#dde0e8;
        border:1px solid #2a2a3a;border-radius:7px;padding:.45rem .7rem;font-size:.8125rem;margin-bottom:.7rem}}
    .modal-box textarea{{resize:vertical;min-height:80px;font-family:inherit}}
    .modal-box .btn-row{{display:flex;gap:.5rem;margin-top:.3rem}}
    .btn-save{{flex:1;background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;border:none;
               border-radius:8px;padding:.55rem;font-weight:700;cursor:pointer;font-size:.8125rem}}
    .btn-cancel-modal{{flex:1;background:#1d1d35;color:#aaa;border:1px solid #2a2a3a;
                        border-radius:8px;padding:.55rem;cursor:pointer;font-size:.8125rem}}
    .status-msg{{font-size:.75rem;margin-top:.5rem;min-height:1em}}
    /* Chart */
    .chart{{display:flex;align-items:flex-end;gap:3px;height:80px;padding:.5rem 0}}
    .chart-bar{{flex:1;background:linear-gradient(to top,#8b9cf4,#c084fc);border-radius:3px 3px 0 0;
                min-width:8px;position:relative;cursor:pointer;transition:opacity .2s}}
    .chart-bar:hover{{opacity:.7}}
    .chart-bar .tip{{display:none;position:absolute;bottom:100%;left:50%;transform:translateX(-50%);
                     background:#1e1e2e;color:#dde0e8;padding:.2rem .4rem;border-radius:4px;
                     font-size:.65rem;white-space:nowrap;z-index:5}}
    .chart-bar:hover .tip{{display:block}}
    .chart-labels{{display:flex;gap:3px;font-size:.6rem;color:#555}}
    .chart-labels span{{flex:1;text-align:center;min-width:8px}}
    /* Activity */
    .activity-item{{display:flex;gap:.6rem;padding:.45rem .6rem;border-bottom:1px solid #1a1a2a;font-size:.8125rem}}
    .activity-item:hover{{background:#13131f}}
    .act-time{{color:#555;font-size:.75rem;min-width:70px}}
    .act-user{{color:#8b9cf4;min-width:120px;overflow:hidden;text-overflow:ellipsis}}
    .act-action{{color:#aaa;flex:1}}
    /* Detail modal */
    .detail-section{{margin-bottom:1rem}}
    .detail-section h4{{font-size:.875rem;color:#8b9cf4;margin-bottom:.4rem;border-bottom:1px solid #1e1e2e;padding-bottom:.2rem}}
    .detail-row{{display:flex;justify-content:space-between;font-size:.8125rem;padding:.2rem 0;border-bottom:1px solid #111118}}
    .detail-row .lbl{{color:#666}}.detail-row .val{{color:#dde0e8}}
    .detail-list{{max-height:150px;overflow-y:auto;font-size:.75rem}}
    .detail-list div{{padding:.2rem 0;border-bottom:1px solid #111118;color:#aaa}}
    /* Churn */
    .churn-alert{{background:#200f0f;border:1px solid #5c1d1d;border-radius:8px;padding:.5rem .8rem;
                  margin-bottom:.4rem;font-size:.8125rem;display:flex;justify-content:space-between}}
    .churn-alert .email{{color:#f87171}}.churn-alert .info{{color:#888}}
    @media(max-width:600px){{.mcard{{min-width:calc(50% - .3rem)}} .search-bar input{{width:100%}} }}
    /* IA Dashboard */
    .charts-2col{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}}
    @media(max-width:700px){{.charts-2col{{grid-template-columns:1fr}}}}
    .chart-wrap{{background:#13131f;border:1px solid #1e1e2e;border-radius:12px;padding:1rem}}
    .chart-wrap h4{{font-size:.72rem;color:#555;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.65rem;font-weight:600}}
    .ia-section{{margin-bottom:1rem}}
    .ia-section-title{{font-size:.8rem;color:#8b9cf4;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.6rem;display:flex;align-items:center;gap:.4rem}}
    .ia-card{{background:#13131f;border:1px solid #2a2a3a;border-radius:10px;padding:.9rem 1rem;margin-bottom:.6rem}}
    .ia-card h4{{font-size:.875rem;font-weight:700;margin-bottom:.35rem;display:flex;align-items:center;gap:.4rem}}
    .ia-card p,.ia-card li{{font-size:.8125rem;color:#aaa;line-height:1.65}}
    .ia-card ul{{padding-left:1.1rem;margin-top:.3rem}}
    .ia-card ul li{{margin-bottom:.25rem}}
    .ia-badge{{display:inline-block;font-size:.65rem;font-weight:700;padding:.1rem .45rem;border-radius:8px;margin-left:.4rem;vertical-align:middle}}
    .ia-badge.green{{background:#0f2a1a;color:#4ade80;border:1px solid #22543d}}
    .ia-badge.red{{background:#200f0f;color:#f87171;border:1px solid #5c1d1d}}
    .ia-badge.yellow{{background:#1c1500;color:#facc15;border:1px solid #713f12}}
    .ia-badge.blue{{background:#0f1535;color:#8b9cf4;border:1px solid #2a3a6a}}
    .ia-health-bar{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}}
    .ia-health-item{{background:#13131f;border:1px solid #1e1e2e;border-radius:8px;padding:.5rem .8rem;font-size:.78rem;flex:1;min-width:100px}}
    .ia-health-val{{font-size:1.3rem;font-weight:800;margin-bottom:.1rem}}
    .ia-health-lbl{{font-size:.68rem;color:#555}}
    .ia-loading{{text-align:center;padding:2.5rem;color:#555;font-size:.875rem}}
    .ia-thinking{{display:flex;align-items:center;justify-content:center;gap:.75rem;padding:1.5rem}}
    .ia-dot{{width:8px;height:8px;border-radius:50%;background:#8b9cf4;animation:ia-pulse 1.2s ease-in-out infinite}}
    .ia-dot:nth-child(2){{animation-delay:.2s}}.ia-dot:nth-child(3){{animation-delay:.4s}}
    @keyframes ia-pulse{{0%,80%,100%{{transform:scale(.6);opacity:.4}}40%{{transform:scale(1);opacity:1}}}}
  </style>
</head><body>
  <a href="/" class="back">< Volver al buscador</a>
  <h1>Panel de administracion</h1>

  <!-- METRICS -->
  <div class="metrics">
    <div class="mcard"><div class="mval">{total_users}</div><div class="mlbl">Usuarios</div></div>
    <div class="mcard"><div class="mval" style="color:#4ade80">{active_subs}</div><div class="mlbl">Suscripciones</div></div>
    <div class="mcard"><div class="mval" style="color:#c084fc">{dl_month}</div><div class="mlbl">Desc. este mes</div></div>
    <div class="mcard"><div class="mval" style="color:#8b9cf4">{total_dl}</div><div class="mlbl">Desc. totales</div></div>
    <div class="mcard"><div class="mval" style="color:#f59e0b">${mrr_estimate:,}</div><div class="mlbl">MRR estimado</div></div>
    <div class="mcard"><div class="mval" style="color:#34d399">${onetime_rev:,}</div><div class="mlbl">Compras únicas (mes)</div></div>
    <div class="mcard" style="border-color:#6366f1"><div class="mval" style="color:#a5b4fc">${total_revenue:,}</div><div class="mlbl">Ingresos totales</div></div>
    <div class="mcard"><div class="mval" style="color:#facc15">{trial_users}</div><div class="mlbl">En trial</div></div>
    <div class="mcard"><div class="mval" style="color:#f472b6">{conversion:.0f}%</div><div class="mlbl">Conversion</div></div>
    <div class="mcard"><div class="mval" style="color:#f87171">{canceled}</div><div class="mlbl">Cancelados</div></div>
  </div>

  <!-- TABS -->
  <div class="tabs">
    <button class="tab active" onclick="switchTab('usuarios')">Usuarios</button>
    <button class="tab" onclick="switchTab('actividad')">Actividad</button>
    <button class="tab" onclick="switchTab('descargas')">Descargas</button>
    <button class="tab" onclick="switchTab('churn')">Alertas</button>
    <button class="tab" onclick="switchTab('realtime')">Tiempo Real</button>
    <button class="tab" onclick="switchTab('ia')" style="background:linear-gradient(135deg,#8b9cf422,#c084fc22);border-color:#8b9cf455;color:#c084fc">🤖 IA</button>
    <button class="tab" onclick="switchTab('email')">Email masivo</button>
    <button class="tab" onclick="switchTab('payouts')" style="color:#4ade80">💸 Transferencias</button>
  </div>

  <!-- TAB: USUARIOS -->
  <div class="tab-content active" id="tab-usuarios">
    <div class="search-bar">
      <input type="text" id="user-search" placeholder="Buscar por nombre, email o plan..." oninput="filterUsers()">
      <select id="filter-status" onchange="filterUsers()">
        <option value="">Todos</option>
        <option value="active">Activos</option>
        <option value="none">Sin plan</option>
        <option value="canceled">Cancelados</option>
      </select>
      <button class="abtn" onclick="exportCSV()">CSV</button>
      <button class="abtn green" onclick="syncNotion(this)">Sync Notion</button>
      <span id="sync-status" style="font-size:.75rem;color:#555"></span>
    </div>
    <div style="overflow-x:auto">
    <table id="users-table">
      <thead><tr>
        <th>ID</th><th>Nombre</th><th>Email</th><th>Plan</th>
        <th>Estado</th><th>Inicio</th><th style="color:#facc15">Renovacion</th>
        <th>Desc.</th><th>Registro</th><th style="color:#c084fc">Equipo</th><th></th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
    </div>
    <p class="count" id="user-count" style="margin-top:.5rem">{len(users_rows)} usuarios</p>
  </div>

  <!-- TAB: ACTIVIDAD -->
  <div class="tab-content" id="tab-actividad">
    <div class="search-bar">
      <button class="abtn" onclick="loadActivity()">Actualizar</button>
      <span style="color:#555;font-size:.75rem">Ultimas 50 acciones</span>
    </div>
    <div id="activity-list" style="color:#555;font-size:.875rem">Cargando actividad...</div>
  </div>

  <!-- TAB: DESCARGAS -->
  <div class="tab-content" id="tab-descargas">
    <h3 style="font-size:.9rem;color:#888;margin-bottom:.5rem">Descargas por dia (ultimos 14 dias)</h3>
    <div class="chart" id="dl-chart"></div>
    <div class="chart-labels" id="dl-chart-labels"></div>
    <div style="margin-top:1rem">
      <h3 style="font-size:.9rem;color:#888;margin-bottom:.5rem">Descargas por usuario (este mes)</h3>
      <div id="user-dl-ranking"></div>
    </div>
  </div>

  <!-- TAB: CHURN ALERTS -->
  <div class="tab-content" id="tab-churn">
    <h3 style="font-size:.9rem;color:#888;margin-bottom:.5rem">Usuarios cancelados o con pagos fallidos</h3>
    <div id="churn-list"></div>
  </div>

  <!-- TAB: TIEMPO REAL -->
  <div class="tab-content" id="tab-realtime">
    <div class="search-bar">
      <button class="abtn" onclick="loadRealtime()">Actualizar</button>
      <label style="font-size:.75rem;color:#555;display:flex;align-items:center;gap:.4rem">
        <input type="checkbox" id="rt-auto" onchange="toggleRtAuto(this)"> Auto (10s)
      </label>
      <span id="rt-last" style="font-size:.72rem;color:#555"></span>
    </div>
    <div id="rt-rpp-status" style="margin-bottom:1rem"></div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:.6rem;margin-bottom:1rem" id="rt-stats"></div>
    <h3 style="font-size:.85rem;color:#888;margin-bottom:.5rem">Audit log (últimas 10 acciones)</h3>
    <div id="rt-audit" style="font-size:.78rem"></div>
  </div>

  <!-- TAB: IA DASHBOARD -->
  <div class="tab-content" id="tab-ia">
    <div class="search-bar" style="margin-bottom:1rem">
      <button class="abtn pink" onclick="loadIAAnalysis()" id="ia-btn">🤖 Analizar con IA</button>
      <button class="abtn" onclick="loadIACharts()" id="ia-charts-btn">📊 Actualizar gráficas</button>
      <span id="ia-status" style="font-size:.75rem;color:#555"></span>
    </div>
    <!-- KPI bar -->
    <div class="ia-health-bar" id="ia-kpi-bar">
      <div class="ia-health-item"><div class="ia-health-val" style="color:#4ade80">—</div><div class="ia-health-lbl">MRR estimado</div></div>
      <div class="ia-health-item"><div class="ia-health-val" style="color:#8b9cf4">—</div><div class="ia-health-lbl">Usuarios activos</div></div>
      <div class="ia-health-item"><div class="ia-health-val" style="color:#c084fc">—</div><div class="ia-health-lbl">Conversión</div></div>
      <div class="ia-health-item"><div class="ia-health-val" style="color:#f87171">—</div><div class="ia-health-lbl">Churn este mes</div></div>
      <div class="ia-health-item"><div class="ia-health-val" style="color:#facc15">—</div><div class="ia-health-lbl">Registros este mes</div></div>
      <div class="ia-health-item"><div class="ia-health-val" style="color:#fb923c">—</div><div class="ia-health-lbl">Desc. este mes</div></div>
    </div>
    <!-- Charts -->
    <div class="charts-2col">
      <div class="chart-wrap"><h4>💰 Ingresos estimados MRR (últimos 12 meses)</h4><canvas id="chart-mrr"></canvas></div>
      <div class="chart-wrap"><h4>👥 Crecimiento de usuarios (últimos 12 meses)</h4><canvas id="chart-users-growth"></canvas></div>
      <div class="chart-wrap"><h4>⬇️ Descargas por día (últimos 30 días)</h4><canvas id="chart-dl-30"></canvas></div>
      <div class="chart-wrap"><h4>🥧 Distribución de planes activos</h4><canvas id="chart-plan-dist"></canvas></div>
    </div>
    <!-- Claude AI Analysis -->
    <div id="ia-analysis">
      <div class="ia-loading">Haz clic en <strong style="color:#c084fc">🤖 Analizar con IA</strong> para obtener recomendaciones personalizadas de Claude basadas en tus métricas.</div>
    </div>
  </div>

  <!-- TAB: EMAIL MASIVO -->
  <div class="tab-content" id="tab-email">
    <div class="modal-box" style="max-width:600px">
      <h3>Enviar correo masivo</h3>
      <label>Destinatarios</label>
      <select id="email-target">
        <option value="all">Todos los usuarios ({total_users})</option>
        <option value="active">Solo suscriptores activos ({active_subs})</option>
        <option value="trial">Solo en trial ({trial_users})</option>
        <option value="free">Solo free / sin plan</option>
      </select>
      <label>Asunto</label>
      <input type="text" id="email-subject" placeholder="Asunto del correo...">
      <label>Mensaje (HTML permitido)</label>
      <textarea id="email-body" placeholder="Escribe tu mensaje aqui..."></textarea>
      <div class="btn-row">
        <button class="btn-save" onclick="sendMassEmail()" id="email-send-btn">Enviar</button>
      </div>
      <div class="status-msg" id="email-msg"></div>
    </div>
  </div>

  <!-- TAB: PAYOUTS -->
  <div class="tab-content" id="tab-payouts">
    <div style="max-width:700px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.25rem">
        <h3 style="font-size:1rem;font-weight:700;color:#dde0e8">Transferencias de Stripe</h3>
        <button class="abtn green" onclick="loadPayouts(this)" id="payouts-btn">Cargar</button>
      </div>
      <div id="payouts-container" style="color:#555;font-size:.875rem">
        Haz clic en "Cargar" para ver las transferencias recientes.
      </div>
    </div>
  </div>

  <!-- GRANT PLAN MODAL -->
  <div class="modal-bg" id="grant-modal">
    <div class="modal-box">
      <h3>Asignar plan</h3>
      <p id="grant-user-name" style="color:#aaa;font-size:.8125rem;margin-bottom:.8rem"></p>
      <label>Plan</label>
      <select id="grant-plan">
        <option value="">Sin plan (free)</option>
        <option value="basico">Basico ($500/mes)</option>
        <option value="pro">Pro ($1,000/mes)</option>
        <option value="empresarial">Empresarial ($2,000/mes)</option>
        <option value="corporativo">Corporativo ($5,000/mes)</option>
        <option value="corporativo_pro">Corporativo Pro ($8,000/mes)</option>
      </select>
      <label>Ciclo de facturacion</label>
      <select id="grant-billing">
        <option value="month">Mensual</option>
        <option value="year">Anual</option>
      </select>
      <label>Estado de suscripcion</label>
      <select id="grant-status">
        <option value="">Sin suscripcion</option>
        <option value="active">Activa</option>
        <option value="canceled">Cancelada</option>
      </select>
      <label>Resetear descargas del mes</label>
      <select id="grant-reset">
        <option value="0">No resetear</option>
        <option value="1">Si, resetear a 0</option>
      </select>
      <div class="btn-row">
        <button class="btn-cancel-modal" onclick="closeGrantModal()">Cancelar</button>
        <button class="btn-save" onclick="saveGrant()">Guardar</button>
      </div>
      <div class="status-msg" id="grant-msg"></div>
    </div>
  </div>

  <!-- CREDITS MODAL -->
  <div class="modal-bg" id="credits-modal">
    <div class="modal-box">
      <h3>Otorgar descargas</h3>
      <p id="credits-user-name" style="color:#aaa;font-size:.8125rem;margin-bottom:.8rem"></p>
      <label>Cantidad de descargas a regalar</label>
      <input type="number" id="credits-qty" min="1" max="100" value="5" style="width:100px">
      <div class="btn-row">
        <button class="btn-cancel-modal" onclick="document.getElementById('credits-modal').classList.remove('open')">Cancelar</button>
        <button class="btn-save" style="background:linear-gradient(135deg,#4ade80,#22c55e)" onclick="saveCredits()">Otorgar</button>
      </div>
      <div class="status-msg" id="credits-msg"></div>
    </div>
  </div>

  <!-- USER DETAIL MODAL -->
  <div class="modal-bg" id="detail-modal">
    <div class="modal-box" style="max-width:520px">
      <h3 id="detail-title">Detalle de usuario</h3>
      <div id="detail-body" style="color:#555;font-size:.875rem">Cargando...</div>
      <div class="btn-row" style="margin-top:1rem">
        <button class="btn-cancel-modal" onclick="document.getElementById('detail-modal').classList.remove('open')">Cerrar</button>
      </div>
    </div>
  </div>

  <script>
  const DL_CHART = {dl_chart_data};
  const CHURN = {churn_list};

  /* === TABS === */
  function switchTab(name) {{
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    event.target.classList.add('active');
    if (name === 'actividad') loadActivity();
    if (name === 'descargas') renderChart();
    if (name === 'churn') renderChurn();
    if (name === 'realtime') loadRealtime();
    if (name === 'ia') loadIACharts();
  }}

  /* === SEARCH / FILTER === */
  function filterUsers() {{
    const q = document.getElementById('user-search').value.toLowerCase();
    const st = document.getElementById('filter-status').value;
    let visible = 0;
    document.querySelectorAll('.user-row').forEach(row => {{
      const name = row.dataset.name.toLowerCase();
      const email = row.dataset.email.toLowerCase();
      const plan = row.dataset.plan;
      const status = row.dataset.status;
      let show = true;
      if (q && !name.includes(q) && !email.includes(q) && !plan.includes(q)) show = false;
      if (st === 'active' && status !== 'active') show = false;
      if (st === 'none' && status === 'active') show = false;
      if (st === 'canceled' && status !== 'canceled') show = false;
      row.style.display = show ? '' : 'none';
      if (show) visible++;
    }});
    document.getElementById('user-count').textContent = visible + ' usuarios';
  }}

  /* === EXPORT CSV === */
  function exportCSV() {{
    const rows = [['ID','Nombre','Email','Plan','Estado','Inicio','Renovacion','Descargas','Registro']];
    document.querySelectorAll('.user-row').forEach(row => {{
      if (row.style.display === 'none') return;
      const cells = row.querySelectorAll('td');
      rows.push(Array.from(cells).slice(0, 9).map(c => c.textContent.trim()));
    }});
    const csv = rows.map(r => r.map(v => '"' + v.replace(/"/g, '""') + '"').join(',')).join('\\n');
    const blob = new Blob([new Uint8Array([0xEF,0xBB,0xBF]), csv], {{type:'text/csv;charset=utf-8'}});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'usuarios_rpp_' + new Date().toISOString().slice(0,10) + '.csv';
    a.click();
  }}

  /* === CHART === */
  function renderChart() {{
    const chart = document.getElementById('dl-chart');
    const labels = document.getElementById('dl-chart-labels');
    if (!DL_CHART.length) {{ chart.innerHTML = '<span style="color:#555">Sin datos</span>'; return; }}
    const max = Math.max(...DL_CHART.map(d => d.count), 1);
    chart.innerHTML = DL_CHART.map(d => {{
      const h = Math.max((d.count / max) * 100, 2);
      return '<div class="chart-bar" style="height:' + h + '%"><div class="tip">' + d.date.slice(5) + ': ' + d.count + '</div></div>';
    }}).join('');
    labels.innerHTML = DL_CHART.map(d => '<span>' + d.date.slice(8) + '</span>').join('');
    // User ranking
    fetch('/admin/user-dl-ranking').then(r=>r.json()).then(data => {{
      const el = document.getElementById('user-dl-ranking');
      if (!data.length) {{ el.innerHTML = '<span style="color:#555">Sin descargas este mes</span>'; return; }}
      el.innerHTML = '<table><thead><tr><th>Usuario</th><th>Email</th><th>Descargas</th></tr></thead><tbody>'
        + data.map(u => '<tr><td>' + (u.name||'') + '</td><td style="color:#aaa;font-size:.75rem">' + u.email + '</td><td style="color:#c084fc;font-weight:700;text-align:center">' + u.count + '</td></tr>').join('')
        + '</tbody></table>';
    }});
  }}

  /* === ACTIVITY LOG === */
  function loadActivity() {{
    const el = document.getElementById('activity-list');
    el.innerHTML = '<span style="color:#555">Cargando...</span>';
    fetch('/admin/activity-log').then(r => r.json()).then(data => {{
      if (!data.length) {{ el.innerHTML = '<span style="color:#555">Sin actividad reciente</span>'; return; }}
      el.innerHTML = data.map(a => {{
        let icon = '📄';
        if (a.type === 'download') icon = '⬇️';
        if (a.type === 'search') icon = '🔍';
        if (a.type === 'login') icon = '🔐';
        return '<div class="activity-item"><span class="act-time">' + (a.ts||'').slice(11,16) + '</span>'
          + '<span class="act-user">' + (a.name || a.email || '') + '</span>'
          + '<span class="act-action">' + icon + ' ' + a.desc + '</span></div>';
      }}).join('');
    }}).catch(() => {{ el.innerHTML = '<span style="color:#f87171">Error al cargar</span>'; }});
  }}

  /* === REAL-TIME METRICS === */
  let _rtInterval = null;
  async function loadRealtime() {{
    const el = document.getElementById('rt-stats');
    const statusEl = document.getElementById('rt-rpp-status');
    const auditEl = document.getElementById('rt-audit');
    const lastEl = document.getElementById('rt-last');
    try {{
      const r = await fetch('/admin/realtime-metrics');
      const d = await r.json();
      // RPP status banner
      const rpp = d.rpp_status || {{}};
      const up = rpp.healthy;
      statusEl.innerHTML = '<div style="display:flex;align-items:center;gap:.6rem;padding:.5rem .8rem;border-radius:8px;background:'
        + (up ? '#0f2a1a' : '#2a0f0f') + ';border:1px solid ' + (up ? '#22543d' : '#5c1d1d') + ';margin-bottom:.5rem">'
        + '<span style="font-size:1.1rem">' + (up ? '🟢' : '🔴') + '</span>'
        + '<span style="font-size:.85rem;font-weight:600;color:' + (up ? '#4ade80' : '#f87171') + '">'
        + 'RPP ' + (up ? 'Operativo' : 'No disponible') + '</span>'
        + '<span style="font-size:.75rem;color:#555;margin-left:auto">Última verificación: ' + (rpp.last_check_ago || '?') + '</span>'
        + '</div>';
      // Stats cards
      const s = d.rpp_stats || {{}};
      const a = d.activity || {{}};
      const cards = [
        ['⬇️', a.downloads_today || 0, 'Descargas hoy', '#8b9cf4'],
        ['👥', a.active_sessions || 0, 'Sesiones activas', '#4ade80'],
        ['⚙️', a.jobs_running || 0, 'Jobs en curso', '#facc15'],
        ['✅', s.success_24h || 0, 'Exitosas 24h', '#4ade80'],
        ['❌', s.error_24h || 0, 'Errores 24h', '#f87171'],
        ['⚡', (s.avg_ms || 0) + 'ms', 'Tiempo prom.', '#c084fc'],
        ['💾', a.cache_size || 0, 'Cache (folios)', '#f59e0b'],
        ['🔄', s.retries_24h || 0, 'Reintentos 24h', '#fb923c'],
      ];
      el.innerHTML = cards.map(([icon, val, lbl, color]) =>
        '<div class="mcard"><div class="mval" style="color:' + color + '">' + icon + ' ' + val + '</div><div class="mlbl">' + lbl + '</div></div>'
      ).join('');
      // Audit log
      const audit = d.audit_log || [];
      if (!audit.length) {{ auditEl.innerHTML = '<span style="color:#555">Sin registros</span>'; }}
      else {{
        auditEl.innerHTML = '<table><thead><tr><th>Acción</th><th>Usuario</th><th>Detalle</th><th>IP</th><th>Hora</th></tr></thead><tbody>'
          + audit.map(a => '<tr><td style="color:#8b9cf4">' + (a.action||'') + '</td><td style="color:#aaa;font-size:.75rem">' + (a.email||'') + '</td><td style="color:#777;font-size:.72rem">' + (a.detail||'') + '</td><td style="color:#555;font-size:.72rem">' + (a.ip||'') + '</td><td style="color:#555;font-size:.72rem">' + (a.ts||'').slice(11,19) + '</td></tr>').join('')
          + '</tbody></table>';
      }}
      lastEl.textContent = 'Act. ' + new Date().toLocaleTimeString('es-MX');
    }} catch(e) {{
      statusEl.innerHTML = '<span style="color:#f87171">Error al cargar métricas</span>';
    }}
  }}
  function toggleRtAuto(cb) {{
    if (cb.checked) {{
      _rtInterval = setInterval(loadRealtime, 10000);
    }} else {{
      clearInterval(_rtInterval); _rtInterval = null;
    }}
  }}

  /* === IA DASHBOARD === */
  var _iaCharts = {{}};
  function _destroyChart(id) {{
    if (_iaCharts[id]) {{ _iaCharts[id].destroy(); delete _iaCharts[id]; }}
  }}
  function _mkChart(id, config) {{
    _destroyChart(id);
    const ctx = document.getElementById(id);
    if (!ctx) return;
    _iaCharts[id] = new Chart(ctx, config);
  }}

  async function loadIACharts() {{
    const statusEl = document.getElementById('ia-status');
    statusEl.textContent = 'Cargando datos...';
    try {{
      const r = await fetch('/admin/dashboard-data');
      const d = await r.json();
      statusEl.textContent = '';
      // Update KPI bar
      const kpis = d.kpis || {{}};
      const items = document.querySelectorAll('.ia-health-item');
      const mrrLabel = document.querySelector('.ia-health-item:first-child .ia-health-lbl');
      if (mrrLabel) mrrLabel.textContent = 'MRR ' + (kpis.mrr_source === 'stripe' ? '(Stripe ✓)' : '(estimado)');
      const vals = [
        ['$' + (kpis.mrr||0).toLocaleString('es-MX'), '#4ade80'],
        [kpis.active_subs||0, '#8b9cf4'],
        [(kpis.conversion||0).toFixed(1) + '%', '#c084fc'],
        [kpis.churn_this_month||0, '#f87171'],
        [kpis.signups_this_month||0, '#facc15'],
        [kpis.downloads_this_month||0, '#fb923c'],
      ];
      vals.forEach(([v,c],i) => {{
        if (items[i]) {{
          items[i].querySelector('.ia-health-val').textContent = v;
          items[i].querySelector('.ia-health-val').style.color = c;
        }}
      }});
      const gridCfg = {{
        color: '#1e1e2e',
        borderColor: '#1e1e2e',
      }};
      const tickCfg = {{ color: '#555', font: {{ size: 10 }} }};
      // MRR Chart
      const mrr = d.mrr_history || [];
      _mkChart('chart-mrr', {{
        type: 'line',
        data: {{
          labels: mrr.map(x => x.month),
          datasets: [{{
            label: 'MRR estimado (MXN)',
            data: mrr.map(x => x.mrr),
            borderColor: '#4ade80',
            backgroundColor: 'rgba(74,222,128,.08)',
            fill: true,
            tension: .35,
            pointRadius: 3,
          }}]
        }},
        options: {{
          responsive: true,
          plugins: {{ legend: {{ labels: {{ color:'#aaa', font:{{ size:10 }} }} }} }},
          scales: {{
            x: {{ grid: gridCfg, ticks: tickCfg }},
            y: {{ grid: gridCfg, ticks: {{ ...tickCfg, callback: v => '$'+v.toLocaleString('es-MX') }} }}
          }}
        }}
      }});
      // User growth chart
      const ug = d.user_growth || [];
      _mkChart('chart-users-growth', {{
        type: 'bar',
        data: {{
          labels: ug.map(x => x.month),
          datasets: [
            {{ label: 'Registros', data: ug.map(x => x.signups), backgroundColor: '#8b9cf4aa', borderRadius: 4 }},
            {{ label: 'Activos', data: ug.map(x => x.active), backgroundColor: '#4ade8077', borderRadius: 4 }},
          ]
        }},
        options: {{
          responsive: true,
          plugins: {{ legend: {{ labels: {{ color:'#aaa', font:{{ size:10 }} }} }} }},
          scales: {{
            x: {{ stacked: false, grid: gridCfg, ticks: tickCfg }},
            y: {{ grid: gridCfg, ticks: tickCfg }}
          }}
        }}
      }});
      // Downloads 30d
      const dl = d.dl_30d || [];
      _mkChart('chart-dl-30', {{
        type: 'bar',
        data: {{
          labels: dl.map(x => x.date.slice(5)),
          datasets: [{{
            label: 'Descargas',
            data: dl.map(x => x.count),
            backgroundColor: '#c084fc88',
            borderRadius: 3,
          }}]
        }},
        options: {{
          responsive: true,
          plugins: {{ legend: {{ display: false }} }},
          scales: {{
            x: {{ grid: gridCfg, ticks: {{ ...tickCfg, maxRotation: 45, minRotation: 30 }} }},
            y: {{ grid: gridCfg, ticks: tickCfg }}
          }}
        }}
      }});
      // Plan distribution
      const pd = d.plan_dist || [];
      const planColors = {{ basico:'#8b9cf4', pro:'#c084fc', empresarial:'#f472b6', corporativo:'#facc15', corporativo_pro:'#f97316', 'null':'#374151','':'#374151' }};
      _mkChart('chart-plan-dist', {{
        type: 'doughnut',
        data: {{
          labels: pd.map(x => x.plan || 'Sin plan'),
          datasets: [{{
            data: pd.map(x => x.count),
            backgroundColor: pd.map(x => planColors[x.plan] || '#555'),
            borderWidth: 2,
            borderColor: '#0d0d14',
          }}]
        }},
        options: {{
          responsive: true,
          plugins: {{
            legend: {{ position: 'bottom', labels: {{ color:'#aaa', font:{{ size:10 }}, padding:8 }} }},
          }}
        }}
      }});
    }} catch(e) {{
      statusEl.style.color = '#f87171';
      statusEl.textContent = 'Error al cargar datos';
    }}
  }}

  async function loadIAAnalysis() {{
    const btn = document.getElementById('ia-btn');
    const statusEl = document.getElementById('ia-status');
    const el = document.getElementById('ia-analysis');
    btn.disabled = true;
    statusEl.textContent = '';
    el.innerHTML = '<div class="ia-thinking"><div class="ia-dot"></div><div class="ia-dot"></div><div class="ia-dot"></div><span style="color:#555;font-size:.875rem;margin-left:.5rem">Claude está analizando tu negocio...</span></div>';
    try {{
      const r = await fetch('/admin/ai-analysis', {{ method: 'POST' }});
      const d = await r.json();
      if (!r.ok) {{
        el.innerHTML = '<div style="color:#f87171;padding:1rem;font-size:.875rem">Error: ' + (d.error||'desconocido') + '</div>';
        btn.disabled = false;
        return;
      }}
      const a = d.analysis;
      // Render sections
      let html = '<div style="font-size:.72rem;color:#555;margin-bottom:1rem">Análisis generado por Claude · ' + new Date().toLocaleString('es-MX') + '</div>';

      function renderSection(icon, title, badge, color, items, type) {{
        if (!items || !items.length) return '';
        const badgeHtml = badge ? '<span class="ia-badge ' + badge + '">' + type + '</span>' : '';
        const listItems = items.map(i => '<li>' + i + '</li>').join('');
        return '<div class="ia-card"><h4>' + icon + ' ' + title + badgeHtml + '</h4><ul>' + listItems + '</ul></div>';
      }}

      if (a.salud_negocio) {{
        html += '<div class="ia-section"><div class="ia-section-title">📊 Salud del negocio</div>';
        html += '<div class="ia-card" style="border-color:#2a3a6a"><p>' + a.salud_negocio + '</p></div></div>';
      }}
      if (a.ventas && a.ventas.length) {{
        html += '<div class="ia-section"><div class="ia-section-title">💰 Ventas — Cómo crecer ingresos</div>';
        html += renderSection('💰','Estrategias de venta','green','#4ade80',a.ventas,'Ingresos');
        html += '</div>';
      }}
      if (a.marketing && a.marketing.length) {{
        html += '<div class="ia-section"><div class="ia-section-title">📣 Marketing — Cómo atraer más usuarios</div>';
        html += renderSection('📣','Acciones de marketing','blue','#8b9cf4',a.marketing,'Adquisición');
        html += '</div>';
      }}
      if (a.retencion && a.retencion.length) {{
        html += '<div class="ia-section"><div class="ia-section-title">🔒 Retención — Reducir churn</div>';
        html += renderSection('🔒','Retención de usuarios','yellow','#facc15',a.retencion,'Churn');
        html += '</div>';
      }}
      if (a.producto && a.producto.length) {{
        html += '<div class="ia-section"><div class="ia-section-title">🛠️ Producto — Mejoras sugeridas</div>';
        html += renderSection('🛠️','Mejoras de producto','blue','#8b9cf4',a.producto,'Producto');
        html += '</div>';
      }}
      if (a.riesgos && a.riesgos.length) {{
        html += '<div class="ia-section"><div class="ia-section-title">⚠️ Riesgos y alertas</div>';
        html += renderSection('⚠️','Riesgos identificados','red','#f87171',a.riesgos,'Riesgo');
        html += '</div>';
      }}
      if (a.prioridad_acciones && a.prioridad_acciones.length) {{
        html += '<div class="ia-section"><div class="ia-section-title">🎯 Top 3 acciones prioritarias esta semana</div>';
        html += '<div class="ia-card" style="border-color:#c084fc55">';
        a.prioridad_acciones.forEach((p,i) => {{
          html += '<div style="display:flex;gap:.6rem;align-items:flex-start;' + (i?'margin-top:.6rem;padding-top:.6rem;border-top:1px solid #1e1e2e':'') + '">';
          html += '<span style="background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;border-radius:50%;width:20px;height:20px;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;flex-shrink:0">' + (i+1) + '</span>';
          html += '<span style="font-size:.8125rem;color:#dde0e8">' + p + '</span></div>';
        }});
        html += '</div></div>';
      }}
      el.innerHTML = html;
    }} catch(e) {{
      el.innerHTML = '<div style="color:#f87171;padding:1rem;font-size:.875rem">Error de red al contactar IA</div>';
    }}
    btn.disabled = false;
  }}

  /* === CHURN ALERTS === */
  function renderChurn() {{
    const el = document.getElementById('churn-list');
    if (!CHURN.length) {{ el.innerHTML = '<span style="color:#555">Sin alertas de churn</span>'; return; }}
    el.innerHTML = CHURN.map(c => '<div class="churn-alert"><span class="email">' + c.email + ' (' + (c.name||'') + ')</span><span class="info">' + c.plan + ' - ' + c.status + ' - ' + (c.date||'') + '</span></div>').join('');
  }}

  /* === GRANT PLAN === */
  let _grantUid = null;
  function openGrantModal(uid, name, plan, status, billing) {{
    _grantUid = uid;
    document.getElementById('grant-user-name').textContent = name;
    document.getElementById('grant-plan').value = plan || '';
    document.getElementById('grant-billing').value = billing || 'month';
    document.getElementById('grant-status').value = status || '';
    document.getElementById('grant-reset').value = '0';
    document.getElementById('grant-msg').textContent = '';
    document.getElementById('grant-modal').classList.add('open');
  }}
  function closeGrantModal() {{ document.getElementById('grant-modal').classList.remove('open'); }}
  async function saveGrant() {{
    const plan=document.getElementById('grant-plan').value, billing=document.getElementById('grant-billing').value;
    const status=document.getElementById('grant-status').value, reset=document.getElementById('grant-reset').value==='1';
    const msg=document.getElementById('grant-msg');
    msg.style.color='#aaa'; msg.textContent='Guardando...';
    try {{
      const r = await fetch('/admin/grant-plan', {{method:'POST',headers:{{'Content-Type':'application/json'}},
        body:JSON.stringify({{uid:_grantUid,plan,billing_interval:billing,status,reset}})}});
      const d = await r.json();
      if (r.ok) {{ msg.style.color='#4ade80'; msg.textContent='OK: '+d.msg; setTimeout(()=>location.reload(),1200); }}
      else {{ msg.style.color='#f87171'; msg.textContent='Error: '+(d.error||''); }}
    }} catch(e) {{ msg.style.color='#f87171'; msg.textContent='Error de red'; }}
  }}

  /* === CREDITS === */
  let _creditsUid = null;
  function openCreditsModal(uid, name) {{
    _creditsUid = uid;
    document.getElementById('credits-user-name').textContent = name;
    document.getElementById('credits-qty').value = 5;
    document.getElementById('credits-msg').textContent = '';
    document.getElementById('credits-modal').classList.add('open');
  }}
  async function saveCredits() {{
    const qty = parseInt(document.getElementById('credits-qty').value) || 0;
    const msg = document.getElementById('credits-msg');
    if (qty < 1) {{ msg.style.color='#f87171'; msg.textContent='Cantidad invalida'; return; }}
    msg.style.color='#aaa'; msg.textContent='Otorgando...';
    try {{
      const r = await fetch('/admin/grant-credits', {{method:'POST',headers:{{'Content-Type':'application/json'}},
        body:JSON.stringify({{uid:_creditsUid,qty}})}});
      const d = await r.json();
      if (r.ok) {{ msg.style.color='#4ade80'; msg.textContent='OK: '+d.msg; setTimeout(()=>location.reload(),1200); }}
      else {{ msg.style.color='#f87171'; msg.textContent='Error: '+(d.error||''); }}
    }} catch(e) {{ msg.style.color='#f87171'; msg.textContent='Error de red'; }}
  }}

  /* === USER DETAIL === */
  async function openDetail(uid) {{
    document.getElementById('detail-modal').classList.add('open');
    document.getElementById('detail-body').innerHTML = '<span style="color:#555">Cargando...</span>';
    try {{
      const r = await fetch('/admin/user-detail/' + uid);
      const d = await r.json();
      document.getElementById('detail-title').textContent = d.name || d.email;
      let html = '<div class="detail-section"><h4>Informacion</h4>';
      html += '<div class="detail-row"><span class="lbl">Email</span><span class="val">' + d.email + '</span></div>';
      html += '<div class="detail-row"><span class="lbl">Plan</span><span class="val">' + (d.plan||'Free') + '</span></div>';
      html += '<div class="detail-row"><span class="lbl">Estado</span><span class="val">' + (d.sub_status||'ninguno') + '</span></div>';
      html += '<div class="detail-row"><span class="lbl">Billing</span><span class="val">' + (d.billing_interval||'month') + '</span></div>';
      html += '<div class="detail-row"><span class="lbl">Registro</span><span class="val">' + (d.created_at||'').slice(0,10) + '</span></div>';
      html += '<div class="detail-row"><span class="lbl">Trial hasta</span><span class="val">' + (d.trial_ends||'-').slice(0,10) + '</span></div>';
      html += '<div class="detail-row"><span class="lbl">Descargas usadas</span><span class="val">' + (d.downloads_used||0) + '</span></div>';
      html += '<div class="detail-row"><span class="lbl">Pack credits</span><span class="val">' + (d.pack_credits||0) + '</span></div>';
      html += '</div>';
      // Downloads
      html += '<div class="detail-section"><h4>Ultimas descargas (' + d.downloads.length + ')</h4><div class="detail-list">';
      d.downloads.forEach(dl => {{ html += '<div>' + (dl.ts||'').slice(0,16) + ' - ' + (dl.folio||dl.nombre||'') + '</div>'; }});
      if (!d.downloads.length) html += '<div>Sin descargas</div>';
      html += '</div></div>';
      // Packs
      if (d.packs && d.packs.length) {{
        html += '<div class="detail-section"><h4>Paquetes comprados</h4><div class="detail-list">';
        d.packs.forEach(p => {{ html += '<div>' + (p.ts||'').slice(0,10) + ' - ' + p.pack_type + ' (' + p.credits_total + ' desc, usadas: ' + p.credits_used + ')</div>'; }});
        html += '</div></div>';
      }}
      // Team
      if (d.team_members && d.team_members.length) {{
        html += '<div class="detail-section"><h4>Miembros de equipo</h4><div class="detail-list">';
        d.team_members.forEach(m => {{ html += '<div>' + m.email + (m.name ? ' (' + m.name + ')' : '') + '</div>'; }});
        html += '</div></div>';
      }}
      document.getElementById('detail-body').innerHTML = html;
    }} catch(e) {{ document.getElementById('detail-body').innerHTML='<span style="color:#f87171">Error al cargar</span>'; }}
  }}

  /* === SYNC NOTION === */
  async function syncNotion(btn) {{
    btn.disabled=true; btn.textContent='Sincronizando...';
    const st=document.getElementById('sync-status');
    try {{
      const r=await fetch('/admin/sync-notion',{{method:'POST',headers:{{'Content-Type':'application/json'}}}});
      const d=await r.json();
      if(r.ok){{st.style.color='#4ade80';st.textContent='OK: '+d.synced+' sincronizados';}}
      else{{st.style.color='#f87171';st.textContent='Error: '+(d.error||'');}}
    }}catch(e){{st.style.color='#f87171';st.textContent='Error de red';}}
    btn.disabled=false;btn.textContent='Sync Notion';
  }}

  /* === DELETE USER === */
  async function deleteUser(uid,name) {{
    if(!confirm('Eliminar a "'+name+'"? No se puede deshacer.'))return;
    try {{
      const r=await fetch('/admin/delete-user',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{uid}})}});
      const d=await r.json();
      if(r.ok){{alert('OK: '+d.msg);location.reload();}}else{{alert('Error: '+(d.error||''));}}
    }}catch(e){{alert('Error de red');}}
  }}

  /* === MASS EMAIL === */
  async function sendMassEmail() {{
    const target=document.getElementById('email-target').value;
    const subject=document.getElementById('email-subject').value.trim();
    const body=document.getElementById('email-body').value.trim();
    const msg=document.getElementById('email-msg');
    const btn=document.getElementById('email-send-btn');
    if(!subject||!body){{msg.style.color='#f87171';msg.textContent='Asunto y mensaje son obligatorios';return;}}
    if(!confirm('Enviar correo a grupo: '+target+'?'))return;
    btn.disabled=true;btn.textContent='Enviando...';msg.style.color='#aaa';msg.textContent='Enviando...';
    try {{
      const r=await fetch('/admin/send-mass-email',{{method:'POST',headers:{{'Content-Type':'application/json'}},
        body:JSON.stringify({{target,subject,body}})}});
      const d=await r.json();
      if(r.ok){{msg.style.color='#4ade80';msg.textContent='OK: '+d.sent+' enviados de '+d.total+' destinatarios';}}
      else{{msg.style.color='#f87171';msg.textContent='Error: '+(d.error||'');}}
    }}catch(e){{msg.style.color='#f87171';msg.textContent='Error de red';}}
    btn.disabled=false;btn.textContent='Enviar';
  }}

  // Auto-render chart on load
  renderChart();

  /* === PAYOUTS === */
  async function loadPayouts(btn) {{
    btn.disabled = true; btn.textContent = 'Cargando...';
    const el = document.getElementById('payouts-container');
    try {{
      const r = await fetch('/admin/payouts');
      const d = await r.json();
      if (!r.ok) {{ el.innerHTML = '<span style="color:#f87171">Error: ' + (d.error||'desconocido') + '</span>'; return; }}
      if (!d.payouts || !d.payouts.length) {{
        el.innerHTML = '<p style="color:#555">No hay transferencias registradas aún.</p>'; return;
      }}
      var rows = d.payouts.map(function(p) {{
        var statusColor = p.status === 'paid' ? '#4ade80' : p.status === 'pending' ? '#f59e0b' : '#f87171';
        var statusLabel = p.status === 'paid' ? 'Transferido' : p.status === 'pending' ? 'En tránsito' : p.status;
        var arrival = p.arrival_date ? new Date(p.arrival_date * 1000).toLocaleDateString('es-MX',{{day:'2-digit',month:'short',year:'numeric'}}) : '—';
        var created = p.created ? new Date(p.created * 1000).toLocaleDateString('es-MX',{{day:'2-digit',month:'short',year:'numeric'}}) : '—';
        return '<tr>'
          + '<td style="color:#dde0e8;font-weight:700">$' + (p.amount/100).toLocaleString('es-MX') + ' ' + (p.currency||'').toUpperCase() + '</td>'
          + '<td><span style="color:' + statusColor + ';font-weight:600">' + statusLabel + '</span></td>'
          + '<td style="color:#aaa">' + arrival + '</td>'
          + '<td style="color:#666;font-size:.75rem">' + created + '</td>'
          + '<td style="color:#555;font-size:.75rem;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + (p.description||'—') + '</td>'
          + '</tr>';
      }}).join('');
      el.innerHTML = '<div style="background:#0d0d14;border-radius:10px;padding:1rem 0;overflow-x:auto">'
        + '<div style="margin-bottom:.75rem;font-size:.8rem;color:#555">Últimas ' + d.payouts.length + ' transferencias · Balance disponible: <strong style="color:#4ade80">$' + (d.balance_available/100).toLocaleString('es-MX') + ' MXN</strong>'
        + ' · En tránsito: <strong style="color:#f59e0b">$' + (d.balance_pending/100).toLocaleString('es-MX') + ' MXN</strong></div>'
        + '<table style="width:100%;border-collapse:collapse;font-size:.8125rem">'
        + '<thead><tr>'
        + '<th style="text-align:left;padding:.4rem .6rem;color:#555;border-bottom:1px solid #1e1e2e;font-size:.7rem;text-transform:uppercase">Monto</th>'
        + '<th style="text-align:left;padding:.4rem .6rem;color:#555;border-bottom:1px solid #1e1e2e;font-size:.7rem;text-transform:uppercase">Estado</th>'
        + '<th style="text-align:left;padding:.4rem .6rem;color:#555;border-bottom:1px solid #1e1e2e;font-size:.7rem;text-transform:uppercase">Llega</th>'
        + '<th style="text-align:left;padding:.4rem .6rem;color:#555;border-bottom:1px solid #1e1e2e;font-size:.7rem;text-transform:uppercase">Creado</th>'
        + '<th style="text-align:left;padding:.4rem .6rem;color:#555;border-bottom:1px solid #1e1e2e;font-size:.7rem;text-transform:uppercase">Descripción</th>'
        + '</tr></thead><tbody>' + rows + '</tbody></table></div>';
    }} catch(e) {{
      el.innerHTML = '<span style="color:#f87171">Error de red</span>';
    }} finally {{
      btn.disabled = false; btn.textContent = 'Actualizar';
    }}
  }}
  </script>
</body></html>"""

# ── HTML: Landing page (public) ───────────────────────────────────────────────
LANDING_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Consulta RPP Chihuahua — Escrituras y Folios Reales al Instante</title>
  <meta name="description" content="Consulta escrituras del Registro Público de la Propiedad de Chihuahua. Busca por folio real, nombre de propietario o lote. Descarga PDFs al instante.">
  <meta name="keywords" content="RPP Chihuahua, Registro Público de la Propiedad, folio real, escrituras, consulta RPP, propiedades Chihuahua">
  <meta property="og:title" content="Consulta RPP Chihuahua — Escrituras al Instante">
  <meta property="og:description" content="Busca escrituras del Registro Público de la Propiedad de Chihuahua por folio real, nombre o lote. Descarga PDFs sin filas.">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://consulta-rpp.javisnes.com">
  <link rel="canonical" href="https://consulta-rpp.javisnes.com">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230d0d14'/%3E%3Crect width='32' height='32' rx='7' fill='url(%23g)'/%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%238b9cf4' stop-opacity='.25'/%3E%3Cstop offset='1' stop-color='%23c084fc' stop-opacity='.25'/%3E%3C/linearGradient%3E%3C/defs%3E%3Ctext x='16' y='21' font-family='Arial Black,Arial' font-size='11' font-weight='900' fill='%23c084fc' text-anchor='middle'%3ERPP%3C/text%3E%3C/svg%3E">
  <link rel="manifest" href="/manifest.json">
  <meta name="theme-color" content="#0d0d14">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <link rel="apple-touch-icon" href="/static/icon-192.png">
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
  <script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-XXXXXXXXXX');</script>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#0d0d14;color:#dde0e8;min-height:100vh}

    /* NAV */
    nav{display:flex;align-items:center;justify-content:space-between;
        padding:.9rem 2rem;border-bottom:1px solid #1a1a2a;position:sticky;top:0;
        background:#0d0d14;z-index:10}
    .nav-logo{height:38px;object-fit:contain}
    .nav-links{display:flex;gap:.75rem;align-items:center}
    .btn-login{color:#7a7a9a;text-decoration:none;font-size:.875rem;
               border:1px solid #2a2a3a;border-radius:20px;padding:.3rem .9rem;transition:all .2s}
    .btn-login:hover{border-color:#8b9cf4;color:#dde0e8}
    .btn-cta-nav{background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;
                 text-decoration:none;font-size:.875rem;border-radius:20px;
                 padding:.35rem 1.1rem;font-weight:600;transition:opacity .2s}
    .btn-cta-nav:hover{opacity:.85}

    /* HERO */
    .hero{text-align:center;padding:5rem 1.5rem 3.5rem;max-width:680px;margin:0 auto}
    .hero-logo{height:80px;margin-bottom:1.5rem;object-fit:contain}
    .hero h1{font-size:2.4rem;font-weight:800;line-height:1.2;margin-bottom:1rem;
             background:linear-gradient(120deg,#8b9cf4,#c084fc);
             -webkit-background-clip:text;-webkit-text-fill-color:transparent}
    .hero p{color:#888;font-size:1rem;line-height:1.7;max-width:500px;margin:0 auto 2rem}
    .btn-hero{display:inline-block;background:linear-gradient(135deg,#8b9cf4,#c084fc);
              color:#fff;text-decoration:none;font-weight:700;font-size:1rem;
              padding:.75rem 2rem;border-radius:30px;transition:opacity .2s;
              box-shadow:0 4px 24px rgba(139,156,244,.35)}
    .btn-hero:hover{opacity:.88}

    /* FEATURES */
    .features{display:flex;flex-wrap:wrap;justify-content:center;gap:.65rem;
               padding:0 1.5rem 3.5rem;max-width:760px;margin:0 auto}
    .feat{background:#13131f;border:1px solid #1e1e2e;border-radius:8px;
          padding:.45rem 1rem;font-size:.8125rem;color:#aaa;display:flex;
          align-items:center;gap:.45rem}
    .feat span{font-size:1rem}

    /* SECTION TITLES */
    .sec-title{text-align:center;font-size:1.5rem;font-weight:700;margin-bottom:.4rem;
               background:linear-gradient(120deg,#8b9cf4,#c084fc);
               -webkit-background-clip:text;-webkit-text-fill-color:transparent}
    .sec-sub{text-align:center;color:#555;font-size:.875rem;margin-bottom:2rem}

    /* HOW IT WORKS */
    .how-section{max-width:820px;margin:0 auto 4rem;padding:0 1.5rem}
    .how-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem}
    .how-card{background:#13131f;border:1px solid #1e1e2e;border-radius:14px;
              padding:1.6rem 1.2rem;text-align:center}
    .how-num{width:40px;height:40px;border-radius:50%;margin:0 auto .9rem;
             background:linear-gradient(135deg,#8b9cf4,#c084fc);
             display:flex;align-items:center;justify-content:center;
             font-size:1.125rem;font-weight:800;color:#fff}
    .how-icon{font-size:1.75rem;margin-bottom:.6rem}
    .how-card h3{font-size:.9375rem;font-weight:700;color:#dde0e8;margin-bottom:.4rem}
    .how-card p{font-size:.8125rem;color:#666;line-height:1.6}

    /* TESTIMONIALS */
    .testi-section{max-width:960px;margin:0 auto 4rem;padding:0 1.5rem}
    .testi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.1rem}
    .testi-card{background:#13131f;border:1px solid #1e1e2e;border-radius:14px;padding:1.4rem;transition:border-color .2s}
    .testi-card:hover{border-color:#2a2a4a}
    .testi-stars{color:#f59e0b;font-size:.85rem;margin-bottom:.5rem;letter-spacing:2px}
    .testi-card p{color:#999;font-size:.875rem;line-height:1.6;margin-bottom:.8rem}
    .testi-author{display:flex;align-items:center;gap:.6rem}
    .testi-avatar{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.75rem;font-weight:700;color:#fff;flex-shrink:0}
    .testi-author cite{color:#a78bfa;font-size:.8rem;font-weight:600;font-style:normal;display:block}
    .testi-role{color:#555;font-size:.7rem;display:block;margin-top:.1rem}
    .testi-trust{display:flex;justify-content:center;gap:2.5rem;margin-top:2.5rem;padding:1.5rem;background:#0f0f1c;border:1px solid #1e1e2e;border-radius:14px;flex-wrap:wrap}
    .trust-item{text-align:center}
    .trust-num{display:block;font-size:1.5rem;font-weight:800;background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
    .trust-label{font-size:.72rem;color:#666;margin-top:.2rem;display:block}

    /* PLANS */
    .plans-section{padding:0 1.5rem 4rem;max-width:1080px;margin:0 auto}
    .billing-toggle{display:flex;align-items:center;justify-content:center;gap:.75rem;margin-bottom:1.75rem}
    .toggle-lbl{font-size:.875rem;color:#555;cursor:pointer;transition:color .2s}
    .toggle-lbl.on{color:#dde0e8;font-weight:600}
    .toggle-track{width:46px;height:24px;background:#2a2a3a;border-radius:12px;cursor:pointer;position:relative;transition:background .2s}
    .toggle-track.annual{background:linear-gradient(135deg,#8b9cf4,#c084fc)}
    .toggle-thumb{position:absolute;top:3px;left:3px;width:18px;height:18px;background:#fff;border-radius:50%;transition:transform .2s}
    .toggle-track.annual .toggle-thumb{transform:translateX(22px)}
    .save-badge{background:linear-gradient(135deg,#4ade80,#22c55e);color:#000;font-size:.68rem;font-weight:700;padding:.15rem .5rem;border-radius:10px;white-space:nowrap}
    .plans-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem}
    .plan-card{background:#13131f;border:1.5px solid #2a2a3a;border-radius:16px;
               padding:1.8rem 1.4rem;position:relative;display:flex;flex-direction:column;
               gap:.7rem;transition:transform .2s,border-color .2s}
    .plan-card:hover{transform:translateY(-3px);border-color:#3a3a5a}
    .plan-card.popular{border-color:#8b9cf4;box-shadow:0 0 0 1px #8b9cf4}
    .popular-badge{position:absolute;top:-11px;left:50%;transform:translateX(-50%);
                   background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;
                   font-size:.68rem;font-weight:700;padding:.2rem .75rem;border-radius:20px;
                   white-space:nowrap;letter-spacing:.04em}
    .corp-badge{position:absolute;top:-11px;left:50%;transform:translateX(-50%);
                font-size:.65rem;font-weight:700;padding:.2rem .8rem;border-radius:20px;white-space:nowrap;color:#000}
    .plan-name{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em}
    .plan-price{font-size:2.1rem;font-weight:800;color:#fff}
    .plan-price span{font-size:.875rem;color:#555;font-weight:400}
    .plan-ann-note{font-size:.8rem;color:#4ade80;display:none}
    .annual-mode .plan-ann-note{display:block}
    .plan-feats{list-style:none;display:flex;flex-direction:column;gap:.45rem;flex:1}
    .plan-feats li{font-size:.875rem;color:#888;padding-left:1.2rem;position:relative}
    .plan-feats li::before{content:"✓";position:absolute;left:0;color:#4ade80}
    .plan-btn{display:block;text-align:center;text-decoration:none;width:100%;
              padding:.65rem;border-radius:10px;color:#fff;font-weight:600;font-size:.875rem;
              cursor:pointer;transition:opacity .2s;margin-top:auto;border:none;background:#2a2a3a}
    .plan-btn:hover{opacity:.85}
    .plan-btn.primary{background:linear-gradient(135deg,#8b9cf4,#c084fc)}
    .corp-section-label{text-align:center;margin:2.5rem 0 1.25rem}
    .corp-section-label span{background:linear-gradient(135deg,#facc15,#f97316);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:1.15rem;font-weight:800;letter-spacing:.03em}
    .corp-section-label p{color:#555;font-size:.8rem;margin-top:.3rem}

    /* COMPARISON TABLE */
    .comparison{margin-top:2rem;overflow-x:auto}
    .comparison table{width:100%;border-collapse:collapse;font-size:.8125rem;min-width:580px}
    .comparison th{padding:.55rem .8rem;text-align:center;border-bottom:1px solid #1e1e2e;
                   font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#555}
    .comparison th:first-child{text-align:left}
    .comparison td{padding:.5rem .8rem;border-bottom:1px solid #111118;color:#888}
    .comparison td:not(:first-child){text-align:center}
    .comparison tr:last-child td{border-bottom:none}
    .yes{color:#4ade80}
    .no{color:#2a2a3a}
    .cmp-corp{background:#0d0f0a}

    /* REFERRAL */
    .referral-section{max-width:680px;margin:0 auto 4rem;padding:0 1.5rem}
    .referral-box{background:linear-gradient(135deg,#13131f,#0f0f1c);
                  border:1.5px solid #2a1a4a;border-radius:18px;
                  padding:2.25rem 2rem;text-align:center}
    .referral-box h2{font-size:1.35rem;font-weight:800;margin-bottom:.5rem;
                     background:linear-gradient(120deg,#8b9cf4,#c084fc);
                     -webkit-background-clip:text;-webkit-text-fill-color:transparent}
    .referral-box p{color:#777;font-size:.9375rem;line-height:1.7;
                    max-width:440px;margin:0 auto 1.5rem}
    .referral-stats{display:flex;justify-content:center;gap:2.5rem;flex-wrap:wrap;margin-bottom:1.75rem}
    .ref-stat-val{font-size:1.75rem;font-weight:800}
    .ref-stat-lbl{font-size:.75rem;color:#555;margin-top:.2rem}

    /* FOOTER */
    footer{text-align:center;color:#2a2a3a;font-size:.75rem;padding:2rem 1rem;
           border-top:1px solid #1a1a2a}
    footer a{color:#555;text-decoration:none}
    footer a:hover{color:#aaa}

    /* BEFORE/AFTER STRIP */
    .ba-strip{background:#0a0a12;border-top:1px solid #1a1a2a;border-bottom:1px solid #1a1a2a;padding:.85rem 1.5rem;display:flex;justify-content:center;gap:1.5rem;flex-wrap:wrap}
    .ba-item{display:flex;align-items:center;gap:.6rem;font-size:.8125rem}
    .ba-before{color:#f87171;text-decoration:line-through;opacity:.7}
    .ba-after{color:#4ade80;font-weight:600}
    .ba-arrow{color:#555;font-size:.7rem}
    /* THEME TOGGLE */
    .theme-toggle-btn{background:none;border:1px solid #2a2a3a;color:#666;border-radius:20px;padding:.28rem .75rem;font-size:.78rem;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:.3rem}
    .theme-toggle-btn:hover{border-color:#8b9cf4;color:#8b9cf4}
    /* ONBOARDING BADGE */
    .hero-trust{display:flex;justify-content:center;gap:1.25rem;flex-wrap:wrap;margin-top:1.5rem}
    .hero-trust-item{font-size:.78rem;color:#555;display:flex;align-items:center;gap:.35rem}
    .hero-trust-item strong{color:#8b9cf4}
    .hero-trial-badge{display:inline-block;background:#0f2a1a;border:1px solid #22543d;color:#4ade80;font-size:.72rem;font-weight:700;padding:.2rem .7rem;border-radius:20px;margin-top:.75rem;letter-spacing:.03em}
    /* FOCUS VISIBLE */
    *:focus-visible{outline:2px solid #8b9cf4;outline-offset:2px}
    button:focus-visible,a:focus-visible{outline:2px solid #8b9cf4;outline-offset:2px}
    /* DARK/LIGHT MODE */
    body.light{background:#f4f4f9;color:#1a1a2a}
    body.light nav{background:#fff;border-color:#e0e0ee}
    body.light .btn-login{color:#888;border-color:#e0e0ee}
    body.light .btn-login:hover{border-color:#8b9cf4;color:#1a1a2a}
    body.light .hero p{color:#555}
    body.light .feat{background:#fff;border-color:#e0e0ee;color:#444}
    body.light .how-card{background:#fff;border-color:#e0e0ee}
    body.light .how-card p{color:#666}
    body.light .testi-card{background:#fff;border-color:#e0e0ee}
    body.light .testi-card p{color:#555}
    body.light .testi-trust{background:#f0f0f8;border-color:#e0e0ee}
    body.light .trust-label{color:#888}
    body.light .plan-card{background:#fff;border-color:#e0e0ee}
    body.light .plan-feats li{color:#555}
    body.light .plan-price{color:#1a1a2a}
    body.light .comparison td{color:#555}
    body.light .comparison td:first-child{color:#333}
    body.light .ba-strip{background:#f0f0f8;border-color:#e0e0ee}
    body.light .ba-item{color:#333}
    body.light .hero-trust-item{color:#888}
    body.light .sec-sub{color:#777}
    body.light footer{color:#aaa;border-color:#e0e0ee}
    body.light footer a{color:#888}
    body.light .referral-box{background:#fff;border-color:#c5c9f0}
    body.light .referral-box p{color:#555}
    body.light .theme-toggle-btn{border-color:#e0e0ee;color:#888}
    /* SPINNER */
    @keyframes spin{to{transform:rotate(360deg)}}
    .spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:.4rem}
    @media(max-width:600px){
      nav{padding:.7rem 1rem}
      .hero{padding:3rem 1rem 2.5rem}
      .hero h1{font-size:1.75rem}
      .hero-logo{height:64px}
      .plans-grid{grid-template-columns:1fr}
      .ba-strip{gap:.75rem}
    }
    @media(max-width:380px){
      .hero h1{font-size:1.5rem}
      .testi-grid{grid-template-columns:1fr}
      .how-grid{grid-template-columns:1fr}
    }
    /* ── ANIMATED BACKGROUND ────────────────────────── */
    .land-bg{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
    .land-content{position:relative;z-index:1}
    .orb{position:absolute;border-radius:50%;filter:blur(115px);will-change:transform}
    .orb-1{width:800px;height:800px;top:-220px;left:-220px;
            background:radial-gradient(circle,rgba(99,102,241,.5) 0%,transparent 65%);
            animation:orb1 32s ease-in-out infinite}
    .orb-2{width:680px;height:680px;top:22%;right:-240px;
            background:radial-gradient(circle,rgba(192,132,252,.45) 0%,transparent 65%);
            animation:orb2 41s ease-in-out infinite}
    .orb-3{width:580px;height:580px;bottom:-100px;left:18%;
            background:radial-gradient(circle,rgba(139,156,244,.38) 0%,transparent 65%);
            animation:orb3 27s ease-in-out infinite}
    #land-particles{position:absolute;inset:0;width:100%;height:100%}
    @keyframes orb1{
      0%,100%{transform:translate(0,0)}
      30%{transform:translate(90px,-85px)}
      60%{transform:translate(-65px,75px)}
      80%{transform:translate(75px,55px)}
    }
    @keyframes orb2{
      0%,100%{transform:translate(0,0)}
      35%{transform:translate(-115px,85px)}
      65%{transform:translate(65px,-95px)}
      85%{transform:translate(-45px,45px)}
    }
    @keyframes orb3{
      0%,100%{transform:translate(0,0)}
      40%{transform:translate(85px,-65px)}
      70%{transform:translate(-95px,55px)}
    }
    body.light .land-bg{display:none}
    nav{backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);
        background:rgba(13,13,20,.82)!important}
    body.light nav{background:rgba(255,255,255,.88)!important}
  </style>
</head>
<body>

<!-- ── Animated background ── -->
<div class="land-bg" aria-hidden="true">
  <div class="orb orb-1"></div>
  <div class="orb orb-2"></div>
  <div class="orb orb-3"></div>
  <canvas id="land-particles"></canvas>
</div>
<div class="land-content">

<nav>
  <img src="/static/logo_clean.png" alt="Consulta RPP" class="nav-logo">
  <div class="nav-links">
    <button class="theme-toggle-btn" id="land-theme-btn" onclick="toggleLandTheme()" aria-label="Cambiar tema">☀ Claro</button>
    <a href="/login" class="btn-login">Iniciar sesión</a>
    <a href="/login" class="btn-cta-nav">Empieza gratis →</a>
  </div>
</nav>

<!-- BEFORE/AFTER STRIP -->
<div class="ba-strip">
  <div class="ba-item"><span class="ba-before">2 horas en fila en el RPP</span><span class="ba-arrow">→</span><span class="ba-after">30 segundos desde tu escritorio</span></div>
  <div class="ba-item"><span class="ba-before">PDF con marca de agua</span><span class="ba-arrow">→</span><span class="ba-after">PDF limpio, listo para presentar</span></div>
  <div class="ba-item"><span class="ba-before">$150 por escritura con gestor</span><span class="ba-arrow">→</span><span class="ba-after">$100/mes, escrituras ilimitadas</span></div>
</div>

<section class="hero">
  <img src="/static/logo_clean.png" alt="Logo" class="hero-logo">
  <h1>Escrituras del RPP sin filas,<br>en segundos</h1>
  <p>Busca por folio real, nombre de propietario o lote. Descarga PDFs
     <strong style="color:#c084fc">sin marca de agua</strong>
     directo del RPP Chihuahua.</p>
  <a href="/login" class="btn-hero">Comenzar gratis →</a>
  <div class="hero-trial-badge">✓ 3 días de prueba gratis · Sin tarjeta de crédito</div>
  <div class="hero-trust">
    <div class="hero-trust-item">✓ <strong>14+</strong> profesionales activos</div>
    <div class="hero-trust-item">✓ <strong>500+</strong> escrituras descargadas</div>
    <div class="hero-trust-item">✓ <strong>80%</strong> de ahorro vs. gestor</div>
    <div class="hero-trust-item">✓ Disponible <strong>24/7</strong></div>
  </div>
</section>

<div class="features">
  <div class="feat"><span>🔍</span> Folio real</div>
  <div class="feat"><span>👤</span> Nombre de propietario</div>
  <div class="feat"><span>🗂</span> Lote y clave catastral</div>
  <div class="feat"><span>📄</span> PDF sin marca de agua</div>
  <div class="feat"><span>⚡</span> Resultados en segundos</div>
  <div class="feat"><span>🔐</span> Login con Google</div>
  <div class="feat"><span>🔔</span> Alertas de cambio en folio</div>
  <div class="feat"><span>👥</span> Multi-usuario para equipos</div>
</div>

<!-- HOW IT WORKS -->
<section class="how-section">
  <h2 class="sec-title">De 2 horas a 30 segundos</h2>
  <p class="sec-sub">Así es como funciona Consulta RPP</p>
  <div class="how-grid">
    <div class="how-card">
      <div class="how-num">1</div>
      <div class="how-icon">🔐</div>
      <h3>Regístrate en 30 segundos</h3>
      <p>Entra con tu cuenta de Google o email. Tienes <strong style="color:#4ade80">3 días gratis</strong> para probar sin compromiso.</p>
    </div>
    <div class="how-card">
      <div class="how-num">2</div>
      <div class="how-icon">🔍</div>
      <h3>Busca tu folio o nombre</h3>
      <p>Ingresa el folio real, nombre del propietario, lote o clave catastral. Sin esperar ni hacer fila en el RPP.</p>
    </div>
    <div class="how-card">
      <div class="how-num">3</div>
      <div class="how-icon">⬇️</div>
      <h3>Descarga el PDF limpio</h3>
      <p>En segundos tienes el documento <strong style="color:#c084fc">sin marca de agua</strong>, listo para presentar a tu cliente.</p>
    </div>
  </div>
</section>

<!-- TESTIMONIALS -->
<section class="testi-section">
  <h2 class="sec-title">Lo que dicen nuestros usuarios</h2>
  <p class="sec-sub" style="margin-bottom:2rem">Profesionales inmobiliarios de Chihuahua que ya ahorran tiempo y dinero</p>
  <div class="testi-grid">
    <div class="testi-card">
      <div class="testi-stars">★★★★★</div>
      <p>"Antes perdía <strong style="color:#f87171">2 horas</strong> en fila en el RPP. Ahora tengo la escritura en <strong style="color:#4ade80">30 segundos</strong>. Uso el tiempo en cerrar más ventas."</p>
      <div class="testi-author">
        <div class="testi-avatar" style="background:#6366f1">LG</div>
        <div>
          <cite>Lic. García</cite>
          <span class="testi-role">Perito Valuador · Chihuahua</span>
          <span style="display:block;margin-top:.2rem;font-size:.7rem;color:#4ade80;font-weight:600">Ahorra 10 hrs/semana</span>
        </div>
      </div>
    </div>
    <div class="testi-card">
      <div class="testi-stars">★★★★★</div>
      <p>"La búsqueda por nombre me permite investigar una propiedad completa antes de la cita con el cliente. <strong style="color:#c084fc">Cierro más rápido</strong>."</p>
      <div class="testi-author">
        <div class="testi-avatar" style="background:#c084fc">AM</div>
        <div>
          <cite>Ana M.</cite>
          <span class="testi-role">Agente Inmobiliaria · RE/MAX Chihuahua</span>
          <span style="display:block;margin-top:.2rem;font-size:.7rem;color:#4ade80;font-weight:600">Plan Pro · 2 años cliente</span>
        </div>
      </div>
    </div>
    <div class="testi-card">
      <div class="testi-stars">★★★★★</div>
      <p>"Proceso <strong style="color:#c084fc">20 folios en minutos</strong> con el lote. Antes me llevaba un día entero. Es indispensable en mi despacho."</p>
      <div class="testi-author">
        <div class="testi-avatar" style="background:#f472b6">RH</div>
        <div>
          <cite>Roberto H.</cite>
          <span class="testi-role">Abogado Inmobiliario · Chihuahua</span>
          <span style="display:block;margin-top:.2rem;font-size:.7rem;color:#4ade80;font-weight:600">Plan Empresarial · Ahorra $3,000/mes</span>
        </div>
      </div>
    </div>
    <div class="testi-card">
      <div class="testi-stars">★★★★★</div>
      <p>"Antes pagaba <strong style="color:#f87171">$150 por escritura</strong> a un gestor. Con el plan Pro son <strong style="color:#4ade80">$100/mes para 10 escrituras</strong>. Ahorro el 80%."</p>
      <div class="testi-author">
        <div class="testi-avatar" style="background:#4ade80">MC</div>
        <div>
          <cite>María C.</cite>
          <span class="testi-role">Notaría Pública · Chihuahua</span>
          <span style="display:block;margin-top:.2rem;font-size:.7rem;color:#4ade80;font-weight:600">Ahorra $1,400/mes vs. gestor</span>
        </div>
      </div>
    </div>
    <div class="testi-card">
      <div class="testi-stars">★★★★★</div>
      <p>"Con el plan Corporativo <strong style="color:#facc15">8 asesores</strong> de mi equipo consultan desde una sola cuenta. Control total, factura unificada."</p>
      <div class="testi-author">
        <div class="testi-avatar" style="background:#f59e0b">JL</div>
        <div>
          <cite>Jorge L.</cite>
          <span class="testi-role">Director · Inmobiliaria JL Propiedades</span>
          <span style="display:block;margin-top:.2rem;font-size:.7rem;color:#facc15;font-weight:600">Plan Corporativo · 8 asesores activos</span>
        </div>
      </div>
    </div>
    <div class="testi-card">
      <div class="testi-stars">★★★★★</div>
      <p>"La alerta de folio me notificó un <strong style="color:#c084fc">cambio de propietario</strong> en una propiedad que negociábamos. Nos salvó de un fraude."</p>
      <div class="testi-author">
        <div class="testi-avatar" style="background:#8b9cf4">LP</div>
        <div>
          <cite>Laura P.</cite>
          <span class="testi-role">Agente Inmobiliaria · Century 21 Chih.</span>
          <span style="display:block;margin-top:.2rem;font-size:.7rem;color:#8b9cf4;font-weight:600">Plan Empresarial · Alertas activas</span>
        </div>
      </div>
    </div>
  </div>
  <div class="testi-trust">
    <div class="trust-item"><span class="trust-num">14+</span><span class="trust-label">Usuarios activos</span></div>
    <div class="trust-item"><span class="trust-num">500+</span><span class="trust-label">Escrituras descargadas</span></div>
    <div class="trust-item"><span class="trust-num">4.9/5</span><span class="trust-label">Satisfacción</span></div>
    <div class="trust-item"><span class="trust-num">80%</span><span class="trust-label">Ahorro promedio</span></div>
  </div>
</section>

<!-- PLANS -->
<section class="plans-section" id="plans">
  <h2 class="sec-title">Elige tu plan</h2>
  <p class="sec-sub">Sin contratos · Cancela cuando quieras · Descargas sin marca de agua</p>

  <!-- BILLING TOGGLE -->
  <div class="billing-toggle">
    <span class="toggle-lbl on" id="lbl-mo" onclick="setPlanBilling('monthly')">Mensual</span>
    <div class="toggle-track" id="billing-track" onclick="togglePlanBilling()">
      <div class="toggle-thumb"></div>
    </div>
    <span class="toggle-lbl" id="lbl-ann" onclick="setPlanBilling('annual')">Anual</span>
    <span class="save-badge">2 meses gratis</span>
  </div>

  <!-- INDIVIDUAL PLANS -->
  <div class="plans-grid" id="plans-grid">

    <div class="plan-card" data-mo="500" data-ann="5000">
      <div class="plan-name" style="color:#8b9cf4">Básico</div>
      <div class="plan-price plan-price-val">$500 <span>MXN/mes</span></div>
      <div class="plan-ann-note">$5,000 MXN/año · <strong>Ahorras $1,000</strong></div>
      <ul class="plan-feats">
        <li>Consultas ilimitadas</li>
        <li>5 descargas de escrituras/mes</li>
        <li>PDF sin marca de agua</li>
        <li>Buscar por folio real y nombre</li>
        <li>👥 Hasta 2 miembros de equipo <small style="color:#facc15">(anual)</small></li>
        <li>📊 Dashboard de equipo <small style="color:#facc15">(anual)</small></li>
      </ul>
      <a href="/pricing" class="plan-btn">Contratar</a>
    </div>

    <div class="plan-card popular" data-mo="1000" data-ann="10000">
      <div class="popular-badge">MÁS POPULAR</div>
      <div class="plan-name" style="color:#c084fc">Pro</div>
      <div class="plan-price plan-price-val">$1,000 <span>MXN/mes</span></div>
      <div class="plan-ann-note">$10,000 MXN/año · <strong>Ahorras $2,000</strong></div>
      <ul class="plan-feats">
        <li>Consultas ilimitadas</li>
        <li>10 descargas de escrituras/mes</li>
        <li>PDF sin marca de agua</li>
        <li>Vista previa del documento</li>
        <li>Soporte WhatsApp</li>
        <li>👥 Hasta 2 miembros de equipo <small style="color:#facc15">(anual)</small></li>
        <li>📊 Dashboard de equipo <small style="color:#facc15">(anual)</small></li>
      </ul>
      <a href="/pricing" class="plan-btn primary">Contratar</a>
    </div>

    <div class="plan-card" data-mo="2000" data-ann="20000">
      <div class="plan-name" style="color:#f472b6">Empresarial</div>
      <div class="plan-price plan-price-val">$2,000 <span>MXN/mes</span></div>
      <div class="plan-ann-note">$20,000 MXN/año · <strong>Ahorras $4,000</strong></div>
      <ul class="plan-feats">
        <li>Consultas ilimitadas</li>
        <li>20 descargas de escrituras/mes</li>
        <li>PDF sin marca de agua</li>
        <li>Buscar por folio, nombre y lote</li>
        <li>Vista previa + Alertas de folio</li>
        <li>Soporte WhatsApp prioritario</li>
        <li>👥 Hasta 2 miembros de equipo <small style="color:#facc15">(anual)</small></li>
        <li>📊 Dashboard de equipo <small style="color:#facc15">(anual)</small></li>
      </ul>
      <a href="/pricing" class="plan-btn">Contratar</a>
    </div>

  </div>

  <!-- CORPORATE PLANS -->
  <div class="corp-section-label">
    <span>✦ Planes Corporativos — Para Inmobiliarias ✦</span>
    <p>Acceso multi-usuario · Factura unificada · Soporte prioritario</p>
  </div>
  <div class="plans-grid" style="grid-template-columns:repeat(auto-fit,minmax(280px,1fr))">

    <div class="plan-card" style="border-color:#facc1533" data-mo="5000" data-ann="50000">
      <div class="corp-badge" style="background:#facc15">PARA INMOBILIARIAS</div>
      <div class="plan-name" style="color:#facc15;margin-top:.75rem">Corporativo</div>
      <div class="plan-price plan-price-val">$5,000 <span>MXN/mes</span></div>
      <div class="plan-ann-note">$50,000 MXN/año · <strong>Ahorras $10,000</strong></div>
      <ul class="plan-feats">
        <li>Hasta 10 asesores con acceso</li>
        <li>100 descargas de escrituras/mes</li>
        <li>Sin marca de agua</li>
        <li>Buscar por folio, nombre, lote y clave catastral</li>
        <li>Vista previa + Alertas de folio</li>
        <li>📊 Dashboard corporativo por asesor</li>
        <li>Reportes consolidados mensuales</li>
        <li>Soporte WhatsApp prioritario</li>
      </ul>
      <p style="font-size:.72rem;color:#555;margin-top:-.25rem">* Asesores adicionales: $300 MXN/mes c/u.</p>
      <a href="/pricing" class="plan-btn" style="background:#facc15;color:#000">Contratar</a>
    </div>

    <div class="plan-card" style="border-color:#f9731633" data-mo="8000" data-ann="80000">
      <div class="corp-badge" style="background:#f97316">ALTO VOLUMEN</div>
      <div class="plan-name" style="color:#f97316;margin-top:.75rem">Corporativo Pro</div>
      <div class="plan-price plan-price-val">$8,000 <span>MXN/mes</span></div>
      <div class="plan-ann-note">$80,000 MXN/año · <strong>Ahorras $16,000</strong></div>
      <ul class="plan-feats">
        <li>Usuarios ilimitados — sin costo adicional</li>
        <li>500 descargas/mes</li>
        <li>Sin marca de agua</li>
        <li>Buscar por folio, nombre, lote y clave catastral</li>
        <li>Vista previa + Alertas de folio</li>
        <li>📊 Dashboard corporativo por asesor</li>
        <li>Reportes consolidados mensuales</li>
        <li>Soporte directo — respuesta garantizada</li>
        <li>Funciones personalizadas a la medida</li>
      </ul>
      <a href="/pricing" class="plan-btn" style="background:#f97316;color:#000">Contratar</a>
    </div>

  </div>

  <!-- COMPARISON TABLE -->
  <div class="comparison" style="margin-top:2.5rem">
    <table>
      <thead>
        <tr>
          <th>Característica</th>
          <th style="color:#8b9cf4">Básico</th>
          <th style="color:#c084fc">Pro</th>
          <th style="color:#f472b6">Empresarial</th>
          <th style="color:#facc15">Corporativo</th>
          <th style="color:#f97316">Corp. Pro</th>
        </tr>
      </thead>
      <tbody>
        <tr><td>Precio mensual</td><td>$500</td><td>$1,000</td><td>$2,000</td><td class="cmp-corp">$5,000</td><td class="cmp-corp">$8,000</td></tr>
        <tr><td>Precio anual <small style="color:#4ade80">(2 meses gratis)</small></td><td>$5,000</td><td>$10,000</td><td>$20,000</td><td class="cmp-corp">$50,000</td><td class="cmp-corp">$80,000</td></tr>
        <tr><td>Descargas incluidas</td><td>5/mes</td><td>10/mes</td><td>20/mes</td><td class="cmp-corp" style="color:#facc15;font-weight:600">100/mes</td><td class="cmp-corp" style="color:#f97316;font-weight:600">500/mes</td></tr>
        <tr><td>Usuarios incluidos</td><td>1</td><td>1</td><td>1</td><td class="cmp-corp" style="color:#facc15;font-weight:600">Hasta 10</td><td class="cmp-corp" style="color:#f97316;font-weight:600">Ilimitados</td></tr>
        <tr><td>Buscar por folio y nombre</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes cmp-corp">✓</td><td class="yes cmp-corp">✓</td></tr>
        <tr><td>Buscar por lote</td><td class="no">—</td><td class="no">—</td><td class="yes">✓</td><td class="yes cmp-corp">✓</td><td class="yes cmp-corp">✓</td></tr>
        <tr><td>Buscar por clave catastral</td><td class="no">—</td><td class="no">—</td><td class="no">—</td><td class="yes cmp-corp">✓</td><td class="yes cmp-corp">✓</td></tr>
        <tr><td>Vista previa del documento</td><td class="no">—</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes cmp-corp">✓</td><td class="yes cmp-corp">✓</td></tr>
        <tr><td>Alertas de cambios en folio</td><td class="no">—</td><td class="no">—</td><td class="yes">✓</td><td class="yes cmp-corp">✓</td><td class="yes cmp-corp">✓</td></tr>
        <tr><td>Soporte WhatsApp</td><td class="no">—</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes cmp-corp">✓ Prioritario</td><td class="yes cmp-corp">✓ Directo</td></tr>
        <tr><td>Dashboard corporativo por asesor</td><td class="no">—</td><td class="no">—</td><td class="no">—</td><td class="yes cmp-corp">✓</td><td class="yes cmp-corp">✓</td></tr>
        <tr><td>Reportes consolidados</td><td class="no">—</td><td class="no">—</td><td class="no">—</td><td class="yes cmp-corp">✓</td><td class="yes cmp-corp">✓</td></tr>
        <tr><td>Funciones personalizadas</td><td class="no">—</td><td class="no">—</td><td class="no">—</td><td class="no cmp-corp">—</td><td class="yes cmp-corp">✓</td></tr>
        <tr><td>Miembros de equipo <small style="color:#facc15">(anual)</small></td><td>Hasta 2</td><td>Hasta 2</td><td>Hasta 2</td><td class="cmp-corp" style="color:#facc15;font-weight:600">Hasta 10</td><td class="cmp-corp" style="color:#f97316;font-weight:600">Hasta 50</td></tr>
      </tbody>
    </table>
  </div>
</section>

<!-- REFERRAL BANNER -->
<section class="referral-section">
  <div class="referral-box">
    <div style="font-size:2rem;margin-bottom:.75rem">🎁</div>
    <h2>Invita y gana descargas gratis</h2>
    <p>Comparte tu link personal con colegas. Cada vez que alguien se registre con tu link,
       <strong style="color:#c084fc">ambos reciben 1 descarga gratis</strong> — sin límite de referidos.</p>
    <div class="referral-stats">
      <div>
        <div class="ref-stat-val" style="color:#c084fc">∞</div>
        <div class="ref-stat-lbl">Sin límite de referidos</div>
      </div>
      <div>
        <div class="ref-stat-val" style="color:#4ade80">+1</div>
        <div class="ref-stat-lbl">Descarga por referido</div>
      </div>
      <div>
        <div class="ref-stat-val" style="color:#8b9cf4">+1</div>
        <div class="ref-stat-lbl">Para tu invitado también</div>
      </div>
    </div>
    <a href="/login" class="btn-hero" style="font-size:.9375rem;padding:.65rem 1.75rem">
      Ver mi link de referido →
    </a>
  </div>
</section>

<footer>Diseñado por Javisness · Consulta RPP Chihuahua · <a href="/terminos">Términos y Condiciones</a> · <a href="/estado" id="status-footer-link">● Estado</a></footer>

<script>
// ── Plan billing toggle ─────────────────────────────────────────────────────
var _planAnnual = false;
function togglePlanBilling() { setPlanBilling(_planAnnual ? 'monthly' : 'annual'); }
function setPlanBilling(mode) {
  _planAnnual = (mode === 'annual');
  var track = document.getElementById('billing-track');
  var grid  = document.getElementById('plans-grid');
  if (track) { _planAnnual ? track.classList.add('annual') : track.classList.remove('annual'); }
  // Toggle label styles
  var lmo = document.getElementById('lbl-mo'), lann = document.getElementById('lbl-ann');
  if (lmo)  { _planAnnual ? lmo.classList.remove('on')  : lmo.classList.add('on'); }
  if (lann) { _planAnnual ? lann.classList.add('on')    : lann.classList.remove('on'); }
  // Update all plan cards
  document.querySelectorAll('.plan-card').forEach(function(card) {
    var moPrice  = card.getAttribute('data-mo');
    var annPrice = card.getAttribute('data-ann');
    var priceEl  = card.querySelector('.plan-price-val');
    if (!priceEl || !moPrice) return;
    if (_planAnnual) {
      priceEl.innerHTML = '$' + parseInt(annPrice).toLocaleString('es-MX') + ' <span>MXN/año</span>';
    } else {
      priceEl.innerHTML = '$' + parseInt(moPrice).toLocaleString('es-MX') + ' <span>MXN/mes</span>';
    }
  });
  // Show/hide annual savings note
  _planAnnual
    ? document.body.classList.add('annual-mode')
    : document.body.classList.remove('annual-mode');
}
// ── Dark mode toggle ────────────────────────────────────────────────────────
(function() {
  var t = localStorage.getItem('rpp_theme');
  if (t === 'light') {
    document.body.classList.add('light');
    var b = document.getElementById('land-theme-btn');
    if (b) b.textContent = '🌙 Oscuro';
  }
})();
function toggleLandTheme() {
  var isLight = document.body.classList.toggle('light');
  localStorage.setItem('rpp_theme', isLight ? 'light' : 'dark');
  var btn = document.getElementById('land-theme-btn');
  if (btn) btn.textContent = isLight ? '🌙 Oscuro' : '☀ Claro';
}
// ── Particle canvas ──────────────────────────────────────────────────────────
(function(){
  var c = document.getElementById('land-particles');
  if (!c) return;
  var ctx = c.getContext('2d');
  var pts = [], N = 55;
  function resize(){ c.width = window.innerWidth; c.height = window.innerHeight; }
  window.addEventListener('resize', resize); resize();
  for (var i = 0; i < N; i++) {
    pts.push({
      x: Math.random() * c.width,
      y: Math.random() * c.height,
      vx: (Math.random() - .5) * .22,
      vy: -(Math.random() * .38 + .06),
      r: Math.random() * 1.6 + .5,
      a: Math.random() * .38 + .08,
      h: Math.random() > .5 ? 250 : 278
    });
  }
  function frame(){
    ctx.clearRect(0, 0, c.width, c.height);
    for (var i = 0; i < N; i++){
      var p = pts[i];
      var g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r * 6);
      g.addColorStop(0, 'hsla(' + p.h + ',72%,72%,' + p.a + ')');
      g.addColorStop(1, 'hsla(' + p.h + ',72%,72%,0)');
      ctx.beginPath(); ctx.fillStyle = g;
      ctx.arc(p.x, p.y, p.r * 6, 0, 6.283); ctx.fill();
      p.x += p.vx; p.y += p.vy;
      if (p.y < -20){ p.y = c.height + 20; p.x = Math.random() * c.width; }
      if (p.x < -20) p.x = c.width + 20;
      if (p.x > c.width + 20) p.x = -20;
    }
    requestAnimationFrame(frame);
  }
  frame();
})();
</script>
</div>
</body>
</html>"""

# ── HTML: Main app ────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Consulta RPP Chihuahua</title>
  <meta name="description" content="Consulta escrituras del RPP Chihuahua. Busca por folio real, nombre o lote.">
  <meta name="robots" content="noindex">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%2309090f'/%3E%3Ctext x='16' y='21' font-family='Arial Black,Arial' font-size='11' font-weight='900' fill='%236366f1' text-anchor='middle'%3ERPP%3C/text%3E%3C/svg%3E">
  <link rel="manifest" href="/manifest.json">
  <meta name="theme-color" content="#09090f">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
  <script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-XXXXXXXXXX');</script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #09090f; --surface: #0f0f18; --border: #1e1e2e;
      --text: #e2e4ed; --muted: #4b5268; --accent: #6366f1;
      --ok-bg: #061812; --ok-border: #14532d; --ok-text: #4ade80;
      --err-bg: #150505; --err-border: #3f1515; --err-text: #f87171;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg); color: var(--text); min-height: 100vh;
      display: flex; align-items: flex-start; justify-content: center; padding: 2rem 1rem;
    }
    .card { width: 100%; max-width: 680px; }
    h1 { font-size: 1.375rem; font-weight: 700; color: var(--text);
         letter-spacing: -.02em; margin-bottom: .25rem; }
    .subtitle { color: var(--muted); font-size: .8125rem; margin-bottom: 1.25rem; }

    /* User bar */
    #user-bar {
      display: flex; align-items: center; gap: .75rem; padding: .625rem .875rem;
      background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
      font-size: .8125rem; margin-bottom: 1.25rem; position: relative;
    }
    #user-bar img { width: 26px; height: 26px; border-radius: 50%; flex-shrink: 0; }
    #user-bar .uname { color: var(--text); font-size: .8125rem; white-space: nowrap;
      overflow: hidden; text-overflow: ellipsis; max-width: 140px; }
    #user-bar .badge { background: #1a1a2e; color: var(--accent);
      padding: .1rem .45rem; border-radius: 4px; font-size: .6875rem; flex-shrink: 0; font-weight: 600; }
    #user-bar .badge.admin { background: #0d1f0d; color: #4ade80; }
    #user-bar .dl-left { color: var(--muted); font-size: .75rem; flex-shrink: 0; }
    .bar-trigger { display: flex; align-items: center; gap: .5rem; cursor: pointer; flex: 1; min-width: 0; }
    .bar-trigger:hover .uname { color: var(--accent); }
    .bar-chevron { color: var(--muted); font-size: .625rem; flex-shrink: 0; transition: transform .2s; }
    .bar-trigger.open .bar-chevron { transform: rotate(180deg); }
    .bar-dropdown {
      display: none; position: absolute; top: calc(100% + 6px); left: 0; right: 0;
      background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
      box-shadow: 0 8px 24px rgba(0,0,0,.6); z-index: 50; overflow: hidden;
    }
    .bar-dropdown.open { display: block; }
    .bar-dropdown a, .bar-dropdown button {
      display: flex; align-items: center; gap: .6rem; width: 100%;
      padding: .625rem 1rem; color: var(--muted); font-size: .8125rem;
      text-decoration: none; background: none; border: none;
      cursor: pointer; text-align: left; transition: background .1s, color .1s;
    }
    .bar-dropdown a:hover, .bar-dropdown button:hover { background: #141420; color: var(--text); }
    .bar-dropdown .dd-sep { height: 1px; background: var(--border); margin: .25rem 0; }
    .bar-dropdown .dd-icon { font-size: .875rem; width: 16px; text-align: center; }
    .bar-dropdown .dd-sub { color: var(--muted); font-size: .6875rem; margin-left: auto; }
    .bar-right { display: flex; align-items: center; gap: .5rem; flex-shrink: 0; }
    #user-bar a { color: var(--muted); text-decoration: none; font-size: .75rem; }
    #user-bar a:hover { color: var(--accent); }
    #user-bar .sub-link { color: var(--accent); font-weight: 600; font-size: .75rem; text-decoration: none; }

    /* No-sub banner */
    .no-sub-banner {
      display: none; padding: 1rem 1.25rem; background: #0c0a18;
      border: 1px solid #2d1f5e; border-radius: 8px;
      font-size: .875rem; color: #c4b5fd; margin-bottom: 1.25rem; text-align: center;
    }
    .no-sub-banner .nsb-title { font-size: .9375rem; font-weight: 700; color: #e9d5ff; margin-bottom: .3rem; }
    .no-sub-banner .nsb-perks { color: var(--muted); font-size: .8125rem; margin-bottom: .75rem; }
    .no-sub-banner .nsb-perks span { color: #a78bfa; font-weight: 600; }
    .no-sub-banner .nsb-btn { display: inline-block; padding: .5rem 1.5rem;
      background: var(--accent); color: #fff; border-radius: 6px;
      font-weight: 600; font-size: .875rem; text-decoration: none; transition: opacity .15s; }
    .no-sub-banner .nsb-btn:hover { opacity: .85; }
    .no-sub-banner a { color: #a78bfa; font-weight: 700; }

    /* Lock overlay */
    .lock-overlay {
      position: absolute; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(9,9,15,.92); backdrop-filter: blur(4px);
      display: flex; align-items: center; justify-content: center;
      border-radius: 8px; z-index: 10;
    }
    .lock-box { text-align: center; padding: 1.5rem; }
    .lock-box h3 { color: var(--text); margin: .5rem 0 .3rem; font-size: 1rem; }
    .lock-box p { color: var(--muted); font-size: .85rem; margin: 0; }
    body.light .lock-overlay { background: rgba(244,244,249,.92); }
    body.light .lock-box h3 { color: #1e293b; }
    body.light .lock-box p { color: #475569; }

    /* Tabs — underline style */
    .tabs { display: flex; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem; }
    .tab-btn {
      flex: 1; padding: .65rem .5rem; background: transparent;
      border: none; border-bottom: 2px solid transparent;
      color: var(--muted); font-size: .875rem; font-weight: 500;
      cursor: pointer; transition: all .15s; margin-bottom: -1px;
    }
    .tab-btn:hover { color: var(--text); }
    .tab-btn.active { color: var(--text); border-bottom-color: var(--accent); font-weight: 600; }
    .tab-panel { display: none; padding-top: 1.25rem; }
    .tab-panel.active { display: block; }

    label { display: block; color: var(--muted); font-size: .8125rem; margin-bottom: .375rem; }
    .field-row { display: flex; gap: .75rem; }
    .field-row > div { flex: 1; }
    input[type="text"] {
      width: 100%; padding: .625rem .875rem;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 7px; color: var(--text); font-size: .9375rem;
      outline: none; transition: border-color .15s; margin-bottom: .875rem;
    }
    input[type="text"]:focus { border-color: var(--accent); }
    .search-btn {
      width: 100%; padding: .65rem; background: var(--accent);
      color: #fff; border: none; border-radius: 7px;
      font-size: .9375rem; font-weight: 600; cursor: pointer; transition: opacity .15s;
    }
    .search-btn:hover { opacity: .85; }
    .search-btn:disabled { opacity: .4; cursor: not-allowed; }

    #status, #status2 {
      margin-top: 1rem; display: none; padding: .875rem 1rem;
      border-radius: 7px; font-size: .875rem; line-height: 1.5;
    }
    .loading { background: var(--surface); border: 1px solid var(--border); color: var(--muted); }
    .success { background: var(--ok-bg); border: 1px solid var(--ok-border); color: var(--ok-text); }
    .error   { background: var(--err-bg); border: 1px solid var(--err-border); color: var(--err-text); }

    .bar { width:100%; height:2px; background: var(--border); border-radius:2px;
           margin-top:.625rem; overflow:hidden; position:relative; }
    .fill { height:100%; border-radius:2px; background: var(--accent);
            animation: sweep 1.8s ease-in-out infinite; }
    @keyframes sweep {
      0%   { width:15%; margin-left:0; }
      50%  { width:55%; margin-left:25%; }
      100% { width:15%; margin-left:100%; }
    }
    .dl-btn { display:inline-block; margin-top:.5rem; padding:.4rem 1rem;
      background: var(--ok-bg); color: var(--ok-text); border: 1px solid var(--ok-border);
      border-radius:6px; text-decoration:none; font-size:.875rem; font-weight:600; }
    .dl-btn:hover { opacity: .85; }

    #results-container { margin-top: 1.5rem; display: none; }
    .results-title { font-size: .75rem; color: var(--muted); margin-bottom: .75rem;
      text-transform: uppercase; letter-spacing: .06em; }
    .prop-card { background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; margin-bottom: .875rem; overflow: hidden; }
    .prop-card-header { padding: .65rem .875rem; border-bottom: 1px solid var(--border);
      display: flex; justify-content: space-between; align-items: center; }
    .prop-person-name { font-weight: 600; color: var(--text); font-size: .9375rem; }
    .prop-distrito { font-size: .75rem; color: var(--muted); background: var(--bg);
      padding: .15rem .55rem; border-radius: 4px; border: 1px solid var(--border); }
    .prop-table-wrap { overflow-x: auto; }
    table.prop-table { width: 100%; border-collapse: collapse; font-size: .8125rem; }
    table.prop-table th { background: var(--bg); color: var(--muted); font-weight: 600;
      padding: .45rem .75rem; text-align: left;
      white-space: nowrap; border-bottom: 1px solid var(--border); }
    table.prop-table td { padding: .5rem .75rem; border-bottom: 1px solid #111118;
      color: var(--text); vertical-align: middle; }
    table.prop-table tr:last-child td { border-bottom: none; }
    table.prop-table tr:hover td { background: #111118; }
    .folio-badge { background: #1a1a2e; color: var(--accent);
      padding: .15rem .45rem; border-radius: 4px; font-family: monospace; font-size: .8125rem; }
    .dl-row-btn { padding: .3rem .75rem; background: var(--accent); color: #fff;
      border: none; border-radius: 5px; font-size: .75rem; font-weight: 600; cursor: pointer;
      white-space: nowrap; transition: opacity .15s; }
    .dl-row-btn:hover { opacity: .85; }
    .dl-row-btn:disabled { opacity: .35; cursor: not-allowed; }
    .dl-row-btn.done { background: var(--ok-bg); color: var(--ok-text); border: 1px solid var(--ok-border); }
    .dl-row-btn.loading-btn { background: #1a1a2e; color: var(--muted); }
    .no-pdf { font-size: .75rem; color: var(--muted); font-style: italic; }

    /* Quota modal */
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.7);
      display: flex; align-items: center; justify-content: center; z-index: 100; display: none; }
    .modal { background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; padding: 1.75rem 1.5rem; max-width: 360px; width: 90%; text-align: center; }
    .modal h3 { margin-bottom: .6rem; font-size: 1.0625rem; }
    .modal p  { color: var(--muted); font-size: .875rem; margin-bottom: 1.25rem; line-height: 1.5; }
    .modal-btns { display: flex; gap: .625rem; justify-content: center; flex-direction: column; }
    .modal-btns button { padding: .55rem 1.1rem; border: none; border-radius: 6px;
      font-weight: 600; font-size: .875rem; cursor: pointer; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-cancel  { background: #1a1a2e; color: var(--muted); }

    .footer { margin-top: 2.5rem; text-align: center; color: #1e1e2e; font-size: .75rem; }

    /* WhatsApp float */
    #wa-float { display:none; position:fixed; bottom:1.25rem; right:1.25rem; z-index:999;
      align-items:center; gap:.5rem; background:#25d366; color:#fff; border:none; border-radius:40px;
      padding:.6rem 1rem .6rem .8rem; font-size:.8125rem; font-weight:600; cursor:pointer;
      text-decoration:none; box-shadow:0 4px 16px rgba(37,211,102,.3);
      transition:transform .15s, box-shadow .15s; }
    #wa-float:hover { transform:scale(1.04); box-shadow:0 6px 20px rgba(37,211,102,.45); color:#fff; }
    #wa-float svg { width:18px; height:18px; fill:#fff; flex-shrink:0; }

    @keyframes shimmer {
      0%   { background-position: -200px 0; }
      100% { background-position: calc(200px + 100%) 0; }
    }
    .loading {
      background: linear-gradient(90deg, var(--surface) 25%, #141420 50%, var(--surface) 75%);
      background-size: 200px 100%; animation: shimmer 1.5s ease-in-out infinite;
      border: 1px solid var(--border); color: var(--muted);
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .spinner { display:inline-block; width:14px; height:14px; border:1.5px solid var(--border);
      border-top-color: var(--accent); border-radius:50%; animation:spin .6s linear infinite;
      vertical-align:middle; margin-right:.4rem; }
    @keyframes progress-slide {
      0%   { transform: translateX(-100%); }
      100% { transform: translateX(400%); }
    }
    .search-progress { height: 2px; background: var(--border); border-radius: 1px;
      overflow: hidden; margin-top: .5rem; }
    .search-progress-bar { height: 100%; width: 25%; background: var(--accent);
      border-radius: 1px; animation: progress-slide 1.2s ease-in-out infinite; }

    #user-bar .dl-low { color: #f59e0b; font-weight: 600; font-size: .75rem; }
    #user-bar .dl-ok  { color: #4ade80; font-size: .75rem; }
    #user-bar a.acct-link { color: var(--accent); font-size: .75rem; }

    .history-chips { display:flex; flex-wrap:wrap; gap:.35rem; margin-top:.375rem; min-height:0; margin-bottom:.75rem; }
    .history-chip { background: var(--surface); border: 1px solid var(--border); border-radius:4px;
      color: var(--muted); font-size:.75rem; padding:.2rem .6rem; cursor:pointer; transition:all .1s; }
    .history-chip:hover { border-color: var(--accent); color: var(--accent); }
    .history-label { font-size:.75rem; color: var(--muted); margin-top:.5rem; margin-bottom:.1rem; }
    .recent-dl-bar { display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; }
    .recent-dl-label { font-size:.75rem; color: var(--muted); white-space:nowrap; }
    .recent-dl-chip { display:inline-flex; align-items:center; gap:.3rem;
      background: var(--surface); border: 1px solid var(--border); border-radius:4px;
      color: var(--accent); font-size:.75rem; padding:.2rem .65rem;
      cursor:pointer; transition:all .1s; text-decoration:none; }
    .recent-dl-chip:hover { border-color: var(--accent); background: #1a1a2e; }

    /* Account modal */
    .acct-panel { display:none; position:fixed; inset:0; background:rgba(0,0,0,.75);
      z-index:999; align-items:center; justify-content:center; padding:1rem; }
    .acct-panel.open { display:flex; }
    .acct-card { background: var(--surface); border: 1px solid var(--border); border-radius:12px;
      padding:1.5rem; width:100%; max-width:460px; max-height:80vh; overflow-y:auto; }
    .acct-card h2 { font-size:1.0625rem; font-weight:700; color: var(--text); margin-bottom:1rem; }
    .acct-stat { display:flex; justify-content:space-between; padding:.45rem 0;
      border-bottom:1px solid var(--border); font-size:.875rem; }
    .acct-stat:last-child { border-bottom:none; }
    .acct-stat .label { color: var(--muted); }
    .acct-stat .val   { color: var(--text); font-weight:600; }
    .acct-hist-title { color: var(--muted); font-size:.75rem; margin:1rem 0 .5rem;
      text-transform:uppercase; letter-spacing:.06em; }
    .hist-row { display:flex; justify-content:space-between; align-items:center;
      padding:.35rem 0; border-bottom:1px solid var(--border); font-size:.875rem; }
    .hist-row .folio { color: var(--accent); font-weight:600; }
    .hist-row .date  { color: var(--muted); font-size:.75rem; }
    .acct-close { float:right; background:none; border:none; color: var(--muted); font-size:1rem; cursor:pointer; }

    /* Preview modal */
    .preview-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.93);
      z-index:200; flex-direction:column; align-items:center; justify-content:center; padding:1rem; }
    .preview-overlay.open { display:flex; }
    .preview-header { width:min(92vw,900px); display:flex; justify-content:space-between;
      align-items:center; padding:.3rem 0 .5rem; }
    .preview-title { color: var(--text); font-size:.875rem; font-weight:600; }
    .preview-close { background:none; border: 1px solid var(--border); color: var(--muted);
      border-radius:5px; padding:.2rem .6rem; font-size:.875rem; cursor:pointer; }
    .preview-iframe { width:min(92vw,900px); height:76vh; border:none; border-radius:8px; }
    .preview-footer { width:min(92vw,900px); display:flex; gap:.625rem;
      justify-content:flex-end; padding:.5rem 0 0; }
    .btn-preview { background: #1a1a2e; border: 1px solid #2d2d5e; color: var(--accent);
      padding:.4rem .875rem; border-radius:6px; font-size:.875rem; font-weight:600; cursor:pointer; }
    .btn-preview:hover { background: #22224e; }

    /* Lote tab */
    .lote-textarea { width:100%; min-height:100px; background: var(--surface);
      border: 1px solid var(--border); color: var(--text); border-radius:7px;
      padding:.625rem .875rem; font-size:.875rem; font-family:monospace;
      resize:vertical; outline:none; margin-bottom:.375rem; }
    .lote-textarea:focus { border-color: var(--accent); }
    .lote-hint { font-size:.75rem; color: var(--muted); margin-bottom:.75rem; }
    .lote-table { width:100%; border-collapse:collapse; font-size:.875rem; margin-top:.875rem; }
    .lote-table th { background: var(--bg); color: var(--muted); font-weight:600;
      padding:.4rem .75rem; text-align:left; border-bottom: 1px solid var(--border);
      font-size:.75rem; white-space:nowrap; }
    .lote-table td { padding:.45rem .75rem; border-bottom: 1px solid #111118; color: var(--text); }
    .lote-st.wait { color: var(--muted); }
    .lote-st.run  { color: #f59e0b; }
    .lote-st.ok   { color: #4ade80; }
    .lote-st.err  { color: #f87171; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.35} }

    /* Theme toggle */
    .theme-btn { background:none; border: 1px solid var(--border); color: var(--muted);
      border-radius:4px; padding:.12rem .5rem; font-size:.75rem; cursor:pointer;
      transition:all .1s; flex-shrink:0; }
    .theme-btn:hover { border-color: var(--accent); color: var(--accent); }

    /* Light theme */
    body.light { background:#f4f4f9; color:#1a1a2a; }
    body.light h1 { color:#1a1a2a; }
    body.light .subtitle { color:#777; }
    body.light #user-bar { background:#fff; border-color:#e0e0ee; }
    body.light #user-bar .uname { color:#333; }
    body.light .tabs { border-bottom-color:#e0e0ee; }
    body.light .tab-btn { color:#888; }
    body.light .tab-btn.active { color:#1a1a2a; border-bottom-color:#6366f1; }
    body.light input[type=text],body.light .lote-textarea { background:#fff; border-color:#e0e0ee; color:#1a1a2a; }
    body.light .loading { background:#eef0ff; border-color:#c5c9f0; color:#4455bb; }
    body.light .success { background:#e8fff3; border-color:#86efac; color:#166534; }
    body.light .error   { background:#fff1f2; border-color:#fca5a5; color:#9b1c1c; }
    body.light .prop-card { background:#fff; border-color:#e0e0ee; }
    body.light .prop-card-header { border-color:#e0e0ee; }
    body.light .prop-person-name { color:#1a1a2a; }
    body.light .prop-table th { background:#f8f8fc; color:#777; border-color:#e0e0ee; }
    body.light .prop-table td { border-color:#e8e8f0; color:#333; }
    body.light .prop-table tr:hover td { background:#f8f8fc; }
    body.light .modal { background:#fff; border-color:#e0e0ee; color:#1a1a2a; }
    body.light .modal p { color:#666; }
    body.light .btn-cancel { background:#f0f0f8; color:#666; }
    body.light .history-chip { background:#f4f4f9; border-color:#ddddf0; color:#777; }
    body.light .acct-card { background:#fff; border-color:#e0e0ee; }
    body.light .acct-stat { border-color:#e8e8f0; }
    body.light .acct-stat .label { color:#888; }
    body.light .acct-stat .val { color:#1a1a2a; }
    body.light .hist-row { border-color:#e8e8f0; }
    body.light .footer { color:#aaa; }
    body.light .theme-btn { border-color:#ddddf0; color:#888; }
    body.light .lote-table th { background:#f8f8fc; color:#888; border-color:#e0e0ee; }
    body.light .lote-table td { border-color:#e8e8f0; }
    body.light .btn-preview { background:#f4f4fc; border-color:#c5c9f0; color:#6366f1; }
    body.light .no-sub-banner { background:#f4f0ff; border-color:#a78bfa; color:#4c1d95; }
    body.light .no-sub-banner .nsb-title { color:#3b0764; }
    body.light .no-sub-banner .nsb-perks { color:#6d28d9; }
    body.light .bar-dropdown { background:#fff; border-color:#e0e0ee; }
    body.light .bar-dropdown a, body.light .bar-dropdown button { color:#555; }
    body.light .bar-dropdown a:hover, body.light .bar-dropdown button:hover { background:#f4f4f9; color:#1a1a2a; }
    body.light .dd-sep { background:#e8e8f0; }
    body.light .bar-right .sub-link { color:#6366f1; }
    body.light .search-progress { background:#e0e0ee; }
    body.light .preview-overlay { background:rgba(244,244,249,.97); }
    body.light .preview-close { border-color:#e0e0ee; color:#666; background:#fff; }
    body.light .dl-btn { background:#e8fff3; color:#166534; border-color:#86efac; }
    body.light .lote-st { color:#666; }

    @media (max-width: 600px) {
      body { padding: 1rem .5rem; }
      .card { max-width: 100%; }
      h1 { font-size: 1.25rem; }
      #user-bar { padding: .5rem .625rem; }
      #user-bar .uname { max-width: 100px; }
      .field-row { flex-direction: column; gap: .5rem; }
      .tab-btn { font-size:.8125rem; padding: .55rem .25rem; }
      .search-btn { font-size:.9375rem; padding: .6rem; }
      .modal { width: 95vw; padding: 1.2rem; }
      .modal-btns { flex-direction: column; }
      .preview-iframe { height: 55vh; max-height: 55vh; }
      .preview-overlay { padding: .5rem; justify-content: flex-start; padding-top: 1rem; }
      .preview-header { width: 100%; }
      .preview-footer { width: 100%; flex-wrap: wrap; }
      #wa-float { padding: .5rem; font-size:.875rem; }
      #wa-float span { display: none; }
    }
  </style>
</head>
<body>
<div class="card">
  <h1>Consulta RPP</h1>
  <p class="subtitle">Consulta RPP CUU</p>

  <div id="user-bar">
    <div class="bar-trigger" onclick="toggleBarMenu(this)">
      <span class="uname" style="color:#444">Cargando...</span>
      <span class="bar-chevron">▼</span>
    </div>
    <div class="bar-right"></div>
    <div class="bar-dropdown" id="bar-dropdown"></div>
  </div>

  <a id="wa-float" href="https://wa.me/526142030953" target="_blank">
    <svg viewBox="0 0 24 24"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347zM12.05 21.785h-.01a9.87 9.87 0 01-5.03-1.378l-.361-.214-3.741.981.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884zM20.52 3.449C18.24 1.245 15.24 0 12.045 0 5.463 0 .104 5.334.101 11.893c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.88 11.88 0 005.683 1.448h.005c6.585 0 11.946-5.336 11.949-11.896 0-3.176-1.24-6.165-3.495-8.411z"/></svg>
    Soporte
  </a>

  <div id="recent-downloads" style="display:none;margin-bottom:.9rem"></div>

  <div class="no-sub-banner" id="no-sub-banner">
    <div class="nsb-title">Modo gratuito — desbloquea todo con una suscripción</div>
    <div class="nsb-perks">Busca por <span>nombre de propietario</span> y <span>lote</span> · Descargas ilimitadas · Sin pagar por cada escritura</div>
    <a href="/pricing" class="nsb-btn">Ver planes desde $500/mes →</a>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('folio')">Por Folio Real</button>
    <button class="tab-btn" onclick="switchTab('nombre')">Por Nombre</button>
    <button class="tab-btn" onclick="switchTab('lote')">Lote</button>
    <button class="tab-btn" onclick="switchTab('agua')" style="color:#38bdf8">💧 Agua JMAS</button>
  </div>

  <!-- TAB: Folio Real -->
  <div class="tab-panel active" id="tab-folio">
    <label for="folio">Folio Real</label>
    <div style="position:relative">
      <input type="text" id="folio" placeholder="Ej. 1298377" autocomplete="off" oninput="showFolioSuggestions(this.value)" onfocus="showFolioSuggestions(this.value)">
      <div id="folio-suggestions" style="display:none;position:absolute;top:100%;left:0;right:0;background:#13131f;border:1px solid #2a2a3a;border-radius:0 0 10px 10px;max-height:160px;overflow-y:auto;z-index:20"></div>
    </div>
    <div id="folio-history" class="history-chips"></div>
    <button class="search-btn" id="btn-folio" onclick="buscarFolio()">Buscar PDF</button>
    <div id="status"></div>
  </div>

  <!-- TAB: Lote -->
  <div class="tab-panel" id="tab-lote">
    <label>Folios Reales (uno por línea, máx. 10)</label>
    <textarea class="lote-textarea" id="lote-input" placeholder="1298377&#10;1298378&#10;1298379"></textarea>
    <div style="display:flex;align-items:center;gap:.75rem;margin:.6rem 0">
      <p class="lote-hint" style="margin:0;flex:1">Pega la lista de folios o sube un archivo CSV.</p>
      <label style="display:inline-flex;align-items:center;gap:.3rem;padding:.35rem .7rem;background:#1a1a2e;border:1px solid #2a2a4a;border-radius:8px;cursor:pointer;font-size:.78rem;color:#8b9cf4;white-space:nowrap">
        📄 Subir CSV
        <input type="file" accept=".csv,.txt" id="csv-upload" onchange="handleCSVUpload(this)" style="display:none">
      </label>
    </div>
    <button class="search-btn" id="btn-lote" onclick="buscarLote()">Procesar Lote</button>
    <div id="lote-status"></div>
    <div id="lote-results"></div>
  </div>

  <!-- TAB: Por Nombre -->
  <div class="tab-panel" id="tab-nombre">
    <div class="field-row">
      <div>
        <label for="nombre">Nombre(s)</label>
        <input type="text" id="nombre" placeholder="Ej. MARTHA" autocomplete="off" style="text-transform:uppercase">
      </div>
    </div>
    <div class="field-row">
      <div>
        <label for="paterno">Primer Apellido</label>
        <input type="text" id="paterno" placeholder="Ej. GALLEGOS" autocomplete="off" style="text-transform:uppercase">
      </div>
      <div>
        <label for="materno">Segundo Apellido</label>
        <input type="text" id="materno" placeholder="Ej. SIFUENTES" autocomplete="off" style="text-transform:uppercase">
      </div>
    </div>
    <div id="nombre-history" class="history-chips"></div>
    <button class="search-btn" id="btn-nombre" onclick="buscarNombre()">Buscar Propietario</button>
    <div id="status2"></div>
    <div id="results-container"></div>
  </div>


  <!-- TAB: Agua JMAS -->
  <div class="tab-panel" id="tab-agua">
    <label>Buscar adeudo de agua – JMAS Chihuahua</label>
    <div class="field-row" style="margin-top:.5rem">
      <div style="flex:2">
        <label for="agua-calle" style="font-size:.78rem;color:#8b9cf4">Calle</label>
        <input type="text" id="agua-calle" placeholder="Ej. PASEO DEL REAL" autocomplete="off" style="text-transform:uppercase">
      </div>
      <div style="flex:1">
        <label for="agua-num" style="font-size:.78rem;color:#8b9cf4">Número</label>
        <input type="text" id="agua-num" placeholder="Ej. 17719" autocomplete="off">
      </div>
    </div>
    <div style="text-align:center;color:#6b7280;font-size:.8rem;margin:.4rem 0">— o buscar por número de cliente —</div>
    <div>
      <label for="agua-ref" style="font-size:.78rem;color:#8b9cf4">No. de cliente / Referencia</label>
      <input type="text" id="agua-ref" placeholder="Ej. o208130" autocomplete="off">
    </div>
    <button class="search-btn" id="btn-agua" onclick="buscarAgua()" style="background:linear-gradient(135deg,#0ea5e9,#0284c7)">Consultar Adeudo</button>
    <div id="agua-status" style="margin-top:.75rem"></div>
    <div id="agua-result"></div>
  </div>

  <p class="footer">Diseñado por Javisness · <a href="/estado" style="color:inherit;text-decoration:none" id="status-footer-link">● Estado del servicio</a></p>
</div>

<!-- Account panel -->
<div class="acct-panel" id="acct-panel">
  <div class="acct-card">
    <button class="acct-close" onclick="closeAcct()">✕</button>
    <h2>Mi Cuenta</h2>
    <div id="acct-content"><p style="color:#555;font-size:.875rem">Cargando...</p></div>
  </div>
</div>

<!-- PDF Preview modal -->
<div class="preview-overlay" id="preview-overlay">
  <div class="preview-header">
    <span class="preview-title" id="preview-title">Vista previa</span>
    <button class="preview-close" onclick="closePreview()">✕ Cerrar</button>
  </div>
  <iframe class="preview-iframe" id="preview-iframe" src=""></iframe>
  <div class="preview-footer">
    <button class="btn-cancel" onclick="closePreview()">Cerrar</button>
    <a class="btn-primary" id="preview-dl-btn" href="" onclick="closePreview()">⬇ Descargar (consume crédito)</a>
  </div>
</div>

<!-- Quota modal -->
<div class="modal-overlay" id="quota-modal">
  <div class="modal">
    <h3>Límite de descargas alcanzado</h3>
    <p id="quota-msg">Has usado todas tus descargas del mes.</p>
    <div class="modal-btns">
      <button class="btn-primary" onclick="buyExtraAndDownload()">Descarga extra — $130 MXN</button>
      <button class="btn-primary" style="background:#6366f1" onclick="window.location='/pricing'">Mejorar plan</button>
      <button class="btn-cancel" onclick="closeQuotaModal()">Cancelar</button>
    </div>
  </div>
</div>

<!--USER_DATA-->
<script src="/app.js"></script>
</body>
</html>"""

# ── App JavaScript (served as external file) ──────────────────────────────────
APP_JS = r"""
// ── Global state ──────────────────────────────────────────────────────────────
let _userInfo  = window.__USER || null;
let _pendingFolio = null;   // folio waiting for extra-download confirmation
let _pendingBtn   = null;

// ── Plan capability helpers ───────────────────────────────────────────────────
// Trial users get full access; admin always has everything
function _isAdmin()      { return _userInfo && _userInfo.role === 'admin'; }
function _inTrial()      { return _userInfo && _userInfo.in_trial; }
function _plan()         { return _userInfo && _userInfo.plan; }
function _canPreview()   { return _isAdmin() || _inTrial() || ['pro','empresarial','corporativo','corporativo_pro'].includes(_plan()) || (_userInfo && _userInfo.is_team_member); }
function _canAlert()     { return _isAdmin() || ['empresarial','corporativo','corporativo_pro'].includes(_plan()); }
function _canLote()      { return _isAdmin() || _inTrial() || ['empresarial','corporativo','corporativo_pro'].includes(_plan()); }
function _canWA()        { return _isAdmin() || _inTrial() || _plan() === 'pro' || _plan() === 'empresarial'; }
function _upgradeBtn(label) {
  return ' &nbsp;<a href="/pricing" style="display:inline-flex;align-items:center;gap:.3rem;font-size:.75rem;padding:.2rem .55rem;border:1px solid #4a3a6a;border-radius:6px;color:#a78bfa;text-decoration:none;background:#1a0f2e">🔒 ' + label + '</a>';
}

// ── Load user bar ─────────────────────────────────────────────────────────────
async function loadUserBar() {
  try {
    let u = _userInfo;
    if (!u) {
      const res = await fetch('/me');
      if (res.status === 401) { window.location = '/login'; return; }
      u = await res.json();
      if (u.error) { window.location = '/login'; return; }
      _userInfo = u;
    }

    const isTeamMember = u.is_team_member || false;
    const planLabel = isTeamMember ? 'Equipo' : ({basico:'Básico',pro:'Pro',empresarial:'Empresarial',corporativo:'Corporativo',corporativo_pro:'Corp. Pro'}[u.plan] || '');
    const isAdmin   = u.role === 'admin';
    const inTrial   = u.in_trial || false;
    const hasSub    = isAdmin || u.sub_status === 'active' || inTrial || isTeamMember;
    const dlLeft    = u.downloads_left || 0;
    const packCreds = u.pack_credits || 0;
    const dlClass   = isAdmin ? 'dl-ok' : (dlLeft <= 2 && hasSub ? 'dl-low' : 'dl-left');
    const trialDays = inTrial ? Math.max(0, Math.ceil((new Date(u.trial_ends) - new Date()) / 864e5)) : 0;
    const dlText    = isAdmin ? '∞' : (hasSub ? `${dlLeft} desc.` : (packCreds > 0 ? `${packCreds} créd.` : ''));

    // Build trigger (left side: photo + name + badge + dl count)
    const trigger = document.querySelector('.bar-trigger');
    trigger.innerHTML =
      (u.picture ? `<img src="${u.picture}" alt="" style="width:28px;height:28px;border-radius:50%;flex-shrink:0">` : '') +
      `<span class="uname">${u.name || u.email}</span>` +
      (isAdmin ? `<span class="badge admin">Admin</span>`
                : (planLabel ? `<span class="badge">${planLabel}</span>` : '')) +
      (inTrial ? `<span class="badge" style="background:#f59e0b;color:#000;font-size:.65rem">Trial ${trialDays}d</span>` : '') +
      (dlText ? `<span class="${dlClass}">${dlText}</span>` : '') +
      `<span class="bar-chevron">▼</span>`;

    // Build right side (theme button + subscribe CTA for free users)
    const barRight = document.querySelector('.bar-right');
    barRight.innerHTML =
      (!hasSub ? `<a href="/pricing" class="sub-link">Suscribirse</a>` : '') +
      (hasSub && !isAdmin && u.billing_interval === 'year'
        ? `<a href="/dashboard" style="color:#4ade80;font-weight:700;font-size:.8rem;text-decoration:none;padding:.3rem .65rem;background:#0a180a;border:1px solid #1a3a1a;border-radius:6px;white-space:nowrap">📊 Mi Panel</a>`
        : '') +
      `<button class="theme-btn" id="theme-toggle-btn" onclick="toggleTheme()">${document.body.classList.contains('light') ? '🌙' : '☀'}</button>`;

    // Build dropdown menu
    const WA_SVG = `<svg viewBox="0 0 24 24" style="width:14px;height:14px;fill:#25d366;flex-shrink:0"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347zM12.05 21.785h-.01a9.87 9.87 0 01-5.03-1.378l-.361-.214-3.741.981.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884zM20.52 3.449C18.24 1.245 15.24 0 12.045 0 5.463 0 .104 5.334.101 11.893c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.88 11.88 0 005.683 1.448h.005c6.585 0 11.946-5.336 11.949-11.896 0-3.176-1.24-6.165-3.495-8.411z"/></svg>`;
    const dd = document.getElementById('bar-dropdown');
    let ddHTML = '';
    // Show/hide floating WhatsApp button (Pro/Empresarial only)
    const waFloat = document.getElementById('wa-float');
    if (waFloat) waFloat.style.display = _canWA() ? 'inline-flex' : 'none';

    if (hasSub && !isAdmin && u.billing_interval === 'year') {
      ddHTML += `<a href="/dashboard" onclick="closeBarMenu()" style="border:1px solid #1a3a1a;border-radius:8px;margin-bottom:.3rem"><span class="dd-icon">📊</span>Mi Panel Anual<span class="dd-sub" style="color:#4ade80">Historial · Reportes</span></a>`;
    }
    if (u.is_corp_plan && !isAdmin) {
      ddHTML += `<a href="/equipo" onclick="closeBarMenu()" style="border:1px solid #1a2a3a;border-radius:8px;margin-bottom:.3rem"><span class="dd-icon">👥</span>Mi Equipo<span class="dd-sub" style="color:#8b9cf4">Gestionar miembros</span></a>`;
    }
    if (hasSub && !isAdmin) {
      ddHTML += `<a href="#" onclick="openAcct();closeBarMenu();return false"><span class="dd-icon">👤</span>Mi cuenta<span class="dd-sub">${dlLeft} descargas</span></a>`;
      if (!isTeamMember) {
        ddHTML += `<a href="https://wa.me/526142030953?text=Hola%2C+necesito+factura+CFDI+por+mi+suscripci%C3%B3n+a+Consulta+RPP." target="_blank" onclick="closeBarMenu()"><span class="dd-icon">🧾</span>Solicitar factura<span class="dd-sub">Vía WhatsApp · CFDI</span></a>`;
        ddHTML += `<a href="/pricing" onclick="closeBarMenu()"><span class="dd-icon">📦</span>Planes y paquetes</a>`;
      }
    }
    if (isAdmin) {
      ddHTML += `<a href="/admin" onclick="closeBarMenu()"><span class="dd-icon">⚙️</span>Panel Admin</a>`;
    }
    if (!hasSub) {
      ddHTML += `<a href="/pricing" onclick="closeBarMenu()"><span class="dd-icon">⭐</span>Ver planes</a>`;
    }
    // Referral promo (all non-admin users)
    if (!isAdmin && u.referral_code) {
      ddHTML += `<div class="dd-sep"></div>`;
      ddHTML += `<a href="/mis-referidos" onclick="closeBarMenu()" style="border:1px solid #2a1a4a;border-radius:8px;margin-bottom:.3rem"><span class="dd-icon">🎁</span>Mis Referidos<span class="dd-sub" style="color:#c084fc">Dashboard · Recompensas</span></a>`;
      ddHTML += `<div style="padding:.6rem .75rem;background:linear-gradient(135deg,#1a1a2e,#16162a);border-radius:8px;margin:.3rem 0">` +
        `<div style="display:flex;align-items:center;gap:.4rem">` +
          `<code style="font-size:.7rem;color:#aaa;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">consulta-rpp.javisnes.com/r/${u.referral_code}</code>` +
          `<button onclick="navigator.clipboard.writeText('https://consulta-rpp.javisnes.com/r/${u.referral_code}');this.textContent='✓ Copiado';setTimeout(()=>this.textContent='Copiar',2000)" ` +
            `style="background:#6366f1;color:#fff;border:none;border-radius:5px;padding:.25rem .55rem;font-size:.7rem;cursor:pointer;flex-shrink:0">Copiar</button>` +
        `</div>` +
      `</div>`;
    }
    // Historial link (all subscribed users)
    if (hasSub && !isAdmin) {
      ddHTML += `<a href="/historial" onclick="closeBarMenu()"><span class="dd-icon">📋</span>Historial<span class="dd-sub">Búsquedas pasadas</span></a>`;
    }
    ddHTML += `<div class="dd-sep"></div>`;
    ddHTML += `<button onclick="toggleTheme();closeBarMenu()"><span class="dd-icon">${document.body.classList.contains('light') ? '🌙' : '☀️'}</span>${document.body.classList.contains('light') ? 'Modo oscuro' : 'Modo claro'}</button>`;
    ddHTML += `<a href="/logout" onclick="closeBarMenu()"><span class="dd-icon">🚪</span>Cerrar sesión</a>`;
    dd.innerHTML = ddHTML;

    if (!hasSub) {
      document.getElementById('no-sub-banner').style.display = 'block';
    } else if (inTrial) {
      const banner = document.getElementById('no-sub-banner');
      const daysLeft = Math.max(0, Math.ceil((new Date(u.trial_ends) - new Date()) / 864e5));
      banner.style.display = 'block';
      banner.style.background = 'rgba(245,158,11,0.1)';
      banner.style.borderColor = '#f59e0b';
      banner.innerHTML = '⏱️ Trial gratuito — te quedan <strong>' + daysLeft + ' día(s)</strong>. Búsqueda por nombre y lote activada. ' +
        '<a href="/pricing">Suscríbete para no perder acceso</a>';
    }

    // Warn when ≤ 2 downloads left
    if (!isAdmin && hasSub && dlLeft <= 2 && dlLeft >= 0) {
      const msg = dlLeft === 0
        ? '⚠️ Sin descargas disponibles. Compra una extra o mejora tu plan.'
        : `⚠️ Solo te quedan ${dlLeft} descarga(s) este mes.`;
      showToastWarning(msg);
    }

    // Recent downloads quick-access bar
    const rdEl = document.getElementById('recent-downloads');
    if (rdEl && u.recent_downloads && u.recent_downloads.length) {
      rdEl.style.display = 'block';
      rdEl.innerHTML = '<div class="recent-dl-bar">'
        + '<span class="recent-dl-label">⬇ Recientes:</span>'
        + u.recent_downloads.map(r =>
            '<button class="recent-dl-chip" onclick="_autoDownload=true;document.getElementById(\'folio\').value=\'' + r.folio + '\';switchTab(\'folio\');buscarFolio()">'
            + '📄 ' + r.folio
            + '</button>'
          ).join('')
        + '</div>';
    }

    // Add 🔒 to locked tabs based on plan
    const tabBtns = document.querySelectorAll('.tab-btn');
    if (tabBtns.length >= 3) {
      tabBtns[1].innerHTML = (!hasSub ? '🔒 ' : '') + 'Por Nombre';
      tabBtns[2].innerHTML = (!_canLote() ? '🔒 ' : '') + '🗂 Lote';
    }

    // Show referral widget if user has a ref code
    if (u.referral_code) maybeShowReferralWidget();
  } catch(e) {
    console.error('loadUserBar error', e);
  }
}

document.addEventListener('DOMContentLoaded', loadUserBar);

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(tab) {
  const tabs = ['folio', 'nombre', 'lote', 'agua'];
  const isFree = _userInfo && _userInfo.sub_status !== 'active' && _userInfo.role !== 'admin' && !_userInfo.in_trial && !_userInfo.is_team_member;
  const locked = (tab === 'nombre' && isFree) || (tab === 'lote' && !_canLote());
  if (locked) {
    const panel = document.getElementById('tab-' + tab);
    // Show the tab but overlay a lock message
    document.querySelectorAll('.tab-btn').forEach((b, i) => {
      b.classList.toggle('active', tabs[i] === tab);
    });
    tabs.forEach(t => {
      document.getElementById('tab-' + t).classList.toggle('active', t === tab);
    });
    // Remove existing overlay so message stays updated
    const existing = panel.querySelector('.lock-overlay');
    if (existing) existing.remove();
    const ov = document.createElement('div');
    ov.className = 'lock-overlay';
    const msgs = {
      nombre: { title: 'Requiere suscripción', body: 'Buscar por nombre de propietario requiere un plan activo.', cta: 'Ver planes desde $500/mes' },
      lote:   { title: 'Exclusivo Plan Empresarial+', body: 'La búsqueda por lote está disponible desde el plan Empresarial.', cta: 'Actualizar plan' },
    };
    const m = msgs[tab] || msgs.nombre;
    ov.innerHTML = '<div class="lock-box">'
      + '<span style="font-size:2rem">🔒</span>'
      + '<h3>' + m.title + '</h3>'
      + '<p>' + m.body + '</p>'
      + '<a href="/pricing" class="btn-primary" style="display:inline-block;margin-top:.5rem;text-decoration:none;padding:.5rem 1.2rem;border-radius:8px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff">' + m.cta + '</a>'
      + '</div>';
    panel.style.position = 'relative';
    panel.appendChild(ov);
    return;
  }
  document.querySelectorAll('.tab-btn').forEach((b, i) => {
    b.classList.toggle('active', tabs[i] === tab);
  });
  tabs.forEach(t => {
    document.getElementById('tab-' + t).classList.toggle('active', t === tab);
  });
}

// ── Handle 401/402 from API ───────────────────────────────────────────────────
async function handleApiError(res, fallbackMsg) {
  const d = await res.json().catch(() => ({}));
  if (res.status === 401) { window.location = d.goto || '/login'; return true; }
  if (res.status === 402) {
    if (d.quota) {
      showQuotaModal(d.folio);
      return true;
    }
    window.location = d.goto || '/pricing';
    return true;
  }
  return false;
}

// ── Folio search ──────────────────────────────────────────────────────────────
let _autoDownload = false; // set true by recent-download chips

async function buscarFolio() {
  const autoDownload = _autoDownload;
  _autoDownload = false;
  const folio = document.getElementById('folio').value.trim();
  if (!folio) return;
  const btn    = document.getElementById('btn-folio');
  const status = document.getElementById('status');
  _saveFolioToHistory(folio);
  _maybeRequestPush();
  btn.disabled = true;
  status.className = 'loading';
  status.style.display = 'block';
  status.innerHTML = '<span class="spinner"></span>Buscando folio <b>' + folio + '</b>... <span id="search-elapsed" style="color:#555;font-size:.75rem"></span>'
    + '<div class="search-progress"><div class="search-progress-bar"></div></div>';
  // Elapsed time counter
  const _t0 = Date.now();
  const _elapsedInterval = setInterval(() => {
    const el = document.getElementById('search-elapsed');
    if (el) el.textContent = ((Date.now() - _t0) / 1000).toFixed(1) + 's';
  }, 200);
  // Store interval to clear on done
  status._elapsedInterval = _elapsedInterval;
  try {
    const res = await fetch('/buscar', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({folio})
    });
    if (!res.ok) {
      if (await handleApiError(res)) { btn.disabled = false; return; }
      if (status._elapsedInterval) clearInterval(status._elapsedInterval);
      const err = await res.json().catch(() => ({error: 'Error desconocido'}));
      status.className = 'error';
      status.innerHTML = '&#10060; ' + (err.error || 'Error desconocido');
      btn.disabled = false;
      return;
    }
    const {job_id} = await res.json();
    pollFolioJob(job_id, folio, btn, status, autoDownload);
  } catch(e) {
    if (status._elapsedInterval) clearInterval(status._elapsedInterval);
    status.className = 'error';
    status.innerHTML = '&#10060; Error de red: ' + e.message;
    btn.disabled = false;
  }
}

function pollFolioJob(job_id, folio, btn, statusEl, autoDownload) {
  const poll = setInterval(async () => {
    // Re-evaluate isFree at result time so loadUserBar updates are captured
    const isFree = _userInfo && _userInfo.sub_status !== 'active' && _userInfo.role !== 'admin' && !(_userInfo && _userInfo.in_trial) && !(_userInfo && _userInfo.is_team_member);
    try {
      const sr = await fetch('/status/' + job_id);
      const s  = await sr.json();
      if (s.status === 'done') {
        clearInterval(poll);
        if (statusEl._elapsedInterval) clearInterval(statusEl._elapsedInterval);
        statusEl.className = 'success';
        const previewBtn = _canPreview()
          ? '<button class="btn-preview" onclick="openPreview(\'' + job_id + '\',\'' + folio + '\')">&#128065; Vista previa</button>'
          : _upgradeBtn('Vista previa — Pro');
        const alertBtn = _canAlert()
          ? ' &nbsp;<button class="btn-preview" style="font-size:.7rem;padding:.2rem .5rem" onclick="toggleAlert(\'' + folio + '\',this)" title="Alerta de cambios">&#128276; Alerta</button>'
          : _upgradeBtn('Alertas — Empresarial');
        if (isFree) {
          statusEl.innerHTML = '&#10003; Documento listo &nbsp;'
            + previewBtn
            + ' &nbsp;<button class="dl-btn" style="border:none;cursor:pointer" onclick="pagarYDescargar(\'' + job_id + '\',\'' + folio + '\')">&#128176; Descargar — $130 MXN</button>'
            + alertBtn;
        } else {
          statusEl.innerHTML = '&#10003; Documento listo &nbsp;'
            + previewBtn
            + ' &nbsp;<a id="dl-auto-' + job_id + '" class="dl-btn" href="/download/' + job_id + '" download="folio_' + folio + '_sin_marca.pdf" onclick="loadUserBar();showToastSuccess(\'✓ Descargando escritura...\')">&#11015; Descargar</a>'
            + alertBtn;
          if (autoDownload) {
            setTimeout(() => {
              const a = document.getElementById('dl-auto-' + job_id);
              if (a) { loadUserBar(); showToastSuccess('✓ Descargando escritura...'); a.click(); }
            }, 200);
          }
        }
        btn.disabled = false;
      } else if (s.status === 'error') {
        clearInterval(poll);
        if (statusEl._elapsedInterval) clearInterval(statusEl._elapsedInterval);
        statusEl.className = 'error';
        statusEl.innerHTML = '&#10060; ' + s.error;
        btn.disabled = false;
      }
    } catch(e) {
      clearInterval(poll);
      if (statusEl._elapsedInterval) clearInterval(statusEl._elapsedInterval);
      statusEl.className = 'error';
      statusEl.innerHTML = '&#10060; Error de red: ' + e.message;
      btn.disabled = false;
    }
  }, 3000);
}


// ── Name search ───────────────────────────────────────────────────────────────
async function buscarNombre() {
  const nombre  = document.getElementById('nombre').value.trim().toUpperCase();
  const paterno = document.getElementById('paterno').value.trim().toUpperCase();
  const materno = document.getElementById('materno').value.trim().toUpperCase();
  if (!nombre && !paterno) {
    document.getElementById('status2').className = 'error';
    document.getElementById('status2').style.display = 'block';
    document.getElementById('status2').innerHTML = '&#10060; Ingresa al menos el nombre o apellido.';
    return;
  }
  const btn     = document.getElementById('btn-nombre');
  const status2 = document.getElementById('status2');
  const results = document.getElementById('results-container');
  btn.disabled = true;
  results.style.display = 'none';
  results.innerHTML = '';
  status2.className = 'loading';
  status2.style.display = 'block';
  status2.innerHTML = '<span class="spinner"></span>Buscando propietario <b>' + [nombre,paterno,materno].filter(Boolean).join(' ') + '</b>...<div class="bar"><div class="fill"></div></div>';
  try {
    const res = await fetch('/buscar-nombre', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({nombre, paterno, materno})
    });
    if (!res.ok) {
      if (await handleApiError(res)) { btn.disabled = false; return; }
      const err = await res.json().catch(() => ({error: 'Error desconocido'}));
      status2.className = 'error';
      status2.innerHTML = '&#10060; ' + (err.error || 'Error');
      btn.disabled = false;
      return;
    }
    const {job_id} = await res.json();
    const poll = setInterval(async () => {
      try {
        const sr = await fetch('/status/' + job_id);
        const s  = await sr.json();
        if (s.status === 'done') {
          clearInterval(poll);
          btn.disabled = false;
          const data = s.results || [];
          if (!data.length) {
            status2.className = 'error';
            status2.innerHTML = '&#10060; No se encontraron propietarios con ese nombre.';
            return;
          }
          let totalProps = data.reduce((a, r) => a + r.propiedades.length, 0);
          status2.className = 'success';
          status2.innerHTML = '&#10003; Se encontró ' + data.length + ' propietario(s) con ' + totalProps + ' propiedad(es).';
          renderResultados(data);
        } else if (s.status === 'error') {
          clearInterval(poll);
          status2.className = 'error';
          status2.innerHTML = '&#10060; ' + s.error;
          btn.disabled = false;
        }
      } catch(e) {
        clearInterval(poll);
        status2.className = 'error';
        status2.innerHTML = '&#10060; Error de red: ' + e.message;
        btn.disabled = false;
      }
    }, 3000);
  } catch(e) {
    status2.className = 'error';
    status2.innerHTML = '&#10060; Error de red: ' + e.message;
    btn.disabled = false;
  }
}

function renderResultados(data) {
  const container = document.getElementById('results-container');
  container.style.display = 'block';
  let html = '<div class="results-title">Propiedades encontradas</div>';
  for (const r of data) {
    const p = r.propietario;
    const nombreCompleto = [p.nombre, p.paterno, p.materno].filter(Boolean).join(' ');
    html += `<div class="prop-card">
      <div class="prop-card-header">
        <span class="prop-person-name">${nombreCompleto}</span>
        <span class="prop-distrito">${p.distrito || ''}</span>
      </div>`;
    if (!r.propiedades || r.propiedades.length === 0) {
      html += '<div style="padding:.75rem 1rem;color:#555;font-size:.875rem;">Sin propiedades registradas.</div>';
    } else {
      html += `<div class="prop-table-wrap"><table class="prop-table">
        <thead><tr>
          <th>Folio Real</th><th>Domicilio</th><th>Colonia</th>
          <th>Municipio</th><th>Superficie</th><th>Clave Catastral</th><th></th>
        </tr></thead><tbody>`;
      for (const prop of r.propiedades) {
        const sup = prop.sup_rest ? prop.sup_rest + ' ' + (prop.unidad || '') : '—';
        html += `<tr>
          <td><span class="folio-badge">${prop.folio_real}</span></td>
          <td>${prop.domicilio || '—'}</td><td>${prop.colonia || '—'}</td>
          <td>${prop.municipio || '—'}</td><td>${sup}</td>
          <td>${prop.clave_cat || '—'}</td>
          <td>${prop.tiene_agregado
            ? `<button class="dl-row-btn" id="dlbtn-${prop.folio_real}"
                 data-nombre="${nombreCompleto.replace(/"/g,'&quot;')}"
                 onclick="descargarPropiedad(${prop.folio_real}, this, this.dataset.nombre)">&#11015; PDF</button>`
            : '<span class="no-pdf">Sin PDF</span>'
          }</td></tr>`;
      }
      html += '</tbody></table></div>';
    }
    html += '</div>';
  }
  container.innerHTML = html;
}

async function descargarPropiedad(folioReal, btnEl, nombreProp) {
  btnEl.disabled = true;
  btnEl.className = 'dl-row-btn loading-btn';
  btnEl.textContent = '⏳ Descargando...';
  try {
    const res = await fetch('/buscar', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({folio: String(folioReal), nombre_prop: nombreProp || ''})
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      if (res.status === 402 && d.quota) {
        btnEl.className = 'dl-row-btn';
        btnEl.textContent = '⬇ PDF';
        btnEl.disabled = false;
        showQuotaModal(folioReal, btnEl);
        return;
      }
      if (res.status === 401 || res.status === 402) {
        window.location = d.goto || '/pricing';
        return;
      }
      btnEl.className = 'dl-row-btn';
      btnEl.textContent = '❌ Error';
      btnEl.disabled = false;
      alert('Error: ' + (d.error || 'Desconocido'));
      return;
    }
    const {job_id} = await res.json();
    const poll = setInterval(async () => {
      try {
        const sr = await fetch('/status/' + job_id);
        const s  = await sr.json();
        if (s.status === 'done') {
          clearInterval(poll);
          btnEl.className = 'dl-row-btn done';
          btnEl.textContent = '✓ Listo';
          // Insert preview + download buttons after the row button
          const cell = btnEl.parentElement;
          const dl = document.createElement('a');
          dl.className = 'dl-row-btn';
          dl.style.cssText = 'margin-left:.4rem;text-decoration:none;display:inline-block;padding:.3rem .7rem;font-size:.75rem';
          dl.href = '/download/' + job_id;
          dl.download = 'folio_' + folioReal + '_sin_marca.pdf';
          dl.textContent = '⬇';
          dl.title = 'Descargar';
          dl.onclick = () => { loadUserBar(); showToastSuccess('✓ Descargando escritura...'); };
          cell.appendChild(dl);
          if (_canPreview()) {
            const prev = document.createElement('button');
            prev.className = 'btn-preview';
            prev.style.cssText = 'margin-left:.4rem;padding:.25rem .6rem;font-size:.75rem';
            prev.textContent = '👁';
            prev.title = 'Vista previa';
            prev.onclick = () => openPreview(job_id, String(folioReal));
            cell.appendChild(prev);
          } else {
            const lockPrev = document.createElement('a');
            lockPrev.href = '/pricing';
            lockPrev.style.cssText = 'margin-left:.4rem;font-size:.7rem;padding:.2rem .5rem;border:1px solid #4a3a6a;border-radius:6px;color:#a78bfa;text-decoration:none;background:#1a0f2e;display:inline-block';
            lockPrev.textContent = '🔒 Vista previa';
            cell.appendChild(lockPrev);
          }
        } else if (s.status === 'error') {
          clearInterval(poll);
          btnEl.className = 'dl-row-btn';
          btnEl.textContent = '❌ Error';
          btnEl.disabled = false;
          alert('Error: ' + s.error);
        }
      } catch(e) {
        clearInterval(poll);
        btnEl.className = 'dl-row-btn';
        btnEl.textContent = '❌ Error';
        btnEl.disabled = false;
      }
    }, 3000);
  } catch(e) {
    btnEl.className = 'dl-row-btn';
    btnEl.textContent = '❌ Error';
    btnEl.disabled = false;
  }
}

// ── Quota modal ───────────────────────────────────────────────────────────────
function showQuotaModal(folio, btn) {
  _pendingFolio = folio;
  _pendingBtn   = btn || null;
  const plan = (_userInfo && _userInfo.plan) ? {basico:'Básico',pro:'Pro',empresarial:'Empresarial'}[_userInfo.plan] : 'tu plan';
  document.getElementById('quota-msg').textContent =
    'Has usado todas las descargas de ' + plan + ' este mes. ' +
    'Puedes comprar una descarga extra por $130 MXN.';
  document.getElementById('quota-modal').style.display = 'flex';
}

function closeQuotaModal() {
  document.getElementById('quota-modal').style.display = 'none';
  _pendingFolio = null; _pendingBtn = null;
}

async function buyExtraAndDownload() {
  closeQuotaModal();
  try {
    const res = await fetch('/create-checkout/extra', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({return_folio: _pendingFolio})
    });
    const d = await res.json();
    if (d.url) window.location = d.url;
    else alert('Error al crear sesión de pago: ' + (d.error || ''));
  } catch(e) { alert('Error de red'); }
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.getElementById('folio').addEventListener('keydown', e => {
  if (e.key === 'Enter') buscarFolio();
});
['nombre','paterno','materno'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', e => {
    if (e.key === 'Enter') buscarNombre();
  });
});

// ── Toast warning ─────────────────────────────────────────────────────────────
let _warnTimer = null;
// ── Folio autocomplete from recent searches ──────────────────────────────────
const _folioHistory = JSON.parse(localStorage.getItem('rpp_folio_history') || '[]');

function _saveFolioToHistory(folio) {
  if (!folio) return;
  const idx = _folioHistory.indexOf(folio);
  if (idx > -1) _folioHistory.splice(idx, 1);
  _folioHistory.unshift(folio);
  if (_folioHistory.length > 20) _folioHistory.length = 20;
  localStorage.setItem('rpp_folio_history', JSON.stringify(_folioHistory));
}

function showFolioSuggestions(val) {
  const box = document.getElementById('folio-suggestions');
  if (!box) return;
  if (!val && !_folioHistory.length) { box.style.display = 'none'; return; }
  const q = val.trim().toLowerCase();
  const matches = q
    ? _folioHistory.filter(f => f.includes(q)).slice(0, 6)
    : _folioHistory.slice(0, 6);
  if (!matches.length) { box.style.display = 'none'; return; }
  box.innerHTML = matches.map(f =>
    `<div onclick="document.getElementById('folio').value='${f}';document.getElementById('folio-suggestions').style.display='none'" style="padding:.5rem .75rem;cursor:pointer;font-size:.85rem;color:#8b9cf4;border-bottom:1px solid #1a1a2a" onmouseenter="this.style.background='#1a1a2e'" onmouseleave="this.style.background=''">${f}</div>`
  ).join('');
  box.style.display = 'block';
}

document.addEventListener('click', e => {
  const box = document.getElementById('folio-suggestions');
  if (box && !e.target.closest('#folio') && !e.target.closest('#folio-suggestions'))
    box.style.display = 'none';
});

// ── Push notifications ───────────────────────────────────────────────────────
function _requestPushPermission() {
  if (!('Notification' in window) || Notification.permission === 'granted') return;
  if (Notification.permission !== 'denied') {
    Notification.requestPermission();
  }
}

function _sendLocalNotification(title, body) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  try { new Notification(title, {body, icon: '/static/logo_clean.png'}); } catch(e) {}
}

// Request permission after first search
let _pushRequested = false;
function _maybeRequestPush() {
  if (_pushRequested) return;
  _pushRequested = true;
  setTimeout(_requestPushPermission, 3000);
}

function showToastSuccess(msg) {
  let t = document.getElementById('toast-ok');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast-ok';
    t.style.cssText = 'position:fixed;bottom:1.2rem;left:50%;transform:translateX(-50%);' +
      'background:#052e16;color:#4ade80;border:1px solid #16a34a;border-radius:8px;' +
      'padding:.65rem 1.2rem;font-size:.875rem;z-index:9999;max-width:90vw;text-align:center;';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.display = 'block';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.style.display = 'none', 4000);
}

function showToastWarning(msg) {
  let t = document.getElementById('toast-warn');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast-warn';
    t.style.cssText = 'position:fixed;bottom:1.2rem;left:50%;transform:translateX(-50%);' +
      'background:#7c2d12;color:#fcd34d;border:1px solid #f59e0b;border-radius:8px;' +
      'padding:.65rem 1.2rem;font-size:.875rem;z-index:9999;max-width:90vw;text-align:center;';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.display = 'block';
  clearTimeout(_warnTimer);
  _warnTimer = setTimeout(() => t.style.display = 'none', 6000);
}

// ── Search history (localStorage) ────────────────────────────────────────────
const HIST_FOLIO_KEY  = 'rpp_hist_folio';
const HIST_NOMBRE_KEY = 'rpp_hist_nombre';

function getHistory(key) {
  try { return JSON.parse(localStorage.getItem(key) || '[]'); } catch { return []; }
}
function saveHistory(key, entry) {
  let arr = getHistory(key).filter(x => x !== entry);
  arr.unshift(entry);
  arr = arr.slice(0, 6);
  localStorage.setItem(key, JSON.stringify(arr));
}
function renderHistoryChips(containerId, histKey, onClickFn) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const items = getHistory(histKey);
  if (!items.length) { el.innerHTML = ''; return; }
  el.innerHTML = '<span class="history-label">Recientes:</span>' +
    items.map(v => `<span class="history-chip" onclick="${onClickFn}('${v.replace(/'/g,"\\'")}')">` +
      v + '</span>').join('');
}
function applyFolioHist(v) {
  document.getElementById('folio').value = v;
  buscarFolio();
}
function applyNombreHist(v) {
  const [a,b,c] = v.split('|');
  document.getElementById('nombre').value  = a || '';
  document.getElementById('paterno').value = b || '';
  document.getElementById('materno').value = c || '';
  buscarNombre();
}

// Override buscarFolio to save history
const _origBuscarFolio = buscarFolio;
buscarFolio = function() {
  const v = document.getElementById('folio').value.trim();
  if (v) { saveHistory(HIST_FOLIO_KEY, v); renderHistoryChips('folio-history', HIST_FOLIO_KEY, 'applyFolioHist'); }
  _origBuscarFolio();
};
const _origBuscarNombre = buscarNombre;
buscarNombre = function() {
  const n = document.getElementById('nombre').value.trim().toUpperCase();
  const p = document.getElementById('paterno').value.trim().toUpperCase();
  const m = document.getElementById('materno').value.trim().toUpperCase();
  if (n || p) { const v = [n,p,m].join('|'); saveHistory(HIST_NOMBRE_KEY, v); renderHistoryChips('nombre-history', HIST_NOMBRE_KEY, 'applyNombreHist'); }
  _origBuscarNombre();
};

// ── Account panel ─────────────────────────────────────────────────────────────
function openAcct() {
  document.getElementById('acct-panel').classList.add('open');
  loadAcctContent();
}
function closeAcct() {
  document.getElementById('acct-panel').classList.remove('open');
}
document.getElementById('acct-panel').addEventListener('click', e => {
  if (e.target === document.getElementById('acct-panel')) closeAcct();
});

async function loadAcctContent() {
  const el = document.getElementById('acct-content');
  try {
    const r = await fetch('/account-data');
    if (!r.ok) { el.innerHTML = '<p style="color:#f87171">Error al cargar</p>'; return; }
    const d = await r.json();
    const planLabel = d.is_team_member ? ('Equipo · ' + (d.team_owner_plan || '')) : ({basico:'Básico',pro:'Pro',empresarial:'Empresarial',corporativo:'Corporativo',corporativo_pro:'Corp. Pro'}[d.plan] || d.plan || '—');
    const _renewDays = (d.billing_interval === 'year') ? 365 : 30;
    const periodEnd = d.period_start ? new Date(new Date(d.period_start).getTime() + _renewDays*864e5).toLocaleDateString('es-MX') : '—';
    // Build usage chart
    let chartHtml = '';
    if (d.daily_usage && d.daily_usage.length) {
      const maxCount = Math.max(...d.daily_usage.map(x => x.count), 1);
      const bars = d.daily_usage.map(x => {
        const pct = Math.round((x.count / maxCount) * 100);
        const day = x.date.slice(8);
        return '<div style="display:flex;flex-direction:column;align-items:center;flex:1;min-width:12px">' +
          '<div style="width:100%;max-width:18px;background:linear-gradient(180deg,#8b9cf4,#c084fc);border-radius:3px 3px 0 0;height:' + Math.max(pct, 8) + '%;min-height:3px;transition:height .3s"></div>' +
          '<span style="font-size:.55rem;color:#555;margin-top:2px">' + day + '</span></div>';
      }).join('');
      chartHtml = '<p class="acct-hist-title">Uso mensual</p>' +
        '<div style="display:flex;align-items:flex-end;gap:2px;height:80px;padding:.5rem 0;border-bottom:1px solid #1e1e2e;margin-bottom:.75rem">' + bars + '</div>';
    }
    const usedPct = d.downloads_limit > 0 ? Math.round((d.downloads_used / d.downloads_limit) * 100) : 0;
    const barColor = usedPct > 85 ? '#f87171' : (usedPct > 60 ? '#f59e0b' : '#4ade80');
    el.innerHTML =
      '<div class="acct-stat"><span class="label">Plan</span><span class="val">' + planLabel + '</span></div>' +
      (d.is_team_member ? '<div class="acct-stat"><span class="label">Equipo de</span><span class="val" style="color:#c084fc">' + (d.team_owner_name||'—') + '</span></div>' : '') +
      '<div class="acct-stat"><span class="label">Estado</span><span class="val" style="color:' + (d.sub_status==='active' || d.is_team_member ?'#4ade80':'#f87171') + '">' + (d.is_team_member ? 'Miembro de equipo' : (d.sub_status||'—')) + '</span></div>' +
      '<div style="margin:.6rem 0">' +
        '<div style="display:flex;justify-content:space-between;font-size:.75rem;margin-bottom:.3rem">' +
          '<span style="color:#888">Descargas</span><span style="color:#dde0e8;font-weight:600">' + d.downloads_used + ' / ' + d.downloads_limit + '</span></div>' +
        '<div style="width:100%;height:6px;background:#1a1a2a;border-radius:3px;overflow:hidden">' +
          '<div style="width:' + usedPct + '%;height:100%;background:' + barColor + ';border-radius:3px;transition:width .4s"></div></div>' +
        '<div style="text-align:right;font-size:.7rem;color:#555;margin-top:.2rem">' + d.downloads_left + ' restantes</div>' +
      '</div>' +
      '<div class="acct-stat"><span class="label">Renovación</span><span class="val">' + periodEnd + '</span></div>' +
      '<div class="acct-stat"><span class="label">Email</span><span class="val" style="font-size:.75rem">' + d.email + '</span></div>' +
      chartHtml +
      '<p class="acct-hist-title">Historial de descargas</p>' +
      (d.downloads.length ? d.downloads.map(h =>
        '<div class="hist-row"><span class="folio">Folio ' + h.folio + '</span><span class="date">' + h.ts.slice(0,16).replace('T',' ') + '</span></div>'
      ).join('') : '<p style="color:#444;font-size:.875rem">Sin descargas registradas aún.</p>') +
      (d.pack_credits > 0 ?
        '<div class="acct-stat" style="margin-top:.5rem"><span class="label">Créditos de paquete</span><span class="val" style="color:#4ade80;font-weight:700">' + d.pack_credits + ' disponibles</span></div>' : '') +
      (d.packs && d.packs.length ?
        '<p class="acct-hist-title">Paquetes</p>' +
        d.packs.map(p =>
          '<div class="hist-row"><span class="folio">' + (p.type === 'pack5' ? '5 descargas' : '10 descargas') + '</span><span class="date">' + (p.total - p.used) + ' restantes · ' + p.ts.slice(0,10) + '</span></div>'
        ).join('') : '') +
      (d.single_purchases && d.single_purchases.length ?
        '<p class="acct-hist-title">Compras individuales ($130 MXN)</p>' +
        d.single_purchases.map(p =>
          '<div class="hist-row"><span class="folio">Folio ' + p.folio + '</span><span class="date">' + p.ts.slice(0,16).replace('T',' ') + '</span></div>'
        ).join('') : '') +
      (d.referral_code ?
        '<p class="acct-hist-title" style="margin-top:.8rem">Invita y gana descargas</p>' +
        '<div style="background:#1a1a2a;padding:.6rem .8rem;border-radius:8px;font-size:.875rem;display:flex;align-items:center;gap:.5rem">' +
          '<span style="color:#888">Tu link:</span>' +
          '<code style="color:#c084fc;flex:1;word-break:break-all">consulta-rpp.javisnes.com/r/' + d.referral_code + '</code>' +
          '<button onclick="navigator.clipboard.writeText(\'https://consulta-rpp.javisnes.com/r/' + d.referral_code + '\');this.textContent=\'✓\';setTimeout(()=>this.textContent=\'Copiar\',2000)" ' +
            'style="background:#6366f1;color:#fff;border:none;border-radius:5px;padding:.3rem .6rem;font-size:.75rem;cursor:pointer">Copiar</button>' +
        '</div>' +
        '<p style="color:#555;font-size:.75rem;margin-top:.3rem">Ambos reciben 1 descarga gratis al registrarse con tu link.</p>'
        : '') +
      '<div style="margin-top:1rem;display:flex;gap:.5rem;flex-wrap:wrap">' +
      (d.is_team_member ? '' : '<button onclick="window.location=\'/pricing\'" style="flex:1;padding:.5rem;background:#1d1d35;color:#8b9cf4;border:1px solid #3a3a5a;border-radius:7px;cursor:pointer;font-size:.875rem">Ver planes</button>') +
      (d.is_team_member ? '' : '<button onclick="window.location=\'/portal\'" style="flex:1;padding:.5rem;background:#1d1d35;color:#c084fc;border:1px solid #3a3a5a;border-radius:7px;cursor:pointer;font-size:.875rem">Gestionar suscripción</button>') +
      '</div>' +
      (d.is_team_member ? '' :
      '<div style="margin-top:.5rem">' +
      '<a href="https://wa.me/526142030953?text=Hola%2C+necesito+factura+CFDI+por+mi+suscripci%C3%B3n+a+Consulta+RPP.+Mi+correo+es:+' + encodeURIComponent(d.email) + '" target="_blank" style="display:block;width:100%;padding:.5rem;background:#0f0f18;color:#4ade80;border:1px solid #1e1e2e;border-radius:7px;text-align:center;text-decoration:none;font-size:.8rem;box-sizing:border-box">🧾 Solicitar factura por WhatsApp</a>' +
      '</div>');
  } catch(e) { el.innerHTML = '<p style="color:#f87171">Error de red</p>'; }
}

// Init history chips on load
document.addEventListener('DOMContentLoaded', () => {
  renderHistoryChips('folio-history',  HIST_FOLIO_KEY,  'applyFolioHist');
  renderHistoryChips('nombre-history', HIST_NOMBRE_KEY, 'applyNombreHist');
  // Apply saved theme
  if (localStorage.getItem('rpp_theme') === 'light') {
    document.body.classList.add('light');
  }
  // Register service worker for PWA
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
  // Onboarding: 3-step modal on first visit
  if (!localStorage.getItem('rpp_onboarded')) {
    setTimeout(showOnboarding, 1200);
  }

  // PWA install prompt
  let _pwaPrompt = null;
  window.addEventListener('beforeinstallprompt', e => {
    e.preventDefault();
    _pwaPrompt = e;
    setTimeout(() => {
      if (!localStorage.getItem('rpp_pwa_dismissed') && _pwaPrompt) showPwaBanner();
    }, 30000);
  });

  // Status dot in footer
  fetch('/api/status').then(r=>r.json()).then(d=>{
    const el = document.getElementById('status-footer-link');
    if(el) el.innerHTML = (d.ok ? '<span style="color:#4ade80">●</span>' : '<span style="color:#f87171">●</span>') + ' Estado del servicio';
  }).catch(()=>{});
});

function showOnboarding() {
  if (localStorage.getItem('rpp_onboarded')) return;
  const steps = [
    { icon:'🏠', title:'¿Qué es el Folio Real?',
      body:'El folio real es el número único que identifica cada propiedad en el Registro Público de Chihuahua. Lo encuentras en tu escritura, boleta predial o contrato de compraventa.' },
    { icon:'🔍', title:'¿Cómo buscar?',
      body:'Escribe el número de folio en el campo de búsqueda, o cambia a la pestaña <strong>Propietario</strong> para buscar por nombre. Los resultados aparecen en segundos.' },
    { icon:'⬇', title:'¿Cómo descargar?',
      body:'Usa el botón <strong>👁</strong> para previsualizar el PDF antes de consumir una descarga. Cuando estés listo, haz clic en <strong>⬇</strong> para guardar la escritura.' },
  ];
  let step = 0;
  const ov = document.createElement('div');
  ov.id = 'ob-overlay';
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9000;display:flex;align-items:center;justify-content:center;padding:1rem;animation:obFadeIn .3s';
  function render() {
    const s = steps[step];
    const isLast = step === steps.length - 1;
    ov.innerHTML = `
      <div style="background:#0f0f18;border:1px solid #2a2a3a;border-radius:16px;padding:2rem;max-width:400px;width:100%;position:relative;box-shadow:0 20px 60px rgba(0,0,0,.6)">
        <button onclick="closeOb()" style="position:absolute;top:.75rem;right:.75rem;background:none;border:none;color:#555;font-size:1.2rem;cursor:pointer;line-height:1">×</button>
        <div style="display:flex;gap:.4rem;justify-content:center;margin-bottom:1.5rem">
          ${steps.map((_,i)=>`<div style="width:8px;height:8px;border-radius:50%;background:${i===step?'#8b9cf4':'#2a2a3a'};transition:background .3s"></div>`).join('')}
        </div>
        <div style="font-size:2.5rem;text-align:center;margin-bottom:.75rem">${s.icon}</div>
        <h3 style="font-size:1.1rem;font-weight:700;text-align:center;color:#e2e4ed;margin-bottom:.75rem">${s.title}</h3>
        <p style="font-size:.875rem;color:#888;text-align:center;line-height:1.6">${s.body}</p>
        <div style="display:flex;gap:.6rem;margin-top:1.5rem">
          ${step > 0 ? `<button onclick="obPrev()" style="flex:1;padding:.6rem;background:#1a1a2a;border:1px solid #2a2a3a;color:#888;border-radius:8px;cursor:pointer;font-size:.85rem">← Anterior</button>` : ''}
          <button onclick="${isLast?'closeOb()':'obNext()'}" style="flex:2;padding:.6rem;background:linear-gradient(135deg,#8b9cf4,#c084fc);border:none;color:#fff;border-radius:8px;cursor:pointer;font-weight:700;font-size:.9rem">
            ${isLast ? 'Empezar ✓' : 'Siguiente →'}
          </button>
        </div>
        <p style="text-align:center;margin-top:.75rem;font-size:.72rem;color:#333">${step+1} de ${steps.length}</p>
      </div>`;
  }
  window.obNext  = () => { step = Math.min(step+1, steps.length-1); render(); };
  window.obPrev  = () => { step = Math.max(step-1, 0); render(); };
  window.closeOb = () => { ov.remove(); localStorage.setItem('rpp_onboarded','1'); };
  render();
  document.body.appendChild(ov);
  const style = document.createElement('style');
  style.textContent = '@keyframes obFadeIn{from{opacity:0}to{opacity:1}}';
  document.head.appendChild(style);
}

function showPwaBanner() {
  if (document.getElementById('pwa-banner')) return;
  const b = document.createElement('div');
  b.id = 'pwa-banner';
  b.style.cssText = 'position:fixed;bottom:1rem;left:50%;transform:translateX(-50%);background:#0f0f18;border:1px solid #2a2a3a;border-radius:12px;padding:.8rem 1.2rem;display:flex;align-items:center;gap:.75rem;z-index:8000;box-shadow:0 8px 30px rgba(0,0,0,.5);max-width:360px;width:90%';
  b.innerHTML = '<span style="font-size:1.3rem">📲</span><div style="flex:1"><div style="font-weight:700;font-size:.85rem;color:#e2e4ed">Instalar app</div><div style="font-size:.72rem;color:#555">Acceso rápido desde tu pantalla</div></div><button onclick="installPwa()" style="background:linear-gradient(135deg,#8b9cf4,#c084fc);border:none;color:#fff;padding:.45rem .85rem;border-radius:8px;cursor:pointer;font-size:.8rem;font-weight:700">Instalar</button><button onclick="dismissPwa()" style="background:none;border:none;color:#444;cursor:pointer;font-size:1rem;padding:.2rem">×</button>';
  document.body.appendChild(b);
}
async function installPwa() {
  if (!_pwaPrompt) return;
  _pwaPrompt.prompt();
  const {outcome} = await _pwaPrompt.userChoice;
  _pwaPrompt = null;
  document.getElementById('pwa-banner')?.remove();
  if (outcome === 'accepted') localStorage.setItem('rpp_pwa_dismissed','1');
}
function dismissPwa() {
  document.getElementById('pwa-banner')?.remove();
  localStorage.setItem('rpp_pwa_dismissed','1');
}

// ── PDF Preview ────────────────────────────────────────────────────────────────
function openPreview(job_id, folio) {
  if (!_canPreview()) { window.location = '/pricing'; return; }
  const overlay = document.getElementById('preview-overlay');
  const iframe  = document.getElementById('preview-iframe');
  const dlBtn   = document.getElementById('preview-dl-btn');
  const isFree  = _userInfo && _userInfo.sub_status !== 'active' && _userInfo.role !== 'admin' && !(_userInfo && _userInfo.in_trial) && !(_userInfo && _userInfo.is_team_member);
  document.getElementById('preview-title').textContent = 'Vista previa — Folio ' + folio;
  iframe.src = '/preview/' + job_id;
  if (isFree) {
    // Free user: replace <a> with a button that triggers payment
    const payBtn = document.createElement('button');
    payBtn.className = 'btn-primary';
    payBtn.innerHTML = '&#128176; Descargar — $130 MXN';
    payBtn.onclick = function() { closePreview(); pagarYDescargar(job_id, folio); };
    dlBtn.replaceWith(payBtn);
    payBtn.id = 'preview-dl-btn';
  } else {
    // Subscriber: normal download link
    dlBtn.href = '/download/' + job_id;
    dlBtn.download = 'folio_' + folio + '_sin_marca.pdf';
    // Restore <a> if it was replaced before
    if (dlBtn.tagName === 'BUTTON') {
      const aBtn = document.createElement('a');
      aBtn.className = 'btn-primary';
      aBtn.id = 'preview-dl-btn';
      aBtn.href = '/download/' + job_id;
      aBtn.download = 'folio_' + folio + '_sin_marca.pdf';
      aBtn.onclick = function() { closePreview(); };
      aBtn.innerHTML = '⬇ Descargar (consume crédito)';
      dlBtn.replaceWith(aBtn);
    }
  }
  overlay.classList.add('open');
}
function closePreview() {
  document.getElementById('preview-overlay').classList.remove('open');
  document.getElementById('preview-iframe').src = '';
}

function handleCSVUpload(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(e) {
    const text = e.target.result;
    const folios = text.split(/[\n\r,;]+/)
      .map(f => f.replace(/[^0-9]/g, '').trim())
      .filter(f => f.length > 0);
    const unique = [...new Set(folios)].slice(0, 10);
    document.getElementById('lote-input').value = unique.join('\\n');
    showToastSuccess('CSV cargado: ' + unique.length + ' folio(s) detectados');
  };
  reader.readAsText(file);
  input.value = '';
}

// ── Batch / lote search ────────────────────────────────────────────────────────
async function buscarLote() {
  const raw = document.getElementById('lote-input').value;
  const folios = [...new Set(
    raw.split(/[\n,;]+/).map(f => f.trim()).filter(f => /^\d+$/.test(f))
  )].slice(0, 10);
  const statusEl  = document.getElementById('lote-status');
  const resultsEl = document.getElementById('lote-results');
  if (!folios.length) {
    statusEl.className = 'error'; statusEl.style.display = 'block';
    statusEl.innerHTML = '&#10060; Ingresa al menos un folio numérico.';
    return;
  }
  const btn = document.getElementById('btn-lote');
  btn.disabled = true;
  statusEl.className = 'loading'; statusEl.style.display = 'block';
  statusEl.innerHTML = '<span class="spinner"></span>Enviando ' + folios.length + ' folio(s)...<div class="bar"><div class="fill"></div></div>';
  resultsEl.innerHTML = '';

  try {
    const res = await fetch('/buscar-lote', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({folios})
    });
    if (!res.ok) {
      if (await handleApiError(res)) { btn.disabled = false; return; }
      const err = await res.json().catch(() => ({}));
      statusEl.className = 'error';
      statusEl.innerHTML = '&#10060; ' + (err.error || 'Error');
      btn.disabled = false; return;
    }
    const {jobs} = await res.json();
    statusEl.style.display = 'none';
    btn.disabled = false;
    renderLoteTable(jobs);
    jobs.forEach(j => pollLoteJob(j.job_id, j.folio));
  } catch(e) {
    statusEl.className = 'error';
    statusEl.innerHTML = '&#10060; Error de red: ' + e.message;
    btn.disabled = false;
  }
}

function renderLoteTable(jobs) {
  const el = document.getElementById('lote-results');
  let html = '<table class="lote-table"><thead><tr><th>Folio</th><th>Estado</th><th>Acciones</th></tr></thead><tbody>';
  for (const j of jobs) {
    html += '<tr id="lote-row-' + j.job_id + '">'
      + '<td><span class="folio-badge">' + j.folio + '</span></td>'
      + '<td><span class="lote-st run" id="lote-st-' + j.job_id + '">⏳ Procesando...</span></td>'
      + '<td id="lote-act-' + j.job_id + '">—</td>'
      + '</tr>';
  }
  html += '</tbody></table>';
  el.innerHTML = html;
}

function pollLoteJob(job_id, folio) {
  const poll = setInterval(async () => {
    try {
      const sr = await fetch('/status/' + job_id);
      const s  = await sr.json();
      if (s.status === 'done') {
        clearInterval(poll);
        const st  = document.getElementById('lote-st-' + job_id);
        const act = document.getElementById('lote-act-' + job_id);
        if (st)  { st.className = 'lote-st ok'; st.textContent = '✓ Listo'; _sendLocalNotification('Folio ' + folio, 'PDF listo para descargar'); }
        if (act) act.innerHTML =
          '<button class="btn-preview" style="padding:.25rem .6rem;font-size:.75rem" onclick="openPreview(\'' + job_id + '\',\'' + folio + '\')">👁 Preview</button>'
          + ' <a class="dl-row-btn" style="text-decoration:none;display:inline-block;padding:.3rem .7rem;font-size:.75rem" href="/download/' + job_id + '" download="folio_' + folio + '_sin_marca.pdf" onclick="loadUserBar();showToastSuccess(\'✓ Descargando escritura...\')">⬇ Descargar</a>';
      } else if (s.status === 'error') {
        clearInterval(poll);
        const st = document.getElementById('lote-st-' + job_id);
        if (st) { st.className = 'lote-st err'; st.textContent = '✗ ' + s.error; }
      }
    } catch(e) {
      clearInterval(poll);
      const st = document.getElementById('lote-st-' + job_id);
      if (st) { st.className = 'lote-st err'; st.textContent = '✗ Error de red'; }
    }
  }, 3000);
}

// ── Agua JMAS ────────────────────────────────────────────────────────────────
async function buscarAgua() {
  const calle  = (document.getElementById('agua-calle').value || '').trim().toUpperCase();
  const num    = (document.getElementById('agua-num').value || '').trim();
  const ref    = (document.getElementById('agua-ref').value || '').trim();
  const statusEl = document.getElementById('agua-status');
  const resultEl = document.getElementById('agua-result');

  if (!ref && (!calle || !num)) {
    statusEl.className = 'error'; statusEl.style.display = 'block';
    statusEl.innerHTML = '&#10060; Ingresa la calle y número, o el número de cliente.';
    return;
  }

  const btn = document.getElementById('btn-agua');
  btn.disabled = true;
  statusEl.className = 'loading'; statusEl.style.display = 'block';
  statusEl.innerHTML = '<span class="spinner"></span>Consultando JMAS...';
  resultEl.innerHTML = '';

  try {
    const res = await fetch('/agua/consultar', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({calle, numero: num, referencia: ref})
    });
    const d = await res.json();
    if (!res.ok) {
      statusEl.className = 'error';
      statusEl.innerHTML = '&#10060; ' + (d.error || 'Error al consultar');
      btn.disabled = false; return;
    }
    statusEl.style.display = 'none';
    btn.disabled = false;
    resultEl.innerHTML = `
      <div style="background:#0f172a;border:1px solid #0ea5e9;border-radius:12px;padding:1.2rem;margin-top:.75rem">
        <div style="display:flex;align-items:center;gap:.6rem;margin-bottom:1rem">
          <span style="font-size:1.4rem">💧</span>
          <h3 style="margin:0;color:#38bdf8;font-size:1rem">JMAS Chihuahua – Adeudo de Agua</h3>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:.88rem">
          <tr><td style="color:#94a3b8;padding:.3rem .5rem;width:40%">Contrato</td><td style="color:#f1f5f9;padding:.3rem .5rem;font-weight:600">${d.contrato || '—'}</td></tr>
          <tr><td style="color:#94a3b8;padding:.3rem .5rem">Usuario</td><td style="color:#f1f5f9;padding:.3rem .5rem">${d.usuario || '—'}</td></tr>
          <tr><td style="color:#94a3b8;padding:.3rem .5rem">Dirección</td><td style="color:#f1f5f9;padding:.3rem .5rem">${d.direccion || '—'}</td></tr>
          <tr style="border-top:1px solid #1e3a5f"><td style="color:#94a3b8;padding:.5rem .5rem">Adeudo Total</td>
            <td style="padding:.5rem .5rem;font-size:1.2rem;font-weight:700;color:${parseFloat(d.monto||0)>0?'#f87171':'#4ade80'}">
              $${parseFloat(d.monto||0).toLocaleString('es-MX', {minimumFractionDigits:2})} MXN
            </td>
          </tr>
        </table>
      </div>`;
  } catch(e) {
    statusEl.className = 'error';
    statusEl.innerHTML = '&#10060; Error de red: ' + e.message;
    btn.disabled = false;
  }
}

// ── Pay per download (single) ────────────────────────────────────────────────
async function pagarYDescargar(jobId, folio) {
  try {
    const res = await fetch('/create-checkout/single', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({return_folio: folio, job_id: jobId})
    });
    const d = await res.json();
    if (d.url) window.location = d.url;
    else alert('Error: ' + (d.error || 'No se pudo crear la sesión de pago'));
  } catch(e) { alert('Error de red'); }
}

async function toggleAlert(folio, btnEl) {
  try {
    const res = await fetch('/alert/subscribe', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({folio})
    });
    const d = await res.json();
    if (d.ok) {
      btnEl.innerHTML = '&#128276; Alerta activa';
      btnEl.style.background = '#4ade80';
      btnEl.style.color = '#000';
      btnEl.disabled = true;
    } else {
      alert(d.error || 'Error');
    }
  } catch(e) { alert('Error de red'); }
}

// ── Theme toggle ───────────────────────────────────────────────────────────────
// ── User bar dropdown ─────────────────────────────────────────────────────────
function toggleBarMenu(trigger) {
  const dd = document.getElementById('bar-dropdown');
  const isOpen = dd.classList.contains('open');
  if (isOpen) { closeBarMenu(); } else { dd.classList.add('open'); trigger.classList.add('open'); }
}
function closeBarMenu() {
  const dd = document.getElementById('bar-dropdown');
  dd.classList.remove('open');
  const t = document.querySelector('.bar-trigger');
  if (t) t.classList.remove('open');
}
document.addEventListener('click', e => {
  if (!e.target.closest('#user-bar')) closeBarMenu();
});

function toggleTheme() {
  const isLight = document.body.classList.toggle('light');
  localStorage.setItem('rpp_theme', isLight ? 'light' : 'dark');
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = isLight ? '🌙 Oscuro' : '☀ Claro';
}

// ── Escape key: close any open modal/panel ────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  const preview = document.getElementById('preview-overlay');
  if (preview && preview.classList.contains('open')) { closePreview(); return; }
  const acct = document.getElementById('acct-panel');
  if (acct && acct.style.display !== 'none' && acct.style.display !== '') { closeAcct(); return; }
  const quota = document.getElementById('quota-modal');
  if (quota && quota.style.display !== 'none' && quota.style.display !== '') { closeQuotaModal(); return; }
  const ob = document.getElementById('ob-overlay');
  if (ob) { ob.remove(); localStorage.setItem('rpp_onboarded','1'); return; }
});

// ── Referral widget (shown in footer when user has ref code) ─────────────────
async function maybeShowReferralWidget() {
  if (!_userInfo || !_userInfo.referral_code) return;
  const existing = document.getElementById('referral-widget');
  if (existing) return;
  const code = _userInfo.referral_code;
  const link = 'https://consulta-rpp.javisnes.com/r/' + code;
  const w = document.createElement('div');
  w.id = 'referral-widget';
  w.style.cssText = 'margin:1rem auto 0;max-width:480px;background:linear-gradient(135deg,#1a1a2e,#0f0f18);border:1px solid #2a2a4a;border-radius:12px;padding:.85rem 1rem;display:flex;align-items:center;gap:.75rem';
  w.innerHTML = '<span style="font-size:1.3rem">🎁</span>'
    + '<div style="flex:1;min-width:0"><div style="font-size:.78rem;font-weight:700;color:#c084fc;margin-bottom:.15rem">Invita y gana descargas gratis</div>'
    + '<code style="font-size:.72rem;color:#8b9cf4;word-break:break-all">' + link + '</code></div>'
    + '<button id="ref-copy-btn" onclick="copyRefLink(\'' + link + '\')" style="flex-shrink:0;background:#6366f1;color:#fff;border:none;border-radius:7px;padding:.4rem .75rem;font-size:.75rem;font-weight:700;cursor:pointer">Copiar</button>';
  const footer = document.querySelector('.footer');
  if (footer) footer.parentNode.insertBefore(w, footer);
  else document.querySelector('.container')?.appendChild(w);
}
function copyRefLink(link) {
  navigator.clipboard.writeText(link).then(() => {
    const btn = document.getElementById('ref-copy-btn');
    if (btn) { btn.textContent = '✓ Copiado'; setTimeout(() => btn.textContent = 'Copiar', 2000); }
  }).catch(() => {});
}
"""

# ── Playwright helpers ─────────────────────────────────────────────────────────

BROWSER_ARGS = [
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
    '--no-zygote', '--disable-extensions', '--disable-background-networking',
    '--disable-background-timer-throttling', '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding', '--disable-sync', '--no-first-run',
    '--mute-audio', '--disable-images', '--blink-settings=imagesEnabled=false',
    '--disable-translate', '--disable-default-apps', '--disable-hang-monitor',
    '--disable-popup-blocking', '--disable-prompt-on-repost',
    '--metrics-recording-only', '--no-default-browser-check',
    '--disable-component-update',
]

_USER_AGENT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
               ' (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')

# ── Browser stats ────────────────────────────────────────────────────────────
_rpp_pool_stats = {'launches': 0, 'logins': 0, 'cache_hits': 0, 'errors': 0, 'retries': 0}
_rpp_login_time = 0


def _rpp_health_check():
    """Quick check if RPP website is reachable. Returns True/False."""
    import urllib.request as _ur
    import urllib.error as _ue
    try:
        req = _ur.Request(RPP_URL, method='GET')
        req.add_header('User-Agent', _USER_AGENT)
        with _ur.urlopen(req, timeout=10) as r:
            return r.status < 500
    except _ue.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


# ── Retry decorator ──────────────────────────────────────────────────────────

def _retry_rpp(func, max_retries=2, backoff_base=3):
    """Retry wrapper for RPP operations. Retries on transient failures."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        last_err = None
        for attempt in range(1, max_retries + 2):  # 1 try + max_retries
            try:
                return func(*args, **kwargs)
            except ValueError as e:
                err_msg = str(e)
                # Don't retry "not found" type errors — they're legitimate
                if any(k in err_msg for k in ('no encontr', 'no apareció', 'no se pudo')):
                    if attempt > 1:
                        raise
                    last_err = e
                    _rpp_pool_stats['retries'] += 1
                    print(f'[RETRY] Attempt {attempt} failed: {err_msg} — retrying...', flush=True)
                    time.sleep(backoff_base)
                    continue
                last_err = e
                _rpp_pool_stats['retries'] += 1
                print(f'[RETRY] Attempt {attempt} failed: {err_msg} — retrying...', flush=True)
                time.sleep(backoff_base * attempt)
            except Exception as e:
                last_err = e
                _rpp_pool_stats['retries'] += 1
                print(f'[RETRY] Attempt {attempt} error: {e} — retrying...', flush=True)
                time.sleep(backoff_base * attempt)
        raise last_err or ValueError("RPP: falló después de múltiples intentos")
    return wrapper


def _ext_dom_click(page, btn_text: str):
    page.evaluate(f"""
        (() => {{
            const b = Ext.ComponentQuery.query("button[text={btn_text}]")[0];
            if (b && b.el) {{
                const d = b.el.dom;
                d.dispatchEvent(new MouseEvent("mousedown", {{bubbles:true,view:window}}));
                d.dispatchEvent(new MouseEvent("mouseup",   {{bubbles:true,view:window}}));
                d.dispatchEvent(new MouseEvent("click",     {{bubbles:true,view:window}}));
            }}
        }})()
    """)


def _navigate_to_consulta(page):
    """From the RPP main menu, click into Consulta de Tramites."""
    try:
        page.wait_for_function(
            '() => Array.from(document.querySelectorAll("*")).some('
            '  e => e.textContent.toLowerCase().includes("consulta") &&'
            '       e.textContent.toLowerCase().includes("tramites") &&'
            '       e.offsetParent !== null)',
            timeout=30000
        )
    except Exception:
        raise ValueError("STEP3: menú principal no apareció")
    page.evaluate("""
        const el = Array.from(document.querySelectorAll("*"))
            .filter(e => e.textContent.toLowerCase().includes("consulta") &&
                         e.textContent.toLowerCase().includes("tramites"))
            .sort((a, b) => a.textContent.length - b.textContent.length)[0];
        if (el) el.click();
    """)


def _login_and_open_consulta(page):
    """Login RPP and click the Consulta Avanzada tile."""
    page.goto(RPP_URL, wait_until="domcontentloaded", timeout=60000)
    page.wait_for_function(
        '() => typeof Ext !== "undefined" && Ext.ComponentQuery &&'
        ' Ext.ComponentQuery.query("textfield[name=userName]").length > 0',
        timeout=40000
    )
    user_id = page.evaluate('Ext.ComponentQuery.query("textfield[name=userName]")[0].getInputId()')
    pwd_id  = page.evaluate('Ext.ComponentQuery.query("textfield[name=password]")[0].getInputId()')
    page.fill(f'#{user_id}', RPP_USER)
    page.fill(f'#{pwd_id}',  RPP_PASS)
    page.wait_for_timeout(300)
    page.evaluate("""
        const lb = Ext.ComponentQuery.query("button[text=Aceptar]").find(b => !b.up("messagebox"));
        if (lb && lb.el) {
            const d = lb.el.dom;
            d.dispatchEvent(new MouseEvent("mousedown", {bubbles:true,view:window}));
            d.dispatchEvent(new MouseEvent("mouseup",   {bubbles:true,view:window}));
            d.dispatchEvent(new MouseEvent("click",     {bubbles:true,view:window}));
        }
    """)
    page.wait_for_timeout(800)
    if page.evaluate('!!document.querySelector("input[type=password]")'):
        page.press(f'#{pwd_id}', 'Enter')
    try:
        page.wait_for_function('() => !document.querySelector("input[type=password]")', timeout=30000)
    except Exception:
        raise ValueError("STEP2: login no completó (password field sigue visible)")
    _navigate_to_consulta(page)


# ── Folio search ───────────────────────────────────────────────────────────────

def _fetch_pdf_for_folio_inner(folio_real: str) -> bytes:
    """Core folio fetch with health check and metrics."""
    global _rpp_login_time
    _t0 = time.time()
    if not _rpp_health_check():
        _rpp_metric('folio_fetch', folio_real, 0, False, 'RPP no responde')
        raise ValueError("El servicio RPP Chihuahua no responde. Intenta de nuevo en unos minutos.")

    _rpp_pool_stats['launches'] += 1
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=BROWSER_ARGS)
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=_USER_AGENT,
        )
        page = context.new_page()
        _login_and_open_consulta(page)
        _rpp_pool_stats['logins'] += 1
        _rpp_login_time = time.time()
        try:
            page.wait_for_function(
                '() => Ext.ComponentQuery.query("numberfield[name=FOLIOREAL]").length > 0',
                timeout=30000
            )
        except Exception:
            browser.close()
            raise ValueError("STEP4: formulario de folio no apareció")

        input_id = page.evaluate('Ext.ComponentQuery.query("numberfield[name=FOLIOREAL]")[0].getInputId()')
        page.fill(f'#{input_id}', str(folio_real))
        page.wait_for_timeout(200)
        _ext_dom_click(page, 'Buscar')
        try:
            page.wait_for_function(
                '() => Array.from(document.querySelectorAll("*")).some(e => e.textContent.trim() === "Ver Agregado")',
                timeout=30000
            )
        except Exception:
            browser.close()
            raise ValueError("STEP5: 'Ver Agregado' no apareció — folio no encontrado o búsqueda falló")

        try:
            page.get_by_text("Ver Agregado", exact=True).first.click(timeout=5000)
            ver_found = 'playwright-click'
        except Exception:
            ver_found = page.evaluate("""
                (() => {
                    const all = Array.from(document.querySelectorAll('*'))
                        .filter(e => e.textContent.trim() === 'Ver Agregado' && e.children.length === 0);
                    if (all.length > 0) { all[0].click(); return 'leaf-click'; }
                    const wide = Array.from(document.querySelectorAll('a,button,span,div'))
                        .filter(e => e.textContent.trim() === 'Ver Agregado')
                        .sort((a, b) => a.textContent.length - b.textContent.length);
                    if (wide.length > 0) { wide[0].click(); return 'wide-click'; }
                    return false;
                })()
            """)
        if not ver_found:
            browser.close()
            raise ValueError("No se encontró el folio real en el registro")

        try:
            page.wait_for_function('() => document.querySelector("iframe") !== null', timeout=45000)
        except Exception:
            browser.close()
            raise ValueError(f"STEP6: iframe del PDF no apareció (click method: {ver_found})")

        pdf_url = None
        for _ in range(10):
            pdf_url = page.evaluate("""
                (() => {
                    try {
                        const iframe = document.querySelector("iframe");
                        if (!iframe) return null;
                        try {
                            const app = iframe.contentWindow.PDFViewerApplication;
                            if (app && app.url) return new URL(app.url, window.location.href).href;
                        } catch(e) {}
                        try {
                            const iSrc = new URL(iframe.src, window.location.href);
                            const filePdf = iSrc.searchParams.get('file');
                            if (filePdf) return new URL(filePdf, iframe.src).href;
                        } catch(e) {}
                        if (iframe.src && iframe.src.toLowerCase().includes('.pdf'))
                            return new URL(iframe.src, window.location.href).href;
                        return null;
                    } catch(e) { return null; }
                })()
            """)
            if pdf_url:
                break
            page.wait_for_timeout(1000)

        if not pdf_url:
            browser.close()
            raise ValueError("No se pudo obtener el PDF del folio real")

        response  = context.request.get(pdf_url)
        pdf_bytes = response.body()
        browser.close()
    _rpp_metric('folio_fetch', folio_real, int((time.time() - _t0) * 1000), True)
    return pdf_bytes


# Apply retry wrapper
fetch_pdf_for_folio = _retry_rpp(_fetch_pdf_for_folio_inner, max_retries=2, backoff_base=3)


# ── Name search ────────────────────────────────────────────────────────────────

def _fetch_properties_by_name_inner(nombre: str, paterno: str, materno: str) -> list:
    """Core name search with health check."""
    import traceback as _tb

    _JS_FIND_PROP_GRID  = """
        Ext.ComponentQuery.query('gridpanel').find(function(g) {
            if (!g.isVisible()) return false;
            var s = g.getStore();
            if (!s || s.getCount() === 0) return false;
            var d = s.getAt(0).data;
            return d.FOLIO_REAL_PROP !== undefined && d.PATERNO !== undefined;
        })
    """
    _JS_FIND_PROPED_GRID = """
        Ext.ComponentQuery.query('gridpanel').find(function(g) {
            if (!g.isVisible()) return false;
            var s = g.getStore();
            if (!s || s.getCount() === 0) return false;
            var d = s.getAt(0).data;
            return d.DOMICILIO !== undefined && d.FOLIO_REAL_PROP === undefined;
        })
    """

    if not _rpp_health_check():
        raise ValueError("El servicio RPP Chihuahua no responde. Intenta de nuevo en unos minutos.")

    _rpp_pool_stats['launches'] += 1
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=BROWSER_ARGS)
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=_USER_AGENT,
        )
        page = context.new_page()
        try:
            _login_and_open_consulta(page)
            _rpp_pool_stats['logins'] += 1
        except Exception:
            browser.close()
            raise

        try:
            page.wait_for_function(
                '() => Ext.ComponentQuery.query("numberfield[name=FOLIOREAL]").length > 0',
                timeout=30000
            )
        except Exception:
            browser.close()
            raise ValueError("STEP4N: formulario de consulta no apareció")

        try:
            page.locator('.x-tab').filter(has_text='Propietarios').first.click(timeout=5000)
        except Exception as e:
            print(f"[RPP-NAME] tab click error: {_tb.format_exc()}", flush=True)
            browser.close()
            raise ValueError(f"STEP4N-TAB: {e}")

        try:
            page.wait_for_load_state('load', timeout=8000)
        except Exception:
            pass

        try:
            page.wait_for_function(
                '() => Ext.ComponentQuery.query("textfield[name=NOMBRE]")'
                '.some(function(f){ return f.isVisible(); })',
                timeout=12000
            )
        except Exception:
            browser.close()
            raise ValueError("STEP4N-NOMBRE: campo Nombre no apareció")

        try:
            page.wait_for_function("""
                () => {
                    var d = Ext.ComponentQuery.query('combobox[name=DISTRITO]')
                                .find(function(c){ return c.isVisible(); });
                    if (!d) return false;
                    d.setValue(0);
                    return true;
                }
            """, timeout=8000)
        except Exception:
            browser.close()
            raise ValueError("STEP4N-DIST: no se pudo fijar Distrito=TODOS")

        def _get_field_id(field_query):
            handle = page.wait_for_function(
                f'() => {{ var f = {field_query}; return f ? f.getInputId() : null; }}',
                timeout=8000
            )
            return handle.json_value()

        nid = _get_field_id('Ext.ComponentQuery.query("textfield[name=NOMBRE]").find(function(f){return f.isVisible();})')
        pid = _get_field_id('Ext.ComponentQuery.query("textfield[name=PATERNO]").find(function(f){return f.isVisible();})')
        mid = _get_field_id('Ext.ComponentQuery.query("textfield[name=MATERNO]").find(function(f){return f.isVisible();})')

        page.fill(f'#{nid}', nombre.upper())
        page.fill(f'#{pid}', paterno.upper())
        page.fill(f'#{mid}', materno.upper())
        page.wait_for_timeout(200)

        _ext_dom_click(page, 'Buscar')

        try:
            page.wait_for_function(f"""
                () => {{
                    var g = {_JS_FIND_PROP_GRID};
                    return !!g;
                }}
            """, timeout=30000)
        except Exception:
            browser.close()
            raise ValueError("No se encontraron propietarios con ese nombre")

        propietarios_raw = page.evaluate(f"""
            (function() {{
                var g = {_JS_FIND_PROP_GRID};
                if (!g) return [];
                var rows = [];
                g.getStore().each(function(r) {{
                    rows.push({{
                        folio_real: r.data.FOLIO_REAL,
                        nombre:     r.data.NOMBRE   || '',
                        paterno:    r.data.PATERNO  || '',
                        materno:    r.data.MATERNO  || '',
                        distrito:   r.data.DISTRITO || ''
                    }});
                }});
                return rows;
            }})()
        """)

        if not propietarios_raw:
            browser.close()
            raise ValueError("No se encontraron propietarios con ese nombre")

        all_results = []
        for i in range(min(len(propietarios_raw), 10)):
            page.evaluate(f"""
                (function() {{
                    var g = {_JS_FIND_PROP_GRID};
                    if (g) g.getSelectionModel().select({i});
                }})()
            """)
            page.wait_for_timeout(2500)

            propiedades = page.evaluate(f"""
                (function() {{
                    var g = {_JS_FIND_PROPED_GRID};
                    if (!g) return [];
                    var rows = [];
                    g.getStore().each(function(r) {{
                        rows.push({{
                            folio_real:     r.data.FOLIO_REAL || 0,
                            domicilio:      r.data.DOMICILIO  || '',
                            colonia:        r.data.COLONIA    || '',
                            municipio:      r.data.MUNLOC     || '',
                            localidad:      r.data.LOCALIDAD  || '',
                            sup_rest:       r.data.SUP_REST   || '',
                            unidad:         (r.data.UNIDAD_MEDIDA || '').trim(),
                            clave_cat:      r.data.CLAVE_CAT  || '',
                            tiene_agregado: r.data.TIENE_AGREGADO === 'S'
                        }});
                    }});
                    return rows;
                }})()
            """)
            all_results.append({'propietario': propietarios_raw[i], 'propiedades': propiedades})

        browser.close()
        return all_results


# Apply retry wrapper
fetch_properties_by_name = _retry_rpp(_fetch_properties_by_name_inner, max_retries=2, backoff_base=3)


def fetch_predial_pdf(clave_catastral: str) -> bytes:  # kept for reference, unused
    """Fetch estado de cuenta PDF — works with or without adeudo."""
    import re as _re
    # Minimal args — avoid automation-detection flags
    browser_args = [
        '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
        '--no-zygote', '--mute-audio',
        '--disable-blink-features=AutomationControlled',
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=browser_args)
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=_USER_AGENT,
            viewport={'width': 1280, 'height': 800},
            java_script_enabled=True,
        )
        # Hide webdriver flag so ADF doesn't detect automation
        context.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
        )
        page = context.new_page()

        # Capture JS errors and console to debug ADF init failure
        _js_errors = []
        _console_msgs = []
        page.on('pageerror', lambda e: _js_errors.append(str(e)))
        page.on('console', lambda m: _console_msgs.append(f'{m.type}:{m.text[:120]}') if m.type in ('error','warning') else None)

        try:
            page.goto(PREDIAL_URL, wait_until='networkidle', timeout=50000)
        except Exception:
            pass  # networkidle timeout ok on slow ADF

        _dbg_url   = page.url
        _dbg_title = page.title()
        app.logger.warning('PREDIAL DEBUG url=%s title=%s jserrors=%s console=%s',
                           _dbg_url, _dbg_title,
                           _js_errors[:5], _console_msgs[:10])

        # Step 1: fill clave catastral
        try:
            page.wait_for_selector('#pt1\\:it1\\:\\:content', timeout=30000)
            page.fill('#pt1\\:it1\\:\\:content', clave_catastral)
        except Exception:
            page.wait_for_selector('input[type=text]', timeout=30000)
            page.fill('input[type=text]', clave_catastral)
        page.evaluate("""
            var inp = document.getElementById('pt1:it1::content');
            if (inp) {
                inp.dispatchEvent(new Event('input',  {bubbles:true}));
                inp.dispatchEvent(new Event('change', {bubbles:true}));
                inp.dispatchEvent(new Event('blur',   {bubbles:true}));
            }
        """)
        page.wait_for_timeout(500)

        # Step 2: click Continuar
        continuar = page.query_selector('#pt1\\:cb1')
        if not continuar:
            browser.close()
            raise ValueError("No se encontró el botón Continuar")
        continuar.click()

        # Step 3: wait for predialAdeudo OR obligaciones (no-adeudo goes straight there)
        try:
            page.wait_for_function(
                "() => {"
                "  var t = (document.title || '').toLowerCase();"
                "  var h = window.location.href;"
                "  return t.includes('adeudo') || t.includes('pagar') || t.includes('obligacion') || h.includes('obligacion');"
                "}",
                timeout=25000
            )
        except Exception:
            err = page.evaluate(
                "() => { var msgs = document.querySelectorAll('[class*=AFErrorText],[class*=message]'); "
                "return Array.from(msgs).map(function(m){return m.textContent;}).join(' '); }"
            )
            browser.close()
            raise ValueError(err.strip() or "Clave catastral no encontrada o formato incorrecto")

        page.wait_for_timeout(800)

        # Step 4: if on the adeudo-selection page, click Siguiente to advance
        title_now = (page.title() or '').lower()
        href_now  = page.url
        if 'adeudo' in title_now or ('obligacion' not in title_now and 'obligacion' not in href_now):
            clicked = page.evaluate("""
                () => {
                    var s = Array.from(document.querySelectorAll('button'))
                                 .find(function(b){ return b.textContent.trim() === 'Siguiente'; });
                    if (s) { s.click(); return true; }
                    return false;
                }
            """)
            if clicked:
                # Wait for obligaciones to load after Siguiente
                try:
                    page.wait_for_function(
                        "() => {"
                        "  var t = (document.title || '').toLowerCase();"
                        "  var h = window.location.href;"
                        "  return t.includes('obligacion') || h.includes('obligacion') || t.includes('pagar');"
                        "}",
                        timeout=20000
                    )
                except Exception:
                    pass
                page.wait_for_timeout(1500)

        # Step 5: extract PDF URL from _extendedScripts embedded in page JS
        # The page auto-fires: window.open('https://...reportprovider...') on load
        pdf_url = None
        for _ in range(20):
            html = page.content()
            m = _re.search(
                r"window\.open\('(https://predialcuu[^']+reportprovider[^']+)'\)",
                html
            )
            if m:
                pdf_url = m.group(1)
                break
            page.wait_for_timeout(600)

        if not pdf_url:
            browser.close()
            raise ValueError(
                "No se encontró el recibo PDF. "
                "La propiedad puede no tener adeudo registrado o la clave es incorrecta."
            )

        # Step 6: download PDF bytes (session cookies shared with context)
        pdf_response = context.request.get(pdf_url, timeout=30000)
        if pdf_response.status != 200:
            browser.close()
            raise ValueError(f"Error al descargar PDF (HTTP {pdf_response.status})")
        pdf_bytes = pdf_response.body()
        browser.close()

    if not pdf_bytes or len(pdf_bytes) < 100:
        raise ValueError("El recibo descargado está vacío")
    return pdf_bytes


# ── Job store ──────────────────────────────────────────────────────────────────

# ── Job Queue (in-memory + SQLite persistence) ───────────────────────────────
# In-memory dict for active jobs (fast access); SQLite for audit trail
_jobs: dict = {}
_jobs_lock = threading.Lock()

def _cleanup_old_jobs():
    """Remove jobs older than 10 minutes from memory."""
    cutoff = time.time() - 600
    with _jobs_lock:
        for jid in list(_jobs):
            if _jobs[jid].get('ts', 0) < cutoff:
                del _jobs[jid]

def _job_set(job_id, updates):
    """Update job state atomically."""
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id].update(updates)

def _job_get(job_id):
    """Get a copy of job state."""
    with _jobs_lock:
        return dict(_jobs.get(job_id, {}))

def _job_create(job_id, initial_state):
    """Create a new job entry."""
    with _jobs_lock:
        _jobs[job_id] = initial_state


# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route('/captcha')
def captcha_challenge():
    import random
    a, b = random.randint(2, 9), random.randint(2, 9)
    session['captcha_answer'] = a + b
    return jsonify({'question': f'¿Cuánto es {a} + {b}?'})


@app.route('/login/email', methods=['POST'])
def login_email():
    from werkzeug.security import check_password_hash
    ip = request.remote_addr or '0.0.0.0'
    if _rate_limited(f'login_ip_{ip}', 5, 60):
        return jsonify({'error': 'Demasiados intentos. Espera un momento.'}), 429
    data     = request.get_json(silent=True) or {}
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')
    captcha  = str(data.get('captcha', '')).strip()
    if captcha != str(session.get('captcha_answer', '')):
        return jsonify({'error': 'Captcha incorrecto'}), 400
    session.pop('captcha_answer', None)
    if not email or not password:
        return jsonify({'error': 'Correo y contraseña requeridos'}), 400
    with _db() as c:
        u = c.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if not u or not u['password_hash']:
        return jsonify({'error': 'Correo o contraseña incorrectos'}), 401
    if not check_password_hash(u['password_hash'], password):
        return jsonify({'error': 'Correo o contraseña incorrectos'}), 401
    tok = str(uuid.uuid4())
    with _db() as c:
        c.execute('UPDATE users SET session_token=? WHERE id=?', (tok, u['id']))
    link_corporate_member(email, u['id'])
    session.clear()
    session['uid'] = u['id']
    session['tok'] = tok
    return jsonify({'ok': True, 'next': '/'})


@app.route('/auth/magic-link', methods=['POST'])
def auth_magic_link():
    """Send a magic login link via email."""
    ip = request.remote_addr or '0.0.0.0'
    if _rate_limited(f'magic_{ip}', 3, 60):
        return jsonify({'error': 'Demasiados intentos. Espera un momento.'}), 429
    data  = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'error': 'Correo inválido'}), 400
    # Rate limit per email too
    if _rate_limited(f'magic_email_{email}', 2, 120):
        return jsonify({'error': 'Ya enviamos un link a este correo. Revisa tu bandeja.'}), 429
    # Generate token
    token = str(uuid.uuid4())
    expires = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    # Store token — reuse password_reset_tokens table
    with _db() as c:
        # Find or create user
        user = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        if user:
            uid = user['id']
        else:
            # Auto-create account
            google_id = f'email:{email}'
            role = 'admin' if email == ADMIN_EMAIL else 'user'
            trial_end = (datetime.utcnow() + timedelta(days=3)).isoformat()
            cur = c.execute(
                "INSERT INTO users(google_id,email,name,role,trial_ends) VALUES(?,?,?,?,?)",
                (google_id, email, email.split('@')[0], role, trial_end))
            uid = cur.lastrowid
            if role == 'admin':
                c.execute("UPDATE users SET plan='admin', sub_status='active' WHERE id=?", (uid,))
            ref_code = email.split('@')[0][:10].lower() + str(uid)
            c.execute('UPDATE users SET referral_code=? WHERE id=?', (ref_code, uid))
            c.execute('INSERT OR IGNORE INTO referral_codes(user_id, code) VALUES(?,?)', (uid, ref_code))
            # Apply referral bonus
            incoming_ref = session.get('ref_code', '')
            if incoming_ref:
                ref_row = c.execute('SELECT user_id FROM referral_codes WHERE code=?', (incoming_ref,)).fetchone()
                if ref_row and ref_row['user_id'] != uid:
                    if not c.execute('SELECT id FROM referral_uses WHERE referred_user_id=?', (uid,)).fetchone():
                        c.execute('INSERT INTO referral_uses(code, referred_user_id, bonus_given) VALUES(?,?,1)',
                                  (incoming_ref, uid))
                        c.execute('INSERT INTO extra_credits(user_id, payment_intent) VALUES(?,?)',
                                  (ref_row['user_id'], f'referral_{uid}'))
                        c.execute('INSERT INTO extra_credits(user_id, payment_intent) VALUES(?,?)',
                                  (uid, f'referral_bonus_{incoming_ref}'))
            # Notify admin of new account created via magic link
            _notify_new_user(
                name=email.split('@')[0], email=email, uid=uid,
                method='Magic Link (cuenta nueva)',
                ip=request.remote_addr or '',
                ref_code=session.get('ref_code', '')
            )
        c.execute('INSERT INTO password_reset_tokens(user_id, token, expires_at) VALUES(?,?,?)',
                  (uid, token, expires))
    # Send email
    base_url = request.host_url.rstrip('/')
    body = f"""
    <div style="font-family:sans-serif;max-width:520px;margin:auto;background:#0d0d14;color:#dde0e8;padding:2rem;border-radius:12px">
      <h2 style="background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem">
        Tu link de acceso
      </h2>
      <p style="color:#aaa;margin:.5rem 0 1.5rem">
        Haz clic en el botón para iniciar sesión en Consulta RPP.
        Este link es válido por <strong>15 minutos</strong>.
      </p>
      <p style="margin:1.5rem 0">
        <a href="{base_url}/auth/magic/{token}" style="background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;
           padding:.75rem 1.5rem;border-radius:8px;text-decoration:none;font-weight:700;display:inline-block">
          Iniciar sesión →
        </a>
      </p>
      <p style="color:#555;font-size:.75rem">Si no solicitaste este link, ignora este correo.</p>
    </div>"""
    sent = _smtp_send(email, 'Tu link de acceso — Consulta RPP', body)
    if not sent:
        return jsonify({'error': 'No se pudo enviar el correo. Intenta con Google.'}), 500
    return jsonify({'ok': True})


@app.route('/auth/magic/<token>')
def auth_magic_verify(token):
    """Verify magic link token and log user in."""
    with _db() as c:
        row = c.execute(
            'SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token=?',
            (token,)).fetchone()
        if not row:
            return redirect('/login?msg=invalid_link')
        if row['used']:
            return redirect('/login?msg=link_used')
        if datetime.utcnow() > datetime.fromisoformat(row['expires_at']):
            return redirect('/login?msg=link_expired')
        # Mark as used
        c.execute('UPDATE password_reset_tokens SET used=1 WHERE token=?', (token,))
        uid = row['user_id']
        # Create session token
        sess_tok = str(uuid.uuid4())
        c.execute('UPDATE users SET session_token=? WHERE id=?', (sess_tok, uid))
        u = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    # Link corporate member
    link_corporate_member(u['email'], uid)
    # Sync to Notion
    notion_sync_user_async(u)
    session.clear()
    session['uid'] = uid
    session['tok'] = sess_tok
    return redirect('/')


@app.route('/register/email', methods=['POST'])
def register_email():
    from werkzeug.security import generate_password_hash
    data     = request.get_json(silent=True) or {}
    name     = data.get('name', '').strip()
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')
    captcha  = str(data.get('captcha', '')).strip()
    if captcha != str(session.get('captcha_answer', '')):
        return jsonify({'error': 'Captcha incorrecto'}), 400
    session.pop('captcha_answer', None)
    if not name or not email or not password:
        return jsonify({'error': 'Todos los campos son requeridos'}), 400
    if len(password) < 8:
        return jsonify({'error': 'La contraseña debe tener al menos 8 caracteres'}), 400
    pw_hash   = generate_password_hash(password)
    google_id = f'email:{email}'
    role      = 'admin' if email == ADMIN_EMAIL else 'user'
    tok       = str(uuid.uuid4())
    try:
        with _db() as c:
            if c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
                return jsonify({'error': 'Este correo ya está registrado'}), 409
            trial_end = (datetime.utcnow() + timedelta(days=3)).isoformat()
            cur = c.execute(
                """INSERT INTO users(google_id,email,name,role,session_token,trial_ends,password_hash)
                   VALUES(?,?,?,?,?,?,?)""",
                (google_id, email, name, role, tok, trial_end, pw_hash))
            uid = cur.lastrowid
            if role == 'admin':
                c.execute("UPDATE users SET plan='admin', sub_status='active' WHERE id=?", (uid,))
            ref_code = email.split('@')[0][:10].lower() + str(uid)
            c.execute('UPDATE users SET referral_code=? WHERE id=?', (ref_code, uid))
            c.execute('INSERT OR IGNORE INTO referral_codes(user_id, code) VALUES(?,?)', (uid, ref_code))
            incoming_ref = session.get('ref_code', '')
            if incoming_ref:
                ref_row = c.execute('SELECT user_id FROM referral_codes WHERE code=?', (incoming_ref,)).fetchone()
                if ref_row and ref_row['user_id'] != uid:
                    if not c.execute('SELECT id FROM referral_uses WHERE referred_user_id=?', (uid,)).fetchone():
                        c.execute('INSERT INTO referral_uses(code, referred_user_id, bonus_given) VALUES(?,?,1)',
                                  (incoming_ref, uid))
                        c.execute('INSERT INTO extra_credits(user_id, payment_intent) VALUES(?,?)',
                                  (ref_row['user_id'], f'referral_{uid}'))
                        c.execute('INSERT INTO extra_credits(user_id, payment_intent) VALUES(?,?)',
                                  (uid, f'referral_bonus_{incoming_ref}'))
    except Exception as ex:
        return jsonify({'error': 'Error al crear cuenta'}), 500
    # Notify admin
    _notify_new_user(
        name=name, email=email, uid=uid,
        method='Email + Contraseña',
        ip=request.remote_addr or '',
        ref_code=session.get('ref_code', '')
    )
    session.clear()
    session['uid'] = uid
    session['tok'] = tok
    return jsonify({'ok': True, 'next': '/'})


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template_string(FORGOT_PW_HTML, msg='', error='')
    email = request.form.get('email', '').strip().lower()
    if not email:
        return render_template_string(FORGOT_PW_HTML, msg='', error='Ingresa tu correo electrónico.')
    with _db() as c:
        u = c.execute('SELECT id, email, password_hash FROM users WHERE email=?', (email,)).fetchone()
    # Always show success message (don't reveal if email exists)
    if u and u['password_hash']:
        token = str(uuid.uuid4())
        expires = (datetime.utcnow() + timedelta(hours=2)).isoformat()
        with _db() as c:
            c.execute('DELETE FROM password_reset_tokens WHERE user_id=?', (u['id'],))
            c.execute('INSERT INTO password_reset_tokens(user_id, token, expires_at) VALUES(?,?,?)',
                      (u['id'], token, expires))
        base_url = request.host_url.rstrip('/')
        link = f"{base_url}/reset-password/{token}"
        body = f"""
        <div style="font-family:sans-serif;max-width:500px;margin:0 auto">
          <h2 style="color:#8b9cf4">Restablecer contraseña</h2>
          <p>Recibiste este correo porque solicitaste restablecer tu contraseña en Consulta RPP.</p>
          <p style="margin:1.5rem 0">
            <a href="{link}" style="background:#8b9cf4;color:#fff;padding:.75rem 1.5rem;
               border-radius:8px;text-decoration:none;font-weight:700">
              Restablecer contraseña
            </a>
          </p>
          <p style="color:#888;font-size:.85rem">Este enlace expira en 2 horas. Si no solicitaste esto, ignora este correo.</p>
          <p style="color:#555;font-size:.8rem">O copia este enlace: {link}</p>
        </div>"""
        threading.Thread(target=_smtp_send,
            args=(u['email'], 'Restablecer contraseña – Consulta RPP', body),
            daemon=True).start()
    msg = 'Si ese correo está registrado, recibirás un enlace para restablecer tu contraseña en los próximos minutos.'
    return render_template_string(FORGOT_PW_HTML, msg=msg, error='')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    from werkzeug.security import generate_password_hash
    with _db() as c:
        row = c.execute(
            'SELECT * FROM password_reset_tokens WHERE token=? AND used=0', (token,)
        ).fetchone()
    if not row:
        return render_template_string(RESET_PW_HTML, token=token, error='Enlace inválido o ya utilizado.', done=False)
    if datetime.utcnow().isoformat() > row['expires_at']:
        return render_template_string(RESET_PW_HTML, token=token, error='Este enlace ha expirado. Solicita uno nuevo.', done=False)
    if request.method == 'GET':
        return render_template_string(RESET_PW_HTML, token=token, error='', done=False)
    password  = request.form.get('password', '')
    password2 = request.form.get('password2', '')
    if len(password) < 8:
        return render_template_string(RESET_PW_HTML, token=token, error='La contraseña debe tener al menos 8 caracteres.', done=False)
    if password != password2:
        return render_template_string(RESET_PW_HTML, token=token, error='Las contraseñas no coinciden.', done=False)
    pw_hash = generate_password_hash(password)
    with _db() as c:
        c.execute('UPDATE users SET password_hash=? WHERE id=?', (pw_hash, row['user_id']))
        c.execute('UPDATE password_reset_tokens SET used=1 WHERE token=?', (token,))
    return render_template_string(RESET_PW_HTML, token=token, error='', done=True)


FORGOT_PW_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Recuperar contraseña – Consulta RPP</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#09090f;color:#e2e4ed;min-height:100vh;display:flex;
         align-items:center;justify-content:center;padding:1rem}
    .card{width:100%;max-width:400px;background:#0f0f18;border:1px solid #1e1e2e;
          border-radius:14px;padding:2.2rem 2rem}
    .logo{font-size:1.3rem;font-weight:700;text-align:center;letter-spacing:-.025em;
          background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;
          -webkit-text-fill-color:transparent;margin-bottom:.2rem}
    .sub{color:#4b5268;font-size:.8rem;text-align:center;margin-bottom:1.5rem}
    .form-group{margin-bottom:.8rem}
    label{display:block;font-size:.78rem;color:#666;margin-bottom:.28rem}
    input[type=email]{width:100%;background:#0a0a12;border:1px solid #1e1e2e;border-radius:8px;
      padding:.55rem .75rem;color:#e2e4ed;font-size:.9rem;outline:none;transition:border .2s}
    input:focus{border-color:#6366f1}
    .btn-main{width:100%;padding:.65rem;background:linear-gradient(135deg,#8b9cf4,#c084fc);
              color:#fff;border:none;border-radius:8px;font-weight:700;font-size:.95rem;
              cursor:pointer;margin-top:.2rem;transition:opacity .2s}
    .btn-main:hover{opacity:.88}
    .err{background:#200a0a;border:1px solid #4a1010;color:#f87171;border-radius:7px;
         padding:.55rem .75rem;font-size:.8rem;margin-top:.6rem}
    .ok{background:#0a1a0a;border:1px solid #1a4a1a;color:#4ade80;border-radius:7px;
        padding:.55rem .75rem;font-size:.82rem;margin-top:.6rem;line-height:1.5}
    .back{text-align:center;margin-top:1rem;font-size:.82rem}
    .back a{color:#8b9cf4;text-decoration:none}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">Consulta RPP</div>
  <p class="sub">Recuperación de contraseña</p>
  {% if msg %}
    <div class="ok">{{ msg }}</div>
    <div class="back" style="margin-top:1.5rem"><a href="/login">← Volver al inicio de sesión</a></div>
  {% else %}
    <p style="font-size:.82rem;color:#888;margin-bottom:1.2rem">
      Ingresa tu correo y te enviaremos un enlace para restablecer tu contraseña.
    </p>
    <form method="POST">
      <div class="form-group">
        <label>Correo electrónico</label>
        <input type="email" name="email" placeholder="correo@ejemplo.com" autocomplete="email" required>
      </div>
      {% if error %}<div class="err">{{ error }}</div>{% endif %}
      <button class="btn-main" type="submit">Enviar enlace</button>
    </form>
    <div class="back"><a href="/login">← Volver al inicio de sesión</a></div>
  {% endif %}
</div>
</body></html>"""

RESET_PW_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Nueva contraseña – Consulta RPP</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#09090f;color:#e2e4ed;min-height:100vh;display:flex;
         align-items:center;justify-content:center;padding:1rem}
    .card{width:100%;max-width:400px;background:#0f0f18;border:1px solid #1e1e2e;
          border-radius:14px;padding:2.2rem 2rem}
    .logo{font-size:1.3rem;font-weight:700;text-align:center;letter-spacing:-.025em;
          background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;
          -webkit-text-fill-color:transparent;margin-bottom:.2rem}
    .sub{color:#4b5268;font-size:.8rem;text-align:center;margin-bottom:1.5rem}
    .form-group{margin-bottom:.8rem}
    label{display:block;font-size:.78rem;color:#666;margin-bottom:.28rem}
    input[type=password]{width:100%;background:#0a0a12;border:1px solid #1e1e2e;border-radius:8px;
      padding:.55rem .75rem;color:#e2e4ed;font-size:.9rem;outline:none;transition:border .2s}
    input:focus{border-color:#6366f1}
    .btn-main{width:100%;padding:.65rem;background:linear-gradient(135deg,#8b9cf4,#c084fc);
              color:#fff;border:none;border-radius:8px;font-weight:700;font-size:.95rem;
              cursor:pointer;margin-top:.2rem;transition:opacity .2s}
    .btn-main:hover{opacity:.88}
    .err{background:#200a0a;border:1px solid #4a1010;color:#f87171;border-radius:7px;
         padding:.55rem .75rem;font-size:.8rem;margin-top:.6rem}
    .ok{background:#0a1a0a;border:1px solid #1a4a1a;color:#4ade80;border-radius:7px;
        padding:.55rem .75rem;font-size:.82rem;margin-top:.6rem;line-height:1.5}
    .back{text-align:center;margin-top:1rem;font-size:.82rem}
    .back a{color:#8b9cf4;text-decoration:none}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">Consulta RPP</div>
  <p class="sub">Nueva contraseña</p>
  {% if done %}
    <div class="ok">Contraseña actualizada correctamente.</div>
    <div class="back" style="margin-top:1.5rem"><a href="/login">Iniciar sesión →</a></div>
  {% elif error and not request.method == 'POST' and 'inválido' in error %}
    <div class="err">{{ error }}</div>
    <div class="back"><a href="/forgot-password">Solicitar nuevo enlace</a></div>
  {% else %}
    <form method="POST">
      <div class="form-group">
        <label>Nueva contraseña</label>
        <input type="password" name="password" placeholder="Mínimo 8 caracteres" minlength="8" required>
      </div>
      <div class="form-group">
        <label>Confirmar contraseña</label>
        <input type="password" name="password2" placeholder="Repite la contraseña" required>
      </div>
      {% if error %}<div class="err">{{ error }}</div>{% endif %}
      <button class="btn-main" type="submit">Guardar contraseña</button>
    </form>
  {% endif %}
</div>
</body></html>"""


@app.route('/login')
def login_page():
    if current_user():
        return redirect(url_for('index'))
    msg = ''
    flash = request.args.get('msg', '')
    if flash == 'other_device':
        msg = '<div class="msg warn">Tu sesión fue iniciada en otro dispositivo.</div>'
    elif flash == 'logged_out':
        msg = '<div class="msg info">Sesión cerrada correctamente.</div>'
    elif flash == 'invalid_link':
        msg = '<div class="msg warn">Link inválido. Solicita uno nuevo.</div>'
    elif flash == 'link_used':
        msg = '<div class="msg warn">Este link ya fue utilizado. Solicita uno nuevo.</div>'
    elif flash == 'link_expired':
        msg = '<div class="msg warn">Link expirado. Solicita uno nuevo.</div>'
    return LOGIN_HTML.replace('__MSG__', msg)


@app.route('/auth/google')
def auth_google():
    cb = url_for('auth_callback', _external=True)
    return _google.authorize_redirect(cb)


@app.route('/auth/callback')
def auth_callback():
    try:
        token    = _google.authorize_access_token()
        userinfo = token.get('userinfo') or _google.userinfo()
    except Exception as e:
        return redirect(url_for('login_page') + '?msg=error')

    google_id = userinfo['sub']
    email     = userinfo.get('email', '')
    name      = userinfo.get('name', '')
    picture   = userinfo.get('picture', '')
    role      = 'admin' if email == ADMIN_EMAIL else 'user'

    tok = str(uuid.uuid4())

    with _db() as c:
        existing = c.execute('SELECT id FROM users WHERE google_id=?', (google_id,)).fetchone()
        if existing:
            c.execute("""UPDATE users SET name=?,picture=?,session_token=?,role=?
                         WHERE google_id=?""",
                      (name, picture, tok, role, google_id))
            uid = existing['id']
        else:
            trial_end = (datetime.utcnow() + timedelta(days=3)).isoformat()
            cur = c.execute("""INSERT INTO users(google_id,email,name,picture,role,session_token,trial_ends)
                                VALUES(?,?,?,?,?,?,?)""",
                            (google_id, email, name, picture, role, tok, trial_end))
            uid = cur.lastrowid
            # Auto-activate admin plan
            if role == 'admin':
                c.execute("UPDATE users SET plan='admin', sub_status='active' WHERE id=?", (uid,))
            # Generate referral code
            ref_code = email.split('@')[0][:10].lower() + str(uid)
            c.execute("UPDATE users SET referral_code=? WHERE id=?", (ref_code, uid))
            c.execute("INSERT OR IGNORE INTO referral_codes(user_id, code) VALUES(?,?)", (uid, ref_code))

            # Apply referral bonus if came via referral link
            incoming_ref = session.get('ref_code', '')
            if incoming_ref:
                ref_row = c.execute('SELECT user_id FROM referral_codes WHERE code=?', (incoming_ref,)).fetchone()
                if ref_row and ref_row['user_id'] != uid:
                    already = c.execute('SELECT id FROM referral_uses WHERE referred_user_id=?', (uid,)).fetchone()
                    if not already:
                        c.execute('INSERT INTO referral_uses(code, referred_user_id, bonus_given) VALUES(?,?,1)',
                                  (incoming_ref, uid))
                        # Give 1 free download credit to referrer
                        c.execute('INSERT INTO extra_credits(user_id, payment_intent) VALUES(?,?)',
                                  (ref_row['user_id'], f'referral_{uid}'))
                        # Give 1 free download credit to referred user
                        c.execute('INSERT INTO extra_credits(user_id, payment_intent) VALUES(?,?)',
                                  (uid, f'referral_bonus_{incoming_ref}'))

    # Link to corporate team if invited
    link_corporate_member(email, uid)

    # Sync user to Notion
    with _db() as c:
        u_row = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if u_row:
        notion_sync_user_async(u_row)

    # Notify admin of new registration (only for truly new users)
    if not existing:
        _notify_new_user(
            name=name, email=email, uid=uid,
            method='Google OAuth',
            ip=request.remote_addr or '',
            ref_code=session.get('ref_code', '')
        )

    next_url = session.pop('next', None)
    session.clear()
    session['uid'] = uid
    session['tok'] = tok
    return redirect(next_url or url_for('index'))


@app.route('/r/<code>')
def referral_link(code):
    """Track referral code in session, then redirect to register/login."""
    session['ref_code'] = code
    return redirect(url_for('login_page'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/app.js')
def app_js():
    return Response(APP_JS, mimetype='application/javascript; charset=utf-8')


@app.route('/manifest.json')
def pwa_manifest():
    manifest = {
        "name": "Consulta RPP Chihuahua",
        "short_name": "RPP Chihuahua",
        "description": "Consulta escrituras del Registro Público de la Propiedad de Chihuahua",
        "start_url": "/app",
        "display": "standalone",
        "background_color": "#0d0d14",
        "theme_color": "#0d0d14",
        "icons": [
            {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"}
        ]
    }
    return Response(json.dumps(manifest), mimetype='application/manifest+json')


@app.route('/sw.js')
def service_worker():
    sw = """
const CACHE = 'rpp-v9';
const PRECACHE = ['/app.js'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE).catch(()=>{})).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))
    .then(() => self.clients.claim())
  );
});
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const url = e.request.url;
  if (url.includes('/app.js') || url.includes('/static/')) {
    e.respondWith(caches.match(e.request).then(cached => cached || fetch(e.request).then(r => {
      const clone = r.clone();
      caches.open(CACHE).then(c => c.put(e.request, clone));
      return r;
    })));
  } else {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
  }
});
/* Push notifications */
self.addEventListener('push', e => {
  const data = e.data ? e.data.json() : {};
  e.waitUntil(self.registration.showNotification(data.title || 'Consulta RPP', {
    body: data.body || '',
    icon: data.icon || '/static/logo_clean.png',
    badge: '/static/logo_clean.png',
    data: data.url ? {url: data.url} : {}
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  if (e.notification.data && e.notification.data.url) {
    e.waitUntil(clients.openWindow(e.notification.data.url));
  }
});
"""
    resp = Response(sw.strip(), mimetype='application/javascript')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


@app.route('/me')
def me():
    u = current_user()
    if not u:
        return jsonify({'error': 'not_logged_in'}), 401
    dl = get_dl_info(u)
    with _db() as c:
        pack_credits = _get_pack_credits(c, u['id'])
        recent_dl = c.execute(
            'SELECT folio_real, ts FROM downloads WHERE user_id=? ORDER BY ts DESC LIMIT 3',
            (u['id'],)
        ).fetchall()
    # Team member: use owner's period_start and billing_interval for renewal display
    period_start    = u.get('period_start', '')
    billing_interval = u.get('billing_interval', 'month')
    team_owner_name = ''
    is_team_member  = dl.get('is_team_member', False)
    if is_team_member:
        owner_id = get_corporate_owner_id(u['id'])
        if owner_id:
            with _db() as _c2:
                owner = _c2.execute('SELECT period_start, billing_interval, name, email FROM users WHERE id=?', (owner_id,)).fetchone()
            if owner:
                period_start     = owner['period_start'] or period_start
                billing_interval = owner['billing_interval'] or billing_interval
                team_owner_name  = owner['name'] or owner['email']
    return jsonify({
        'id':               u['id'],
        'name':             u['name'],
        'email':            u['email'],
        'picture':          u['picture'],
        'role':             u['role'],
        'plan':             u['plan'],
        'sub_status':       u['sub_status'],
        'billing_interval': billing_interval,
        'period_start':     period_start,
        'in_trial':         u.get('in_trial', False),
        'trial_ends':       u.get('trial_ends', ''),
        'downloads_left':   dl['left'],
        'downloads_used':   dl['used'],
        'downloads_limit':  dl['limit'],
        'pack_credits':     pack_credits,
        'referral_code':    u.get('referral_code', ''),
        'recent_downloads': [{'folio': r['folio_real'], 'ts': r['ts']} for r in recent_dl],
        'is_corp_plan':     _has_team_access(u),
        'is_team_member':   is_team_member,
        'team_owner_name':  team_owner_name,
    })


@app.route('/account-data')
@login_required
def account_data():
    u = current_user()
    dl = get_dl_info(u)
    with _db() as c:
        recent = c.execute(
            'SELECT folio_real, ts FROM downloads WHERE user_id=? ORDER BY ts DESC LIMIT 20',
            (u['id'],)
        ).fetchall()
        extra_avail = c.execute(
            'SELECT COUNT(*) FROM extra_credits WHERE user_id=? AND used=0',
            (u['id'],)
        ).fetchone()[0]
        single = c.execute(
            'SELECT folio_real, amount, ts FROM single_purchases WHERE user_id=? ORDER BY ts DESC LIMIT 20',
            (u['id'],)
        ).fetchall()
        pack_credits = _get_pack_credits(c, u['id'])
        packs = c.execute(
            'SELECT pack_type, credits_total, credits_used, ts FROM download_packs WHERE user_id=? ORDER BY ts DESC LIMIT 10',
            (u['id'],)
        ).fetchall()
        # Usage chart: downloads per day for last 30 days
        thirty_ago = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d')
        daily = c.execute(
            "SELECT DATE(ts) as d, COUNT(*) as n FROM downloads "
            "WHERE user_id=? AND ts >= ? GROUP BY DATE(ts) ORDER BY d",
            (u['id'], thirty_ago)
        ).fetchall()
    is_team_member = dl.get('is_team_member', False)
    team_owner_name = ''
    team_owner_plan = ''
    period_start_display = u['period_start']
    billing_interval_display = u.get('billing_interval', 'month')
    if is_team_member:
        owner_id = get_corporate_owner_id(u['id'])
        if owner_id:
            with _db() as c2:
                owner = c2.execute('SELECT name, email, plan, period_start, billing_interval FROM users WHERE id=?', (owner_id,)).fetchone()
            if owner:
                team_owner_name = owner['name'] or owner['email']
                team_owner_plan = PLAN_LABELS.get(owner['plan'], owner['plan'] or '')
                if owner['period_start']:
                    period_start_display = owner['period_start']
                if owner['billing_interval']:
                    billing_interval_display = owner['billing_interval']
    return jsonify({
        'email':           u['email'],
        'name':            u['name'],
        'plan':            u['plan'],
        'plan_label':      PLAN_LABELS.get(u['plan'], u['plan'] or '—') if u['plan'] else '—',
        'sub_status':      u['sub_status'],
        'downloads_used':  dl['used'],
        'downloads_limit': dl['limit'],
        'downloads_left':  dl['left'],
        'extra_credits':   extra_avail,
        'pack_credits':    pack_credits,
        'packs':           [{'type': r['pack_type'], 'total': r['credits_total'],
                             'used': r['credits_used'], 'ts': r['ts']} for r in packs],
        'period_start':    period_start_display,
        'billing_interval': billing_interval_display,
        'created_at':      u['created_at'],
        'referral_code':   u.get('referral_code', ''),
        'downloads':       [{'folio': r['folio_real'], 'ts': r['ts']} for r in recent],
        'daily_usage':     [{'date': r['d'], 'count': r['n']} for r in daily],
        'single_purchases': [{'folio': r['folio_real'], 'amount': r['amount'], 'ts': r['ts']} for r in single],
        'is_team_member':  is_team_member,
        'team_owner_name': team_owner_name,
        'team_owner_plan': team_owner_plan,
    })


# ── Subscription routes ────────────────────────────────────────────────────────

@app.route('/pricing')
def pricing():
    return render_pricing(current_user())


@app.route('/create-checkout/<plan>', methods=['POST'])
@login_required
def create_checkout(plan):
    if plan not in ('basico', 'pro', 'empresarial',
                    'basico_annual', 'pro_annual', 'empresarial_annual',
                    'corporativo', 'corporativo_pro',
                    'corporativo_annual', 'corporativo_pro_annual',
                    'extra', 'single', 'pack5', 'pack10'):
        return jsonify({'error': 'Plan inválido'}), 400

    u = current_user()
    price_id = STRIPE_PRICE.get(plan, '')
    if not price_id:
        return jsonify({'error': f'Precio de Stripe para "{plan}" no configurado. Agrega STRIPE_PRICE_{plan.upper()} al entorno.'}), 500
    if not _stripe.api_key:
        return jsonify({'error': 'Stripe no configurado (STRIPE_SECRET_KEY faltante)'}), 500

    try:
        # Get or create Stripe customer (handles stale test-mode IDs gracefully)
        customer_id = u.get('stripe_customer_id')
        if customer_id:
            try:
                _stripe.Customer.retrieve(customer_id)
            except _stripe.error.InvalidRequestError:
                # Customer doesn't exist in current mode (e.g. test→live migration)
                customer_id = None
        if not customer_id:
            customer = _stripe.Customer.create(email=u['email'], name=u['name'],
                                               metadata={'user_id': u['id']})
            customer_id = customer['id']
            with _db() as c:
                c.execute('UPDATE users SET stripe_customer_id=? WHERE id=?',
                          (customer_id, u['id']))

        base = os.environ.get('BASE_URL', 'https://consulta-rpp.javisnes.com')

        if plan == 'single':
            # Single download payment ($130 MXN)
            return_folio = (request.get_json(silent=True) or {}).get('return_folio', '')
            job_id = (request.get_json(silent=True) or {}).get('job_id', '')
            success_url  = f"{base}/subscription/success?single=1&folio={return_folio}&job_id={job_id}"
            checkout = _stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='payment',
                success_url=success_url,
                cancel_url=f"{base}/",
                metadata={'user_id': str(u['id']), 'type': 'single', 'folio': return_folio, 'job_id': job_id},
            )
        elif plan in ('pack5', 'pack10'):
            pack = PACK_CONFIG[plan]
            success_url = f"{base}/subscription/success?pack={plan}"
            checkout = _stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='payment',
                success_url=success_url,
                cancel_url=f"{base}/pricing",
                metadata={'user_id': str(u['id']), 'type': plan, 'credits': str(pack['qty'])},
            )
        elif plan == 'extra':
            # One-time payment
            return_folio = (request.get_json(silent=True) or {}).get('return_folio', '')
            success_url  = f"{base}/subscription/success?extra=1&folio={return_folio}"
            checkout = _stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='payment',
                success_url=success_url,
                cancel_url=f"{base}/pricing",
                metadata={'user_id': str(u['id']), 'type': 'extra'},
            )
        else:
            # Subscription
            checkout = _stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='subscription',
                success_url=f"{base}/subscription/success?plan={plan}",
                cancel_url=f"{base}/pricing",
                metadata={'user_id': str(u['id']), 'plan': plan},
            )
        return jsonify({'url': checkout.url})
    except _stripe.error.StripeError as e:
        return jsonify({'error': str(e)}), 500


@app.route('/subscription/success')
@login_required
def subscription_success():
    plan   = request.args.get('plan', '')
    extra  = request.args.get('extra', '')
    single = request.args.get('single', '')
    pack   = request.args.get('pack', '')
    folio  = request.args.get('folio', '')
    job_id = request.args.get('job_id', '')
    msg    = ''
    if pack:
        u = current_user()
        pack_info = PACK_CONFIG.get(pack, {})
        credits = pack_info.get('qty', 5)
        with _db() as c:
            c.execute('INSERT INTO download_packs(user_id,pack_type,credits_total,payment_intent) VALUES(?,?,?,?)',
                      (u['id'], pack, credits, f'redirect_{pack}'))
        msg = f'Paquete de {credits} descargas activado.'
    elif single:
        # Mark job as paid and record purchase
        u = current_user()
        pi_key = f'redirect_{job_id}'
        if job_id and _job_get(job_id):
            _job_set(job_id, {'pay_per_download': False, 'single_paid': True})
        with _db() as c:
            c.execute('INSERT OR IGNORE INTO single_purchases(user_id,folio_real,payment_intent) VALUES(?,?,?)',
                      (u['id'], folio, pi_key))
            # Give 1 extra_credit as fallback so user can always download
            existing = c.execute('SELECT id FROM extra_credits WHERE payment_intent=?', (pi_key,)).fetchone()
            if not existing:
                c.execute('INSERT INTO extra_credits(user_id,payment_intent) VALUES(?,?)', (u['id'], pi_key))
        msg = 'Pago recibido. Tu documento está listo para descargar.'
    elif extra:
        msg = 'Descarga extra agregada a tu cuenta.'
    elif plan:
        msg = f'Suscripción {PLAN_LABELS.get(plan, plan)} activada. ¡Bienvenido!'
    # For packs, singles and extras: no webhook needed — redirect immediately
    if not plan:
        dest = f'/?auto_folio={folio}' if folio else '/'
        return f"""<!DOCTYPE html><html><head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="2;url={dest}">
        <style>body{{background:#0d0d14;color:#4ade80;font-family:sans-serif;display:flex;
        align-items:center;justify-content:center;height:100vh;text-align:center}}</style>
        </head><body>
        <div><p style="font-size:1.4rem">✓ {msg}</p>
        <p style="color:#555;margin-top:.5rem;font-size:.875rem">
        Redirigiendo... <a href="{dest}" style="color:#8b9cf4">Ir ahora</a></p>
        </div></body></html>"""

    # For subscriptions: poll /me until sub_status = active (webhook may lag)
    plan_label = PLAN_LABELS.get(plan, plan)
    return f"""<!DOCTYPE html>
<html lang="es"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Activando tu plan...</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d0d14;color:#dde0e8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}}
  .card{{text-align:center;max-width:420px;width:100%}}
  .icon{{font-size:3.5rem;margin-bottom:1.25rem;display:block}}
  h1{{font-size:1.6rem;font-weight:800;margin-bottom:.5rem;
      background:linear-gradient(120deg,#8b9cf4,#c084fc);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
  .sub{{color:#666;font-size:.9rem;margin-bottom:2rem;line-height:1.6}}
  .progress{{height:4px;background:#1e1e2e;border-radius:2px;overflow:hidden;margin-bottom:1.5rem}}
  .progress-bar{{height:100%;background:linear-gradient(90deg,#8b9cf4,#c084fc);
                 border-radius:2px;width:0;transition:width .4s ease}}
  .status{{font-size:.8125rem;color:#555;margin-bottom:1.5rem;min-height:1.2em}}
  .status.ok{{color:#4ade80}}
  .status.err{{color:#f87171}}
  .btn{{display:inline-block;background:linear-gradient(135deg,#8b9cf4,#c084fc);
        color:#fff;text-decoration:none;padding:.65rem 1.75rem;border-radius:10px;
        font-weight:700;font-size:.9rem;opacity:0;transition:opacity .4s;pointer-events:none}}
  .btn.show{{opacity:1;pointer-events:auto}}
  .dots span{{animation:blink 1.2s ease-in-out infinite}}
  .dots span:nth-child(2){{animation-delay:.2s}}
  .dots span:nth-child(3){{animation-delay:.4s}}
  @keyframes blink{{0%,80%,100%{{opacity:.2}}40%{{opacity:1}}}}
</style>
</head><body>
<div class="card">
  <span id="icon" class="icon">⏳</span>
  <h1 id="title">Activando Plan {plan_label}</h1>
  <p class="sub">Tu pago fue recibido. Estamos confirmando tu suscripción<br>con Stripe y activando tu cuenta.</p>
  <div class="progress"><div class="progress-bar" id="bar"></div></div>
  <p class="status" id="status">Verificando pago<span class="dots"><span>.</span><span>.</span><span>.</span></span></p>
  <a href="/" class="btn" id="go-btn">Ir al buscador →</a>
</div>
<script>
var MAX_TRIES = 18, INTERVAL = 2500, tries = 0;
var bar = document.getElementById('bar');
var status = document.getElementById('status');
var btn   = document.getElementById('go-btn');
var icon  = document.getElementById('icon');
var title = document.getElementById('title');

function setSuccess() {{
  icon.textContent  = '✅';
  title.textContent = '¡Plan {plan_label} activo!';
  bar.style.width   = '100%';
  bar.style.background = '#4ade80';
  status.className  = 'status ok';
  status.textContent = 'Tu suscripción está activa. Redirigiendo...';
  btn.classList.add('show');
  setTimeout(function(){{ window.location.href = '/'; }}, 1800);
}}

function setError() {{
  icon.textContent  = '⚠️';
  bar.style.width   = '100%';
  bar.style.background = '#f59e0b';
  status.className  = 'status err';
  status.textContent = 'Tardó más de lo esperado. Intenta recargar o contacta soporte.';
  btn.classList.add('show');
}}

function poll() {{
  tries++;
  var pct = Math.min(90, (tries / MAX_TRIES) * 90);
  bar.style.width = pct + '%';

  fetch('/me').then(function(r){{ return r.json(); }}).then(function(u) {{
    if (u.sub_status === 'active') {{
      setSuccess();
    }} else if (tries >= MAX_TRIES) {{
      setError();
    }} else {{
      setTimeout(poll, INTERVAL);
    }}
  }}).catch(function() {{
    if (tries >= MAX_TRIES) setError();
    else setTimeout(poll, INTERVAL);
  }});
}}

setTimeout(poll, 1200);
</script>
</body></html>"""


@app.route('/portal')
@login_required
def portal():
    u = current_user()
    cid = u.get('stripe_customer_id')
    if not cid or not _stripe.api_key:
        return redirect(url_for('pricing'))
    base = os.environ.get('BASE_URL', 'https://consulta-rpp.javisnes.com')
    try:
        ps = _stripe.billing_portal.Session.create(
            customer=cid,
            return_url=f"{base}/pricing",
        )
        return redirect(ps.url)
    except _stripe.error.StripeError as e:
        return redirect(url_for('pricing'))


@app.route('/dashboard')
@login_required
def dashboard():
    import datetime as _dt
    u = current_user()
    if u['role'] == 'admin':
        return redirect('/admin')
    if u.get('sub_status') != 'active' or u.get('billing_interval') != 'year':
        return redirect('/pricing')

    selected_year  = int(request.args.get('year',  _dt.datetime.utcnow().year))
    selected_month = int(request.args.get('month', 0))

    period_start = u.get('period_start') or '1970-01-01'
    plan         = u.get('plan') or 'basico'
    annual_quota = ANNUAL_QUOTAS.get(plan, 60)

    with _db() as c:
        # Total used since period_start (annual counter)
        annual_used = c.execute(
            'SELECT COUNT(*) FROM downloads WHERE user_id=? AND ts >= ?',
            (u['id'], period_start)
        ).fetchone()[0]

        # Monthly counts for selected year
        rows = c.execute(
            "SELECT strftime('%m', ts) as m, COUNT(*) as n FROM downloads "
            "WHERE user_id=? AND strftime('%Y', ts)=? GROUP BY m",
            (u['id'], str(selected_year))
        ).fetchall()
        monthly_counts = {r['m']: r['n'] for r in rows}

        # History — filtered by year + optional month
        if selected_month > 0:
            month_str = f'{selected_year}-{str(selected_month).zfill(2)}'
            history = c.execute(
                "SELECT folio_real, nombre, ts FROM downloads "
                "WHERE user_id=? AND strftime('%Y-%m', ts)=? ORDER BY ts DESC",
                (u['id'], month_str)
            ).fetchall()
        else:
            history = c.execute(
                "SELECT folio_real, nombre, ts FROM downloads "
                "WHERE user_id=? AND strftime('%Y', ts)=? ORDER BY ts DESC",
                (u['id'], str(selected_year))
            ).fetchall()

    dl = get_dl_info(u)
    return render_dashboard(u, dl, [dict(r) for r in history],
                            monthly_counts, annual_used, annual_quota,
                            selected_year, selected_month)


@app.route('/dashboard/report')
@login_required
def dashboard_report():
    import datetime as _dt, csv, io as _io
    u = current_user()
    if u['role'] == 'admin':
        return redirect('/admin')
    if u.get('sub_status') != 'active' or u.get('billing_interval') != 'year':
        return redirect('/pricing')

    selected_year  = int(request.args.get('year',  _dt.datetime.utcnow().year))
    selected_month = int(request.args.get('month', 0))

    with _db() as c:
        if selected_month > 0:
            month_str = f'{selected_year}-{str(selected_month).zfill(2)}'
            rows = c.execute(
                "SELECT folio_real, nombre, ts FROM downloads "
                "WHERE user_id=? AND strftime('%Y-%m', ts)=? ORDER BY ts",
                (u['id'], month_str)
            ).fetchall()
            fname = f'reporte_{selected_year}_{str(selected_month).zfill(2)}.csv'
        else:
            rows = c.execute(
                "SELECT folio_real, nombre, ts FROM downloads "
                "WHERE user_id=? AND strftime('%Y', ts)=? ORDER BY ts",
                (u['id'], str(selected_year))
            ).fetchall()
            fname = f'reporte_{selected_year}.csv'

    buf = _io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['Fecha', 'Hora', 'Folio Real', 'Propietario'])
    for r in rows:
        ts = r['ts'] or ''
        writer.writerow([ts[:10], ts[11:16], r['folio_real'] or '', r['nombre'] or ''])

    out = _io.BytesIO(buf.getvalue().encode('utf-8-sig'))
    return send_file(out, mimetype='text/csv', as_attachment=True, download_name=fname)


@app.route('/equipo')
@login_required
def equipo():
    u = current_user()
    plan = u.get('plan') or ''
    if u['role'] != 'admin' and not _has_team_access(u):
        return redirect('/pricing')

    max_members = MAX_TEAM_MEMBERS.get(plan, 0)
    plan_limit  = PLAN_LIMITS.get(plan, 0)
    period_start = u.get('period_start') or '1970-01-01'
    team_used    = get_team_downloads_used(u['id'], period_start)

    with _db() as c:
        members = c.execute(
            """SELECT cm.id, cm.invite_email, cm.member_id, cm.joined_at, cm.active,
                      us.name as member_name,
                      (SELECT COUNT(*) FROM downloads d WHERE d.user_id = cm.member_id
                         AND d.ts >= ?) as member_used
               FROM corporate_members cm
               LEFT JOIN users us ON us.id = cm.member_id
               WHERE cm.owner_id = ? AND cm.active = 1
               ORDER BY cm.ts""",
            (period_start, u['id'])).fetchall()

    return render_template_string(EQUIPO_HTML,
        u=u,
        members=[dict(m) for m in members],
        max_members=max_members,
        plan_limit=plan_limit,
        team_used=team_used,
        plan_label=PLAN_LABELS.get(plan, plan),
        error=request.args.get('error', ''),
        success=request.args.get('success', ''),
    )


@app.route('/equipo/invite', methods=['POST'])
@login_required
def equipo_invite():
    u = current_user()
    plan = u.get('plan') or ''
    if u['role'] != 'admin' and not _has_team_access(u):
        return redirect('/pricing')

    email = request.form.get('email', '').strip().lower()
    if not email or '@' not in email:
        return redirect('/equipo?error=Correo inválido')
    if email == u['email']:
        return redirect('/equipo?error=No puedes invitarte a ti mismo')

    max_members = MAX_TEAM_MEMBERS.get(plan, 0)
    with _db() as c:
        count = c.execute('SELECT COUNT(*) FROM corporate_members WHERE owner_id=? AND active=1',
                          (u['id'],)).fetchone()[0]
    if count >= max_members:
        return redirect(f'/equipo?error=Límite de {max_members} miembros alcanzado')

    with _db() as c:
        # Check if already invited
        existing = c.execute('SELECT id FROM corporate_members WHERE owner_id=? AND invite_email=?',
                              (u['id'], email)).fetchone()
        if existing:
            return redirect('/equipo?error=Ese correo ya fue invitado')
        # Check if user exists, link immediately if so
        member_user = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        member_id   = member_user['id'] if member_user else None
        joined_at   = datetime.utcnow().isoformat() if member_id else None
        c.execute('INSERT INTO corporate_members(owner_id, invite_email, member_id, joined_at) VALUES(?,?,?,?)',
                  (u['id'], email, member_id, joined_at))

    # Send invitation email
    base_url = request.host_url.rstrip('/')
    plan_label = PLAN_LABELS.get(plan, plan)
    owner_name = u.get('name') or u['email']
    body = f"""
    <div style="font-family:sans-serif;max-width:520px;margin:auto;background:#0d0d14;color:#dde0e8;padding:2rem;border-radius:12px">
      <h2 style="background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent">
        Invitación a Consulta RPP
      </h2>
      <p style="color:#aaa;margin:.5rem 0 1.5rem">
        <strong>{owner_name}</strong> te ha dado acceso al <strong style="color:#c084fc">Plan {plan_label}</strong>
        en Consulta RPP — Sistema de consulta del Registro Público de la Propiedad de Chihuahua.
      </p>
      <p style="margin:1.5rem 0">
        <a href="{base_url}/login" style="background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;
           padding:.75rem 1.5rem;border-radius:8px;text-decoration:none;font-weight:700">
          Iniciar sesión con este correo
        </a>
      </p>
      <p style="color:#666;font-size:.8rem">Inicia sesión con <strong>{email}</strong> para activar tu acceso.</p>
    </div>"""
    threading.Thread(target=_smtp_send,
        args=(email, f'Acceso a Consulta RPP — {plan_label}', body),
        daemon=True).start()

    return redirect('/equipo?success=Invitación enviada correctamente')


@app.route('/equipo/remove/<int:member_id>', methods=['POST'])
@login_required
def equipo_remove(member_id):
    u = current_user()
    with _db() as c:
        row = c.execute('SELECT owner_id FROM corporate_members WHERE id=?', (member_id,)).fetchone()
        if not row or (row['owner_id'] != u['id'] and u['role'] != 'admin'):
            return redirect('/equipo?error=No autorizado')
        c.execute('UPDATE corporate_members SET active=0 WHERE id=?', (member_id,))
    return redirect('/equipo?success=Miembro eliminado')


EQUIPO_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Mi Equipo – Consulta RPP</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#09090f;color:#e2e4ed;min-height:100vh;padding:2rem 1rem}
    .wrap{max-width:700px;margin:0 auto}
    h1{font-size:1.4rem;font-weight:700;background:linear-gradient(120deg,#8b9cf4,#c084fc);
       -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.25rem}
    .sub{color:#4b5268;font-size:.82rem;margin-bottom:1.8rem}
    .stats{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
    .stat{background:#0f0f18;border:1px solid #1e1e2e;border-radius:10px;padding:1rem 1.25rem;flex:1;min-width:130px}
    .stat .lbl{font-size:.72rem;color:#555;margin-bottom:.3rem}
    .stat .val{font-size:1.3rem;font-weight:700;color:#8b9cf4}
    .card{background:#0f0f18;border:1px solid #1e1e2e;border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}
    .card h2{font-size:.95rem;font-weight:700;color:#c084fc;margin-bottom:1rem}
    .invite-row{display:flex;gap:.6rem}
    .invite-row input{flex:1;background:#0a0a12;border:1px solid #1e1e2e;border-radius:8px;
                      padding:.55rem .75rem;color:#e2e4ed;font-size:.9rem;outline:none}
    .invite-row input:focus{border-color:#6366f1}
    .btn{padding:.55rem 1.1rem;background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;
         border:none;border-radius:8px;font-weight:700;font-size:.85rem;cursor:pointer}
    .btn:hover{opacity:.88}
    .btn-danger{background:#3a1010;border:1px solid #5a1a1a;color:#f87171;padding:.35rem .7rem;
                border-radius:6px;font-size:.78rem;cursor:pointer;border:none}
    .member-row{display:flex;align-items:center;gap:.75rem;padding:.65rem 0;
                border-bottom:1px solid #1a1a2a;font-size:.85rem}
    .member-row:last-child{border-bottom:none}
    .badge{display:inline-block;padding:.18rem .55rem;border-radius:20px;font-size:.68rem;font-weight:700}
    .badge.joined{background:#0a2a0a;color:#4ade80;border:1px solid #1a4a1a}
    .badge.pending{background:#1a1a0a;color:#f59e0b;border:1px solid #3a3a1a}
    .ok{background:#0a1a0a;border:1px solid #1a4a1a;color:#4ade80;border-radius:7px;
        padding:.55rem .75rem;font-size:.82rem;margin-bottom:1rem}
    .err{background:#200a0a;border:1px solid #4a1010;color:#f87171;border-radius:7px;
         padding:.55rem .75rem;font-size:.82rem;margin-bottom:1rem}
    .back{margin-bottom:1.2rem}
    .back a{color:#8b9cf4;text-decoration:none;font-size:.82rem}
    .progress-bar{background:#1a1a2a;border-radius:20px;height:6px;margin-top:.5rem}
    .progress-fill{height:6px;border-radius:20px;background:#4ade80;transition:width .4s}
  </style>
</head>
<body>
<div class="wrap">
  <div class="back"><a href="/">← Volver al inicio</a></div>
  <h1>Mi Equipo</h1>
  <p class="sub">Plan {{ plan_label }} — Gestiona los miembros que comparten tu cupo de descargas</p>

  {% if success %}<div class="ok">{{ success }}</div>{% endif %}
  {% if error %}<div class="err">{{ error }}</div>{% endif %}

  <div class="stats">
    <div class="stat">
      <div class="lbl">Descargas usadas</div>
      <div class="val">{{ team_used }} / {{ plan_limit }}</div>
      <div class="progress-bar"><div class="progress-fill"
        style="width:{{ [100, (team_used*100//plan_limit if plan_limit else 0)]|min }}%;
               background:{% if team_used*100//plan_limit > 89 %}#f87171{% elif team_used*100//plan_limit > 69 %}#f59e0b{% else %}#4ade80{% endif %}">
      </div></div>
    </div>
    <div class="stat">
      <div class="lbl">Miembros activos</div>
      <div class="val">{{ members|length }} / {{ max_members }}</div>
    </div>
    <div class="stat">
      <div class="lbl">Descargas restantes</div>
      <div class="val" style="color:#4ade80">{{ [0, plan_limit - team_used]|max }}</div>
    </div>
  </div>

  <!-- Invite form -->
  {% if members|length < max_members %}
  <div class="card">
    <h2>Invitar miembro</h2>
    <form action="/equipo/invite" method="POST">
      <div class="invite-row">
        <input type="email" name="email" placeholder="correo@empresa.com" required>
        <button class="btn" type="submit">Invitar</button>
      </div>
    </form>
    <p style="margin-top:.6rem;font-size:.72rem;color:#444">
      El invitado recibirá un correo. Al iniciar sesión con ese correo tendrá acceso inmediato.
    </p>
  </div>
  {% else %}
  <div class="card">
    <h2>Invitar miembro</h2>
    <p style="color:#666;font-size:.85rem">Has alcanzado el límite de {{ max_members }} miembros para el Plan {{ plan_label }}.</p>
  </div>
  {% endif %}

  <!-- Members list -->
  <div class="card">
    <h2>Miembros del equipo</h2>
    {% if members %}
      {% for m in members %}
      <div class="member-row">
        <div style="flex:1">
          <div style="font-weight:600;color:#dde0e8">{{ m.member_name or m.invite_email }}</div>
          {% if m.member_name %}<div style="font-size:.72rem;color:#555">{{ m.invite_email }}</div>{% endif %}
        </div>
        <span class="badge {{ 'joined' if m.member_id else 'pending' }}">
          {{ 'Activo' if m.member_id else 'Pendiente' }}
        </span>
        {% if m.member_id %}
        <span style="font-size:.78rem;color:#888;min-width:70px;text-align:right">
          {{ m.member_used or 0 }} desc.
        </span>
        {% endif %}
        <form action="/equipo/remove/{{ m.id }}" method="POST" style="margin:0"
              onsubmit="return confirm('¿Eliminar a este miembro?')">
          <button class="btn-danger" type="submit">Eliminar</button>
        </form>
      </div>
      {% endfor %}
    {% else %}
      <p style="color:#444;font-size:.85rem">Aún no has invitado a ningún miembro.</p>
    {% endif %}
  </div>
</div>
</body></html>"""


ESTADO_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="60">
  <title>Estado del Servicio \u2013 Consulta RPP</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#09090f;color:#e2e4ed;min-height:100vh;display:flex;
         align-items:center;justify-content:center;padding:1rem}
    .wrap{max-width:500px;width:100%}
    .card{background:#0f0f18;border:1px solid #1e1e2e;border-radius:14px;padding:2rem;margin-bottom:1rem}
    h1{font-size:1.2rem;font-weight:700;background:linear-gradient(120deg,#8b9cf4,#c084fc);
       -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.25rem}
    .sub{font-size:.78rem;color:#444;margin-bottom:1.5rem}
    .status-row{display:flex;align-items:center;gap:.75rem;padding:.8rem 0;border-bottom:1px solid #1a1a2a}
    .status-row:last-child{border-bottom:none}
    .dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
    .dot.ok{background:#4ade80;box-shadow:0 0 8px #4ade8088}
    .dot.down{background:#f87171;box-shadow:0 0 8px #f8717188}
    .dot.warn{background:#f59e0b;box-shadow:0 0 8px #f59e0b88}
    .svc-name{font-weight:600;font-size:.9rem;flex:1}
    .svc-detail{font-size:.75rem;color:#555}
    .badge{font-size:.72rem;font-weight:700;padding:.2rem .55rem;border-radius:20px}
    .badge.ok{background:#0a2a0a;color:#4ade80}
    .badge.down{background:#2a0a0a;color:#f87171}
    .back{text-align:center;margin-top:1rem;font-size:.82rem}
    .back a{color:#8b9cf4;text-decoration:none}
    .ts{font-size:.68rem;color:#333;text-align:center;margin-top:.5rem}
  </style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>Estado del Servicio</h1>
    <p class="sub">Actualizaci\u00f3n autom\u00e1tica cada 60 segundos</p>

    <div class="status-row">
      <div class="dot {{ 'ok' if status.ok else 'down' }}"></div>
      <div class="svc-name">RPP Chihuahua (Gobierno)</div>
      <div class="svc-detail">{{ status.response_ms }}ms</div>
      <span class="badge {{ 'ok' if status.ok else 'down' }}">
        {{ 'Operativo' if status.ok else 'No disponible' }}
      </span>
    </div>

    <div class="status-row">
      <div class="dot ok"></div>
      <div class="svc-name">Consulta RPP App</div>
      <div class="svc-detail">Este servidor</div>
      <span class="badge ok">Operativo</span>
    </div>

    {% if status.message %}
    <div style="margin-top:1rem;padding:.75rem;background:#1a1000;border:1px solid #3a2a00;
                border-radius:8px;color:#f59e0b;font-size:.82rem">
      \u26a0 {{ status.message }}
    </div>
    {% endif %}

    <p class="ts">Última verificaci\u00f3n: {{ status.checked_at or 'Iniciando...' }} UTC</p>
  </div>

  <div class="back"><a href="/">\u2190 Volver al inicio</a></div>
</div>
</body></html>"""

ANALYTICS_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Analytics \u2013 Consulta RPP</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#09090f;color:#e2e4ed;padding:2rem 1rem}
    .wrap{max-width:900px;margin:0 auto}
    h1{font-size:1.4rem;font-weight:700;background:linear-gradient(120deg,#8b9cf4,#c084fc);
       -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:1.5rem}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem;margin-bottom:2rem}
    .card{background:#0f0f18;border:1px solid #1e1e2e;border-radius:12px;padding:1.25rem}
    .card h2{font-size:.9rem;font-weight:700;color:#c084fc;margin-bottom:.85rem}
    table{width:100%;border-collapse:collapse;font-size:.82rem}
    th{color:#555;font-weight:600;text-align:left;padding:.4rem .5rem;border-bottom:1px solid #1a1a2a}
    td{padding:.4rem .5rem;border-bottom:1px solid #111;color:#dde0e8}
    tr:last-child td{border-bottom:none}
    .bar{background:#1a1a2a;border-radius:4px;height:6px;margin-top:.3rem}
    .bar-fill{height:6px;border-radius:4px;background:linear-gradient(90deg,#8b9cf4,#c084fc)}
    .back{margin-bottom:1rem}
    .back a{color:#8b9cf4;text-decoration:none;font-size:.82rem}
    .stat-big{font-size:1.8rem;font-weight:700;color:#8b9cf4}
    .stat-label{font-size:.72rem;color:#555;margin-top:.2rem}
    .summary{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
    .sum-card{background:#0f0f18;border:1px solid #1e1e2e;border-radius:10px;padding:1rem 1.25rem;flex:1;min-width:120px}
  </style>
</head>
<body>
<div class="wrap">
  <div class="back"><a href="/admin">\u2190 Admin</a></div>
  <h1>Analytics \u00b7 \u00daltimos 30 d\u00edas</h1>

  <div class="summary">
    {% set searches = namespace(n=0) %}
    {% for e in event_totals %}{% if e.event in ['search_folio','search_nombre'] %}{% set searches.n = searches.n + e.n %}{% endif %}{% endfor %}
    {% set downloads = (event_totals|selectattr('event','equalto','download')|list or [{'n':0}])[0].n %}
    {% set pageviews = (event_totals|selectattr('event','equalto','pageview')|list or [{'n':0}])[0].n %}
    <div class="sum-card"><div class="stat-big">{{ searches.n }}</div><div class="stat-label">B\u00fasquedas</div></div>
    <div class="sum-card"><div class="stat-big">{{ downloads }}</div><div class="stat-label">Descargas</div></div>
    <div class="sum-card"><div class="stat-big">{{ pageviews }}</div><div class="stat-label">Visitas</div></div>
    <div class="sum-card"><div class="stat-big">{{ event_totals|length }}</div><div class="stat-label">Tipos de eventos</div></div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Eventos por tipo</h2>
      <table>
        <tr><th>Evento</th><th>Total</th></tr>
        {% set max_n = (event_totals[0].n if event_totals else 1) %}
        {% for e in event_totals %}
        <tr>
          <td>{{ e.event }}</td>
          <td>{{ e.n }}
            <div class="bar"><div class="bar-fill" style="width:{{ (e.n*100//max_n) }}%"></div></div>
          </td>
        </tr>
        {% endfor %}
        {% if not event_totals %}<tr><td colspan="2" style="color:#444">Sin datos</td></tr>{% endif %}
      </table>
    </div>

    <div class="card">
      <h2>Descargas por plan</h2>
      <table>
        <tr><th>Plan</th><th>Descargas</th></tr>
        {% set max_dl = (dl_by_plan[0].n if dl_by_plan else 1) %}
        {% for d in dl_by_plan %}
        <tr>
          <td>{{ d.plan or '\u2014' }}</td>
          <td>{{ d.n }}
            <div class="bar"><div class="bar-fill" style="width:{{ (d.n*100//max_dl) }}%"></div></div>
          </td>
        </tr>
        {% endfor %}
        {% if not dl_by_plan %}<tr><td colspan="2" style="color:#444">Sin datos</td></tr>{% endif %}
      </table>
    </div>

    <div class="card">
      <h2>Folios m\u00e1s buscados</h2>
      <table>
        <tr><th>Folio</th><th>B\u00fasquedas</th></tr>
        {% for f in top_folios %}
        <tr><td style="font-family:monospace">{{ f.meta }}</td><td>{{ f.n }}</td></tr>
        {% endfor %}
        {% if not top_folios %}<tr><td colspan="2" style="color:#444">Sin datos</td></tr>{% endif %}
      </table>
    </div>

    <div class="card">
      <h2>Nombres m\u00e1s buscados</h2>
      <table>
        <tr><th>Nombre</th><th>B\u00fasquedas</th></tr>
        {% for n in top_names %}
        <tr><td>{{ n.meta }}</td><td>{{ n.n }}</td></tr>
        {% endfor %}
        {% if not top_names %}<tr><td colspan="2" style="color:#444">Sin datos</td></tr>{% endif %}
      </table>
    </div>
  </div>
</div>
</body></html>"""


@app.route('/estado')
def estado_servicio():
    s = _rpp_status
    return render_template_string(ESTADO_HTML, status=s)


@app.route('/admin/set-status', methods=['POST'])
@login_required
def admin_set_status():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    msg = request.form.get('message', '').strip()
    force_ok = request.form.get('force_ok', '') == '1'
    if force_ok:
        _rpp_status.update({'ok': True, 'message': msg or ''})
    else:
        _rpp_status.update({'ok': False, 'message': msg or 'Mantenimiento programado'})
    return redirect('/estado')


@app.route('/api/status')
def api_status():
    return jsonify({'ok': _rpp_status['ok'], 'checked_at': _rpp_status['checked_at'], 'ms': _rpp_status['response_ms']})


@app.route('/admin/analytics')
@login_required
def admin_analytics():
    u = current_user()
    if u['role'] != 'admin':
        return redirect('/')
    with _db() as c:
        events_by_day = c.execute("""
            SELECT strftime('%Y-%m-%d', ts) as day, event, COUNT(*) as n
            FROM analytics_events
            WHERE ts >= date('now', '-30 days')
            GROUP BY day, event ORDER BY day
        """).fetchall()
        top_folios = c.execute("""
            SELECT meta, COUNT(*) as n FROM analytics_events
            WHERE event='search_folio' AND ts >= date('now', '-30 days')
            GROUP BY meta ORDER BY n DESC LIMIT 10
        """).fetchall()
        top_names = c.execute("""
            SELECT meta, COUNT(*) as n FROM analytics_events
            WHERE event='search_nombre' AND ts >= date('now', '-30 days')
            GROUP BY meta ORDER BY n DESC LIMIT 10
        """).fetchall()
        event_totals = c.execute("""
            SELECT event, COUNT(*) as n FROM analytics_events
            WHERE ts >= date('now', '-30 days')
            GROUP BY event ORDER BY n DESC
        """).fetchall()
        dl_by_plan = c.execute("""
            SELECT plan, COUNT(*) as n FROM analytics_events
            WHERE event='download' AND ts >= date('now', '-30 days')
            GROUP BY plan ORDER BY n DESC
        """).fetchall()
    return render_template_string(ANALYTICS_HTML,
        events_by_day=[dict(r) for r in events_by_day],
        top_folios=[dict(r) for r in top_folios],
        top_names=[dict(r) for r in top_names],
        event_totals=[dict(r) for r in event_totals],
        dl_by_plan=[dict(r) for r in dl_by_plan],
    )


@app.route('/track', methods=['POST'])
def track_event():
    ip = request.remote_addr or '0.0.0.0'
    if _rate_limited(f'track_{ip}', 30, 60):
        return '', 204
    data  = request.get_json(silent=True) or {}
    event = str(data.get('event', ''))[:50]
    meta  = str(data.get('meta', ''))[:200]
    if not event:
        return '', 204
    u = current_user()
    uid  = u['id'] if u else None
    plan = u.get('plan') if u else None
    with _db() as c:
        c.execute('INSERT INTO analytics_events(event,user_id,plan,meta) VALUES(?,?,?,?)',
                  (event, uid, plan, meta or None))
    return '', 204




@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    if check_webhook_rate():
        return 'rate limited', 429
    payload = request.get_data()
    sig     = request.headers.get('Stripe-Signature', '')
    if not STRIPE_WEBHOOK_SECRET:
        return 'webhook secret not configured', 400
    try:
        event = _stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except _stripe.error.SignatureVerificationError:
        return 'invalid signature', 400

    evt_type = event['type']
    # Use raw JSON to avoid StripeObject .get() incompatibility in stripe>=5
    import json as _json
    data     = _json.loads(payload)['data']['object']

    if evt_type == 'checkout.session.completed':
        uid  = int(data.get('metadata', {}).get('user_id', 0))
        kind = data.get('metadata', {}).get('type', '')
        if not uid:
            return 'ok', 200
        if kind == 'single':
            # Single download payment — record purchase and mark job
            pi = data.get('payment_intent', '')
            folio = data.get('metadata', {}).get('folio', '')
            job_id = data.get('metadata', {}).get('job_id', '')
            with _db() as c:
                c.execute('INSERT OR IGNORE INTO single_purchases(user_id,folio_real,payment_intent) VALUES(?,?,?)',
                          (uid, folio, pi))
                # Always give 1 extra_credit so user can download even if job is gone
                existing = c.execute('SELECT id FROM extra_credits WHERE payment_intent=?', (pi,)).fetchone()
                if not existing:
                    c.execute('INSERT INTO extra_credits(user_id,payment_intent) VALUES(?,?)', (uid, pi))
            if job_id and _job_get(job_id):
                _job_set(job_id, {'pay_per_download': False, 'single_paid': True})
            # Send receipt email
            with _db() as c:
                u_row = c.execute('SELECT email,name FROM users WHERE id=?', (uid,)).fetchone()
            if u_row:
                threading.Thread(
                    target=send_receipt_email,
                    args=(u_row['email'], u_row['name'] or '', folio),
                    daemon=True
                ).start()
        elif kind in ('pack5', 'pack10'):
            pi = data.get('payment_intent', '')
            credits = int(data.get('metadata', {}).get('credits', PACK_CONFIG.get(kind, {}).get('qty', 5)))
            with _db() as c:
                c.execute('INSERT INTO download_packs(user_id,pack_type,credits_total,payment_intent) VALUES(?,?,?,?)',
                          (uid, kind, credits, pi))
            # Send receipt
            with _db() as c:
                u_row = c.execute('SELECT email,name FROM users WHERE id=?', (uid,)).fetchone()
            if u_row:
                threading.Thread(
                    target=send_pack_email,
                    args=(u_row['email'], u_row['name'] or '', kind, credits),
                    daemon=True
                ).start()
        elif kind == 'extra':
            # Add 1 extra download credit
            pi = data.get('payment_intent', '')
            with _db() as c:
                c.execute('INSERT INTO extra_credits(user_id,payment_intent) VALUES(?,?)',
                          (uid, pi))
        else:
            plan_raw = data.get('metadata', {}).get('plan', '')
            # Detect billing interval before normalising
            billing_interval = 'year' if '_annual' in (plan_raw or '') else 'month'
            # Normalise annual plan keys → base plan name stored in DB
            plan   = plan_raw.replace('_annual', '') if plan_raw else plan_raw
            sub_id = data.get('subscription', '')
            if plan and sub_id:
                with _db() as c:
                    c.execute("""UPDATE users SET plan=?,stripe_sub_id=?,sub_status='active',
                                  downloads_used=0,period_start=?,billing_interval=?,annual_reminder_sent=NULL WHERE id=?""",
                              (plan, sub_id, datetime.utcnow().isoformat(), billing_interval, uid))
                    user_row = c.execute('SELECT email,name FROM users WHERE id=?', (uid,)).fetchone()
                if user_row:
                    threading.Thread(
                        target=send_welcome_email,
                        args=(user_row['email'], user_row['name'] or '', plan),
                        daemon=True
                    ).start()
                # Sync to Notion after plan activation
                with _db() as c:
                    full_row = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
                if full_row:
                    notion_sync_user_async(full_row)

    elif evt_type == 'customer.subscription.updated':
        sub_id = data['id']
        status = data['status']
        plan   = None
        # Extract plan from items
        items = data.get('items', {}).get('data', [])
        for item in items:
            price_id = item.get('price', {}).get('id', '')
            for k, v in STRIPE_PRICE.items():
                if v == price_id:
                    plan = k
                    break
        if plan:
            plan = plan.replace('_annual', '')
        with _db() as c:
            if plan:
                c.execute("UPDATE users SET sub_status=?,plan=? WHERE stripe_sub_id=?",
                          (status, plan, sub_id))
            else:
                c.execute("UPDATE users SET sub_status=? WHERE stripe_sub_id=?",
                          (status, sub_id))
        # Reset downloads on renewal (status=active and period reset)
        if status == 'active':
            with _db() as c:
                c.execute("""UPDATE users SET downloads_used=0,period_start=?
                             WHERE stripe_sub_id=?""",
                          (datetime.utcnow().isoformat(), sub_id))
        # Notion sync
        with _db() as c:
            u_row = c.execute('SELECT * FROM users WHERE stripe_sub_id=?', (sub_id,)).fetchone()
        if u_row:
            notion_sync_user_async(u_row)

    elif evt_type == 'customer.subscription.deleted':
        sub_id = data['id']
        with _db() as c:
            c.execute("UPDATE users SET sub_status='canceled',plan=NULL WHERE stripe_sub_id=?",
                      (sub_id,))
            u_row = c.execute('SELECT * FROM users WHERE stripe_sub_id=?', (sub_id,)).fetchone()
        if u_row:
            notion_sync_user_async(u_row)

    elif evt_type == 'invoice.payment_failed':
        sub_id = data.get('subscription', '')
        if sub_id:
            with _db() as c:
                c.execute("UPDATE users SET sub_status='past_due' WHERE stripe_sub_id=?",
                          (sub_id,))
                u_row = c.execute('SELECT * FROM users WHERE stripe_sub_id=?', (sub_id,)).fetchone()
            if u_row:
                notion_sync_user_async(u_row)
                plan_label = PLAN_LABELS.get(u_row['plan'], u_row['plan'] or 'tu plan')
                threading.Thread(target=send_payment_failed_email,
                                 args=(u_row['email'], u_row['name'], plan_label),
                                 daemon=True).start()

    return 'ok', 200


@app.route('/admin')
@login_required
def admin_panel():
    u = current_user()
    if u['role'] != 'admin':
        return redirect(url_for('index'))
    now = datetime.utcnow()
    month_start = now.replace(day=1).strftime('%Y-%m-%d')
    with _db() as c:
        users = c.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
        total_dl   = c.execute('SELECT COUNT(*) FROM downloads').fetchone()[0]
        dl_month   = c.execute("SELECT COUNT(*) FROM downloads WHERE ts >= ?", (month_start,)).fetchone()[0]
        # Downloads per day (last 14 days)
        dl_per_day = c.execute(
            "SELECT date(ts) as d, COUNT(*) as cnt FROM downloads WHERE ts >= date('now','-14 days') GROUP BY date(ts) ORDER BY d"
        ).fetchall()
        # Churn: canceled or past_due users
        churn_rows = c.execute(
            "SELECT name, email, plan, sub_status, period_start FROM users WHERE sub_status IN ('canceled','past_due') ORDER BY period_start DESC"
        ).fetchall()
        # One-time purchase revenue this month
        single_rev_month = c.execute(
            "SELECT COALESCE(SUM(amount),0) FROM single_purchases WHERE ts >= ?", (month_start,)
        ).fetchone()[0] or 0
        extra_rev_month = c.execute(
            "SELECT COUNT(*) FROM extra_credits WHERE ts >= ? AND payment_intent NOT LIKE 'referral%' AND payment_intent NOT LIKE 'manual%'", (month_start,)
        ).fetchone()[0] or 0
        pack_rows_month = c.execute(
            "SELECT pack_type, COUNT(*) as cnt FROM download_packs WHERE ts >= ? GROUP BY pack_type", (month_start,)
        ).fetchall()
        pack_rev_month = sum(
            (500 if r['pack_type'] == 'pack5' else 900 if r['pack_type'] == 'pack10' else 0) * r['cnt']
            for r in pack_rows_month
        )
        # single_rev_month is stored in centavos → convert to MXN pesos
        onetime_rev_month = int(single_rev_month / 100) + (extra_rev_month * 100) + pack_rev_month
        # Total revenue all time (one-time purchases)
        single_rev_total = c.execute(
            "SELECT COALESCE(SUM(amount),0) FROM single_purchases"
        ).fetchone()[0] or 0
        extra_rev_total = c.execute(
            "SELECT COUNT(*) FROM extra_credits WHERE payment_intent NOT LIKE 'referral%' AND payment_intent NOT LIKE 'manual%'"
        ).fetchone()[0] or 0
        pack_rows_total = c.execute(
            "SELECT pack_type, COUNT(*) as cnt FROM download_packs GROUP BY pack_type"
        ).fetchall()
        pack_rev_total = sum(
            (500 if r['pack_type'] == 'pack5' else 900 if r['pack_type'] == 'pack10' else 0) * r['cnt']
            for r in pack_rows_total
        )
        onetime_rev_total = int(single_rev_total / 100) + (extra_rev_total * 100) + pack_rev_total
        # Team memberships: member_id → owner info (including period_start + billing_interval)
        team_rows = c.execute(
            'SELECT cm.member_id, u.name as owner_name, u.email as owner_email, u.id as owner_id, '
            '       u.period_start as owner_period_start, u.billing_interval as owner_billing_interval '
            'FROM corporate_members cm JOIN users u ON u.id = cm.owner_id '
            'WHERE cm.active=1 AND cm.member_id IS NOT NULL'
        ).fetchall()
    team_map = {r['member_id']: {
        'owner_id':               r['owner_id'],
        'owner_name':             r['owner_name'] or r['owner_email'],
        'owner_period_start':     r['owner_period_start'],
        'owner_billing_interval': r['owner_billing_interval'] or 'month',
    } for r in team_rows}
    users_list = [dict(r) for r in users]
    # Attach team info to each user dict
    for ud in users_list:
        tm = team_map.get(ud['id'])
        if tm:
            ud['_team_owner']            = tm['owner_name']
            ud['_team_owner_id']         = tm['owner_id']
            # Override period_start and billing_interval so renewal shows owner's date
            ud['period_start']           = tm['owner_period_start'] or ud.get('period_start')
            ud['billing_interval']       = tm['owner_billing_interval']
        else:
            ud['_team_owner']    = ''
            ud['_team_owner_id'] = None
    active_subs = sum(1 for r in users_list if r.get('sub_status') == 'active')
    trial_users = sum(1 for r in users_list if r.get('trial_ends') and r.get('trial_ends') > now.isoformat() and r.get('sub_status') != 'active')
    canceled    = sum(1 for r in users_list if r.get('sub_status') in ('canceled', 'past_due'))
    mrr = sum(PLAN_PRICES.get(r['plan'], 0) for r in users_list if r.get('sub_status') == 'active')
    total_non_admin = sum(1 for r in users_list if r.get('role') != 'admin')
    conversion = (active_subs / total_non_admin * 100) if total_non_admin else 0
    # Total revenue: Stripe invoices paid + one-time from DB
    stripe_total = 0
    try:
        if _stripe.api_key:
            for inv in _stripe.Invoice.list(status='paid', limit=100).auto_paging_iter():
                stripe_total += (inv.amount_paid or 0)
            stripe_total = int(stripe_total / 100)  # centavos → MXN
    except Exception:
        pass
    total_revenue = stripe_total + onetime_rev_total if stripe_total else (mrr + onetime_rev_total)
    dl_chart = [{'date': r['d'], 'count': r['cnt']} for r in dl_per_day]
    churn_alerts = [{'name': r['name'], 'email': r['email'], 'plan': PLAN_LABELS.get(r['plan'], r['plan'] or ''), 'status': r['sub_status'], 'date': (r['period_start'] or '')[:10]} for r in churn_rows]
    metrics = {
        'total_users': len(users_list), 'active_subs': active_subs,
        'total_downloads': total_dl, 'downloads_this_month': dl_month,
        'onetime_rev_month': onetime_rev_month,
        'total_revenue': total_revenue,
        'mrr': mrr, 'trial_users': trial_users, 'canceled': canceled,
        'conversion_rate': conversion, 'dl_per_day': dl_chart,
        'churn_alerts': churn_alerts,
    }
    return render_admin(users_list, metrics)


# ── Main app routes ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    u = current_user()
    if u:
        dl = get_dl_info(u)
        with _db() as _c_idx:
            _pack_idx = _get_pack_credits(_c_idx, u['id'])
        user_data = json.dumps({
            'id': u['id'], 'name': u['name'], 'email': u['email'],
            'picture': u['picture'], 'role': u['role'], 'plan': u['plan'],
            'sub_status': u['sub_status'], 'billing_interval': u.get('billing_interval', 'month'),
            'downloads_left': dl['left'], 'downloads_used': dl['used'], 'downloads_limit': dl['limit'],
            'is_corp_plan': _has_team_access(u),
            'is_team_member': dl.get('is_team_member', False),
            'referral_code': u.get('referral_code', ''),
            'in_trial':    u.get('in_trial', False),
            'trial_ends':  u.get('trial_ends', ''),
            'pack_credits': _pack_idx,
        })
        # Build user bar HTML server-side
        is_admin = u['role'] == 'admin'
        in_trial = u.get('in_trial', False)
        is_team_member = dl.get('is_team_member', False)
        has_sub = is_admin or u.get('sub_status') == 'active' or in_trial or is_team_member
        plan_labels = {'basico': 'Básico', 'pro': 'Pro', 'empresarial': 'Empresarial', 'corporativo': 'Corporativo', 'corporativo_pro': 'Corp. Pro'}
        if is_team_member:
            owner_id = get_corporate_owner_id(u['id'])
            with _db() as c:
                owner = c.execute('SELECT plan, name, email FROM users WHERE id=?', (owner_id,)).fetchone()
            owner_plan = owner['plan'] if owner else ''
            owner_name = (owner['name'] or owner['email']) if owner else ''
            plan_label = f"Equipo {plan_labels.get(owner_plan, '')}"
        else:
            plan_label = plan_labels.get(u['plan'], '')
        dl_left = dl['left']
        name = u['name'] or u['email']
        pic = f'<img src="{u["picture"]}" alt="">' if u.get('picture') else ''
        trial_badge = ''
        if in_trial:
            try:
                days_left = max(0, (datetime.fromisoformat(u['trial_ends']) - datetime.utcnow()).days)
            except Exception:
                days_left = 0
            trial_badge = f'<span class="badge" style="background:#f59e0b;color:#000;font-size:.65rem">Trial {days_left}d</span>'
        badge = '<span class="badge admin">Admin</span>' if is_admin else (
            f'<span class="badge">{plan_label}</span>' if plan_label else '') + trial_badge
        if is_admin:
            dl_text = '<span class="dl-ok">∞ acceso ilimitado</span>'
        elif has_sub:
            dl_cls = 'dl-low' if dl_left <= 2 else 'dl-left'
            dl_text = f'<span class="{dl_cls}">{dl_left} desc. restantes</span>'
        else:
            dl_text = ''
        sub_link = '' if has_sub else '<a href="/pricing" class="sub-link">Suscribirse</a>'
        acct_link = '<a href="#" class="acct-link" onclick="openAcct();return false">Mi cuenta</a>' if has_sub and not is_admin else ''
        dash_link  = '<a href="/dashboard" style="color:#4ade80;font-weight:700">📊 Mi Panel</a>' if (has_sub and not is_admin and u.get('billing_interval') == 'year') else ''
        team_link  = '<a href="/equipo" style="color:#8b9cf4;font-weight:700">👥 Equipo</a>' if (has_sub and not is_admin and _has_team_access(u)) else ''
        admin_link = '<a href="/admin">Admin</a>' if is_admin else ''
        bar_html = (f'{pic}<span class="uname">{name}</span>{badge}'
                    f'{dl_text}{sub_link}{acct_link}{dash_link}{team_link}{admin_link}'
                    f'<a href="/logout">Salir</a>'
                    f'<button class="theme-btn" id="theme-toggle-btn" onclick="toggleTheme()">☀ Claro</button>')
        page = HTML.replace('<!--USER_DATA-->',
                            f'<script>window.__USER={user_data};</script>')
        page = page.replace(
            '<span class="uname" style="color:#444">Cargando...</span>',
            bar_html)
        if GOOGLE_ANALYTICS_ID:
            page = page.replace('G-XXXXXXXXXX', GOOGLE_ANALYTICS_ID)
        else:
            page = page.replace(
                '<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>\n  <script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag(\'js\',new Date());gtag(\'config\',\'G-XXXXXXXXXX\');</script>',
                '')
        return render_template_string(page)
    landing = LANDING_HTML
    if GOOGLE_ANALYTICS_ID:
        landing = landing.replace('G-XXXXXXXXXX', GOOGLE_ANALYTICS_ID)
    else:
        landing = landing.replace(
            '<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>\n  <script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag(\'js\',new Date());gtag(\'config\',\'G-XXXXXXXXXX\');</script>',
            '')
    return render_template_string(landing)


@app.route('/buscar', methods=['POST'])
@login_required
def buscar():
    u     = current_user()
    rl = check_search_rate(u)
    if rl: return rl
    data   = request.get_json()
    folio  = (data or {}).get('folio', '').strip()
    nombre_prop = (data or {}).get('nombre_prop', '').strip()
    if not folio:
        return jsonify({'error': 'Folio real requerido'}), 400

    is_admin = u['role'] == 'admin'
    is_team_member = bool(get_corporate_owner_id(u['id']))
    has_sub  = is_admin or u.get('sub_status') == 'active' or u.get('in_trial') or is_team_member

    # Subscribed users: check quota
    if has_sub:
        dl = get_dl_info(u)
        if dl['left'] <= 0:
            return jsonify({'error': 'Límite de descargas alcanzado', 'quota': True,
                            'folio': folio}), 402
        use_extra = dl['use_extra']
        use_pack  = dl['use_pack']
    else:
        # Free user: check for pack credits first
        with _db() as c:
            pack_credits = _get_pack_credits(c, u['id'])
        use_extra = False
        use_pack  = pack_credits > 0

    _cleanup_old_jobs()
    job_id = str(uuid.uuid4())
    _job_create(job_id, {
        'status': 'running', 'pdf': None, 'error': None,
        'type': 'folio', 'folio': folio, 'ts': time.time(),
        'user_id': u['id'], 'use_extra': use_extra, 'use_pack': use_pack,
        'pay_per_download': not has_sub and not use_pack,
        'nombre_prop': nombre_prop,
    })

    # Track abandoned cart for free users
    if not has_sub and not use_pack:
        _track_abandoned_search(u['id'], folio)

    # Track search event + audit
    threading.Thread(target=_track, args=('search_folio', u['id'], u.get('plan'), folio), daemon=True).start()
    threading.Thread(target=_audit, args=(u['id'], 'search_folio', folio, request.remote_addr), daemon=True).start()

    def run():
        try:
            cached = _get_cached_pdf(folio)
            if cached:
                _rpp_pool_stats['cache_hits'] += 1
                _job_set(job_id, {'status': 'done', 'pdf': cached})
                return
            raw_pdf   = fetch_pdf_for_folio(folio)
            clean_pdf = remove_watermarks(raw_pdf)
            _set_cached_pdf(folio, clean_pdf)
            _job_set(job_id, {'status': 'done', 'pdf': clean_pdf})
        except ValueError as e:
            _job_set(job_id, {'status': 'error', 'error': str(e)})
        except Exception as e:
            _job_set(job_id, {'status': 'error', 'error': f'Error: {e}'})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'job_id': job_id})



@app.route('/buscar-nombre', methods=['POST'])
@sub_required
def buscar_nombre():
    u = current_user()
    rl = check_search_rate(u)
    if rl: return rl
    data    = request.get_json()
    nombre  = (data or {}).get('nombre',  '').strip()
    paterno = (data or {}).get('paterno', '').strip()
    materno = (data or {}).get('materno', '').strip()
    if not nombre and not paterno:
        return jsonify({'error': 'Ingresa al menos nombre o primer apellido'}), 400

    # Track name search event
    meta_nombre = ' '.join(filter(None, [paterno, materno, nombre]))[:100]
    threading.Thread(target=_track, args=('search_nombre', u['id'], u.get('plan'), meta_nombre), daemon=True).start()

    _cleanup_old_jobs()
    job_id = str(uuid.uuid4())
    _job_create(job_id, {'status': 'running', 'results': None, 'error': None,
                         'type': 'nombre', 'ts': time.time()})

    def run():
        try:
            results = fetch_properties_by_name(nombre, paterno, materno)
            _job_set(job_id, {'status': 'done', 'results': results})
        except ValueError as e:
            _job_set(job_id, {'status': 'error', 'error': str(e)})
        except Exception as e:
            import traceback as _tb
            print(f"[RPP-NAME ERROR] {_tb.format_exc()}", flush=True)
            _job_set(job_id, {'status': 'error', 'error': f'Error: {e}'})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'job_id': job_id})


@app.route('/status/<job_id>')
def job_status(job_id):
    job = _job_get(job_id)
    if not job:
        return jsonify({'status': 'error', 'error': 'Job no encontrado'}), 404
    if job['status'] == 'error':
        return jsonify({'status': 'error', 'error': job['error']})
    if job['status'] == 'done':
        if job.get('type') == 'nombre':
            return jsonify({'status': 'done', 'results': job['results']})
        return jsonify({'status': 'done'})
    return jsonify({'status': job['status']})


@app.route('/preview/<job_id>')
def preview(job_id):
    u = current_user()
    if not u:
        return redirect(url_for('login_page'))
    job = _job_get(job_id)
    if not job or job['status'] != 'done' or not job.get('pdf'):
        return jsonify({'error': 'PDF no disponible'}), 404
    # Truncate to first 2 pages for preview
    try:
        from pypdf import PdfReader, PdfWriter
        reader = PdfReader(io.BytesIO(job['pdf']))
        if len(reader.pages) > 2:
            writer = PdfWriter()
            for i in range(min(2, len(reader.pages))):
                writer.add_page(reader.pages[i])
            buf = io.BytesIO()
            writer.write(buf)
            preview_pdf = buf.getvalue()
        else:
            preview_pdf = job['pdf']
    except Exception:
        preview_pdf = job['pdf']
    return send_file(
        io.BytesIO(preview_pdf),
        mimetype='application/pdf',
        as_attachment=False,
        download_name=f'preview_{job.get("folio","folio")}.pdf',
    )


@app.route('/buscar-lote', methods=['POST'])
@sub_required
def buscar_lote():
    u = current_user()
    rl = check_search_rate(u)
    if rl: return rl
    data   = request.get_json()
    folios = list(dict.fromkeys(  # deduplicate, preserve order
        str(f).strip() for f in (data or {}).get('folios', []) if str(f).strip()
    ))[:10]
    if not folios:
        return jsonify({'error': 'Sin folios'}), 400

    dl = get_dl_info(u)
    if u['role'] != 'admin' and dl['left'] <= 0:
        return jsonify({'error': 'Límite de descargas alcanzado', 'quota': True}), 402

    _cleanup_old_jobs()
    jobs = []
    for folio in folios:
        job_id = str(uuid.uuid4())
        _job_create(job_id, {
            'status': 'running', 'pdf': None, 'error': None,
            'type': 'folio', 'folio': folio, 'ts': time.time(),
            'user_id': u['id'], 'use_extra': dl['use_extra'], 'use_pack': dl['use_pack'],
        })
        jobs.append({'job_id': job_id, 'folio': folio})

    # Run folios sequentially in a single background thread to avoid
    # concurrent Playwright sessions conflicting with each other.
    def run_all(job_list=jobs):
        for item in job_list:
            jid = item['job_id']
            f   = item['folio']
            try:
                raw_pdf   = fetch_pdf_for_folio(f)
                clean_pdf = remove_watermarks(raw_pdf)
                _job_set(jid, {'status': 'done', 'pdf': clean_pdf})
            except ValueError as e:
                _job_set(jid, {'status': 'error', 'error': str(e)})
            except Exception as e:
                _job_set(jid, {'status': 'error', 'error': f'Error: {e}'})

    threading.Thread(target=run_all, daemon=True).start()

    return jsonify({'jobs': jobs})


@app.route('/download/<job_id>')
def download(job_id):
    u = current_user()
    if not u:
        return redirect(url_for('login_page'))
    job = _job_get(job_id)
    if not job or job['status'] != 'done' or not job.get('pdf'):
        return jsonify({'error': 'PDF no disponible'}), 404
    # Block if pay-per-download and not yet paid
    if job.get('pay_per_download') and not job.get('single_paid'):
        return jsonify({'error': 'Pago requerido', 'pay_required': True,
                        'folio': job.get('folio', '')}), 402
    # Record the download
    record_dl(job.get('user_id', u['id']), job.get('folio', ''), job.get('use_extra', False), job.get('use_pack', False), nombre=job.get('nombre_prop', ''))
    # Track download event
    threading.Thread(target=_track, args=('download', u['id'], u.get('plan'), job.get('folio', '')), daemon=True).start()
    # Low-downloads warning email (only 1 left after this download)
    if u.get('sub_status') == 'active' and u.get('role') != 'admin':
        dl_after = get_dl_info(u)
        if dl_after['left'] == 1:
            threading.Thread(target=send_low_downloads_email,
                             args=(u['email'], u['name'], 1), daemon=True).start()
    folio = job.get('folio', 'folio')
    return send_file(
        io.BytesIO(job['pdf']),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'folio_{folio}_sin_marca.pdf',
    )


# ── Términos y Condiciones ─────────────────────────────────────────────────────
@app.route('/terminos')
def terminos():
    return """<!DOCTYPE html>
<html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Términos y Condiciones — Consulta RPP</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d0d14;color:#dde0e8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.7}
  .nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 2rem;border-bottom:1px solid #1e1a2e;background:#0d0d14;position:sticky;top:0;z-index:10}
  .nav-logo{font-weight:700;font-size:1.125rem;color:#c084fc;text-decoration:none}
  .nav-back{font-size:.875rem;color:#a78bfa;text-decoration:none;display:flex;align-items:center;gap:.4rem}
  .nav-back:hover{color:#c084fc}
  .wrap{max-width:760px;margin:0 auto;padding:3rem 1.5rem 5rem}
  h1{font-size:1.75rem;font-weight:700;color:#c084fc;margin-bottom:.5rem}
  .subtitle{color:#7a7a9a;font-size:.875rem;margin-bottom:3rem}
  h2{font-size:1.125rem;font-weight:600;color:#a78bfa;margin:2rem 0 .75rem}
  p{color:#b0b3c0;font-size:.9375rem;margin-bottom:.75rem}
  ul{color:#b0b3c0;font-size:.9375rem;padding-left:1.25rem;margin-bottom:.75rem}
  ul li{margin-bottom:.4rem}
  .badge{display:inline-flex;align-items:center;gap:.4rem;background:#1a1a2e;border:1px solid #2a2a4a;border-radius:8px;padding:.5rem 1rem;font-size:.875rem;color:#c084fc;margin:.25rem .25rem .25rem 0}
  .footer-note{margin-top:3rem;padding-top:1.5rem;border-top:1px solid #1e1a2e;color:#555;font-size:.8125rem;text-align:center}
  a{color:#a78bfa}
</style>
</head><body>

<nav class="nav">
  <a href="/" class="nav-logo">📋 Consulta RPP</a>
  <a href="/" class="nav-back">← Volver al inicio</a>
</nav>

<div class="wrap">
  <h1>Términos y Condiciones</h1>
  <p class="subtitle">Última actualización: marzo 2026 · Consulta RPP — Chihuahua, México</p>

  <h2>1. Descripción del Servicio</h2>
  <p>Consulta RPP es una herramienta digital que permite a usuarios registrados consultar y descargar documentos del Registro Público de la Propiedad del Estado de Chihuahua de forma automatizada, cómoda y sin marcas de agua.</p>
  <p>El servicio actúa como intermediario técnico. Toda la información proviene de fuentes públicas oficiales del RPP.</p>

  <h2>2. Seguridad de la Información</h2>
  <div style="display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem">
    <span class="badge">🔒 Conexión HTTPS cifrada</span>
    <span class="badge">🛡️ Contraseñas encriptadas</span>
    <span class="badge">✅ Sin almacenamiento de PDFs</span>
    <span class="badge">🔐 Datos no compartidos con terceros</span>
  </div>
  <p>Todas las comunicaciones entre tu dispositivo y nuestros servidores se realizan mediante HTTPS con cifrado TLS. Las contraseñas se almacenan exclusivamente en formato hash (bcrypt); nunca en texto plano.</p>
  <p>Los documentos PDF generados son entregados directamente al usuario y <strong>no se almacenan permanentemente en nuestros servidores</strong>. Los archivos se eliminan automáticamente de la memoria del sistema poco después de que son descargados.</p>

  <h2>3. Confidencialidad de los Datos</h2>
  <p>Los datos personales que proporcionas (nombre, correo electrónico) se utilizan exclusivamente para:</p>
  <ul>
    <li>Identificar tu cuenta y gestionar tu suscripción</li>
    <li>Enviarte notificaciones relacionadas con tu servicio (alertas de folio, recordatorios de renovación)</li>
    <li>Emitir recibos de pago a través de Stripe</li>
  </ul>
  <p><strong>No vendemos, cedemos ni compartimos tu información personal con terceros</strong> bajo ninguna circunstancia, salvo obligación legal expresa.</p>

  <h2>4. Los Archivos no se Quedan en Nuestros Servidores</h2>
  <p>Cada vez que realizas una consulta, el documento se obtiene en tiempo real del RPP Chihuahua y se transfiere directamente a tu dispositivo. <strong>Los PDFs se mantienen en memoria únicamente durante el tiempo necesario para completar la descarga</strong> (máximo unos pocos minutos) y son eliminados automáticamente.</p>
  <p>No existe ninguna base de datos de documentos ni archivo histórico de los PDFs descargados por nuestros usuarios.</p>

  <h2>5. Uso Aceptable</h2>
  <p>El servicio está diseñado para uso profesional y personal legítimo relacionado con consultas registrales. Queda prohibido:</p>
  <ul>
    <li>Automatizar consultas masivas de forma abusiva</li>
    <li>Revender o redistribuir los documentos obtenidos con fines comerciales no autorizados</li>
    <li>Intentar vulnerar la seguridad o el funcionamiento del sistema</li>
    <li>Compartir credenciales de acceso con terceros</li>
  </ul>

  <h2>6. Procesamiento de Pagos</h2>
  <p>Los pagos se procesan a través de <strong>Stripe</strong>, un proveedor de pagos certificado PCI DSS. Consulta RPP <strong>nunca tiene acceso a los datos de tu tarjeta bancaria</strong>; estos se manejan exclusivamente por Stripe en sus servidores seguros.</p>

  <h2>7. Disponibilidad del Servicio</h2>
  <p>El servicio depende de la disponibilidad del portal público del RPP Chihuahua. No nos responsabilizamos por interrupciones causadas por mantenimientos o cambios en dicho portal gubernamental. En caso de indisponibilidad prolongada, se contemplará la extensión o compensación proporcional de las suscripciones afectadas.</p>

  <h2>8. Limitación de Responsabilidad</h2>
  <p>Consulta RPP proporciona acceso a información pública. La exactitud y vigencia de los documentos es responsabilidad del Registro Público de la Propiedad. El servicio se ofrece "tal cual" sin garantías de exactitud sobre el contenido registral.</p>

  <h2>9. Modificaciones</h2>
  <p>Nos reservamos el derecho de actualizar estos términos. Los cambios significativos se notificarán por correo electrónico con al menos 7 días de anticipación. El uso continuado del servicio implica la aceptación de los términos vigentes.</p>

  <h2>10. Contacto</h2>
  <p>Para dudas, solicitudes de datos o reporte de incidentes de seguridad: <a href="mailto:hola@javisnes.com">hola@javisnes.com</a></p>

  <p class="footer-note">© 2026 Consulta RPP · Chihuahua, México · <a href="/">Inicio</a></p>
</div>

</body></html>"""


# ── 404 page ──────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return """<!DOCTYPE html>
<html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>404 — Consulta RPP</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#0d0d14;color:#dde0e8;min-height:100vh;display:flex;
       align-items:center;justify-content:center;padding:2rem}
  .c{text-align:center;max-width:420px}
  .code{font-size:6rem;font-weight:800;
        background:linear-gradient(120deg,#8b9cf4,#c084fc);
        -webkit-background-clip:text;-webkit-text-fill-color:transparent;
        line-height:1;margin-bottom:.5rem}
  .msg{color:#666;font-size:1rem;margin-bottom:2rem;line-height:1.6}
  .back{display:inline-block;padding:.6rem 1.5rem;
        background:linear-gradient(135deg,#8b9cf4,#c084fc);
        color:#fff;border-radius:8px;text-decoration:none;font-weight:600;
        font-size:1rem;transition:opacity .2s}
  .back:hover{opacity:.85}
  .icon{font-size:3rem;margin-bottom:1rem;opacity:.6}
</style>
</head><body>
<div class="c">
  <div class="icon">🔍</div>
  <div class="code">404</div>
  <p class="msg">La página que buscas no existe o fue movida.<br>Verifica la dirección e intenta de nuevo.</p>
  <a href="/" class="back">← Ir al inicio</a>
</div>
</body></html>""", 404


# ── Notion sync (admin) ──────────────────────────────────────────────────────

NOTION_DS_ID = '672efb98-52f2-4214-a9f9-80e25bd3413c'

@app.route('/admin/grant-plan', methods=['POST'])
@login_required
def admin_grant_plan():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    data             = request.get_json() or {}
    uid              = int(data.get('uid', 0))
    plan             = data.get('plan', '') or None
    billing_interval = data.get('billing_interval', 'month') or 'month'
    status           = data.get('status', '') or None
    reset            = data.get('reset', False)
    if not uid:
        return jsonify({'error': 'UID inválido'}), 400
    with _db() as c:
        target = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        if not target:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        if reset:
            c.execute('''UPDATE users SET plan=?, sub_status=?, billing_interval=?,
                         downloads_used=0, period_start=? WHERE id=?''',
                      (plan, status, billing_interval, datetime.utcnow().isoformat(), uid))
        else:
            c.execute('UPDATE users SET plan=?, sub_status=?, billing_interval=? WHERE id=?',
                      (plan, status, billing_interval, uid))
        updated = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    notion_sync_user_async(updated)
    plan_label = PLAN_LABELS.get(plan, plan or 'free')
    return jsonify({'ok': True, 'msg': f'Plan {plan_label} asignado a {target["name"] or target["email"]}'})


@app.route('/admin/delete-user', methods=['POST'])
@login_required
def admin_delete_user():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    data = request.get_json() or {}
    uid  = int(data.get('uid', 0))
    if not uid:
        return jsonify({'error': 'UID inválido'}), 400
    with _db() as c:
        target = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        if not target:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        if target['role'] == 'admin':
            return jsonify({'error': 'No se puede eliminar un admin'}), 400
        # Archive in Notion before deleting
        _notion_archive_user(dict(target))
        # Remove related data
        c.execute('DELETE FROM downloads WHERE user_id=?', (uid,))
        c.execute('DELETE FROM extra_credits WHERE user_id=?', (uid,))
        c.execute('DELETE FROM single_purchases WHERE user_id=?', (uid,))
        c.execute('DELETE FROM download_packs WHERE user_id=?', (uid,))
        c.execute('DELETE FROM referral_codes WHERE user_id=?', (uid,))
        c.execute('DELETE FROM referral_uses WHERE referred_user_id=?', (uid,))
        c.execute('DELETE FROM folio_alerts WHERE user_id=?', (uid,))
        c.execute('DELETE FROM abandoned_carts WHERE user_id=?', (uid,))
        c.execute('DELETE FROM corporate_members WHERE owner_id=? OR member_id=?', (uid, uid))
        c.execute('DELETE FROM analytics_events WHERE user_id=?', (uid,))
        c.execute('DELETE FROM password_reset_tokens WHERE user_id=?', (uid,))
        c.execute('DELETE FROM users WHERE id=?', (uid,))
    return jsonify({'ok': True, 'msg': f'Usuario {target["name"] or target["email"]} eliminado'})


@app.route('/admin/user-detail/<int:uid>')
@login_required
def admin_user_detail(uid):
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    with _db() as c:
        target = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        if not target:
            return jsonify({'error': 'No encontrado'}), 404
        downloads = c.execute(
            'SELECT folio_real, nombre, ts FROM downloads WHERE user_id=? ORDER BY ts DESC LIMIT 30', (uid,)
        ).fetchall()
        packs = c.execute(
            'SELECT pack_type, credits_total, credits_used, ts FROM download_packs WHERE user_id=? ORDER BY ts DESC', (uid,)
        ).fetchall()
        team = c.execute(
            '''SELECT cm.invite_email as email, us.name as name FROM corporate_members cm
               LEFT JOIN users us ON us.id = cm.member_id
               WHERE cm.owner_id=? AND cm.active=1''', (uid,)
        ).fetchall()
        pack_credits = 0
        prows = c.execute('SELECT credits_total, credits_used FROM download_packs WHERE user_id=?', (uid,)).fetchall()
        for p in prows:
            pack_credits += (p['credits_total'] - p['credits_used'])
    t = dict(target)
    return jsonify({
        'id': t['id'], 'name': t['name'], 'email': t['email'], 'plan': t['plan'],
        'sub_status': t['sub_status'], 'billing_interval': t.get('billing_interval'),
        'created_at': t['created_at'], 'trial_ends': t.get('trial_ends'),
        'downloads_used': t['downloads_used'], 'pack_credits': pack_credits,
        'stripe_customer_id': t.get('stripe_customer_id'),
        'stripe_sub_id': t.get('stripe_sub_id'),
        'downloads': [{'folio': d['folio_real'], 'nombre': d['nombre'], 'ts': d['ts']} for d in downloads],
        'packs': [{'pack_type': p['pack_type'], 'credits_total': p['credits_total'], 'credits_used': p['credits_used'], 'ts': p['ts']} for p in packs],
        'team_members': [{'email': m['email'], 'name': m['name']} for m in team],
    })


@app.route('/admin/activity-log')
@login_required
def admin_activity_log():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    results = []
    with _db() as c:
        # Recent downloads
        dls = c.execute(
            '''SELECT d.ts, d.folio_real, d.nombre, u.name, u.email
               FROM downloads d JOIN users u ON u.id=d.user_id
               ORDER BY d.ts DESC LIMIT 25'''
        ).fetchall()
        for d in dls:
            desc = d['folio_real'] or d['nombre'] or ''
            results.append({'ts': d['ts'], 'name': d['name'], 'email': d['email'],
                           'type': 'download', 'desc': 'Descarga: ' + desc})
        # Recent analytics events (searches, logins)
        evts = c.execute(
            '''SELECT a.ts, a.event, a.meta, u.name, u.email
               FROM analytics_events a JOIN users u ON u.id=a.user_id
               ORDER BY a.ts DESC LIMIT 25'''
        ).fetchall()
        for e in evts:
            etype = 'search' if 'search' in (e['event'] or '') else 'login'
            desc = (e['event'] or '') + (': ' + e['meta'] if e['meta'] else '')
            results.append({'ts': e['ts'], 'name': e['name'], 'email': e['email'],
                           'type': etype, 'desc': desc})
    results.sort(key=lambda x: x.get('ts') or '', reverse=True)
    return jsonify(results[:50])


@app.route('/admin/user-dl-ranking')
@login_required
def admin_user_dl_ranking():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    month_start = datetime.utcnow().replace(day=1).strftime('%Y-%m-%d')
    with _db() as c:
        rows = c.execute(
            '''SELECT u.name, u.email, COUNT(*) as cnt
               FROM downloads d JOIN users u ON u.id=d.user_id
               WHERE d.ts >= ? GROUP BY d.user_id ORDER BY cnt DESC LIMIT 20''', (month_start,)
        ).fetchall()
    return jsonify([{'name': r['name'], 'email': r['email'], 'count': r['cnt']} for r in rows])


@app.route('/admin/grant-credits', methods=['POST'])
@login_required
def admin_grant_credits():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    data = request.get_json() or {}
    uid = int(data.get('uid', 0))
    qty = int(data.get('qty', 0))
    if not uid or qty < 1:
        return jsonify({'error': 'Datos invalidos'}), 400
    with _db() as c:
        target = c.execute('SELECT name, email FROM users WHERE id=?', (uid,)).fetchone()
        if not target:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        c.execute(
            'INSERT INTO download_packs(user_id, pack_type, credits_total, credits_used, payment_intent, ts) VALUES(?,?,?,?,?,?)',
            (uid, 'regalo_admin', qty, 0, 'admin_grant', datetime.utcnow().isoformat())
        )
    # Send notification email
    name = target['name'] or ''
    email = target['email']
    html = f"""<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:520px;margin:0 auto;background:#0d0d14;padding:2rem;border-radius:16px">
      <div style="text-align:center;margin-bottom:1.5rem">
        <h2 style="color:#c084fc;margin:0;font-size:1.5rem">Consulta RPP</h2>
      </div>
      <div style="background:#13131f;border:1.5px solid #2a2a3a;border-radius:12px;padding:1.5rem;text-align:center">
        <div style="font-size:2.5rem;margin-bottom:.5rem">🎁</div>
        <h3 style="color:#4ade80;font-size:1.25rem;margin-bottom:.5rem">Recibiste {qty} descargas gratis</h3>
        <p style="color:#ccc;font-size:.9375rem;line-height:1.6;margin-bottom:1rem">
          Hola{(' ' + name) if name else ''}, te hemos otorgado
          <strong style="color:#4ade80">{qty} descargas gratuitas</strong>
          de escrituras del RPP Chihuahua.
        </p>
        <div style="background:#0d0d14;border:1px solid #1e1e2e;border-radius:10px;padding:1rem;margin-bottom:1.2rem">
          <p style="color:#888;font-size:.8125rem;margin-bottom:.6rem">Tus descargas se aplican automaticamente:</p>
          <p style="color:#dde0e8;font-size:.875rem;margin-bottom:.3rem">1. Inicia sesion en <strong style="color:#8b9cf4">consulta-rpp.javisnes.com</strong></p>
          <p style="color:#dde0e8;font-size:.875rem;margin-bottom:.3rem">2. Busca por folio real o nombre de propietario</p>
          <p style="color:#dde0e8;font-size:.875rem;margin-bottom:0">3. Descarga la escritura que necesites</p>
        </div>
        <p style="color:#888;font-size:.8125rem">Tus creditos no expiran y se usan automaticamente al descargar.</p>
        <a href="https://consulta-rpp.javisnes.com" style="display:inline-block;margin-top:1rem;background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;text-decoration:none;padding:.65rem 1.8rem;border-radius:25px;font-weight:700;font-size:.9375rem">Ir a Consulta RPP</a>
      </div>
      <p style="text-align:center;color:#333;font-size:.7rem;margin-top:1.5rem">Consulta RPP by Javisness - consulta-rpp.javisnes.com</p>
    </div>"""
    threading.Thread(target=_smtp_send, args=(email, f'🎁 Recibiste {qty} descargas gratis - Consulta RPP', html), daemon=True).start()
    return jsonify({'ok': True, 'msg': f'{qty} descargas otorgadas a {target["name"] or target["email"]}'})


@app.route('/admin/payouts')
@login_required
def admin_payouts():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    if not _stripe.api_key:
        return jsonify({'error': 'Stripe no configurado'}), 400
    try:
        payouts = []
        for p in _stripe.Payout.list(limit=20).auto_paging_iter():
            payouts.append({
                'id':           p.id,
                'amount':       p.amount,
                'currency':     p.currency,
                'status':       p.status,
                'arrival_date': p.arrival_date,
                'created':      p.created,
                'description':  p.description or '',
            })
        balance = _stripe.Balance.retrieve()
        avail   = sum(b.amount for b in balance.available if b.currency == 'mxn') or \
                  sum(b.amount for b in balance.available)
        pending = sum(b.amount for b in balance.pending  if b.currency == 'mxn') or \
                  sum(b.amount for b in balance.pending)
        return jsonify({'payouts': payouts, 'balance_available': avail, 'balance_pending': pending})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/send-mass-email', methods=['POST'])
@login_required
def admin_send_mass_email():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    data = request.get_json() or {}
    target  = data.get('target', 'all')
    subject = data.get('subject', '').strip()
    body    = data.get('body', '').strip()
    if not subject or not body:
        return jsonify({'error': 'Asunto y mensaje requeridos'}), 400
    with _db() as c:
        if target == 'active':
            users = c.execute("SELECT email, name FROM users WHERE sub_status='active'").fetchall()
        elif target == 'trial':
            users = c.execute("SELECT email, name FROM users WHERE trial_ends > ? AND sub_status != 'active'",
                            (datetime.utcnow().isoformat(),)).fetchall()
        elif target == 'free':
            users = c.execute("SELECT email, name FROM users WHERE (sub_status IS NULL OR sub_status != 'active') AND role != 'admin'").fetchall()
        else:
            users = c.execute("SELECT email, name FROM users").fetchall()
    sent = 0
    for usr in users:
        html = f"""<div style="font-family:sans-serif;max-width:560px;margin:0 auto;background:#0d0d14;color:#dde0e8;padding:2rem;border-radius:12px">
            <div style="text-align:center;margin-bottom:1.5rem">
                <h2 style="color:#c084fc;margin:0">Consulta RPP</h2>
            </div>
            <p style="color:#dde0e8">Hola{(' ' + usr['name']) if usr['name'] else ''},</p>
            <div style="color:#ccc;line-height:1.7;margin:1rem 0">{body}</div>
            <hr style="border:none;border-top:1px solid #2a2a3a;margin:1.5rem 0">
            <p style="font-size:.75rem;color:#555;text-align:center">Consulta RPP - consulta-rpp.javisnes.com</p>
        </div>"""
        try:
            if _smtp_send(usr['email'], subject, html):
                sent += 1
        except Exception:
            pass
    return jsonify({'ok': True, 'sent': sent, 'total': len(users)})


def _notion_archive_user(user_row):
    """Archive (set to deleted status) a user page in Notion."""
    if not NOTION_API_KEY:
        return
    try:
        headers = {
            'Authorization': f'Bearer {NOTION_API_KEY}',
            'Notion-Version': '2022-06-28',
            'Content-Type': 'application/json',
        }
        # Find page by email
        search_body = json.dumps({
            "filter": {"property": "Email", "email": {"equals": user_row['email']}},
        }).encode()
        req = urllib.request.Request(
            f'https://api.notion.com/v1/databases/{NOTION_DB_ID}/query',
            data=search_body, headers=headers, method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.loads(resp.read())['results']
        if results:
            page_id = results[0]['id']
            # Update status to "deleted" and archive the page
            body = json.dumps({
                "archived": True,
                "properties": {
                    "Estado Suscripción": {"select": {"name": "deleted"}},
                }
            }).encode()
            req = urllib.request.Request(
                f'https://api.notion.com/v1/pages/{page_id}',
                data=body, headers=headers, method='PATCH'
            )
            urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f'[Notion archive error] {e}')


@app.route('/admin/sync-notion', methods=['POST'])
@login_required
def sync_notion():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    with _db() as c:
        users = c.execute('SELECT * FROM users ORDER BY id').fetchall()
    for row in users:
        notion_sync_user_async(row)
    return jsonify({'synced': len(users), 'status': 'ok'})


@app.route('/admin/pool-stats')
@login_required
def pool_stats():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    disk_count = 0
    try:
        disk_count = len([f for f in os.listdir(_DISK_CACHE_DIR) if f.endswith('.pdf')])
    except Exception:
        pass
    return jsonify({
        'browser': _rpp_pool_stats,
        'last_login_ago': int(time.time() - _rpp_login_time) if _rpp_login_time else None,
        'cache_memory': len(_pdf_cache),
        'cache_disk': disk_count,
        'cache_ttl_hours': PDF_CACHE_TTL // 3600,
    })


@app.route('/admin/realtime-metrics')
@login_required
def realtime_metrics():
    """Real-time metrics for admin dashboard."""
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    now = datetime.utcnow()
    hour_ago  = (now - timedelta(hours=1)).isoformat()[:19]
    day_ago   = (now - timedelta(days=1)).isoformat()[:19]
    month_start = now.replace(day=1).strftime('%Y-%m-%d')
    with _db() as c:
        # Downloads per hour (last 24h, grouped by hour)
        dl_per_hour = c.execute(
            "SELECT strftime('%H', ts) as h, COUNT(*) as cnt FROM downloads "
            "WHERE ts >= ? GROUP BY h ORDER BY h",
            (day_ago,)
        ).fetchall()
        # RPP metrics last 24h
        rpp_total   = c.execute("SELECT COUNT(*) FROM rpp_metrics WHERE ts >= ?", (day_ago,)).fetchone()[0]
        rpp_errors  = c.execute("SELECT COUNT(*) FROM rpp_metrics WHERE ts >= ? AND success=0", (day_ago,)).fetchone()[0]
        rpp_avg_ms  = c.execute("SELECT AVG(duration_ms) FROM rpp_metrics WHERE ts >= ? AND success=1 AND duration_ms > 0", (day_ago,)).fetchone()[0]
        # Active users (made a download in last hour)
        active_now  = c.execute("SELECT COUNT(DISTINCT user_id) FROM downloads WHERE ts >= ?", (hour_ago,)).fetchone()[0]
        # Downloads today
        dl_today    = c.execute("SELECT COUNT(*) FROM downloads WHERE date(ts) = date('now')", ).fetchone()[0]
        # Searches today
        searches_today = c.execute("SELECT COUNT(*) FROM analytics_events WHERE event LIKE 'search%' AND date(ts)=date('now')").fetchone()[0]
        # Queue jobs running
        with _jobs_lock:
            jobs_snapshot = list(_jobs.values())
        jobs_running = sum(1 for j in jobs_snapshot if j.get('status') == 'running')
        jobs_done    = sum(1 for j in jobs_snapshot if j.get('status') == 'done')
        # Audit log last 10
        audit_rows  = c.execute(
            "SELECT a.action, a.detail, a.ip, a.ts, u.email FROM audit_log a "
            "LEFT JOIN users u ON u.id=a.user_id ORDER BY a.ts DESC LIMIT 10"
        ).fetchall()
        # Recent errors
        rpp_recent_errors = c.execute(
            "SELECT folio, error_msg, ts FROM rpp_metrics WHERE success=0 ORDER BY ts DESC LIMIT 5"
        ).fetchall()
    disk_count = 0
    try:
        disk_count = len([f for f in os.listdir(_DISK_CACHE_DIR) if f.endswith('.pdf')])
    except Exception:
        pass
    return jsonify({
        'rpp_status': _rpp_status,
        'rpp_stats': {
            'total_24h': rpp_total,
            'errors_24h': rpp_errors,
            'error_rate': round(rpp_errors / rpp_total * 100, 1) if rpp_total else 0,
            'avg_ms': int(rpp_avg_ms or 0),
        },
        'rpp_recent_errors': [{'folio': r['folio'], 'error': r['error_msg'], 'ts': r['ts']} for r in rpp_recent_errors],
        'activity': {
            'active_users_1h': active_now,
            'downloads_today': dl_today,
            'searches_today': searches_today,
            'jobs_running': jobs_running,
            'jobs_done': jobs_done,
        },
        'dl_per_hour': [{'hour': r['h'], 'count': r['cnt']} for r in dl_per_hour],
        'cache': {'memory': len(_pdf_cache), 'disk': disk_count},
        'browser': _rpp_pool_stats,
        'audit_log': [{'action': r['action'], 'detail': r['detail'], 'ip': r['ip'], 'ts': r['ts'], 'email': r['email']} for r in audit_rows],
    })


# ── IA Dashboard endpoints ────────────────────────────────────────────────────

def _stripe_mrr_now():
    """MRR real desde Stripe (subscripciones activas). Retorna int MXN o None si falla."""
    if not _stripe.api_key:
        return None
    try:
        total_cents = 0
        params = {'status': 'active', 'limit': 100, 'expand': ['data.items.data.price']}
        while True:
            subs = _stripe.Subscription.list(**params)
            for sub in subs.auto_paging_iter():
                for item in sub['items']['data']:
                    price = item.get('price') or {}
                    amount = price.get('unit_amount') or 0
                    recurring = price.get('recurring') or {}
                    interval  = recurring.get('interval', 'month')
                    interval_count = recurring.get('interval_count', 1) or 1
                    if interval == 'year':
                        amount = amount // 12
                    elif interval_count > 1:
                        amount = amount // interval_count
                    total_cents += amount
            break  # auto_paging_iter handles pagination
        return total_cents // 100  # centavos a MXN entero
    except Exception as e:
        app.logger.warning(f'[Stripe MRR] {e}')
        return None


def _stripe_mrr_history(months=12):
    """Ingresos mensuales reales de Stripe usando invoices pagadas."""
    if not _stripe.api_key:
        return None
    try:
        now = datetime.utcnow()
        cutoff = int((now - timedelta(days=months * 31)).timestamp())
        history = {}
        for inv in _stripe.Invoice.list(status='paid', limit=100, created={'gte': cutoff}).auto_paging_iter():
            mo = datetime.fromtimestamp(inv['created']).strftime('%Y-%m')
            history[mo] = history.get(mo, 0) + (inv.get('amount_paid') or 0)
        result = []
        for i in range(months - 1, -1, -1):
            mo = (now.replace(day=1) - timedelta(days=i * 30)).strftime('%Y-%m')
            result.append({'month': mo, 'mrr': history.get(mo, 0) // 100})
        return result
    except Exception as e:
        app.logger.warning(f'[Stripe MRR history] {e}')
        return None


@app.route('/admin/dashboard-data')
@login_required
def admin_dashboard_data():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    now = datetime.utcnow()

    # ── Stripe data (real) ────────────────────────────────────────────────────
    stripe_mrr     = _stripe_mrr_now()           # int MXN o None
    stripe_history = _stripe_mrr_history(12)     # lista o None

    with _db() as c:
        # MRR history fallback (DB) si Stripe falla o no hay invoices
        db_mrr_history = []
        for i in range(11, -1, -1):
            mo_start = (now.replace(day=1) - timedelta(days=i * 30)).strftime('%Y-%m')
            mo_end   = (now.replace(day=1) - timedelta(days=max(i-1,0) * 30)).strftime('%Y-%m')
            rows = c.execute(
                "SELECT plan FROM users WHERE sub_status='active' AND period_start <= ?",
                (mo_end + '-31',)
            ).fetchall()
            db_mrr_history.append({'month': mo_start, 'mrr': sum(PLAN_PRICES.get(r['plan'], 0) for r in rows)})

        # User growth last 12 months
        user_growth = []
        for i in range(11, -1, -1):
            mo = (now.replace(day=1) - timedelta(days=i * 30)).strftime('%Y-%m')
            signups = c.execute(
                "SELECT COUNT(*) FROM users WHERE strftime('%Y-%m', created_at) = ?", (mo,)
            ).fetchone()[0]
            active = c.execute(
                "SELECT COUNT(*) FROM users WHERE sub_status='active' AND strftime('%Y-%m', period_start) <= ?", (mo,)
            ).fetchone()[0]
            user_growth.append({'month': mo, 'signups': signups, 'active': active})

        # Downloads last 30 days
        dl_30d = c.execute(
            "SELECT date(ts) as date, COUNT(*) as count FROM downloads "
            "WHERE ts >= date('now', '-30 days') GROUP BY date(ts) ORDER BY date(ts)"
        ).fetchall()

        # Plan distribution (active)
        plan_dist = c.execute(
            "SELECT plan, COUNT(*) as count FROM users WHERE sub_status='active' GROUP BY plan ORDER BY count DESC"
        ).fetchall()

        # KPIs
        month_start     = now.replace(day=1).strftime('%Y-%m-%d')
        active_subs     = c.execute("SELECT COUNT(*) FROM users WHERE sub_status='active'").fetchone()[0]
        total_non_admin = c.execute("SELECT COUNT(*) FROM users WHERE role != 'admin'").fetchone()[0]
        conversion      = round(active_subs / total_non_admin * 100, 1) if total_non_admin else 0
        churn_mo        = c.execute(
            "SELECT COUNT(*) FROM users WHERE sub_status='canceled' AND period_start >= ?", (month_start,)
        ).fetchone()[0]
        signups_mo      = c.execute("SELECT COUNT(*) FROM users WHERE created_at >= ?", (month_start,)).fetchone()[0]
        dl_mo           = c.execute("SELECT COUNT(*) FROM downloads WHERE ts >= ?", (month_start,)).fetchone()[0]
        # DB MRR estimate (fallback)
        all_active = c.execute("SELECT plan FROM users WHERE sub_status='active'").fetchall()
        db_mrr_now = sum(PLAN_PRICES.get(r['plan'], 0) for r in all_active)

    mrr_now     = stripe_mrr if stripe_mrr is not None else db_mrr_now
    mrr_history = stripe_history if stripe_history else db_mrr_history
    mrr_source  = 'stripe' if stripe_mrr is not None else 'estimado'

    return jsonify({
        'kpis': {
            'mrr': mrr_now,
            'mrr_source': mrr_source,
            'active_subs': active_subs,
            'conversion': conversion,
            'churn_this_month': churn_mo,
            'signups_this_month': signups_mo,
            'downloads_this_month': dl_mo,
        },
        'mrr_history': mrr_history,
        'user_growth': user_growth,
        'dl_30d': [{'date': r['date'], 'count': r['count']} for r in dl_30d],
        'plan_dist': [{'plan': r['plan'], 'count': r['count']} for r in plan_dist],
    })


@app.route('/admin/ai-analysis', methods=['POST'])
@login_required
def admin_ai_analysis():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    if not ANTHROPIC_API_KEY:
        return jsonify({'error': 'Configura ANTHROPIC_API_KEY en el entorno del servidor para usar esta función.'}), 400
    if not _ANTHROPIC_AVAILABLE:
        return jsonify({'error': 'Instala el paquete anthropic: pip install anthropic'}), 400

    now = datetime.utcnow()
    month_start = now.replace(day=1).strftime('%Y-%m-%d')
    with _db() as c:
        total_users     = c.execute("SELECT COUNT(*) FROM users WHERE role != 'admin'").fetchone()[0]
        active_subs     = c.execute("SELECT COUNT(*) FROM users WHERE sub_status='active'").fetchone()[0]
        trial_users     = c.execute("SELECT COUNT(*) FROM users WHERE trial_ends > ?", (now.isoformat()[:19],)).fetchone()[0]
        churn_mo        = c.execute("SELECT COUNT(*) FROM users WHERE sub_status='canceled' AND period_start >= ?", (month_start,)).fetchone()[0]
        signups_mo      = c.execute("SELECT COUNT(*) FROM users WHERE created_at >= ?", (month_start,)).fetchone()[0]
        dl_mo           = c.execute("SELECT COUNT(*) FROM downloads WHERE ts >= ?", (month_start,)).fetchone()[0]
        dl_total        = c.execute("SELECT COUNT(*) FROM downloads").fetchone()[0]
        plan_dist_rows  = c.execute("SELECT plan, COUNT(*) as n FROM users WHERE sub_status='active' GROUP BY plan ORDER BY n DESC").fetchall()
        dl_by_plan_rows = c.execute("SELECT u.plan, COUNT(*) as n FROM downloads d JOIN users u ON u.id=d.user_id WHERE d.ts >= ? GROUP BY u.plan ORDER BY n DESC", (month_start,)).fetchall()
        rpp_errors_24h  = c.execute("SELECT COUNT(*) FROM rpp_metrics WHERE success=0 AND ts >= ?", ((now - timedelta(days=1)).isoformat()[:19],)).fetchone()[0]
        rpp_total_24h   = c.execute("SELECT COUNT(*) FROM rpp_metrics WHERE ts >= ?", ((now - timedelta(days=1)).isoformat()[:19],)).fetchone()[0]
        top_folios      = c.execute("SELECT folio_real, COUNT(*) as n FROM downloads WHERE ts >= ? GROUP BY folio_real ORDER BY n DESC LIMIT 5", (month_start,)).fetchall()
        referral_uses   = c.execute("SELECT COUNT(*) FROM referral_uses WHERE ts >= ?", (month_start,)).fetchone()[0]

    all_active = c.execute("SELECT plan FROM users WHERE sub_status='active'").fetchall() if False else []
    with _db() as c2:
        all_active = c2.execute("SELECT plan FROM users WHERE sub_status='active'").fetchall()
    mrr_now   = sum(PLAN_PRICES.get(r['plan'], 0) for r in all_active)
    conversion = round(active_subs / total_users * 100, 1) if total_users else 0
    error_rate = round(rpp_errors_24h / rpp_total_24h * 100, 1) if rpp_total_24h else 0

    plan_dist_str  = ', '.join(f"{r['plan'] or 'sin_plan'}: {r['n']}" for r in plan_dist_rows)
    dl_by_plan_str = ', '.join(f"{r['plan'] or 'sin_plan'}: {r['n']}" for r in dl_by_plan_rows)
    top_folios_str = ', '.join(f"{r['folio_real']} ({r['n']} veces)" for r in top_folios)

    prompt = f"""Eres un asesor de negocios experto en SaaS B2B. Analiza las métricas de "Consulta RPP Chihuahua" — un servicio de consulta del Registro Público de la Propiedad de Chihuahua, México.
El cliente principal son agentes inmobiliarios, notarios y personas que consultan escrituras.

MÉTRICAS ACTUALES:
- Usuarios registrados: {total_users}
- Suscripciones activas: {active_subs}
- Usuarios en trial: {trial_users}
- MRR estimado: ${mrr_now:,} MXN
- Tasa de conversión (registrado → pago): {conversion}%
- Cancelaciones este mes: {churn_mo}
- Registros nuevos este mes: {signups_mo}
- Descargas totales: {dl_total}
- Descargas este mes: {dl_mo}
- Distribución de planes activos: {plan_dist_str or 'sin datos'}
- Descargas por plan (este mes): {dl_by_plan_str or 'sin datos'}
- Errores RPP últimas 24h: {rpp_errors_24h}/{rpp_total_24h} ({error_rate}%)
- Folios más consultados este mes: {top_folios_str or 'sin datos'}
- Referidos generados este mes: {referral_uses}

PLANES DISPONIBLES:
- Básico: $500/mes · 5 desc
- Pro: $1,000/mes · 10 desc
- Empresarial: $2,000/mes · 20 desc
- Corporativo: $5,000/mes · 100 desc · hasta 10 asesores
- Corporativo Pro: $8,000/mes · 500 desc · usuarios ilimitados

Responde ÚNICAMENTE en JSON con esta estructura exacta (sin markdown, solo JSON puro):
{{
  "salud_negocio": "párrafo de 2-3 oraciones sobre la salud general del negocio",
  "ventas": ["acción concreta 1", "acción concreta 2", "acción concreta 3", "acción concreta 4"],
  "marketing": ["acción concreta 1", "acción concreta 2", "acción concreta 3"],
  "retencion": ["estrategia 1", "estrategia 2", "estrategia 3"],
  "producto": ["mejora 1", "mejora 2", "mejora 3"],
  "riesgos": ["riesgo 1", "riesgo 2"],
  "prioridad_acciones": ["acción #1 más urgente esta semana", "acción #2", "acción #3"]
}}"""

    raw = ''
    try:
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        last_err = None
        for attempt in range(3):
            try:
                msg = client.messages.create(
                    model='claude-sonnet-4-6',
                    max_tokens=4096,
                    messages=[{'role': 'user', 'content': prompt}],
                )
                raw = msg.content[0].text.strip()
                break
            except Exception as e:
                last_err = e
                err_str = str(e)
                # Retry on overload (529) or rate limit (529/529)
                if '529' in err_str or 'overloaded' in err_str.lower() or '529' in repr(e):
                    if attempt < 2:
                        time.sleep(8 * (attempt + 1))
                        continue
                raise
        else:
            return jsonify({'error': f'API de Anthropic sobrecargada. Intenta en unos segundos. ({last_err})'}), 503
        # Strip markdown code fences if present
        if raw.startswith('```'):
            raw = raw.split('\n', 1)[1].rsplit('```', 1)[0].strip()
        analysis = json.loads(raw)
        return jsonify({'analysis': analysis})
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Error al parsear respuesta de IA: {e}', 'raw': raw[:300]}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Referral Dashboard ────────────────────────────────────────────────────────

@app.route('/mis-referidos')
@login_required
def mis_referidos():
    u = current_user()
    with _db() as c:
        # Get referral code
        ref_code = u.get('referral_code', '')
        if not ref_code:
            rc_row = c.execute('SELECT code FROM referral_codes WHERE user_id=?', (u['id'],)).fetchone()
            ref_code = rc_row['code'] if rc_row else ''

        # Get referred users
        referred = c.execute('''
            SELECT ru.ts, u.name, u.email, u.plan, u.sub_status
            FROM referral_uses ru
            JOIN referral_codes rc ON rc.code = ru.code
            LEFT JOIN users u ON u.id = ru.referred_user_id
            WHERE rc.user_id = ?
            ORDER BY ru.ts DESC
        ''', (u['id'],)).fetchall()

        # Count earned credits
        earned_credits = c.execute(
            "SELECT COUNT(*) FROM extra_credits WHERE user_id=? AND payment_intent LIKE 'referral_%'",
            (u['id'],)).fetchone()[0]

        # Count used referral credits
        used_ref_credits = c.execute(
            "SELECT COUNT(*) FROM extra_credits WHERE user_id=? AND payment_intent LIKE 'referral_%' AND used=1",
            (u['id'],)).fetchone()[0]

    avail_credits = earned_credits - used_ref_credits
    ref_link = f'https://consulta-rpp.javisnes.com/r/{ref_code}' if ref_code else ''

    referred_html = ''
    for r in referred:
        name = r['name'] or r['email'] or 'Usuario'
        email_masked = r['email'][:3] + '***' + r['email'][r['email'].index('@'):] if r['email'] and '@' in r['email'] else ''
        plan_badge = f'<span style="background:#1a1a2e;color:#8b9cf4;padding:.15rem .45rem;border-radius:4px;font-size:.7rem">{r["plan"] or "free"}</span>' if r['plan'] else ''
        status_dot = '<span style="color:#4ade80">●</span>' if r['sub_status'] == 'active' else '<span style="color:#666">●</span>'
        date_str = r['ts'][:10] if r['ts'] else ''
        referred_html += f'''
        <div style="display:flex;align-items:center;justify-content:space-between;padding:.75rem;background:#0f0f1c;border:1px solid #1a1a2a;border-radius:10px;margin-bottom:.5rem">
          <div style="display:flex;align-items:center;gap:.6rem">
            {status_dot}
            <div>
              <div style="font-weight:600;font-size:.85rem">{name}</div>
              <div style="font-size:.72rem;color:#555">{email_masked}</div>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:.6rem">
            {plan_badge}
            <span style="font-size:.72rem;color:#555">{date_str}</span>
            <span style="color:#4ade80;font-weight:700;font-size:.8rem">+1 🎁</span>
          </div>
        </div>'''

    if not referred:
        referred_html = '''
        <div style="text-align:center;padding:2.5rem 1rem;color:#555">
          <div style="font-size:2.5rem;margin-bottom:.75rem">🎁</div>
          <p style="font-size:.9rem;margin-bottom:.5rem">Aún no tienes referidos</p>
          <p style="font-size:.78rem;color:#444">Comparte tu link y ambos reciben +1 descarga gratis</p>
        </div>'''

    page = f'''<!DOCTYPE html>
<html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Mis Referidos — Consulta RPP</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d0d14;color:#dde0e8;min-height:100vh}}
.wrap{{max-width:700px;margin:0 auto;padding:1.5rem}}
a{{color:#8b9cf4;text-decoration:none}}
.back{{display:inline-flex;align-items:center;gap:.4rem;font-size:.85rem;color:#666;margin-bottom:1.5rem}}
.back:hover{{color:#8b9cf4}}
h1{{font-size:1.5rem;font-weight:800;margin-bottom:.3rem;background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.subtitle{{color:#555;font-size:.85rem;margin-bottom:1.5rem}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:.75rem;margin-bottom:1.75rem}}
.stat-card{{background:#13131f;border:1px solid #1e1e2e;border-radius:12px;padding:1rem;text-align:center}}
.stat-val{{font-size:1.8rem;font-weight:800;margin-bottom:.2rem}}
.stat-lbl{{font-size:.72rem;color:#666}}
.link-box{{background:linear-gradient(135deg,#13131f,#0f0f1c);border:1.5px solid #2a1a4a;border-radius:14px;padding:1.25rem;margin-bottom:1.75rem}}
.link-row{{display:flex;align-items:center;gap:.5rem;margin-top:.75rem}}
.link-input{{flex:1;background:#0a0a14;border:1px solid #2a2a3a;border-radius:8px;padding:.55rem .75rem;color:#8b9cf4;font-size:.82rem;font-family:monospace}}
.btn-copy{{background:#6366f1;color:#fff;border:none;border-radius:8px;padding:.55rem 1rem;font-size:.82rem;font-weight:600;cursor:pointer}}
.btn-copy:hover{{background:#5558e6}}
.section-title{{font-size:1rem;font-weight:700;margin-bottom:.75rem;color:#ccc}}
.share-btns{{display:flex;gap:.5rem;margin-top:.75rem;flex-wrap:wrap}}
.share-btn{{display:inline-flex;align-items:center;gap:.35rem;padding:.4rem .8rem;border-radius:8px;font-size:.78rem;font-weight:600;border:none;cursor:pointer;text-decoration:none}}
.share-wa{{background:#25d366;color:#fff}}
.share-email{{background:#1a1a2e;color:#8b9cf4;border:1px solid #2a2a4a}}
.theme-btn{{position:fixed;top:1rem;right:1rem;background:#1a1a2e;border:1px solid #2a2a4a;color:#8b9cf4;border-radius:8px;padding:.35rem .7rem;font-size:.8rem;cursor:pointer;z-index:100}}
body.light{{background:#f4f4f9;color:#1a1a2a}}
body.light .stat-card{{background:#fff;border-color:#e0e0ee}}
body.light .link-box{{background:#fff;border-color:#c5c9f0}}
body.light .link-input{{background:#f0f0f8;border-color:#d0d0e8;color:#333}}
body.light .section-title{{color:#333}}
body.light .share-email{{background:#f0f0f8;border-color:#d0d0e8}}
body.light .back{{color:#999}}
body.light .theme-btn{{background:#fff;border-color:#e0e0ee;color:#6366f1}}
</style></head><body>
<button class="theme-btn" id="theme-toggle-btn" onclick="toggleTheme()">☀ Claro</button>
<div class="wrap">
  <a href="/" class="back">← Volver</a>
  <h1>🎁 Mis Referidos</h1>
  <p class="subtitle">Comparte tu link y gana descargas gratis por cada persona que se registre</p>

  <div class="stats">
    <div class="stat-card">
      <div class="stat-val" style="color:#c084fc">{len(referred)}</div>
      <div class="stat-lbl">Referidos totales</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#4ade80">{earned_credits}</div>
      <div class="stat-lbl">Descargas ganadas</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#8b9cf4">{avail_credits}</div>
      <div class="stat-lbl">Disponibles</div>
    </div>
  </div>

  <div class="link-box">
    <div style="font-weight:700;font-size:.9rem">Tu link de referido</div>
    <div style="font-size:.78rem;color:#666;margin-top:.2rem">Cada registro con tu link = +1 descarga gratis para ambos</div>
    <div class="link-row">
      <input class="link-input" id="ref-link" value="{ref_link}" readonly onclick="this.select()">
      <button class="btn-copy" onclick="navigator.clipboard.writeText(document.getElementById('ref-link').value);this.textContent='Copiado!';setTimeout(()=>this.textContent='Copiar',2000)">Copiar</button>
    </div>
    <div class="share-btns">
      <a href="https://wa.me/?text=Consulta%20escrituras%20del%20RPP%20Chihuahua%20al%20instante.%20Reg%C3%ADstrate%20con%20mi%20link%20y%20ambos%20recibimos%20una%20descarga%20gratis%3A%20{ref_link}" target="_blank" class="share-btn share-wa">WhatsApp</a>
      <a href="mailto:?subject=Consulta%20RPP%20Chihuahua&body=Hola!%20Te%20comparto%20esta%20herramienta%20para%20consultar%20escrituras%20del%20RPP.%20Si%20te%20registras%20con%20mi%20link%20ambos%20recibimos%20una%20descarga%20gratis%3A%20{ref_link}" class="share-btn share-email">Email</a>
    </div>
  </div>

  <div class="section-title">Personas referidas ({len(referred)})</div>
  {referred_html}
</div>
<script>
(function(){{
  const t = localStorage.getItem('rpp_theme');
  if (t === 'light') {{ document.body.classList.add('light'); const b = document.getElementById('theme-toggle-btn'); if(b) b.textContent='🌙 Oscuro'; }}
}})();
function toggleTheme() {{
  const isLight = document.body.classList.toggle('light');
  localStorage.setItem('rpp_theme', isLight ? 'light' : 'dark');
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = isLight ? '🌙 Oscuro' : '☀ Claro';
}}
</script>
</body></html>'''
    return render_template_string(page)


# ── Historial de consultas ───────────────────────────────────────────────────

@app.route('/historial')
@login_required
def historial():
    u = current_user()
    page_num = int(request.args.get('page', 1))
    per_page = 50
    offset = (page_num - 1) * per_page

    with _db() as c:
        total = c.execute('SELECT COUNT(*) FROM downloads WHERE user_id=?', (u['id'],)).fetchone()[0]
        rows = c.execute(
            'SELECT folio_real, nombre, ts FROM downloads WHERE user_id=? ORDER BY ts DESC LIMIT ? OFFSET ?',
            (u['id'], per_page, offset)).fetchall()

    total_pages = max(1, (total + per_page - 1) // per_page)

    rows_html = ''
    for r in rows:
        folio = r['folio_real'] or ''
        nombre = r['nombre'] or ''
        ts = r['ts'][:16].replace('T', ' ') if r['ts'] else ''
        # Check if folio is in cache for re-download
        in_cache = folio in _pdf_cache and time.time() - _pdf_cache[folio]['ts'] < PDF_CACHE_TTL
        cache_badge = '<span style="color:#4ade80;font-size:.7rem;font-weight:600">● En cache</span>' if in_cache else ''
        redownload_btn = f'<button onclick="redownloadFolio(\'{folio}\')" style="background:#1a1a2e;color:#8b9cf4;border:1px solid #2a2a4a;border-radius:6px;padding:.25rem .6rem;font-size:.72rem;cursor:pointer">🔄 Re-descargar</button>' if in_cache else f'<button onclick="redownloadFolio(\'{folio}\')" style="background:#1a1a2e;color:#666;border:1px solid #1a1a2a;border-radius:6px;padding:.25rem .6rem;font-size:.72rem;cursor:pointer" title="Buscar de nuevo (consume crédito)">🔍 Buscar</button>'
        rows_html += f'''
        <div style="display:flex;align-items:center;justify-content:space-between;padding:.65rem .75rem;background:#0f0f1c;border:1px solid #1a1a2a;border-radius:10px;margin-bottom:.4rem">
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:.5rem">
              <span style="font-weight:700;color:#8b9cf4;font-size:.9rem">{folio}</span>
              {cache_badge}
            </div>
            <div style="font-size:.72rem;color:#555;margin-top:.15rem">{nombre} · {ts}</div>
          </div>
          {redownload_btn}
        </div>'''

    if not rows:
        rows_html = '''
        <div style="text-align:center;padding:2.5rem 1rem;color:#555">
          <div style="font-size:2.5rem;margin-bottom:.75rem">📋</div>
          <p style="font-size:.9rem">Sin descargas registradas</p>
        </div>'''

    # Pagination
    pag_html = ''
    if total_pages > 1:
        pag_html = '<div style="display:flex;justify-content:center;gap:.4rem;margin-top:1rem">'
        if page_num > 1:
            pag_html += f'<a href="/historial?page={page_num-1}" style="padding:.4rem .7rem;background:#1a1a2e;border:1px solid #2a2a4a;border-radius:6px;font-size:.8rem;color:#8b9cf4">← Anterior</a>'
        pag_html += f'<span style="padding:.4rem .7rem;font-size:.8rem;color:#666">Pág. {page_num} de {total_pages}</span>'
        if page_num < total_pages:
            pag_html += f'<a href="/historial?page={page_num+1}" style="padding:.4rem .7rem;background:#1a1a2e;border:1px solid #2a2a4a;border-radius:6px;font-size:.8rem;color:#8b9cf4">Siguiente →</a>'
        pag_html += '</div>'

    page = f'''<!DOCTYPE html>
<html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Historial — Consulta RPP</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d0d14;color:#dde0e8;min-height:100vh}}
.wrap{{max-width:700px;margin:0 auto;padding:1.5rem}}
a{{color:#8b9cf4;text-decoration:none}}
.back{{display:inline-flex;align-items:center;gap:.4rem;font-size:.85rem;color:#666;margin-bottom:1.5rem}}
.back:hover{{color:#8b9cf4}}
h1{{font-size:1.5rem;font-weight:800;margin-bottom:.3rem}}
.subtitle{{color:#555;font-size:.85rem;margin-bottom:1.5rem}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:.75rem;margin-bottom:1.5rem}}
.stat-card{{background:#13131f;border:1px solid #1e1e2e;border-radius:12px;padding:.85rem;text-align:center}}
.stat-val{{font-size:1.4rem;font-weight:800}}
.stat-lbl{{font-size:.7rem;color:#666}}
.search-bar{{display:flex;gap:.5rem;margin-bottom:1rem}}
.search-bar input{{flex:1;background:#0f0f1c;border:1px solid #1e1e2e;border-radius:8px;padding:.5rem .75rem;color:#dde0e8;font-size:.85rem}}
.theme-btn{{position:fixed;top:1rem;right:1rem;background:#1a1a2e;border:1px solid #2a2a4a;color:#8b9cf4;border-radius:8px;padding:.35rem .7rem;font-size:.8rem;cursor:pointer;z-index:100}}
body.light{{background:#f4f4f9;color:#1a1a2a}}
body.light .stat-card{{background:#fff;border-color:#e0e0ee}}
body.light .search-bar input{{background:#fff;border-color:#e0e0ee;color:#1a1a2a}}
body.light .back{{color:#999}}
body.light .theme-btn{{background:#fff;border-color:#e0e0ee;color:#6366f1}}
</style></head><body>
<button class="theme-btn" id="theme-toggle-btn" onclick="toggleTheme()">☀ Claro</button>
<div class="wrap">
  <a href="/" class="back">← Volver</a>
  <h1>📋 Historial de Consultas</h1>
  <p class="subtitle">Todas tus búsquedas y descargas pasadas · {total} registros</p>

  <div class="stats">
    <div class="stat-card">
      <div class="stat-val" style="color:#8b9cf4">{total}</div>
      <div class="stat-lbl">Total descargas</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#4ade80">{len([f for f in _pdf_cache if time.time() - _pdf_cache[f]['ts'] < PDF_CACHE_TTL])}</div>
      <div class="stat-lbl">En cache (gratis)</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#c084fc">{len(rows)}</div>
      <div class="stat-lbl">Mostrando</div>
    </div>
  </div>

  <div class="search-bar">
    <input type="text" id="hist-filter" placeholder="Filtrar por folio o nombre..." oninput="filterHist()">
  </div>

  <div id="hist-rows">
  {rows_html}
  </div>

  {pag_html}
</div>

<script>
(function(){{
  const t = localStorage.getItem('rpp_theme');
  if (t === 'light') {{ document.body.classList.add('light'); const b = document.getElementById('theme-toggle-btn'); if(b) b.textContent='🌙 Oscuro'; }}
}})();
function toggleTheme() {{
  const isLight = document.body.classList.toggle('light');
  localStorage.setItem('rpp_theme', isLight ? 'light' : 'dark');
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = isLight ? '🌙 Oscuro' : '☀ Claro';
}}
function filterHist() {{
  const q = document.getElementById('hist-filter').value.toLowerCase();
  document.querySelectorAll('#hist-rows > div').forEach(el => {{
    el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}

async function redownloadFolio(folio) {{
  if (!confirm('Buscar folio ' + folio + '? Si no está en cache consumirá 1 crédito.')) return;
  try {{
    const r = await fetch('/buscar', {{
      method: 'POST',
      headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{folio: folio}})
    }});
    if (!r.ok) {{ alert('Error: ' + (await r.json()).error); return; }}
    const {{job_id}} = await r.json();
    // Poll for completion
    const poll = setInterval(async () => {{
      const sr = await fetch('/status/' + job_id);
      const s = await sr.json();
      if (s.status === 'done') {{
        clearInterval(poll);
        window.location.href = '/download/' + job_id;
      }} else if (s.status === 'error') {{
        clearInterval(poll);
        alert('Error: ' + s.error);
      }}
    }}, 2000);
  }} catch(e) {{ alert('Error de red'); }}
}}
</script>
</body></html>'''
    return render_template_string(page)


# ── Re-download from cache (free) ───────────────────────────────────────────

@app.route('/redownload/<folio>')
@login_required
def redownload_folio(folio):
    """Download a folio from cache without consuming a credit."""
    cached = _get_cached_pdf(folio)
    if not cached:
        return jsonify({'error': 'No está en cache. Usa la búsqueda normal.'}), 404
    return send_file(
        io.BytesIO(cached),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'folio_{folio}_sin_marca.pdf',
    )


# ── Folio Alerts ─────────────────────────────────────────────────────────────

@app.route('/alert/subscribe', methods=['POST'])
@login_required
def alert_subscribe():
    u = current_user()
    data = request.get_json() or {}
    folio = data.get('folio', '').strip()
    if not folio:
        return jsonify({'error': 'Folio requerido'}), 400
    with _db() as c:
        existing = c.execute('SELECT COUNT(*) FROM folio_alerts WHERE user_id=?', (u['id'],)).fetchone()[0]
        if existing >= 10:
            return jsonify({'error': 'Máximo 10 alertas permitidas'}), 400
        c.execute('INSERT OR IGNORE INTO folio_alerts(user_id, folio_real) VALUES(?,?)', (u['id'], folio))
    return jsonify({'ok': True, 'msg': f'Alerta activada para folio {folio}'})

@app.route('/alert/unsubscribe', methods=['POST'])
@login_required
def alert_unsubscribe():
    u = current_user()
    folio = (request.get_json() or {}).get('folio', '').strip()
    with _db() as c:
        c.execute('DELETE FROM folio_alerts WHERE user_id=? AND folio_real=?', (u['id'], folio))
    return jsonify({'ok': True})

@app.route('/alert/list')
@login_required
def alert_list():
    u = current_user()
    with _db() as c:
        rows = c.execute('SELECT folio_real, ts FROM folio_alerts WHERE user_id=? AND active=1 ORDER BY ts DESC',
                         (u['id'],)).fetchall()
    return jsonify({'alerts': [{'folio': r['folio_real'], 'ts': r['ts']} for r in rows]})


# ── PDF Cache (disk + memory, 24h TTL) ───────────────────────────────────────
_pdf_cache = {}  # folio -> {'pdf': bytes, 'ts': time.time()}
PDF_CACHE_TTL = 86400  # 24 hours
_DISK_CACHE_DIR = os.path.join(os.path.dirname(DB_PATH), 'pdf_cache')
os.makedirs(_DISK_CACHE_DIR, exist_ok=True)


def _get_cached_pdf(folio):
    """Check memory cache first, then disk cache."""
    # Memory cache
    entry = _pdf_cache.get(folio)
    if entry and time.time() - entry['ts'] < PDF_CACHE_TTL:
        return entry['pdf']
    # Disk cache
    safe_name = ''.join(c for c in str(folio) if c.isalnum() or c in '-_')
    disk_path = os.path.join(_DISK_CACHE_DIR, f'{safe_name}.pdf')
    try:
        if os.path.exists(disk_path):
            file_age = time.time() - os.path.getmtime(disk_path)
            if file_age < PDF_CACHE_TTL:
                with open(disk_path, 'rb') as f:
                    pdf_bytes = f.read()
                # Promote to memory cache
                _pdf_cache[folio] = {'pdf': pdf_bytes, 'ts': time.time() - file_age}
                return pdf_bytes
            else:
                # Expired — clean up
                os.remove(disk_path)
    except Exception:
        pass
    return None


def _set_cached_pdf(folio, pdf_bytes):
    """Save to both memory and disk cache."""
    # Memory cache — keep under 200 entries
    if len(_pdf_cache) > 200:
        oldest = min(_pdf_cache, key=lambda k: _pdf_cache[k]['ts'])
        del _pdf_cache[oldest]
    _pdf_cache[folio] = {'pdf': pdf_bytes, 'ts': time.time()}
    # Disk cache
    safe_name = ''.join(c for c in str(folio) if c.isalnum() or c in '-_')
    disk_path = os.path.join(_DISK_CACHE_DIR, f'{safe_name}.pdf')
    try:
        with open(disk_path, 'wb') as f:
            f.write(pdf_bytes)
    except Exception as e:
        print(f'[CACHE] Disk write error: {e}', flush=True)


def _cleanup_disk_cache():
    """Remove expired PDFs from disk cache. Runs daily."""
    try:
        now = time.time()
        removed = 0
        for fname in os.listdir(_DISK_CACHE_DIR):
            fpath = os.path.join(_DISK_CACHE_DIR, fname)
            if os.path.isfile(fpath) and now - os.path.getmtime(fpath) > PDF_CACHE_TTL:
                os.remove(fpath)
                removed += 1
        if removed:
            print(f'[CACHE] Cleaned up {removed} expired PDFs from disk', flush=True)
    except Exception as e:
        print(f'[CACHE] Cleanup error: {e}', flush=True)


# ── Abandoned Cart Tracking ──────────────────────────────────────────────────

def _track_abandoned_search(user_id, folio):
    """Track when a free user searches but doesn't download."""
    with _db() as c:
        c.execute('INSERT INTO abandoned_carts(user_id, folio_real) VALUES(?,?)', (user_id, folio))

def send_abandoned_cart_emails():
    """Send emails for abandoned carts older than 24h. Called by cron."""
    import smtplib, ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    host = os.environ.get('SMTP_HOST', '')
    port = int(os.environ.get('SMTP_PORT', 587))
    user = os.environ.get('SMTP_USER', '')
    pwd  = os.environ.get('SMTP_PASS', '')
    frm  = os.environ.get('SMTP_FROM', user)
    if not host or not user:
        return 0
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    sent = 0
    with _db() as c:
        rows = c.execute("""
            SELECT ac.id, ac.folio_real, u.email, u.name
            FROM abandoned_carts ac JOIN users u ON ac.user_id = u.id
            WHERE ac.emailed = 0 AND ac.ts <= ? AND ac.ts >= ?
            LIMIT 20
        """, (cutoff, (datetime.utcnow() - timedelta(hours=48)).isoformat())).fetchall()
        for r in rows:
            body_html = f"""
<div style="font-family:sans-serif;max-width:520px;margin:auto;background:#0d0d14;color:#dde0e8;padding:2rem;border-radius:12px">
  <h2 style="background:linear-gradient(120deg,#8b9cf4,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent">
    Tu escritura te espera
  </h2>
  <p style="color:#aaa;margin:.5rem 0 1rem">Hola {r['name'] or 'usuario'}, buscaste el folio <strong style="color:#c084fc">{r['folio_real']}</strong> pero no lo descargaste.</p>
  <p style="color:#aaa">Tu documento sigue disponible por solo <strong style="color:#4ade80">$130 MXN</strong>.</p>
  <a href="https://consulta-rpp.javisnes.com/?auto_folio={r['folio_real']}" style="display:block;margin-top:1.5rem;text-align:center;
     background:linear-gradient(135deg,#8b9cf4,#c084fc);color:#fff;padding:.7rem 1.5rem;
     border-radius:8px;text-decoration:none;font-weight:600">Descargar ahora →</a>
</div>"""
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f'Tu escritura del folio {r["folio_real"]} sigue disponible'
            msg['From'] = frm
            msg['To'] = r['email']
            msg.attach(MIMEText(body_html, 'html'))
            try:
                ctx = ssl.create_default_context()
                if port == 465:
                    with smtplib.SMTP_SSL(host, port, context=ctx) as s:
                        s.login(user, pwd)
                        s.sendmail(frm, [r['email']], msg.as_string())
                else:
                    with smtplib.SMTP(host, port) as s:
                        s.ehlo(); s.starttls(context=ctx); s.ehlo()
                        s.login(user, pwd)
                        s.sendmail(frm, [r['email']], msg.as_string())
                c.execute('UPDATE abandoned_carts SET emailed=1 WHERE id=?', (r['id'],))
                sent += 1
            except Exception as e:
                print(f'[EMAIL] Abandoned cart failed for {r["email"]}: {e}', flush=True)
    return sent

@app.route('/admin/send-abandoned-emails', methods=['POST'])
@login_required
def admin_send_abandoned():
    u = current_user()
    if u['role'] != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    sent = send_abandoned_cart_emails()
    return jsonify({'sent': sent})


def _cron_auth():
    """Returns True if request is authorized as cron or admin."""
    key    = request.args.get('key', '')
    secret = os.environ.get('CRON_SECRET', '')
    if key and secret and key == secret:
        return True
    u = current_user()
    return bool(u and u.get('role') == 'admin')

@app.route('/admin/check-folio-alerts', methods=['POST'])
def cron_check_folio_alerts():
    if not _cron_auth():
        return jsonify({'error': 'No autorizado'}), 403
    def run():
        n = check_folio_alerts()
        print(f'[CRON] check_folio_alerts: {n} notified', flush=True)
    threading.Thread(target=run, daemon=True).start()
    return jsonify({'ok': True, 'msg': 'Folio alert check started in background'})

@app.route('/admin/send-renewal-reminders', methods=['POST'])
def cron_send_renewal_reminders():
    if not _cron_auth():
        return jsonify({'error': 'No autorizado'}), 403
    sent = send_renewal_reminders()
    return jsonify({'ok': True, 'sent': sent})

@app.route('/admin/send-trial-reminders', methods=['POST'])
def cron_send_trial_reminders():
    if not _cron_auth():
        return jsonify({'error': 'No autorizado'}), 403
    sent = send_trial_expiry_reminders()
    return jsonify({'ok': True, 'sent': sent})


# ── Structured Logging ───────────────────────────────────────────────────────
import logging
from logging.handlers import RotatingFileHandler

_log_path = os.environ.get('LOG_PATH', '/opt/rpp/rpp.log')
_file_handler = RotatingFileHandler(_log_path, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
_file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
_file_handler.setLevel(logging.INFO)
app.logger.addHandler(_file_handler)
app.logger.setLevel(logging.INFO)

@app.after_request
def _log_request(response):
    path = request.path
    # CDN/browser cache headers for static assets
    if path.startswith('/static') or path == '/favicon.ico':
        # Versioned assets (contain hash-like fingerprint) → long cache
        if any(ext in path for ext in ('.woff', '.woff2', '.ttf', '.eot')):
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        elif path.endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.webp')):
            response.headers['Cache-Control'] = 'public, max-age=86400, stale-while-revalidate=3600'
        else:
            response.headers['Cache-Control'] = 'public, max-age=3600'
        return response
    u = current_user()
    uid = u['id'] if u else '-'
    app.logger.info(f'{request.method} {path} {response.status_code} uid={uid} ip={request.remote_addr}')
    return response


# ── Agua JMAS ────────────────────────────────────────────────────────────────
@app.route('/agua/consultar', methods=['POST'])
@login_required
def agua_consultar():
    import requests as _requests
    import warnings as _warnings
    _warnings.filterwarnings('ignore')

    data = request.get_json() or {}
    calle     = (data.get('calle') or '').strip().upper()
    numero    = (data.get('numero') or '').strip()
    referencia = (data.get('referencia') or '').strip()

    if not referencia and (not calle or not numero):
        return jsonify({'error': 'Proporciona calle y número, o número de cliente'}), 400

    JMAS_URL = 'https://www.pagosdigitales.com/Website/JmasChihuahua/ConsultarSaldo/a7072e66-990e-11e8-9a86-5600006e8c82'
    sess = _requests.Session()
    sess.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'es-MX,es;q=0.9',
    })
    try:
        r1 = sess.get(JMAS_URL, timeout=15, verify=False)
        import re as _re
        csrf = _re.search(r'name="__RequestVerificationToken"[^>]+value="([^"]+)"', r1.text)
        token = csrf.group(1) if csrf else ''

        post_data = {
            '__RequestVerificationToken': token,
            'id': 'a7072e66-990e-11e8-9a86-5600006e8c82',
            'hRef': 'nulo',
            'fuente': '',
            'dirCuenta': calle,
            'numCalle': numero,
            'Referencia': referencia,
        }
        sess.headers.update({
            'Referer': JMAS_URL,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://www.pagosdigitales.com',
        })
        r2 = sess.post(JMAS_URL, data=post_data, timeout=20, verify=False)
    except Exception as e:
        return jsonify({'error': f'Error de conexión: {e}'}), 502

    html = r2.text
    # Detect no results (returns home page — 23977 bytes approx, no formaResultadoConsulta)
    if 'formaResultadoConsulta' not in html:
        return jsonify({'error': 'No se encontró cuenta de agua para esa dirección'}), 404

    # Parse result
    import re as _re
    monto_m    = _re.search(r'name="monto"\s+value="([^"]+)"', html)
    ref_m      = _re.search(r'referencia=([^"&\s]+)', html)
    # Extract label-value pairs from summary table
    vals       = _re.findall(r'row justify-content-start[^>]*>\s*([^\n<]{2,80})', html)
    contrato   = vals[0].strip() if len(vals) > 0 else ''
    usuario    = vals[1].strip() if len(vals) > 1 else ''
    direccion  = vals[2].strip() if len(vals) > 2 else ''

    return jsonify({
        'contrato':  contrato,
        'usuario':   usuario,
        'direccion': direccion,
        'monto':     monto_m.group(1) if monto_m else '0',
        'referencia': ref_m.group(1) if ref_m else '',
    })


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    threading.Timer(1.5, lambda: webbrowser.open(f'http://localhost:{port}')).start()
    print(f"\n  RPP Consulta — http://localhost:{port}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
