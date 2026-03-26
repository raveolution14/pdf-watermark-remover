#!/usr/bin/env python3
"""
RPP Chihuahua - Buscador de Folio Real
Descarga automáticamente el PDF y elimina la marca de agua.
"""

import io
import threading
import webbrowser
import os
import uuid
import time

from flask import Flask, request, send_file, render_template_string, jsonify
from playwright.sync_api import sync_playwright

# Reutilizamos el removedor de marcas de agua
from main import remove_watermarks

app = Flask(__name__)

RPP_URL  = "https://srppn.chihuahua.gob.mx/rpp/RppApp/"
RPP_USER = "CEMVCHIH"
RPP_PASS = "Cemv2026$1"

# ── HTML ──────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Consulta RPP Chihuahua</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0d0d14;
      color: #dde0e8;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .card {
      width: 100%;
      max-width: 480px;
      padding: 2.5rem 2rem;
    }
    h1 {
      font-size: 1.8rem;
      font-weight: 700;
      background: linear-gradient(120deg, #8b9cf4, #c084fc);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: .3rem;
    }
    .subtitle { color: #555; font-size: .88rem; margin-bottom: 2rem; }

    label { display: block; color: #aaa; font-size: .85rem; margin-bottom: .4rem; }
    input[type="text"] {
      width: 100%;
      padding: .7rem 1rem;
      background: #13131f;
      border: 1.5px solid #2a2a3a;
      border-radius: 8px;
      color: #eee;
      font-size: 1rem;
      outline: none;
      transition: border-color .2s;
    }
    input[type="text"]:focus { border-color: #8b9cf4; }

    button {
      width: 100%;
      margin-top: 1rem;
      padding: .7rem;
      background: linear-gradient(135deg, #8b9cf4, #c084fc);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: opacity .2s;
    }
    button:hover { opacity: .9; }
    button:disabled { opacity: .5; cursor: not-allowed; }

    #status {
      margin-top: 1.2rem;
      display: none;
      padding: .9rem 1.1rem;
      border-radius: 9px;
      font-size: .88rem;
      line-height: 1.5;
    }
    #status.loading { background:#13131f; border:1px solid #2a2a3a; color:#aaa; }
    #status.success { background:#0a2118; border:1px solid #1d5c3a; color:#4ade80; }
    #status.error   { background:#200f0f; border:1px solid #5c1d1d; color:#f87171; }

    .bar { width:100%; height:3px; background:#222; border-radius:2px; margin-top:.7rem; overflow:hidden; }
    .fill {
      height:100%; border-radius:2px;
      background: linear-gradient(90deg,#8b9cf4,#c084fc);
      animation: sweep 1.4s ease-in-out infinite;
    }
    @keyframes sweep {
      0%  { width:0%;  margin-left:0; }
      50% { width:60%; margin-left:20%; }
      100%{ width:0%;  margin-left:100%; }
    }
    .dl-btn {
      display:inline-block; margin-top:.6rem;
      padding:.45rem 1.1rem;
      background:#1d5c3a; color:#4ade80;
      border-radius:7px; text-decoration:none;
      font-size:.85rem; font-weight:600;
    }
    .dl-btn:hover { background:#256b46; }

    .footer { margin-top:2.5rem; text-align:center; color:#333; font-size:.72rem; }
  </style>
</head>
<body>
<div class="card">
  <h1>Consulta RPP</h1>
  <p class="subtitle">Ingresa el folio real para descargar el documento sin marca de agua</p>

  <label for="folio">Folio Real</label>
  <input type="text" id="folio" placeholder="Ej. 1298377" autocomplete="off">
  <button id="btn" onclick="buscar()">Buscar</button>

  <div id="status"></div>
  <p class="footer">Diseñado por Javisness</p>
</div>

<script>
async function buscar() {
  const folio = document.getElementById('folio').value.trim();
  if (!folio) return;

  const btn    = document.getElementById('btn');
  const status = document.getElementById('status');

  btn.disabled = true;
  status.className = 'loading';
  status.style.display = 'block';
  status.innerHTML = 'Buscando folio <b>' + folio + '</b>...<div class="bar"><div class="fill"></div></div>';

  try {
    const res = await fetch('/buscar', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({folio})
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({error: 'Error desconocido'}));
      status.className = 'error';
      status.innerHTML = '&#10060; ' + err.error;
      btn.disabled = false;
      return;
    }
    const {job_id} = await res.json();

    // Poll until done
    const poll = setInterval(async () => {
      try {
        const sr = await fetch('/status/' + job_id);
        const s  = await sr.json();
        if (s.status === 'done') {
          clearInterval(poll);
          const dlName = 'folio_' + folio + '_sin_marca.pdf';
          status.className = 'success';
          status.innerHTML = '&#10003; Documento listo — <a class="dl-btn" href="/download/' + job_id + '" download="' + dlName + '">&#11015; Descargar PDF</a>';
          btn.disabled = false;
        } else if (s.status === 'error') {
          clearInterval(poll);
          status.className = 'error';
          status.innerHTML = '&#10060; ' + s.error;
          btn.disabled = false;
        }
      } catch(e) {
        clearInterval(poll);
        status.className = 'error';
        status.innerHTML = '&#10060; Error de red: ' + e.message;
        btn.disabled = false;
      }
    }, 3000);

  } catch(e) {
    status.className = 'error';
    status.innerHTML = '&#10060; Error de red: ' + e.message;
    btn.disabled = false;
  }
}

document.getElementById('folio').addEventListener('keydown', e => {
  if (e.key === 'Enter') buscar();
});
</script>
</body>
</html>
"""

# ── Playwright automation ─────────────────────────────────────────────────────

def _ext_dom_click(page, btn_text: str):
    """Click an ExtJS button via its DOM element (works in headless mode)."""
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


def fetch_pdf_for_folio(folio_real: str) -> bytes:
    """Login to RPP, search folio real, download PDF and return bytes."""
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--no-zygote',
                '--disable-extensions',
                '--disable-background-networking',
                '--disable-background-timer-throttling',
                '--disable-backgrounding-occluded-windows',
                '--disable-renderer-backgrounding',
                '--disable-sync',
                '--no-first-run',
                '--mute-audio',
                '--disable-images',
                '--blink-settings=imagesEnabled=false',
            ]
        )
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            )
        )
        page = context.new_page()

        # ── 1. Login via ExtJS API ─────────────────────────────────────────────
        page.goto(RPP_URL, wait_until="load")
        # Wait for ExtJS login form to be ready
        page.wait_for_function(
            '() => typeof Ext !== "undefined" && Ext.ComponentQuery && '
            'Ext.ComponentQuery.query("textfield[name=userName]").length > 0',
            timeout=20000
        )
        # Use fill() on real DOM inputs (more reliable than ExtJS setValue)
        user_id = page.evaluate('Ext.ComponentQuery.query("textfield[name=userName]")[0].getInputId()')
        pwd_id  = page.evaluate('Ext.ComponentQuery.query("textfield[name=password]")[0].getInputId()')
        page.fill(f'#{user_id}', RPP_USER)
        page.fill(f'#{pwd_id}',  RPP_PASS)
        page.wait_for_timeout(300)
        # Submit: try DOM click on Aceptar button first
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
        # Fallback: press Enter on password field if still on login screen
        if page.evaluate('!!document.querySelector("input[type=password]")'):
            page.press(f'#{pwd_id}', 'Enter')
        try:
            page.wait_for_function('() => !document.querySelector("input[type=password]")', timeout=30000)
        except Exception:
            raise ValueError("STEP2: login no completó (password field sigue visible)")
        # Wait for main menu tile to appear instead of fixed sleep
        try:
            page.wait_for_function(
                '() => Array.from(document.querySelectorAll("*")).some('
                '  e => e.textContent.toLowerCase().includes("consulta") && '
                '       e.textContent.toLowerCase().includes("tramites") && '
                '       e.offsetParent !== null)',
                timeout=20000
            )
        except Exception:
            raise ValueError("STEP3: menú principal no apareció")

        # ── 2. Consulta Avanzada tile ─────────────────────────────────────────
        # Note: site has a typo — "avazada" not "avanzada"
        page.evaluate("""
            const all = Array.from(document.querySelectorAll("*"));
            const el = all
                .filter(e => e.textContent.toLowerCase().includes("consulta") &&
                             e.textContent.toLowerCase().includes("tramites"))
                .sort((a, b) => a.textContent.length - b.textContent.length)[0];
            if (el) el.click();
        """)
        # Wait for the folio search form to appear
        try:
            page.wait_for_function(
                '() => Ext.ComponentQuery.query("numberfield[name=FOLIOREAL]").length > 0',
                timeout=20000
            )
        except Exception:
            raise ValueError("STEP4: formulario de folio no apareció")

        # ── 3. Escribir folio real via CDP fill (not ExtJS setValue) ──────────
        input_id = page.evaluate('Ext.ComponentQuery.query("numberfield[name=FOLIOREAL]")[0].getInputId()')
        page.fill(f'#{input_id}', str(folio_real))
        page.wait_for_timeout(200)

        # ── 4. Click Buscar ───────────────────────────────────────────────────
        _ext_dom_click(page, 'Buscar')
        # Wait for "Ver Agregado" to appear instead of fixed sleep
        try:
            page.wait_for_function(
                '() => Array.from(document.querySelectorAll("*")).some(e => e.textContent.trim() === "Ver Agregado")',
                timeout=30000
            )
        except Exception:
            raise ValueError("STEP5: 'Ver Agregado' no apareció — folio no encontrado o búsqueda falló")

        # ── 5. Click Ver Agregado ─────────────────────────────────────────────
        ver_found = page.evaluate("""
            (() => {
                const el = Array.from(document.querySelectorAll("*"))
                    .find(e => e.textContent.trim() === "Ver Agregado");
                if (el) { el.click(); return true; }
                return false;
            })()
        """)
        if not ver_found:
            browser.close()
            raise ValueError("No se encontró el folio real en el registro")
        # Wait for iframe to appear instead of fixed sleep
        try:
            page.wait_for_function(
                '() => document.querySelector("iframe") !== null',
                timeout=30000
            )
        except Exception:
            raise ValueError("STEP6: iframe del PDF no apareció")

        # ── 6. Obtener URL del PDF desde el visor ─────────────────────────────
        pdf_url = None
        for _ in range(10):
            pdf_url = page.evaluate("""
                (() => {
                    try {
                        const iframe = document.querySelector("iframe");
                        if (!iframe) return null;

                        // 1. PDFViewerApplication.url (most reliable, needs time to load)
                        try {
                            const app = iframe.contentWindow.PDFViewerApplication;
                            if (app && app.url) {
                                return new URL(app.url, window.location.href).href;
                            }
                        } catch(e) {}

                        // 2. Parse file= query param from iframe src (pdf.js viewer pattern)
                        try {
                            const iSrc = new URL(iframe.src, window.location.href);
                            const filePdf = iSrc.searchParams.get('file');
                            if (filePdf) return new URL(filePdf, iframe.src).href;
                        } catch(e) {}

                        // 3. iframe src only if it is itself a PDF
                        if (iframe.src && iframe.src.toLowerCase().includes('.pdf')) {
                            return new URL(iframe.src, window.location.href).href;
                        }
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

        # ── 7. Descargar PDF con cookies de sesión ────────────────────────────
        # Use context.request so the PDF is fetched in Python (not in the
        # browser JS heap), which avoids doubling memory and is more stable.
        response = context.request.get(pdf_url)
        pdf_bytes = response.body()
        browser.close()

    return pdf_bytes


# ── Job store ─────────────────────────────────────────────────────────────────

_jobs: dict = {}  # job_id -> {status, pdf, error, folio, ts}

def _cleanup_old_jobs():
    cutoff = time.time() - 600  # 10 min
    for jid in list(_jobs):
        if _jobs[jid].get('ts', 0) < cutoff:
            del _jobs[jid]

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/buscar', methods=['POST'])
def buscar():
    data  = request.get_json()
    folio = (data or {}).get('folio', '').strip()
    if not folio:
        return {'error': 'Folio real requerido'}, 400

    _cleanup_old_jobs()
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {'status': 'running', 'pdf': None, 'error': None,
                     'folio': folio, 'ts': time.time()}

    def run():
        try:
            raw_pdf   = fetch_pdf_for_folio(folio)
            clean_pdf = remove_watermarks(raw_pdf)
            _jobs[job_id].update({'status': 'done', 'pdf': clean_pdf})
        except ValueError as e:
            _jobs[job_id].update({'status': 'error', 'error': str(e)})
        except Exception as e:
            _jobs[job_id].update({'status': 'error', 'error': f'Error: {e}'})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'job_id': job_id})


@app.route('/status/<job_id>')
def job_status(job_id):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({'status': 'error', 'error': 'Job no encontrado'}), 404
    if job['status'] == 'error':
        return jsonify({'status': 'error', 'error': job['error']})
    return jsonify({'status': job['status']})


@app.route('/download/<job_id>')
def download(job_id):
    job = _jobs.get(job_id)
    if not job or job['status'] != 'done' or not job['pdf']:
        return jsonify({'error': 'PDF no disponible'}), 404
    folio = job.get('folio', 'folio')
    return send_file(
        io.BytesIO(job['pdf']),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'folio_{folio}_sin_marca.pdf',
    )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    threading.Timer(1.5, lambda: webbrowser.open(f'http://localhost:{port}')).start()
    print(f"\n  RPP Consulta — http://localhost:{port}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
