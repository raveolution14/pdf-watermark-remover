#!/usr/bin/env python3
"""
PDF Watermark Remover - Web Interface
Removes diagonal text watermarks from PDF files.
"""

import io
import re

from flask import Flask, request, send_file, render_template_string
from pypdf import PdfReader, PdfWriter
from pypdf.generic import ArrayObject

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

# ── HTML ─────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Eliminar Marca de Agua PDF</title>
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
      max-width: 560px;
      padding: 2.5rem 2rem;
    }
    h1 {
      font-size: 1.9rem;
      font-weight: 700;
      background: linear-gradient(120deg, #8b9cf4, #c084fc);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: .4rem;
    }
    .subtitle { color: #666; font-size: .9rem; margin-bottom: 2rem; }

    #dropzone {
      border: 2px dashed #2a2a3a;
      border-radius: 14px;
      padding: 3rem 1.5rem;
      text-align: center;
      cursor: pointer;
      transition: border-color .25s, background .25s;
      background: #13131f;
    }
    #dropzone:hover, #dropzone.over {
      border-color: #8b9cf4;
      background: #16162a;
    }
    .icon { font-size: 2.8rem; margin-bottom: .8rem; }
    .hint { color: #888; font-size: .95rem; margin-bottom: .5rem; }
    .sep  { color: #444; font-size: .85rem; margin: .4rem 0 .8rem; }
    .pick-btn {
      display: inline-block;
      padding: .55rem 1.4rem;
      background: linear-gradient(135deg, #8b9cf4, #c084fc);
      color: #fff;
      border-radius: 8px;
      font-weight: 600;
      font-size: .9rem;
      pointer-events: none; /* let the <label> handle click */
    }
    input[type="file"] { display: none; }

    /* Status box */
    #status { margin-top: 1.4rem; display: none; }
    #status.show { display: block; }

    .box {
      padding: .9rem 1.2rem;
      border-radius: 10px;
      font-size: .9rem;
      line-height: 1.5;
    }
    .box.loading { background: #13131f; border: 1px solid #2a2a3a; color: #aaa; }
    .box.success { background: #0a2118; border: 1px solid #1d5c3a; color: #4ade80; }
    .box.error   { background: #200f0f; border: 1px solid #5c1d1d; color: #f87171; }

    .bar { width: 100%; height: 3px; background: #222; border-radius: 2px; margin-top: .7rem; overflow: hidden; }
    .fill {
      height: 100%;
      border-radius: 2px;
      background: linear-gradient(90deg, #8b9cf4, #c084fc);
      animation: sweep 1.4s ease-in-out infinite;
    }
    @keyframes sweep {
      0%   { width: 0%;   margin-left: 0; }
      50%  { width: 60%;  margin-left: 20%; }
      100% { width: 0%;   margin-left: 100%; }
    }

    .dl-btn {
      display: inline-block;
      margin-top: .65rem;
      padding: .45rem 1.1rem;
      background: #1d5c3a;
      color: #4ade80;
      border-radius: 7px;
      text-decoration: none;
      font-size: .85rem;
      font-weight: 600;
      transition: background .2s;
    }
    .dl-btn:hover { background: #256b46; }

    /* Multi-file list */
    #file-list { margin-top: 1.2rem; }
    .file-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: .55rem .9rem;
      background: #13131f;
      border: 1px solid #2a2a3a;
      border-radius: 8px;
      margin-bottom: .5rem;
      font-size: .88rem;
    }
    .file-item .fname { color: #ccc; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 280px; }
    .file-item .badge {
      font-size: .75rem;
      padding: .2rem .6rem;
      border-radius: 5px;
      white-space: nowrap;
    }
    .badge.pending  { background:#1e1e30; color:#888; }
    .badge.working  { background:#1a1a40; color:#8b9cf4; }
    .badge.done     { background:#0a2118; color:#4ade80; }
    .badge.fail     { background:#200f0f; color:#f87171; }
    .file-item .dl-sm {
      color: #4ade80;
      text-decoration: none;
      font-size: .8rem;
      margin-left: .5rem;
    }
  </style>
</head>
<body>
<div class="card">
  <h1>Eliminar Marca de Agua</h1>
  <p class="subtitle">Sube uno o varios PDFs — la marca de agua diagonal se elimina automaticamente</p>

  <label for="fileInput">
    <div id="dropzone">
      <div class="icon">📄</div>
      <p class="hint">Arrastra y suelta tus PDFs aqui</p>
      <p class="sep">o</p>
      <span class="pick-btn">Seleccionar archivos</span>
    </div>
  </label>
  <input type="file" id="fileInput" accept=".pdf" multiple>

  <div id="file-list"></div>
  <div id="status"></div>
</div>

<script>
const dropzone  = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const fileList  = document.getElementById('file-list');
const status    = document.getElementById('status');

// drag events
dropzone.addEventListener('dragover',  e => { e.preventDefault(); dropzone.classList.add('over'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('over'));
dropzone.addEventListener('drop', e => {
  e.preventDefault();
  dropzone.classList.remove('over');
  handleFiles([...e.dataTransfer.files].filter(f => f.type === 'application/pdf'));
});
fileInput.addEventListener('change', e => {
  handleFiles([...e.target.files]);
  e.target.value = '';
});

async function handleFiles(files) {
  if (!files.length) return;
  status.className = '';
  status.style.display = 'none';
  fileList.innerHTML = '';

  // Build rows
  const rows = files.map((f, i) => {
    const div = document.createElement('div');
    div.className = 'file-item';
    div.id = 'row-' + i;
    div.innerHTML = `<span class="fname" title="${f.name}">${f.name}</span>
                     <span><span class="badge pending" id="badge-${i}">Esperando...</span></span>`;
    fileList.appendChild(div);
    return div;
  });

  // Process each file sequentially
  for (let i = 0; i < files.length; i++) {
    const badge = document.getElementById('badge-' + i);
    badge.className = 'badge working';
    badge.textContent = 'Procesando...';

    try {
      const fd = new FormData();
      fd.append('pdf', files[i]);
      const res = await fetch('/process', { method: 'POST', body: fd });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Error desconocido' }));
        badge.className = 'badge fail';
        badge.textContent = 'Error';
        const span = rows[i].querySelector('span:last-child');
        span.innerHTML += `<span style="color:#f87171;font-size:.75rem;margin-left:.4rem">${err.error}</span>`;
      } else {
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const dlName = files[i].name.replace(/\.pdf$/i, '_sin_marca.pdf');
        badge.className = 'badge done';
        badge.textContent = 'Listo';
        const span = rows[i].querySelector('span:last-child');
        span.innerHTML += `<a class="dl-sm" href="${url}" download="${dlName}">⬇ Descargar</a>`;
      }
    } catch (e) {
      badge.className = 'badge fail';
      badge.textContent = 'Error de red';
    }
  }
}
</script>
</body>
</html>
"""

# ── Watermark removal logic ───────────────────────────────────────────────────

# Matches: a b c d e f Tm   (text matrix set)
_TM_RE = re.compile(
    r'([-+]?\d*\.?\d+)\s+([-+]?\d*\.?\d+)\s+([-+]?\d*\.?\d+)\s+'
    r'([-+]?\d*\.?\d+)\s+([-+]?\d*\.?\d+)\s+([-+]?\d*\.?\d+)\s+Tm'
)
# Matches: a b c d e f cm   (current transformation matrix)
_CM_RE = re.compile(
    r'([-+]?\d*\.?\d+)\s+([-+]?\d*\.?\d+)\s+([-+]?\d*\.?\d+)\s+'
    r'([-+]?\d*\.?\d+)\s+([-+]?\d*\.?\d+)\s+([-+]?\d*\.?\d+)\s+cm'
)
_BT_ET_RE = re.compile(r'BT\b.*?\bET', re.DOTALL)
_Q_Q_RE   = re.compile(r'q\b.*?\bQ',   re.DOTALL)


def _has_rotation(m):
    """Return True if the regex match for Tm/cm includes rotation."""
    try:
        return abs(float(m.group(2))) > 0.05 or abs(float(m.group(3))) > 0.05
    except ValueError:
        return False


def _remove_rotated_text(content_bytes: bytes, watermark_image_names: set = None) -> bytes:
    """
    Strip watermarks from a single PDF content stream.

    Strategy:
      1. BT…ET blocks whose Tm operator includes rotation → remove.
      2. q…Q blocks that (a) contain a rotated cm and (b) contain text
         but no path/image drawing → likely a watermark layer → remove.
      3. q…Q blocks that reference a known semi-transparent image watermark → remove.
    """
    try:
        content = content_bytes.decode('latin-1')
    except Exception:
        return content_bytes

    # Pass 1 – rotated Tm inside BT…ET
    def _bt_filter(m):
        block = m.group(0)
        for tm in _TM_RE.finditer(block):
            if _has_rotation(tm):
                return ''
        return block

    content = _BT_ET_RE.sub(_bt_filter, content)

    # Pass 2 – q…Q with rotated cm that contains only text (no draws)
    _DRAW_OPS = re.compile(r'\b(f|F|S|s|b|B|n|re|l|m|c|v|y|h|W|EI|Do)\b')

    def _q_filter(m):
        block = m.group(0)
        # Must have text
        if 'BT' not in block or 'ET' not in block:
            return block
        # Must have a rotated cm
        has_rot_cm = any(_has_rotation(cm) for cm in _CM_RE.finditer(block))
        if not has_rot_cm:
            return block
        # Reject if the block also draws paths / images (could be real content)
        inner = re.sub(r'BT.*?ET', '', block, flags=re.DOTALL)
        if _DRAW_OPS.search(inner):
            return block
        return ''

    content = _Q_Q_RE.sub(_q_filter, content)

    # Pass 3 – q…Q blocks referencing known semi-transparent image watermarks
    if watermark_image_names:
        for name in watermark_image_names:
            pat = re.compile(
                r'q\b.*?/' + re.escape(name) + r'\s+Do\b.*?Q',
                re.DOTALL
            )
            content = pat.sub('', content)

    try:
        return content.encode('latin-1')
    except Exception:
        return content_bytes


def _find_image_watermark_names(page) -> set:
    """
    Identify Image XObjects that are semi-transparent overlays (watermarks).

    Heuristic: an Image with an SMask where the mask has some non-zero values
    (partially opaque) but the coverage is sparse (< 30% of pixels) suggests
    a watermark stamp rather than real content.
    """
    names = set()
    try:
        res = page.get('/Resources')
        if res is None:
            return names
        if hasattr(res, 'get_object'):
            res = res.get_object()
        xobjs = res.get('/XObject')
        if xobjs is None:
            return names
        if hasattr(xobjs, 'get_object'):
            xobjs = xobjs.get_object()
        for key in list(xobjs.keys()):
            ref = xobjs[key]
            obj = ref.get_object() if hasattr(ref, 'get_object') else ref
            if obj.get('/Subtype') != '/Image':
                continue
            smask_ref = obj.get('/SMask')
            if smask_ref is None:
                continue
            try:
                smask_obj = smask_ref.get_object() if hasattr(smask_ref, 'get_object') else smask_ref
                smask_data = smask_obj.get_data()
                if not smask_data:
                    continue
                non_zero = sum(1 for b in smask_data if b > 0)
                ratio = non_zero / len(smask_data)
                # Semi-transparent overlay: some pixels visible but sparse coverage
                if 0 < ratio < 0.40:
                    names.add(key.lstrip('/'))
            except Exception:
                continue
    except Exception:
        pass
    return names


def _patch_stream_inplace(stream_obj, watermark_image_names: set = None):
    """Modify a stream object's data in place (avoids indirect_reference issues)."""
    try:
        data     = stream_obj.get_data()
        new_data = _remove_rotated_text(data, watermark_image_names)
        stream_obj.set_data(new_data)
    except Exception:
        pass


def _process_page(page):
    """Remove watermarks from all content streams of a page (in-place)."""
    if "/Contents" not in page:
        return

    # Detect semi-transparent image watermarks on this page
    watermark_image_names = _find_image_watermark_names(page)

    contents = page["/Contents"]
    if hasattr(contents, 'get_object'):
        contents = contents.get_object()

    if isinstance(contents, ArrayObject):
        for item in contents:
            _patch_stream_inplace(
                item.get_object() if hasattr(item, 'get_object') else item,
                watermark_image_names,
            )
    else:
        _patch_stream_inplace(contents, watermark_image_names)

    # Also process Form XObjects (separate watermark layers)
    try:
        res = page.get("/Resources")
        if res is None:
            return
        if hasattr(res, 'get_object'):
            res = res.get_object()
        xobjs = res.get("/XObject")
        if xobjs is None:
            return
        if hasattr(xobjs, 'get_object'):
            xobjs = xobjs.get_object()
        for key in list(xobjs.keys()):
            xobj_ref = xobjs[key]
            xobj = xobj_ref.get_object() if hasattr(xobj_ref, 'get_object') else xobj_ref
            if xobj.get("/Subtype") == "/Form":
                _patch_stream_inplace(xobj, watermark_image_names)
    except Exception:
        pass


def remove_watermarks(pdf_bytes: bytes) -> bytes:
    """Process a PDF and return the cleaned bytes."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    writer.clone_reader_document_root(reader)

    for page in writer.pages:
        _process_page(page)

    out = io.BytesIO()
    writer.write(out)
    out.seek(0)
    return out.read()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/process', methods=['POST'])
def process():
    if 'pdf' not in request.files:
        return {'error': 'No se envio ningun archivo PDF'}, 400

    f = request.files['pdf']
    if not f.filename.lower().endswith('.pdf'):
        return {'error': 'El archivo debe ser .pdf'}, 400

    try:
        result = remove_watermarks(f.read())
        out_name = f.filename.rsplit('.', 1)[0] + '_sin_marca.pdf'
        return send_file(
            io.BytesIO(result),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=out_name,
        )
    except Exception as e:
        return {'error': f'Error procesando el PDF: {e}'}, 500


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print()
    print("  ╔══════════════════════════════════════╗")
    print("  ║   PDF Watermark Remover  –  listo    ║")
    print("  ║                                      ║")
    print("  ║   Abre en tu navegador:              ║")
    print("  ║   http://localhost:5000              ║")
    print("  ║                                      ║")
    print("  ║   Presiona Ctrl+C para detener       ║")
    print("  ╚══════════════════════════════════════╝")
    print()
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
