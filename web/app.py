import os, sys, json, threading, queue, datetime, subprocess
from flask import (Flask, render_template, request, redirect,
                   url_for, session, Response)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from web.db import init_db, save_scan, update_scan, get_scan, get_all_scans
from web.translations import t as _t, LANG_DEFAULT
from secauto.model import load_findings
from secauto import metrics as sec_metrics

app = Flask(__name__)
app.secret_key = 'secauto-ui-2026'
app.jinja_env.filters['from_json'] = json.loads

BASE   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPS   = os.path.join(BASE, 'reports')
PYTHON = sys.executable

_queues: dict[str, queue.Queue] = {}
_qlock  = threading.Lock()

# ── catalogue ────────────────────────────────────────────────────────────────
TARGETS = {
    'juice-shop': {
        'name': 'Juice Shop', 'url': 'http://localhost:3000',
        'icon': '🛒',
        'fr': 'Fausse boutique Node.js/Angular avec des failles OWASP classiques.',
        'en': 'Vulnerable Node.js/Angular shop with classic OWASP flaws.',
        'tags': ['SQLi', 'XSS', 'JWT', 'SCA'],
    },
    'crapi': {
        'name': 'crAPI', 'url': 'http://localhost:8888',
        'icon': '🚗',
        'fr': 'API microservices de voitures connectées — BOLA, BFLA, JWT falsifié.',
        'en': 'Connected-car microservices API — BOLA, BFLA, forged JWT.',
        'tags': ['BOLA', 'BFLA', 'JWT', 'API'],
    },
    'roundcube': {
        'name': 'Roundcube', 'url': 'http://localhost:8080',
        'icon': '📧',
        'fr': 'Client email PHP réel — headers manquants, CSRF, configuration.',
        'en': 'Real PHP webmail — missing headers, CSRF, misconfiguration.',
        'tags': ['Headers', 'CSRF', 'PHP'],
    },
}

TOOLS = {
    'sast': {
        'name': 'SAST', 'sub': 'Semgrep', 'icon': '🔍', 'dur': '~2 min',
        'fr': 'Lit le code source et cherche SQLi, injections et secrets codés en dur.',
        'en': 'Reads source code to find SQLi, injections and hardcoded secrets.',
    },
    'sca': {
        'name': 'SCA', 'sub': 'Trivy + npm audit', 'icon': '📦', 'dur': '~2 min',
        'fr': 'Compare les bibliothèques utilisées à une base de CVE connues.',
        'en': 'Checks used libraries against a known CVE database.',
    },
    'dast': {
        'name': 'DAST', 'sub': 'OWASP ZAP', 'icon': '🌐', 'dur': '~3 min',
        'fr': 'Attaque l\'application en marche avec des centaines de requêtes malformées.',
        'en': 'Attacks the live app with hundreds of crafted requests.',
    },
    'custom': {
        'name': 'Custom', 'sub': 'Détecteurs Python', 'icon': '⚡', 'dur': '~30 s',
        'fr': 'Scripts ciblés : accès objet d\'un autre user (BOLA), fonction admin accessible (BFLA), JWT falsifié.',
        'en': 'Targeted scripts: cross-user object access (BOLA), admin bypass (BFLA), forged JWT.',
    },
}

SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

# ── helpers ──────────────────────────────────────────────────────────────────
def lang():
    return session.get('lang', LANG_DEFAULT)

@app.context_processor
def _ctx():
    l = lang()
    return {'lang': l, 't': lambda k: _t(k, l),
            'TARGETS': TARGETS, 'TOOLS': TOOLS}

# ── routes ───────────────────────────────────────────────────────────────────
@app.get('/')
def index():
    return render_template('index.html')

@app.get('/lang/<l>')
def set_lang(l):
    if l in ('fr', 'en'):
        session['lang'] = l
    return redirect(request.referrer or url_for('index'))

@app.post('/scan/start')
def scan_start():
    sel_targets = request.form.getlist('targets')
    sel_tools   = request.form.getlist('tools')
    if not sel_targets or not sel_tools:
        return redirect(url_for('index'))

    now    = datetime.datetime.now()
    run_id = 'web-' + now.strftime('%Y%m%d-%H%M%S')
    save_scan(run_id, sel_targets, sel_tools, now.isoformat(), lang())

    with _qlock:
        _queues[run_id] = queue.Queue()

    threading.Thread(target=_bg_scan,
                     args=(run_id, sel_targets, ','.join(sel_tools)),
                     daemon=True).start()

    return redirect(url_for('scan_page', run_id=run_id))

def _bg_scan(run_id, targets, tools_str):
    q = _queues[run_id]
    total_f = total_tp = 0
    for target in targets:
        q.put({'type': 'target_start', 'target': target})
        cmd = [PYTHON, '-m', 'secauto', 'run',
               '--target', target, '--tools', tools_str, '--run-id', run_id]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, cwd=BASE)
            for line in proc.stdout:
                if line.strip():
                    q.put({'type': 'log', 'target': target, 'text': line.strip()})
            proc.wait()
        except Exception as e:
            q.put({'type': 'log', 'target': target, 'text': f'[erreur] {e}'})

        mf = os.path.join(REPS, target, run_id, 'metrics.json')
        if os.path.exists(mf):
            m = json.load(open(mf)).get('overall', {})
            total_f  += m.get('tp', 0) + m.get('fp', 0)
            total_tp += m.get('tp', 0)
        q.put({'type': 'target_done', 'target': target})

    update_scan(run_id, 'done', datetime.datetime.now().isoformat(), total_f, total_tp)
    q.put({'type': 'done', 'run_id': run_id})

@app.get('/scan/<run_id>')
def scan_page(run_id):
    scan = get_scan(run_id)
    return render_template('scan.html', scan=scan, run_id=run_id)

@app.get('/scan/<run_id>/stream')
def scan_stream(run_id):
    def gen():
        q = _queues.get(run_id)
        if not q:
            yield f"data: {json.dumps({'type':'done','run_id':run_id})}\n\n"
            return
        while True:
            try:
                msg = q.get(timeout=25)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get('type') == 'done':
                    with _qlock: _queues.pop(run_id, None)
                    break
            except queue.Empty:
                yield "data: {\"type\":\"ping\"}\n\n"
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.get('/results/<run_id>')
def results(run_id):
    scan = get_scan(run_id)
    if scan:
        targets_list = json.loads(scan['targets'])
    else:
        # Exécution lancée hors interface (CLI, make) : on déduit les cibles
        # des rapports archivés sur le disque.
        targets_list = sorted(t for t in (os.listdir(REPS) if os.path.isdir(REPS) else [])
                              if os.path.exists(os.path.join(REPS, t, run_id, 'findings.json')))
    findings, metrics = [], {}
    for tgt in targets_list:
        ff = os.path.join(REPS, tgt, run_id, 'findings.json')
        mf = os.path.join(REPS, tgt, run_id, 'metrics.json')
        if os.path.exists(ff):
            for f in json.load(open(ff)).get('findings', []):
                f['_target'] = tgt
                findings.append(f)
        if os.path.exists(mf):
            metrics[tgt] = json.load(open(mf))

    findings.sort(key=lambda x: SEV_ORDER.get(x.get('severity', 'info'), 4))
    sev = {}
    for f in findings:
        s = f.get('severity', 'info')
        sev[s] = sev.get(s, 0) + 1

    return render_template('results.html', scan=scan, run_id=run_id,
                           findings=findings, metrics=metrics, sev=sev,
                           targets_list=targets_list)

@app.get('/history')
def history():
    return render_template('history.html', scans=get_all_scans())

# ── comparaison avant / après ────────────────────────────────────────────────
def _list_runs():
    """Analyses disponibles : celles de la base + celles archivées sur disque."""
    runs, seen = [], set()
    for s in get_all_scans():
        targets = json.loads(s['targets']) if s.get('targets') else []
        runs.append({'run_id': s['run_id'], 'started_at': s['started_at'],
                     'targets': targets, 'status': s['status'], 'on_disk': False})
        seen.add(s['run_id'])
    if os.path.isdir(REPS):
        for tgt in sorted(os.listdir(REPS)):
            tgt_dir = os.path.join(REPS, tgt)
            if not os.path.isdir(tgt_dir) or tgt.startswith('.'):
                continue
            for run_id in sorted(os.listdir(tgt_dir), reverse=True):
                if run_id in seen or not os.path.exists(
                        os.path.join(tgt_dir, run_id, 'findings.json')):
                    continue
                seen.add(run_id)
                started = run_id  # ex. 20260101-120000 ou ci-12
                try:
                    started = datetime.datetime.strptime(run_id[:15], '%Y%m%d-%H%M%S').isoformat()
                except ValueError:
                    pass
                runs.append({'run_id': run_id, 'started_at': started,
                             'targets': [], 'status': 'done', 'on_disk': True})
    runs.sort(key=lambda r: r['started_at'], reverse=True)
    return runs

def _collect_run(run_id):
    """Tous les constats d'une exécution, toutes cibles confondues."""
    out = []
    if os.path.isdir(REPS):
        for tgt in sorted(os.listdir(REPS)):
            path = os.path.join(REPS, tgt, run_id, 'findings.json')
            if os.path.exists(path):
                out.extend(load_findings(path))
    return out

def _metrics_delta(before, after):
    """Évolution des métriques par cible entre deux exécutions."""
    deltas = []
    if os.path.isdir(REPS):
        for tgt in sorted(os.listdir(REPS)):
            mb = os.path.join(REPS, tgt, before, 'metrics.json')
            ma = os.path.join(REPS, tgt, after, 'metrics.json')
            if os.path.exists(mb) and os.path.exists(ma):
                ob = json.load(open(mb)).get('overall', {})
                oa = json.load(open(ma)).get('overall', {})
                deltas.append({'target': tgt, 'before': ob, 'after': oa})
    return deltas

def _run_exists(run_id):
    if os.path.isdir(REPS):
        for tgt in sorted(os.listdir(REPS)):
            if os.path.exists(os.path.join(REPS, tgt, run_id, 'findings.json')):
                return True
    return False

@app.get('/compare')
def compare():
    before = request.args.get('before', '')
    after  = request.args.get('after', '')
    runs   = _list_runs()
    result = None
    if before and after:
        if before == after:
            result = {'error': 'same'}
        elif not _run_exists(before) or not _run_exists(after):
            result = {'error': 'missing'}
        else:
            fb, fa = _collect_run(before), _collect_run(after)
            diff = sec_metrics.diff_runs(fb, fa)
            new        = sorted(diff['new'],        key=lambda f: SEV_ORDER.get(f.get('severity', 'info'), 4))
            fixed      = sorted(diff['fixed'],      key=lambda f: SEV_ORDER.get(f.get('severity', 'info'), 4))
            persistent = sorted(diff['persistent'], key=lambda f: SEV_ORDER.get(f.get('severity', 'info'), 4))
            result = {
                'new': new, 'fixed': fixed, 'persistent': persistent,
                'deltas': _metrics_delta(before, after),
            }
    return render_template('compare.html', runs=runs, before=before, after=after, result=result)

# ── main ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    import webbrowser, time
    threading.Timer(1.2, lambda: webbrowser.open('http://localhost:5000')).start()
    app.run(debug=False, threaded=True, port=5000)
