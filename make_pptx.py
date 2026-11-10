import sys
sys.path.insert(0, '/home/amine/whisper-env/lib/python3.12/site-packages')

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt

DARK_BLUE  = RGBColor(0x0D, 0x2F, 0x5E)
MID_BLUE   = RGBColor(0x1A, 0x5F, 0xA8)
ACCENT     = RGBColor(0xE8, 0x2B, 0x2B)
WHITE      = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT_GRAY = RGBColor(0xF4, 0xF6, 0xF9)
TEXT_DARK  = RGBColor(0x1A, 0x1A, 0x2E)
GREEN      = RGBColor(0x27, 0xAE, 0x60)
ORANGE     = RGBColor(0xE6, 0x7E, 0x22)

prs = Presentation()
prs.slide_width  = Inches(13.33)
prs.slide_height = Inches(7.5)
blank = prs.slide_layouts[6]  # blank layout

def add_rect(slide, l, t, w, h, fill=None, line=None):
    shape = slide.shapes.add_shape(1, Inches(l), Inches(t), Inches(w), Inches(h))
    shape.line.fill.background()
    if fill:
        shape.fill.solid()
        shape.fill.fore_color.rgb = fill
    else:
        shape.fill.background()
    if line:
        shape.line.color.rgb = line
        shape.line.width = Pt(1)
    else:
        shape.line.fill.background()
    return shape

def add_text(slide, text, l, t, w, h, size=18, bold=False, color=TEXT_DARK,
             align=PP_ALIGN.LEFT, wrap=True, italic=False):
    txb = slide.shapes.add_textbox(Inches(l), Inches(t), Inches(w), Inches(h))
    txb.word_wrap = wrap
    tf = txb.text_frame
    tf.word_wrap = wrap
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    return txb

def add_multiline(slide, lines, l, t, w, h, size=14, color=TEXT_DARK,
                  bullet=True, bold_first=False, line_spacing=1.15):
    txb = slide.shapes.add_textbox(Inches(l), Inches(t), Inches(w), Inches(h))
    txb.word_wrap = True
    tf = txb.text_frame
    tf.word_wrap = True
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = PP_ALIGN.LEFT
        prefix = "• " if bullet else ""
        run = p.add_run()
        run.text = prefix + line
        run.font.size = Pt(size)
        run.font.color.rgb = color
        run.font.bold = (bold_first and i == 0)
    return txb

def header_bar(slide, title, subtitle=None):
    add_rect(slide, 0, 0, 13.33, 1.4, fill=DARK_BLUE)
    add_rect(slide, 0, 1.4, 13.33, 0.07, fill=ACCENT)
    add_text(slide, title, 0.4, 0.15, 12.5, 0.75, size=28, bold=True,
             color=WHITE, align=PP_ALIGN.LEFT)
    if subtitle:
        add_text(slide, subtitle, 0.4, 0.9, 12.5, 0.45, size=14,
                 color=RGBColor(0xCC, 0xDD, 0xEE), align=PP_ALIGN.LEFT)

def footer(slide, num, total):
    add_rect(slide, 0, 7.15, 13.33, 0.35, fill=DARK_BLUE)
    add_text(slide, "École Polytechnique Sousse — Sécurité des Applications Web & Email",
             0.3, 7.17, 10, 0.3, size=9, color=RGBColor(0xAA, 0xBB, 0xCC))
    add_text(slide, f"{num} / {total}", 12.5, 7.17, 0.8, 0.3, size=9,
             color=WHITE, align=PP_ALIGN.RIGHT)

TOTAL = 13

# ── Slide 1 : Title ──────────────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 0, 13.33, 7.5, fill=DARK_BLUE)
add_rect(s, 0, 5.8, 13.33, 0.12, fill=ACCENT)
add_rect(s, 0, 5.92, 13.33, 1.58, fill=RGBColor(0x0A, 0x24, 0x4A))

# decorative stripe
add_rect(s, 0, 2.6, 0.18, 2.6, fill=ACCENT)

add_text(s, "secauto", 0.5, 0.5, 12, 0.7, size=20, bold=True,
         color=RGBColor(0x7E, 0xC8, 0xE3), align=PP_ALIGN.LEFT)
add_text(s,
    "Conception et évaluation d'une plateforme\nautomatisée de détection de vulnérabilités",
    0.5, 1.3, 12.3, 1.8, size=36, bold=True, color=WHITE, align=PP_ALIGN.LEFT)
add_text(s,
    "SAST  ·  DAST  ·  SCA  ·  Mécanisme personnalisé  ·  CI/CD  ·  Métriques",
    0.5, 3.3, 12.3, 0.6, size=16, color=RGBColor(0xAA, 0xCC, 0xEE), align=PP_ALIGN.LEFT)

add_text(s, "Module : Sécurité des Applications Web & Email",
         0.5, 6.1, 10, 0.4, size=13, color=RGBColor(0xAA, 0xBB, 0xCC))
add_text(s, "Mohamed Amin Smida  —  S1-2026",
         0.5, 6.55, 10, 0.4, size=13, color=WHITE, bold=True)
add_text(s, f"1 / {TOTAL}", 12.2, 6.55, 1, 0.4, size=12,
         color=RGBColor(0x88, 0x99, 0xAA), align=PP_ALIGN.RIGHT)

# ── Slide 2 : Problème ───────────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Le problème", "Trois familles d'outils, trois angles morts")
footer(s, 2, TOTAL)

cols = [
    ("SAST", "Lit le code source\nsans l'exécuter", "✓ SQLi, secrets, flux\n✗ Comportement réel\n✗ Configuration runtime", MID_BLUE),
    ("DAST", "Attaque l'application\nen marche", "✓ XSS, headers\n✗ Code source\n✗ Dépendances", GREEN),
    ("SCA", "Analyse les composants\net leurs CVE", "✓ Vulnérabilités connues\n✗ Logique métier\n✗ Code maison", ORANGE),
]
for i, (title, desc, detail, col) in enumerate(cols):
    x = 0.35 + i * 4.3
    add_rect(s, x, 1.75, 4.0, 4.9, fill=WHITE, line=col)
    add_rect(s, x, 1.75, 4.0, 0.55, fill=col)
    add_text(s, title, x + 0.1, 1.78, 3.8, 0.5, size=20, bold=True,
             color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, desc, x + 0.15, 2.4, 3.7, 0.7, size=13, italic=True, color=TEXT_DARK)
    add_multiline(s, detail.split("\n"), x + 0.15, 3.15, 3.7, 2.5,
                  size=12, bullet=False, color=TEXT_DARK)

add_rect(s, 0.35, 6.4, 12.6, 0.5, fill=RGBColor(0xFF, 0xF0, 0xD0))
add_text(s,
    "→  La question du projet : comment mesurer ce que chaque outil détecte réellement ?",
    0.55, 6.43, 12.2, 0.44, size=13, bold=True, color=ORANGE)

# ── Slide 3 : Objectifs ──────────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Objectifs du projet")
footer(s, 3, TOTAL)

objectives = [
    ("🎯", "Déployer", "un environnement de test reproductible (3 cibles vulnérables par conception)"),
    ("⚙️", "Exécuter", "SAST, DAST, SCA et détection personnalisée de façon automatisée"),
    ("📐", "Normaliser", "tous les résultats dans un format unique (CWE, OWASP, sévérité, preuve)"),
    ("📊", "Mesurer", "la détection : TP / FP / FN, précision, rappel, F1 — par outil"),
    ("🔄", "Automatiser", "avec GitHub Actions : push → analyse, nightly DAST, archivage 30 j"),
    ("📋", "Comparer", "avant / après correctif avec diff et rapport HTML/JSON/SARIF"),
]
for i, (ico, kw, detail) in enumerate(objectives):
    row, col = divmod(i, 2)
    x = 0.4 + col * 6.5
    y = 1.75 + row * 1.6
    add_rect(s, x, y, 6.1, 1.4, fill=WHITE, line=MID_BLUE)
    add_rect(s, x, y, 0.55, 1.4, fill=MID_BLUE)
    add_text(s, ico, x + 0.03, y + 0.3, 0.5, 0.7, size=18, align=PP_ALIGN.CENTER)
    add_text(s, kw, x + 0.65, y + 0.1, 1.2, 0.5, size=15, bold=True, color=MID_BLUE)
    add_text(s, detail, x + 0.65, y + 0.6, 5.3, 0.75, size=11.5, color=TEXT_DARK)

# ── Slide 4 : Architecture ───────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Architecture de la plateforme")
footer(s, 4, TOTAL)

# CLI box top
add_rect(s, 4.5, 1.75, 4.3, 0.65, fill=DARK_BLUE)
add_text(s, "secauto  (CLI Python)", 4.55, 1.82, 4.2, 0.5,
         size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)

# Runners row
runners = [
    ("SAST", "Semgrep\nSonarQube", MID_BLUE),
    ("SCA", "Trivy\nnpm audit", GREEN),
    ("DAST", "ZAP\nbaseline", ORANGE),
    ("CUSTOM", "BOLA/BFLA\nJWT/Headers", ACCENT),
]
for i, (label, tools, col) in enumerate(runners):
    x = 0.3 + i * 3.2
    add_rect(s, x, 2.65, 3.0, 1.1, fill=col)
    add_text(s, label, x + 0.1, 2.68, 2.8, 0.42,
             size=13, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, tools, x + 0.1, 3.1, 2.8, 0.6,
             size=11, color=WHITE, align=PP_ALIGN.CENTER)

# Finding normalisé
add_rect(s, 3.5, 4.0, 6.3, 0.75, fill=WHITE, line=MID_BLUE)
add_text(s, "Finding normalisé  (CWE · OWASP · sévérité · endpoint · preuve · fingerprint)",
         3.6, 4.08, 6.1, 0.6, size=11.5, color=MID_BLUE, align=PP_ALIGN.CENTER, bold=True)

# Output boxes
outputs = ["findings.json", "metrics.json", "report.html", "secauto.sarif", "summary.md"]
for i, out in enumerate(outputs):
    x = 0.3 + i * 2.55
    add_rect(s, x, 5.0, 2.35, 0.55, fill=DARK_BLUE)
    add_text(s, out, x + 0.05, 5.05, 2.25, 0.45,
             size=11, color=WHITE, align=PP_ALIGN.CENTER)

add_text(s, "reports/<cible>/<run-id>/", 5.5, 5.75, 3.0, 0.4,
         size=11, color=TEXT_DARK, italic=True, align=PP_ALIGN.CENTER)

# Metrics box right
add_rect(s, 10.8, 2.65, 2.3, 1.1, fill=RGBColor(0x2C, 0x3E, 0x50))
add_text(s, "METRICS\nTP/FP/FN\nP · R · F1",
         10.85, 2.68, 2.2, 1.0, size=11, color=WHITE, align=PP_ALIGN.CENTER)

# ── Slide 5 : Environnement ──────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Environnement de test", "3 cibles vulnérables par conception — Docker Compose")
footer(s, 5, TOTAL)

targets_info = [
    ("Juice Shop", "Node.js / Angular", "3000", MID_BLUE,
     ["SQLi (séquelize)", "XSS réfléchi / stocké", "Secret JWT codé en dur",
      "Faiblesses d'authentification", "Prototype pollution (lodash)"]),
    ("crAPI", "Microservices (Spring/Python)", "8888", ACCENT,
     ["BOLA — véhicule d'un autre utilisateur", "BFLA — endpoint admin accessible",
      "JWT — signature non vérifiée", "Assignation de masse", "Exposition excessive de données"]),
    ("Roundcube", "PHP (messagerie réelle)", "8080", GREEN,
     ["En-têtes de sécurité manquants", "CSRF sur actions sensibles",
      "Application PHP en production réelle", "Surface d'attaque email"]),
]
for i, (name, stack, port, col, vulns) in enumerate(targets_info):
    x = 0.3 + i * 4.3
    add_rect(s, x, 1.75, 4.1, 5.1, fill=WHITE, line=col)
    add_rect(s, x, 1.75, 4.1, 0.6, fill=col)
    add_text(s, name, x + 0.1, 1.78, 3.9, 0.5,
             size=18, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, stack, x + 0.1, 2.42, 3.9, 0.35,
             size=11, italic=True, color=TEXT_DARK, align=PP_ALIGN.CENTER)
    add_rect(s, x + 0.9, 2.82, 2.3, 0.3, fill=LIGHT_GRAY)
    add_text(s, f"http://localhost:{port}", x + 0.9, 2.84, 2.3, 0.28,
             size=10, color=col, align=PP_ALIGN.CENTER)
    add_multiline(s, vulns, x + 0.15, 3.2, 3.8, 2.5, size=11.5, color=TEXT_DARK)

add_rect(s, 0.3, 6.5, 12.7, 0.4, fill=DARK_BLUE)
add_text(s, "make up  →  Juice Shop :3000  |  crAPI :8888  |  Roundcube :8080  — versions épinglées",
         0.5, 6.53, 12.3, 0.35, size=11, color=WHITE, align=PP_ALIGN.CENTER)

# ── Slide 6 : Chaîne d'analyse ───────────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Chaîne d'analyse automatisée",
           "python3 -m secauto run --target crapi  —  une commande, quatre familles")
footer(s, 6, TOTAL)

chain = [
    ("SAST", MID_BLUE, [
        "Semgrep : packs OWASP + JavaScript",
        "5 règles Semgrep maison (SQLi, injection\n  de commande, JWT, BFLA Java)",
        "SonarQube (optionnel, via API)",
        "→ Sortie : findings.json + SARIF",
    ]),
    ("SCA", GREEN, [
        "Trivy filesystem : vulnérabilités + secrets",
        "npm audit (si package-lock.json présent)",
        "Résultats CVE avec sévérité CVSS",
        "→ Sortie : trivy.json + npm-audit.json",
    ]),
    ("DAST", ORANGE, [
        "OWASP ZAP baseline / full / api-scan",
        "Lancé via Docker (ghcr.io/zaproxy/zaproxy)",
        "Cible : application démarrée localement",
        "→ Sortie : zap-report.json + HTML",
    ]),
    ("CUSTOM", ACCENT, [
        "idor_probe.py : BOLA + BFLA (2 comptes,\n  échange d'IDs, appel fonction admin)",
        "check_jwt.py : signature altérée rejouée",
        "check_headers.py : headers, cookies, CORS",
        "→ Contrat commun : {\"findings\": [...]}",
    ]),
]
for i, (label, col, items) in enumerate(chain):
    x = 0.3 + i * 3.25
    add_rect(s, x, 1.75, 3.1, 4.9, fill=WHITE, line=col)
    add_rect(s, x, 1.75, 3.1, 0.5, fill=col)
    add_text(s, label, x + 0.1, 1.78, 2.9, 0.44,
             size=15, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_multiline(s, items, x + 0.1, 2.33, 2.9, 3.3, size=11, bullet=False, color=TEXT_DARK)

add_rect(s, 0.3, 6.5, 12.7, 0.4, fill=DARK_BLUE)
add_text(s, "Chaque outil conserve sa sortie brute dans raw/  —  rien n'est perdu, tout est auditable",
         0.5, 6.53, 12.3, 0.35, size=11, color=WHITE, align=PP_ALIGN.CENTER)

# ── Slide 7 : Mécanisme complémentaire ──────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Mécanisme de détection complémentaire",
           "Ce que les outils industriels ne voient pas sans scénario")
footer(s, 7, TOTAL)

# Left: Semgrep rules
add_rect(s, 0.3, 1.75, 5.9, 4.9, fill=WHITE, line=MID_BLUE)
add_rect(s, 0.3, 1.75, 5.9, 0.5, fill=MID_BLUE)
add_text(s, "5 Règles Semgrep maison", 0.4, 1.78, 5.7, 0.44,
         size=14, bold=True, color=WHITE)
rules = [
    "secauto-sqli-sequelize-template  (CWE-89)",
    "secauto-sqli-string-concat       (CWE-89)",
    "secauto-command-injection        (CWE-78)",
    "secauto-jwt-hardcoded-secret     (CWE-798)",
    "secauto-java-endpoint-without-authz (CWE-862)",
]
add_multiline(s, rules, 0.4, 2.35, 5.7, 2.4, size=12, bullet=True, color=TEXT_DARK)
add_text(s, "Ciblées, précision 100 % — pas de bruit AWS/GH Actions",
         0.4, 4.85, 5.7, 0.55, size=11, italic=True, color=MID_BLUE)

# Right: Python detectors
add_rect(s, 6.5, 1.75, 6.5, 4.9, fill=WHITE, line=ACCENT)
add_rect(s, 6.5, 1.75, 6.5, 0.5, fill=ACCENT)
add_text(s, "3 Détecteurs Python autonomes", 6.6, 1.78, 6.3, 0.44,
         size=14, bold=True, color=WHITE)

detectors = [
    ("idor_probe.py", "BOLA + BFLA",
     "Crée 2 comptes, collecte les IDs d'objets\nexposés (forum), rejoue avec jeton croisé,\nappelle endpoint /admin avec user standard"),
    ("check_jwt.py", "JWT",
     "Altère la signature d'un jeton valide,\nrevoie sur endpoint protégé —\nsi 200 : signature non vérifiée (critical)"),
    ("check_headers.py", "Headers",
     "Requête HTTP brute, vérifie CSP / HSTS /\nX-Frame-Options, cookies HttpOnly/Secure,\nCORS permissif"),
]
for i, (script, label, desc) in enumerate(detectors):
    y = 2.35 + i * 1.4
    add_rect(s, 6.6, y, 6.2, 1.25, fill=LIGHT_GRAY)
    add_text(s, f"{script}  [{label}]", 6.7, y + 0.05, 6.0, 0.4,
             size=12, bold=True, color=ACCENT)
    add_text(s, desc, 6.7, y + 0.45, 6.0, 0.75, size=10.5, color=TEXT_DARK)

# ── Slide 8 : Résultats Juice Shop ──────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Résultats — OWASP Juice Shop v20.2.0",
           "Exécutions réelles archivées dans reports/juice-shop/")
footer(s, 8, TOTAL)

# Table
headers = ["Configuration", "Constats", "TP", "FP", "Précision", "Rappel"]
rows = [
    ["Semgrep, règles maison seules (--offline)", "3", "3", "0", "100 %", "23 %"],
    ["Semgrep, packs OWASP + JS + règles maison", "36", "6", "30", "17 %", "23 %"],
    ["Trivy fs (vulnérabilités + secrets)", "5", "1", "4", "20 %", "8 %"],
    ["ZAP baseline (DAST)", "51", "3", "48", "6 %", "8 %"],
    ["Campagne baseline (SAST + Trivy)", "41", "7", "34", "17 %", "23 %"],
]
col_w = [5.5, 1.1, 0.7, 0.7, 1.1, 1.0]
col_x = [0.3]
for w in col_w[:-1]:
    col_x.append(col_x[-1] + w + 0.05)

# header row
for j, (hdr, cx, cw) in enumerate(zip(headers, col_x, col_w)):
    add_rect(s, cx, 1.78, cw, 0.42, fill=DARK_BLUE)
    add_text(s, hdr, cx + 0.05, 1.8, cw - 0.1, 0.38,
             size=11, bold=True, color=WHITE, align=PP_ALIGN.CENTER)

for i, row in enumerate(rows):
    bg = WHITE if i % 2 == 0 else LIGHT_GRAY
    bold_row = (i == 4)
    for j, (cell, cx, cw) in enumerate(zip(row, col_x, col_w)):
        add_rect(s, cx, 2.25 + i * 0.52, cw, 0.5, fill=bg if not bold_row else RGBColor(0xE8, 0xF4, 0xFD))
        add_text(s, cell, cx + 0.05, 2.27 + i * 0.52, cw - 0.1, 0.46,
                 size=11, bold=bold_row,
                 color=MID_BLUE if bold_row else TEXT_DARK,
                 align=PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER)

# Key insight
add_rect(s, 0.3, 5.0, 12.7, 1.3, fill=WHITE, line=MID_BLUE)
insights = [
    "• Les règles maison sont précises (100 %) — les packs génériques n'ajoutent que du bruit sans gain de rappel",
    "• ZAP ne retrouve que les en-têtes manquants — les injections et failles métier restent invisibles sans scénario",
    "• Rappel global = 23 % (minorant) — la vérité terrain est partielle (13 entrées vérifiées manuellement)",
]
add_multiline(s, insights, 0.4, 5.05, 12.4, 1.2, size=11, bullet=False, color=TEXT_DARK)

# ── Slide 9 : Résultats crAPI ────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Résultats — crAPI (détecteurs maison + campagne complète)",
           "Vérité terrain : 7 challenges OWASP API Security Top 10")
footer(s, 9, TOTAL)

# Left: custom table
add_rect(s, 0.3, 1.78, 6.0, 0.4, fill=DARK_BLUE)
add_text(s, "Détecteurs maison  (--tools custom)", 0.4, 1.8, 5.8, 0.36,
         size=12, bold=True, color=WHITE)
c_rows = [
    ["custom:idor-api  (BOLA + BFLA)", "2", "2", "0", "100 %", "29 %"],
    ["custom:jwt", "1", "1", "0", "100 %", "14 %"],
    ["custom:headers", "6", "0", "6", "0 %", "0 %"],
    ["Total", "9", "3", "6", "33 %", "43 %"],
]
c_hdr = ["Détecteur", "Const.", "TP", "FP", "P", "R"]
c_cw  = [3.3, 0.7, 0.5, 0.5, 0.7, 0.7]
c_cx  = [0.3]
for w in c_cw[:-1]: c_cx.append(c_cx[-1] + w + 0.03)
for j, (h, cx, cw) in enumerate(zip(c_hdr, c_cx, c_cw)):
    add_rect(s, cx, 2.22, cw, 0.35, fill=MID_BLUE)
    add_text(s, h, cx + 0.03, 2.24, cw - 0.06, 0.31,
             size=10, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
for i, row in enumerate(c_rows):
    bold_r = (i == 3)
    bg = RGBColor(0xE8, 0xF4, 0xFD) if bold_r else (WHITE if i % 2 == 0 else LIGHT_GRAY)
    for j, (cell, cx, cw) in enumerate(zip(row, c_cx, c_cw)):
        add_rect(s, cx, 2.6 + i * 0.45, cw, 0.43, fill=bg)
        add_text(s, cell, cx + 0.03, 2.62 + i * 0.45, cw - 0.06, 0.39,
                 size=10.5, bold=bold_r,
                 color=ACCENT if bold_r else TEXT_DARK,
                 align=PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER)

# Right: full campaign + DAST comparison
add_rect(s, 6.6, 1.78, 6.4, 0.4, fill=DARK_BLUE)
add_text(s, "Campagne complète  (SAST + SCA + DAST + Custom)", 6.7, 1.8, 6.2, 0.36,
         size=12, bold=True, color=WHITE)
add_rect(s, 6.6, 2.22, 6.4, 1.6, fill=WHITE, line=ACCENT)
full_lines = [
    "449 constats  —  6 TP  —  précision 1 %  —  rappel 43 %",
    "",
    "Trivy (SCA) : 271 CVE  →  0 TP  (hors périmètre GT)",
    "Semgrep : 143 constats  →  3 TP  (règle Java BFLA)",
    "ZAP (DAST) : 26 constats  →  0 TP  (en-têtes seuls)",
    "Détecteurs maison : 9  →  3 TP  (BOLA, BFLA, JWT)",
]
add_multiline(s, full_lines, 6.7, 2.26, 6.1, 1.5, size=11, bullet=False, color=TEXT_DARK)

# DAST 3 targets
add_rect(s, 6.6, 3.95, 6.4, 0.38, fill=DARK_BLUE)
add_text(s, "Comparaison DAST — 3 cibles", 6.7, 3.97, 6.2, 0.34,
         size=12, bold=True, color=WHITE)
dast_rows = [
    ["Juice Shop", "51", "3", "6 %", "8 %"],
    ["crAPI", "28", "0", "0 %", "0 %"],
    ["Roundcube", "52", "4", "8 %", "33 %"],
]
dast_hdr = ["Cible", "Constats", "TP", "P", "R"]
dast_cw = [2.3, 1.1, 0.7, 0.9, 0.9]
dast_cx = [6.6]
for w in dast_cw[:-1]: dast_cx.append(dast_cx[-1] + w + 0.04)
for j, (h, cx, cw) in enumerate(zip(dast_hdr, dast_cx, dast_cw)):
    add_rect(s, cx, 4.37, cw, 0.33, fill=ORANGE)
    add_text(s, h, cx + 0.03, 4.39, cw - 0.06, 0.29,
             size=10, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
for i, row in enumerate(dast_rows):
    bg = WHITE if i % 2 == 0 else LIGHT_GRAY
    for j, (cell, cx, cw) in enumerate(zip(row, dast_cx, dast_cw)):
        add_rect(s, cx, 4.73 + i * 0.42, cw, 0.4, fill=bg)
        add_text(s, cell, cx + 0.03, 4.75 + i * 0.42, cw - 0.06, 0.36,
                 size=10.5, color=TEXT_DARK,
                 align=PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER)

add_rect(s, 6.6, 6.05, 6.4, 0.5, fill=RGBColor(0xFF, 0xF0, 0xD0))
add_text(s, "→ ZAP ne retrouve que les headers — 0 faille métier sans scénario authentifié",
         6.7, 6.08, 6.2, 0.44, size=11, bold=True, color=ORANGE)

# ── Slide 10 : Avant/Après correctif ────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Comparaison avant / après correctif",
           "Juice Shop — SQLi dans routes/login.ts")
footer(s, 10, TOTAL)

# Timeline
add_rect(s, 0.4, 2.1, 12.5, 0.08, fill=MID_BLUE)
steps = [
    (0.4, "1. Scan initial\nbefore-fix", MID_BLUE),
    (3.8, "2. Correctif\nappliqué", ORANGE),
    (7.2, "3. Nouveau\nscan after-fix", GREEN),
    (10.6, "4. Comparaison\ndiff", ACCENT),
]
for x, label, col in steps:
    add_rect(s, x, 1.95, 0.25, 0.25, fill=col)
    add_text(s, label, x - 0.4, 2.3, 1.5, 0.6, size=11, color=col, align=PP_ALIGN.CENTER)

# Commands
cmds = [
    "python3 -m secauto run --target juice-shop --tools sast --offline --run-id before-fix",
    "bash scripts/demo-juiceshop-fix.sh   # applique requête paramétrée dans routes/login.ts",
    "python3 -m secauto run --target juice-shop --tools sast --offline --run-id after-fix",
    "python3 -m secauto compare --target juice-shop --before before-fix --after after-fix",
]
for i, cmd in enumerate(cmds):
    add_rect(s, 0.4, 3.1 + i * 0.65, 12.5, 0.58, fill=RGBColor(0x1A, 0x1A, 0x2E))
    add_text(s, f"$ {cmd}", 0.55, 3.13 + i * 0.65, 12.2, 0.52,
             size=11, color=RGBColor(0x7E, 0xC8, 0xE3), align=PP_ALIGN.LEFT)

# Result box
add_rect(s, 0.4, 5.85, 12.5, 0.75, fill=GREEN)
add_text(s,
    "Résultat :  Corrigées : 1  (secauto-sqli-sequelize-template disparaît)  "
    "·  Persistantes : 2  ·  Nouvelles : 0",
    0.6, 5.95, 12.1, 0.55, size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)

# ── Slide 11 : CI/CD ─────────────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Automatisation CI/CD",
           ".github/workflows/security.yml — GitHub Actions")
footer(s, 11, TOTAL)

jobs = [
    ("push / PR", MID_BLUE, [
        "Matrice : juice-shop, crapi",
        "Semgrep + Trivy + npm audit",
        "Conversion SARIF → GitHub code scanning",
        "Artefacts 30 jours",
        "--fail-on high : barrière de merge",
    ]),
    ("Nightly (lundi 03:00 UTC)", ORANGE, [
        "Démarrage automatique de Juice Shop",
        "OWASP ZAP baseline complet",
        "Rapport HTML archivé",
        "Job summary dans GitHub Actions",
    ]),
    ("Agrégation", GREEN, [
        "Artefact unique reports-all",
        "Résumé Markdown dans le job summary",
        "Chaque run identifié : ci-<numéro>",
        "reports/index.json maintenu",
    ]),
]
for i, (trigger, col, items) in enumerate(jobs):
    x = 0.3 + i * 4.3
    add_rect(s, x, 1.75, 4.1, 5.0, fill=WHITE, line=col)
    add_rect(s, x, 1.75, 4.1, 0.55, fill=col)
    add_text(s, trigger, x + 0.1, 1.78, 3.9, 0.5,
             size=13, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_multiline(s, items, x + 0.15, 2.38, 3.8, 3.3, size=12, color=TEXT_DARK)

add_rect(s, 0.3, 6.5, 12.7, 0.4, fill=DARK_BLUE)
add_text(s, "make scan TARGET=crapi  ·  make ci TARGET=juice-shop  ·  make compare TARGET=juice-shop BEFORE=… AFTER=…",
         0.5, 6.53, 12.3, 0.35, size=11, color=WHITE, align=PP_ALIGN.CENTER)

# ── Slide 12 : Limites & Perspectives ───────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 1.6, 13.33, 5.55, fill=LIGHT_GRAY)
header_bar(s, "Limites connues & Perspectives")
footer(s, 12, TOTAL)

limits = [
    "Vérité terrain partielle — le rappel calculé est un minorant (13 entrées JS, 7 entrées crAPI)",
    "ZAP baseline non authentifié — zones privées couvertes uniquement par les détecteurs custom",
    "npm audit dépend du registre npm et d'un lockfile — flaky sans réseau (timeout consigné)",
    "Règle Java Semgrep (CWE-862) : confiance faible — confirmation manuelle requise",
]
persp = [
    "ZAP avec authentification (OpenAPI spec + jeton JWT) pour couvrir les zones privées",
    "SonarQube intégré en CI (serveur managed) pour une couverture SAST plus profonde",
    "Corrélation SAST ↔ DAST par empreinte — déduplication inter-outils",
    "Tableau de bord historique — évolution des métriques run-to-run",
]

add_rect(s, 0.3, 1.75, 6.0, 0.4, fill=ACCENT)
add_text(s, "Limites", 0.4, 1.77, 5.8, 0.36, size=13, bold=True, color=WHITE)
add_rect(s, 0.3, 2.19, 6.0, 4.5, fill=WHITE, line=ACCENT)
add_multiline(s, limits, 0.4, 2.25, 5.8, 4.3, size=12, color=TEXT_DARK)

add_rect(s, 6.8, 1.75, 6.2, 0.4, fill=GREEN)
add_text(s, "Perspectives", 6.9, 1.77, 6.0, 0.36, size=13, bold=True, color=WHITE)
add_rect(s, 6.8, 2.19, 6.2, 4.5, fill=WHITE, line=GREEN)
add_multiline(s, persp, 6.9, 2.25, 6.0, 4.3, size=12, color=TEXT_DARK)

# ── Slide 13 : Conclusion ────────────────────────────────────────────────────
s = prs.slides.add_slide(blank)
add_rect(s, 0, 0, 13.33, 7.5, fill=DARK_BLUE)
add_rect(s, 0, 1.3, 13.33, 0.07, fill=ACCENT)
add_rect(s, 0, 1.37, 13.33, 0.07, fill=MID_BLUE)

add_text(s, "Conclusion", 0.5, 0.3, 12, 0.85,
         size=32, bold=True, color=WHITE, align=PP_ALIGN.LEFT)

points = [
    ("Orchestration & Normalisation",
     "SAST · DAST · SCA · Custom — un seul modèle Finding en sortie,\ncomparable et exploitable par un SIEM ou un tableau de bord.",
     MID_BLUE),
    ("Mesure objective",
     "TP / FP / FN, précision et rappel calculés par outil et par catégorie\ncontre une vérité terrain versionnée — pas une liste de 'alertes'.",
     GREEN),
    ("Reproductibilité",
     "Une commande, un run-id, des rapports archivés.\nLe correctif est prouvé par le diff avant / après.",
     ORANGE),
]
for i, (title, body, col) in enumerate(points):
    y = 1.65 + i * 1.7
    add_rect(s, 0.4, y, 0.1, 1.4, fill=col)
    add_rect(s, 0.55, y, 12.4, 1.4, fill=RGBColor(0x0A, 0x24, 0x4A))
    add_text(s, title, 0.75, y + 0.1, 11.8, 0.5,
             size=16, bold=True, color=col)
    add_text(s, body, 0.75, y + 0.6, 11.8, 0.75,
             size=13, color=RGBColor(0xCC, 0xDD, 0xEE))

add_text(s, "Merci — Questions ?", 0.5, 6.7, 12.3, 0.5,
         size=18, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
add_text(s, f"1 / {TOTAL}", 12.2, 7.1, 1, 0.3, size=10,
         color=RGBColor(0x88, 0x99, 0xAA), align=PP_ALIGN.RIGHT)

# ── Save ─────────────────────────────────────────────────────────────────────
out = "/home/amine/secauto/docs/secauto-presentation.pptx"
prs.save(out)
print(f"Saved → {out}")
