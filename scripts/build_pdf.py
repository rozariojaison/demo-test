"""
Build PRESENTATION_GUIDE.pdf using ReportLab (pure Python, no system libs).
Run: python scripts/build_pdf.py
"""
import os, re, textwrap
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Preformatted, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.colors import HexColor, white, black

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT, "docs", "PRESENTATION_GUIDE.md")
OUT  = os.path.join(ROOT, "docs", "PRESENTATION_GUIDE.pdf")

# ── Colours ────────────────────────────────────────────────────────────────────
C_INDIGO    = HexColor("#4f46e5")
C_INDIGO_DK = HexColor("#1e1b4b")
C_INDIGO_LT = HexColor("#ede9fe")
C_SLATE     = HexColor("#1f2937")
C_GRAY      = HexColor("#6b7280")
C_LGRAY     = HexColor("#f3f4f6")
C_BORDER    = HexColor("#e5e7eb")
C_RED       = HexColor("#dc2626")
C_RED_LT    = HexColor("#fef2f2")
C_GREEN     = HexColor("#16a34a")
C_GREEN_LT  = HexColor("#f0fdf4")
C_YELLOW    = HexColor("#d97706")
C_YELLOW_LT = HexColor("#fffbeb")
C_BLUE      = HexColor("#2563eb")
C_BLUE_LT   = HexColor("#eff6ff")
C_CODE_BG   = HexColor("#0f172a")
C_CODE_FG   = HexColor("#e2e8f0")

W, H = A4
ML = MR = 18*mm
MT = MB = 15*mm
TW = W - ML - MR   # text width

# ── Cover drawn as canvas callback ────────────────────────────────────────────
def draw_cover(canvas, doc):
    canvas.saveState()
    pw, ph = A4
    # Dark background
    canvas.setFillColor(HexColor("#0f172a"))
    canvas.rect(0, 0, pw, ph, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#1e1b4b"))
    canvas.rect(0, ph*0.3, pw, ph*0.4, fill=1, stroke=0)
    # Decorative lines
    canvas.setStrokeColor(HexColor("#4f46e5"))
    canvas.setLineWidth(2)
    canvas.line(pw*0.15, ph*0.88, pw*0.85, ph*0.88)
    canvas.line(pw*0.15, ph*0.26, pw*0.85, ph*0.26)
    # Top label
    canvas.setFillColor(HexColor("#818cf8"))
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(pw/2, ph*0.84, "CYBERSECURITY PORTFOLIO PROJECT")
    # Title
    canvas.setFillColor(white)
    canvas.setFont("Helvetica-Bold", 42)
    canvas.drawCentredString(pw/2, ph*0.70, "API Security")
    canvas.drawCentredString(pw/2, ph*0.61, "Testing Lab")
    # Subtitle
    canvas.setFillColor(HexColor("#a5b4fc"))
    canvas.setFont("Helvetica", 13)
    canvas.drawCentredString(pw/2, ph*0.54, "Complete Presentation & Interview Guide")
    # Pills row
    pills = [("OWASP API Top 10","#ef4444"), ("FastAPI","#3b82f6"),
             ("Python","#22c55e"), ("JWT Security","#a855f7"), ("Rate Limiting","#f59e0b")]
    pill_y = ph*0.46
    pill_ws = [len(lbl)*5.5 + 20 for lbl, _ in pills]
    total_w = sum(pill_ws) + (len(pills)-1)*8
    x = (pw - total_w) / 2
    for (label, col), pw2 in zip(pills, pill_ws):
        canvas.setFillColor(HexColor(col))
        canvas.setStrokeColor(HexColor(col))
        canvas.setFillAlpha(0.2)
        canvas.roundRect(x, pill_y-3, pw2, 17, 8, fill=1, stroke=1)
        canvas.setFillAlpha(1)
        canvas.setFillColor(HexColor(col))
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawCentredString(x + pw2/2, pill_y+3.5, label)
        x += pw2 + 8
    # Footer stats
    canvas.setFillColor(HexColor("#6b7280"))
    canvas.setFont("Helvetica", 9)
    canvas.drawCentredString(pw/2, ph*0.36,
        "5 Vulnerabilities  |  2 Modes  |  30 Interview Q&As  |  Full Demo Script")
    canvas.restoreState()

# ── Styles ─────────────────────────────────────────────────────────────────────
base = getSampleStyleSheet()

def S(name, **kw):
    return ParagraphStyle(name, **kw)

sNormal  = S("sNormal",  fontName="Helvetica", fontSize=10, leading=15,
             textColor=C_SLATE, spaceAfter=6, wordWrap="LTR")
sBody    = S("sBody",    parent=sNormal, firstLineIndent=0, alignment=TA_JUSTIFY)
sH1      = S("sH1",      fontName="Helvetica-Bold", fontSize=20, leading=24,
             textColor=white, spaceBefore=8, spaceAfter=4,
             backColor=C_INDIGO_DK, leftPadding=8, rightPadding=8,
             topPadding=6, bottomPadding=6)
sH2      = S("sH2",      fontName="Helvetica-Bold", fontSize=14, leading=18,
             textColor=C_INDIGO_DK, spaceBefore=14, spaceAfter=4,
             borderPad=(4,4,4,8), leftPadding=10, backColor=C_INDIGO_LT,
             borderColor=C_INDIGO, borderWidth=0)
sH3      = S("sH3",      fontName="Helvetica-Bold", fontSize=11, leading=14,
             textColor=C_SLATE, spaceBefore=10, spaceAfter=3)
sH4      = S("sH4",      fontName="Helvetica-BoldOblique", fontSize=9, leading=12,
             textColor=C_GRAY, spaceBefore=8, spaceAfter=2)
sBQ      = S("sBQ",      fontName="Helvetica-Oblique", fontSize=9.5, leading=14,
             textColor=HexColor("#374151"), spaceBefore=4, spaceAfter=6,
             leftIndent=12, rightIndent=12, backColor=C_YELLOW_LT,
             borderPad=8, borderColor=C_YELLOW, borderWidth=1)
sBullet  = S("sBullet",  fontName="Helvetica", fontSize=10, leading=14,
             textColor=C_SLATE, spaceAfter=3, leftIndent=16, bulletIndent=4,
             bulletFontName="Helvetica", bulletFontSize=10)
sCode    = S("sCode",    fontName="Courier", fontSize=8, leading=11,
             textColor=C_CODE_FG, backColor=C_CODE_BG,
             leftPadding=8, rightPadding=8, topPadding=6, bottomPadding=6,
             spaceAfter=8)
sTOC     = S("sTOC",     fontName="Helvetica", fontSize=10, leading=14,
             textColor=C_BLUE, leftIndent=0)
sLabel   = S("sLabel",   fontName="Helvetica-Bold", fontSize=8,
             textColor=white, backColor=C_INDIGO,
             leftPadding=4, rightPadding=4, topPadding=2, bottomPadding=2)

# ── Header/footer ──────────────────────────────────────────────────────────────
def on_page(canvas, doc):
    if doc.page == 1:
        return
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(C_GRAY)
    canvas.drawString(ML, 9*mm, "API Security Lab  ·  Presentation Guide")
    canvas.drawRightString(W - MR, 9*mm, f"Page {doc.page}")
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(ML, 11*mm, W - MR, 11*mm)
    canvas.restoreState()

# ── Markdown parser ────────────────────────────────────────────────────────────
def inline(text):
    """Convert inline markdown to ReportLab XML, safe tag nesting."""
    # 1. Protect inline code spans first (may contain *, &, <, >)
    placeholders: dict[str, str] = {}
    counter = [0]
    def stash_code(m):
        key = f"\x00CODE{counter[0]}\x00"
        counter[0] += 1
        raw = m.group(1).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
        placeholders[key] = (
            f'<font name="Courier" size="8.5" color="#dc2626" '
            f'backColor="#f3f4f6"> {raw} </font>'
        )
        return key
    text = re.sub(r'`([^`]+)`', stash_code, text)

    # 2. Escape raw & < > outside code spans (those are already stashed)
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    # 3. Bold-italic, bold, italic (no * inside stashed regions)
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<b><i>\1</i></b>', text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'\*([^*\n]+?)\*', r'<i>\1</i>', text)

    # 4. Links — keep display text only
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)

    # 5. Em-dash
    text = text.replace('—', '&#8212;')

    # 6. Restore code spans
    for key, val in placeholders.items():
        text = text.replace(key, val)

    return text

def escape_pre(text):
    return text.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')

def parse_md(md_text):
    story = []
    lines = md_text.splitlines()
    i = 0
    in_code = False
    code_buf = []
    in_table = False
    table_rows = []

    def flush_table():
        nonlocal in_table, table_rows
        if not table_rows: return
        # first row = header, second = separator (skip), rest = data
        rows = [r for r in table_rows if not re.match(r'^\s*[-|: ]+\s*$', r)]
        data = []
        for row in rows:
            cells = [c.strip() for c in row.strip().strip('|').split('|')]
            data.append(cells)
        if not data:
            in_table = False; table_rows = []; return
        # Pad columns
        ncols = max(len(r) for r in data)
        for r in data: r.extend(['']*(ncols-len(r)))
        col_w = TW / ncols
        tdata = []
        for ri, row in enumerate(data):
            tdata.append([
                Paragraph(f'<b>{inline(c)}</b>' if ri==0 else inline(c),
                          ParagraphStyle('tc', fontName='Helvetica' + ('-Bold' if ri==0 else ''),
                                         fontSize=9, leading=13, textColor=white if ri==0 else C_SLATE))
                for c in row
            ])
        ts = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_INDIGO_DK),
            ('TEXTCOLOR',  (0,0), (-1,0), white),
            ('GRID',       (0,0), (-1,-1), 0.5, C_BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [white, C_LGRAY]),
            ('TOPPADDING',  (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 7),
            ('RIGHTPADDING', (0,0), (-1,-1), 7),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ])
        t = Table(tdata, colWidths=[col_w]*ncols, repeatRows=1)
        t.setStyle(ts)
        story.append(KeepTogether([t, Spacer(1, 8)]))
        in_table = False; table_rows = []

    while i < len(lines):
        line = lines[i]

        # Code block
        if line.startswith('```'):
            if not in_code:
                in_code = True
                code_buf = []
            else:
                in_code = False
                text = '\n'.join(code_buf)
                # Wrap long lines
                wrapped = []
                for ln in text.splitlines():
                    if len(ln) > 90:
                        wrapped.extend(textwrap.wrap(ln, 90, subsequent_indent='    '))
                    else:
                        wrapped.append(ln)
                story.append(Preformatted(
                    '\n'.join(wrapped),
                    ParagraphStyle('pre', fontName='Courier', fontSize=7.5, leading=11,
                                   textColor=C_CODE_FG, backColor=C_CODE_BG,
                                   leftPadding=10, rightPadding=10, topPadding=8, bottomPadding=8,
                                   spaceAfter=10)
                ))
            i += 1; continue

        if in_code:
            code_buf.append(escape_pre(line))
            i += 1; continue

        # Table row
        if '|' in line and line.strip().startswith('|'):
            if not in_table:
                in_table = True
                table_rows = []
            table_rows.append(line)
            i += 1; continue
        else:
            if in_table:
                flush_table()

        stripped = line.strip()

        # Skip ToC entries (lines starting with numbers or dashes in ToC)
        if re.match(r'^\d+\. \[', stripped):
            i += 1; continue

        # Headings
        if stripped.startswith('#### '):
            story.append(Paragraph(inline(stripped[5:]), sH4))
        elif stripped.startswith('### '):
            story.append(Paragraph(inline(stripped[4:]), sH3))
        elif stripped.startswith('## '):
            text = inline(stripped[3:])
            story.append(Spacer(1, 6))
            story.append(Paragraph(text, sH2))
            story.append(HRFlowable(width=TW, thickness=1.5, color=C_INDIGO, spaceAfter=4))
        elif stripped.startswith('# '):
            text = inline(stripped[2:])
            if stripped == '# API Security Lab — Complete Presentation Guide':
                i += 1; continue  # skip top-level title (already on cover)
            story.append(PageBreak())
            story.append(Paragraph(text, sH1))
            story.append(Spacer(1, 6))

        # Horizontal rule
        elif stripped.startswith('---') and len(stripped) >= 3 and all(c in '-' for c in stripped):
            story.append(Spacer(1, 4))
            story.append(HRFlowable(width=TW, thickness=0.5, color=C_BORDER, spaceAfter=4))

        # Blockquote
        elif stripped.startswith('> '):
            story.append(Paragraph(inline(stripped[2:]), sBQ))

        # Bullet list
        elif re.match(r'^[-*+] ', stripped):
            story.append(Paragraph(
                inline(stripped[2:]),
                ParagraphStyle('bullet', parent=sBullet, bulletText='•')
            ))

        # Numbered list
        elif re.match(r'^\d+\. ', stripped):
            num = re.match(r'^(\d+)\. ', stripped).group(1)
            story.append(Paragraph(
                inline(re.sub(r'^\d+\. ', '', stripped)),
                ParagraphStyle('ol', parent=sBullet, bulletText=f'{num}.', leftIndent=20)
            ))

        # Bold Q&A headers (Q: / A:)
        elif stripped.startswith('**Q:'):
            story.append(Spacer(1, 4))
            story.append(Paragraph(inline(stripped),
                ParagraphStyle('q', fontName='Helvetica-Bold', fontSize=10, leading=14,
                               textColor=C_INDIGO_DK, spaceBefore=6, spaceAfter=2,
                               backColor=C_BLUE_LT, leftPadding=6, topPadding=4, bottomPadding=4)))
        elif stripped.startswith('> '):
            story.append(Paragraph(inline(stripped[2:]), sBQ))

        # Empty line
        elif stripped == '':
            story.append(Spacer(1, 4))

        # Normal paragraph
        else:
            if stripped:
                story.append(Paragraph(inline(stripped), sBody))

        i += 1

    if in_table:
        flush_table()

    return story

# ── Build PDF ──────────────────────────────────────────────────────────────────
print(f"Source : {SRC}")
print(f"Output : {OUT}")
print("Building ...")

doc = SimpleDocTemplate(
    OUT,
    pagesize=A4,
    leftMargin=ML, rightMargin=MR,
    topMargin=MT, bottomMargin=MB,
    title="API Security Lab — Presentation Guide",
    author="API Security Lab",
    subject="OWASP API Security Top 10 Demo",
)

with open(SRC, encoding="utf-8") as f:
    md = f.read()

story = []
# First element is a PageBreak — cover is drawn by draw_cover() callback, not as a flowable
story.append(PageBreak())
# Content
story.extend(parse_md(md))

def first_page(canvas, doc):
    draw_cover(canvas, doc)      # draw the cover art
    # no header/footer on cover

doc.build(story, onFirstPage=first_page, onLaterPages=on_page)

size_kb = os.path.getsize(OUT) // 1024
print(f"Done!  {size_kb} KB  >>  {OUT}")
