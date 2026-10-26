"""Organization-scoped VATA compliance summaries in PDF format."""
from datetime import datetime, timezone
from html import escape
from io import BytesIO
import hashlib
import json

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

MAX_REPORTED_FINDINGS = 1000
PAGE_WIDTH, _ = letter
INK = colors.HexColor('#202a28')
FOREST = colors.HexColor('#185d4d')
MUTED = colors.HexColor('#64716c')
LINE = colors.HexColor('#d8ddd2')
SURFACE = colors.HexColor('#f3f1e9')
STANDARD_SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')


def compute_canonical_findings_hash(findings, severity_counts):
    """Compute SHA256 hash of findings and severity counts, excluding generation timestamp.

    This hash is deterministic and reproducible: same findings always produce same hash.
    Used for chain-of-custody verification across JSON and PDF exports.
    """
    canonical = {
        'severity_counts': dict(sorted(severity_counts.items())),
        'findings': [
            {
                'server_name': f.get('server_name'),
                'rule': f.get('rule'),
                'vector_type': f.get('vector_type'),
                'severity': f.get('severity'),
                'description': f.get('description'),
                'remediation': f.get('remediation'),
                'created_at': f.get('created_at'),
            }
            for f in findings
        ]
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode()).hexdigest()


def _plain_text(value, *, limit=1000):
    """Escape untrusted database strings for ReportLab's Paragraph markup."""
    text = str(value or '').replace('\r\n', '\n').replace('\r', '\n')
    text = ''.join(character for character in text
                   if character in '\n\t' or ord(character) >= 32 and ord(character) != 127)
    truncated = len(text) > limit
    text = text[:limit].encode('cp1252', errors='replace').decode('cp1252')
    if truncated:
        text += ' [truncated]'
    return escape(text).replace('\n', '<br/>')


def _paragraph(text, style):
    return Paragraph(text or '&nbsp;', style)



def _scan_note(summary, scan_rows):
    """Note on scan status when assessment is not complete."""
    if summary.get('compliance_score') is not None or not scan_rows:
        return ''
    named = ', '.join(
        f"{_plain_text(str(r.get('target') or 'unknown'))} "
        f"({_plain_text(str(r.get('status') or 'unknown').lower())})"
        for r in scan_rows)
    return '<br/>Scans recorded, none completed: ' + named



def generate_compliance_pdf(organization, summary, severity_counts, findings, scan_rows=(), content_hash=None):
    """Create a printable summary using the app's own score and tenant-scoped data."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter, leftMargin=36, rightMargin=36,
        topMargin=42, bottomMargin=46, title='VATA Compliance Summary',
        author='VATA',
    )
    source_styles = getSampleStyleSheet()
    styles = {
        'title': ParagraphStyle(
            'VataReportTitle', parent=source_styles['Title'], fontName='Helvetica-Bold',
            fontSize=21, leading=26, textColor=INK, alignment=TA_LEFT, spaceAfter=7,
        ),
        'org': ParagraphStyle(
            'VataReportOrg', parent=source_styles['Heading2'], fontName='Helvetica',
            fontSize=12, leading=16, textColor=MUTED, spaceAfter=5,
        ),
        'section': ParagraphStyle(
            'VataReportSection', parent=source_styles['Heading2'], fontName='Helvetica-Bold',
            fontSize=12, leading=15, textColor=INK, spaceBefore=14, spaceAfter=7,
        ),
        'body': ParagraphStyle(
            'VataReportBody', parent=source_styles['BodyText'], fontName='Helvetica',
            fontSize=8.5, leading=12, textColor=INK, spaceAfter=3, wordWrap='CJK',
        ),
        'muted': ParagraphStyle(
            'VataReportMuted', parent=source_styles['BodyText'], fontName='Helvetica',
            fontSize=8, leading=11, textColor=MUTED, spaceAfter=4, wordWrap='CJK',
        ),
        'cell': ParagraphStyle(
            'VataReportCell', parent=source_styles['BodyText'], fontName='Helvetica',
            fontSize=7.5, leading=10, textColor=INK, wordWrap='CJK',
        ),
        'cell_header': ParagraphStyle(
            'VataReportCellHeader', parent=source_styles['BodyText'],
            fontName='Helvetica-Bold', fontSize=7.5, leading=9,
            textColor=colors.white, wordWrap='CJK',
        ),
        'score': ParagraphStyle(
            'VataReportScore', parent=source_styles['BodyText'], fontName='Helvetica-Bold',
            fontSize=16, leading=19, textColor=FOREST, alignment=TA_RIGHT,
        ),
        'center': ParagraphStyle(
            'VataReportCenter', parent=source_styles['BodyText'], fontName='Helvetica',
            fontSize=8, leading=10, textColor=INK, alignment=TA_CENTER,
        ),
    }
    content_width = PAGE_WIDTH - doc.leftMargin - doc.rightMargin
    created = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    story = [
        Paragraph('VATA Compliance Summary', styles['title']),
        _paragraph(_plain_text(organization.get('name') or 'Security workspace'),
                   styles['org']),
        Paragraph(f'Workspace ID: {_plain_text(organization["id"])}', styles['muted']),
        Paragraph(f'Generated: {created}', styles['muted']),
        Spacer(1, 0.12 * inch),
        Paragraph('Current compliance overview', styles['section']),
    ]

    score_table = Table(
        [[
            Paragraph(
                '<b>VATA compliance score</b><br/>'
                + ('Not assessed: no scans recorded'
                   if summary.get('compliance_score') is None
                   else f'{summary["total_findings"]} findings included in the score')
                + _scan_note(summary, scan_rows),
                styles['body'],
            ),
            Paragraph('Not assessed', styles['score'])
            if summary.get('compliance_score') is None
            else Paragraph(f'{summary["compliance_score"]}%', styles['score']),
        ]],
        colWidths=[content_width * 0.72, content_width * 0.28],
    )
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), SURFACE),
        ('BOX', (0, 0), (-1, -1), 0.7, LINE),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 11),
        ('RIGHTPADDING', (0, 0), (-1, -1), 11),
        ('TOPPADDING', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
    ]))
    story.extend([
        score_table,
        Paragraph(
            'This score uses VATA’s existing severity-based formula. '
            'It is not a SOC 2 attestation, certification, or audit opinion.',
            styles['muted'],
        ),
        *_scan_section(scan_rows, styles),
        Paragraph('Findings by severity', styles['section']),
    ])

    normalized_counts = {
        str(severity or '').strip().upper(): int(count)
        for severity, count in severity_counts.items()
    }
    other_count = sum(
        count for severity, count in normalized_counts.items()
        if severity not in STANDARD_SEVERITIES
    )
    summary_rows = [[
        _paragraph('Severity', styles['cell_header']),
        _paragraph('Findings', styles['cell_header']),
    ]]
    for severity in (*STANDARD_SEVERITIES, 'OTHER / UNSPECIFIED'):
        count = other_count if severity == 'OTHER / UNSPECIFIED' else normalized_counts.get(severity, 0)
        summary_rows.append([
            _paragraph(severity.title(), styles['cell']),
            _paragraph(str(count), styles['center']),
        ])
    summary_table = Table(
        summary_rows, colWidths=[content_width * 0.72, content_width * 0.28],
        hAlign='LEFT',
    )
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), FOREST),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, SURFACE]),
        ('GRID', (0, 0), (-1, -1), 0.4, LINE),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Paragraph('Finding details', styles['section']))

    if summary['total_findings'] > MAX_REPORTED_FINDINGS:
        story.append(Paragraph(
            f'The summary score and severity counts include all '
            f'{summary["total_findings"]} findings. The detail section is limited '
            f'to the {MAX_REPORTED_FINDINGS} most recent.',
            styles['muted'],
        ))

    if findings:
        story.append(Paragraph(
            f'Showing {len(findings)} findings for this organization. '
            'Severity totals above include all recorded findings.',
            styles['muted'],
        ))
        column_widths = [60, 108, 112, content_width - 280]
        rows = [[
            _paragraph('Severity', styles['cell_header']),
            _paragraph('Server', styles['cell_header']),
            _paragraph('Rule', styles['cell_header']),
            _paragraph('Recorded', styles['cell_header']),
        ]]
        details = []
        for finding in findings:
            severity = str(finding.get('severity') or '').strip().upper() or 'UNSPECIFIED'
            rows.append([
                _paragraph(_plain_text(severity, limit=30), styles['cell']),
                _paragraph(_plain_text(finding.get('server_name') or '—', limit=200), styles['cell']),
                _paragraph(_plain_text(finding.get('rule') or finding.get('vector_type') or 'Finding',
                                       limit=200), styles['cell']),
                _paragraph(_plain_text(finding.get('created_at') or 'Not recorded', limit=80),
                           styles['cell']),
            ])
            description = _plain_text(finding.get('description') or 'No description provided.')
            detail = [_paragraph(f'<b>Description:</b> {description}', styles['cell'])]
            remediation_text = str(finding.get('remediation') or '')
            if remediation_text:
                remediation = _plain_text(remediation_text)
                detail.append(_paragraph(f'<b>Remediation:</b> {remediation}', styles['cell']))
            details.append(detail)
        detail_start = len(rows)
        rows.extend([[detail] for detail in details])
        findings_table = LongTable(
            rows, colWidths=column_widths, repeatRows=1, splitByRow=1, hAlign='LEFT',
        )
        commands = [
            ('BACKGROUND', (0, 0), (-1, 0), FOREST),
            ('GRID', (0, 0), (-1, detail_start - 1), 0.4, LINE),
            ('ROWBACKGROUNDS', (0, 1), (-1, detail_start - 1), [colors.white, SURFACE]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]
        for row_number in range(detail_start, len(rows)):
            commands.extend([
                ('SPAN', (0, row_number), (-1, row_number)),
                ('BACKGROUND', (0, row_number), (-1, row_number),
                 colors.white if row_number % 2 == 0 else SURFACE),
                ('LINEBELOW', (0, row_number), (-1, row_number), 0.7, LINE),
            ])
        findings_table.setStyle(TableStyle(commands))
        story.append(findings_table)
    else:
        story.append(Paragraph(
            'No findings are recorded for this organization.',
            styles['body'],
        ))

    if summary['total_findings'] > MAX_REPORTED_FINDINGS:
        story.extend([
            Paragraph('Report coverage', styles['section']),
            Paragraph(
                f'This PDF shows the {MAX_REPORTED_FINDINGS} most recent findings. '
                f'The summary score and severity counts cover all '
                f'{summary["total_findings"]} findings.',
                styles['body'],
            ),
        ])

    # Add content hash if provided (excludes generation timestamp)
    if content_hash:
        story.extend([
            Spacer(1, 0.2 * inch),
            Paragraph('Report Integrity', styles['section']),
            Paragraph(
                f'<b>Content Hash (SHA256):</b><br/>'
                f'<code>{content_hash}</code><br/><br/>'
                f'<b>To Verify:</b> Serialize findings + severity_counts as JSON (key order: severity_counts first, sorted keys, no spaces after separators). '
                f'Compute SHA256 of that JSON string. Result must match hash above. '
                f'Excludes: generation timestamp, PDF metadata.',
                styles['body'],
            ),
        ])

    def draw_footer(pdf_canvas, report_doc):
        pdf_canvas.saveState()
        pdf_canvas.setStrokeColor(LINE)
        pdf_canvas.line(doc.leftMargin, 34, PAGE_WIDTH - doc.rightMargin, 34)
        pdf_canvas.setFont('Helvetica', 7)
        pdf_canvas.setFillColor(MUTED)
        pdf_canvas.drawString(doc.leftMargin, 22, 'VATA · Organization compliance summary')
        pdf_canvas.drawRightString(PAGE_WIDTH - doc.rightMargin, 22,
                                   f'Page {report_doc.page}')
        pdf_canvas.restoreState()

    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    return buffer.getvalue()


def _scan_section(scan_rows, styles):
    """Render details of recorded scans when assessment is complete."""
    if not scan_rows:
        return []
    lines = [
        f"{_plain_text(str(r.get('target') or 'unknown'))} | "
        f"{_plain_text(str(r.get('status') or 'unknown'))} | "
        f"{r.get('total_checks') or 0} checks | {r.get('findings_count') or 0} findings | "
        f"completed {_plain_text(str(r.get('completed_at') or 'not completed'))} | "
        f"authorization {'on file' if r.get('attested_at') else 'not on file'}"
        for r in scan_rows
    ]
    return [
        Paragraph('Scans on record', styles['section']),
        _paragraph('<br/>'.join(lines), styles['body']),
    ]
