#!/usr/bin/env python3
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from datetime import datetime

class VATAReportGenerator:
    def __init__(self, org_name, findings, compliance_score):
        self.org_name = org_name
        self.findings = findings
        self.compliance_score = compliance_score
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate(self, filename):
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#667eea'), spaceAfter=30)
        story.append(Paragraph("VATA Security Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph(f"<b>Organization:</b> {self.org_name}", styles['Normal']))
        story.append(Paragraph(f"<b>Generated:</b> {self.timestamp}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        score_style = ParagraphStyle('Score', parent=styles['Heading2'], fontSize=18, textColor=colors.HexColor('#2e7d32') if self.compliance_score >= 80 else colors.HexColor('#ff9800'))
        story.append(Paragraph(f"SOC 2 Compliance: {self.compliance_score}%", score_style))
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("Findings Summary", styles['Heading2']))
        
        severity_counts = {
            'CRITICAL': len([f for f in self.findings if f.get('severity') == 'CRITICAL']),
            'HIGH': len([f for f in self.findings if f.get('severity') == 'HIGH']),
            'MEDIUM': len([f for f in self.findings if f.get('severity') == 'MEDIUM']),
            'LOW': len([f for f in self.findings if f.get('severity') == 'LOW'])
        }
        
        summary_data = [['Severity', 'Count'], ['CRITICAL', str(severity_counts['CRITICAL'])], ['HIGH', str(severity_counts['HIGH'])], ['MEDIUM', str(severity_counts['MEDIUM'])], ['LOW', str(severity_counts['LOW'])], ['TOTAL', str(len(self.findings))]]
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke), ('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('FONTSIZE', (0, 0), (-1, 0), 14), ('BOTTOMPADDING', (0, 0), (-1, 0), 12), ('BACKGROUND', (0, 1), (-1, -1), colors.beige), ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
        story.append(summary_table)
        
        doc.build(story)
        return filename

if __name__ == "__main__":
    test_findings = [{'server_url': 'mcp-1', 'vector_type': 'path_traversal', 'severity': 'CRITICAL'}, {'server_url': 'mcp-2', 'vector_type': 'auth_bypass', 'severity': 'CRITICAL'}, {'server_url': 'mcp-3', 'vector_type': 'info_disclosure', 'severity': 'HIGH'}]
    gen = VATAReportGenerator("TestOrg", test_findings, 85)
    filename = gen.generate("test_report.pdf")
    print(f"✅ PDF generated: {filename}")
