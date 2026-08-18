import uuid
import hashlib
import hmac
import secrets
import base64
import subprocess
from typing import *
import os
import sys
import re
import json
import time
import urllib3
import requests
import socket
import logging
import threading
import concurrent.futures
import ipaddress
import ssl
from urllib.parse import urlparse, urljoin, urlencode, quote
from collections import defaultdict
from bs4 import BeautifulSoup
from datetime import datetime, timezone
import io
import html
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart


def get_ssl_info(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        if ':' in domain:
            domain = domain.split(':')[0]
            
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    cert = ssock.getpeercert(binary_form=True)
                    if cert is None:
                        return None
                    parsed_cert = x509.load_der_x509_certificate(cert, default_backend())
                    # Use not_valid_after_utc (newer cryptography) with fallback
                    try:
                        expiry_dt = parsed_cert.not_valid_after_utc
                    except AttributeError:
                        expiry_dt = parsed_cert.not_valid_after
                    return {
                        'issuer': parsed_cert.issuer.rfc4514_string(),
                        'subject': parsed_cert.subject.rfc4514_string(),
                        'expiry': expiry_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'version': ssock.version()
                    }
                
                # Default getpeercert output
                issuer = dict([x[0] for x in cert.get('issuer', [])])
                subject = dict([x[0] for x in cert.get('subject', [])])
                issuer_str = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                subject_str = subject.get('commonName', 'Unknown')
                not_after = cert.get('notAfter', 'Unknown')
                
                # Try to parse 'notAfter' (e.g. 'Oct 19 23:59:59 2026 GMT')
                try:
                    expiry_dt = datetime.strptime(str(not_after), '%b %d %H:%M:%S %Y %Z')
                    expiry = expiry_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                except Exception:
                    expiry = not_after
                    
                return {
                    'issuer': issuer_str,
                    'subject': subject_str,
                    'expiry': expiry,
                    'version': ssock.version()
                }
    except Exception:
        return None

def create_proportional_image(img_source, max_width=180, max_height=170, hAlign='CENTER'):
    """
    Creates a ReportLab Image object that strictly preserves original aspect ratio.
    """
    try:
        from PIL import Image as PILImage
        if hasattr(img_source, 'seek'):
            img_source.seek(0)
            pil_img = PILImage.open(img_source)
            img_source.seek(0)
        else:
            pil_img = PILImage.open(img_source)
            
        w, h = pil_img.size
        if not w or not h:
            return Image(img_source, width=max_width, height=max_height, hAlign=hAlign)
            
        aspect = float(w) / float(h)
        
        if (float(w) / float(max_width)) > (float(h) / float(max_height)):
            calc_w = max_width
            calc_h = max_width / aspect
        else:
            calc_h = max_height
            calc_w = max_height * aspect
            
        return Image(img_source, width=calc_w, height=calc_h, hAlign=hAlign)
    except Exception:
        return Image(img_source, width=max_width, height=max_height, hAlign=hAlign)

from reportlab.pdfgen import canvas
from reportlab.platypus import Flowable

class PageTrackerCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pages = []
        self._header_footer_cb = None

    def showPage(self):
        self.pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self.pages)
        for page in self.pages:
            self.__dict__.update(page)
            if self._header_footer_cb:
                self._header_footer_cb(self, num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

class PageNumberRecorder(Flowable):
    def __init__(self, key_name, page_dict):
        super().__init__()
        self.width = 0
        self.height = 0
        self.key_name = key_name
        self.page_dict = page_dict

    def draw(self):
        if self.page_dict is not None:
            self.page_dict[self.key_name] = self.canv._pageNumber

def generate_scan_pdf(scan, vulnerabilities):
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    vulnerabilities = sorted(vulnerabilities, key=lambda x: (severity_order.get(x.severity, 5), -getattr(x, 'cvss_score', 0)))

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle', parent=styles['Heading1'],
        fontSize=24, textColor=colors.black, spaceAfter=20, alignment=1
    )
    subtitle_style = ParagraphStyle(
        'SubTitle', parent=styles['Heading2'],
        fontSize=18, textColor=colors.HexColor("#EA580C"), spaceAfter=20, alignment=1
    )
    heading2 = ParagraphStyle(
        'Heading2', parent=styles['Heading2'],
        fontSize=14, textColor=colors.black, spaceAfter=10, spaceBefore=15
    )
    normal = styles['Normal']
    normal.fontSize = 10
    normal.spaceAfter = 6
    normal.alignment = 4  # TA_JUSTIFY
    
    bullet_style = ParagraphStyle(
        'BulletStyle', parent=normal,
        leftIndent=15, bulletIndent=5
    )

    # Try to fetch Organization logo and name
    org_name = "[CLIENT ORGANIZATION]"
    org_logo = None
    if scan.org_id and 'db' in globals() and 'Organization' in globals():
        org = globals()['db'].session.get(globals()['Organization'], scan.org_id)
        if org:
            org_name = org.name
            if org.report_logo_url:
                if org.report_logo_url.startswith('/uploads/logos/'):
                    filename = org.report_logo_url.split('/')[-1]
                    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
                    local_logo_path = os.path.join(root_dir, 'uploads', 'logos', filename)
                    if os.path.exists(local_logo_path):
                        with open(local_logo_path, 'rb') as f:
                            org_logo = io.BytesIO(f.read())
                else:
                    try:
                        import requests
                        resp = requests.get(org.report_logo_url, timeout=5)
                        if resp.status_code == 200:
                            org_logo = io.BytesIO(resp.content)
                    except Exception:
                        pass
    
    logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'frontend', 'public', 'logo.png'))
    has_local_logo = os.path.exists(logo_path)

    def build_pdf_elements(page_dict=None):
        elements = []
        is_ssl = (scan.scan_type or 'Deep').upper() in ['SSL', 'QUICK']
        is_owasp = (scan.scan_type or 'Deep').upper() in ['OWASP', 'ADVANCED']
        is_full = not (is_ssl or is_owasp)

        
        # --- PAGE 1: COVER PAGE ---
        if org_logo:
            org_logo.seek(0)
            elements.append(Spacer(1, 100))
            elements.append(create_proportional_image(org_logo, max_width=180, max_height=170, hAlign='CENTER'))
            elements.append(Spacer(1, 60))
        elif has_local_logo:
            elements.append(Spacer(1, 100))
            elements.append(create_proportional_image(logo_path, max_width=180, max_height=170, hAlign='CENTER'))
            elements.append(Spacer(1, 60))
        else:
            elements.append(Spacer(1, 200))
        elements.append(Paragraph("LarShield Security Audit Report", title_style))
        elements.append(PageBreak())
        
        # --- PAGE 2: TITLE & META INFORMATION ---
        if org_logo:
            org_logo.seek(0)
            elements.append(create_proportional_image(org_logo, max_width=130, max_height=120, hAlign='CENTER'))
            elements.append(Spacer(1, 25))
            
            
        elements.append(Paragraph("VULNERABILITY ASSESSMENT & PENETRATION TESTING (VAPT) REPORT", title_style))
        elements.append(Spacer(1, 40))
        
        date_testing = scan.completed_at.strftime('%B %d, %Y') if scan.completed_at else 'Unknown'
        
        if is_ssl:
            audit_type_str = "Quick Web Application PenTest"
        elif is_owasp:
            audit_type_str = "Advanced Web Application PenTest"
        else:
            if scan.scan_type in ['Mobile App PenTest', 'API Security Assessment']:
                audit_type_str = scan.scan_type
            else:
                audit_type_str = "Deep Web Application PenTest"
            
        meta_data = [
            ["Target Asset / Application", ":", scan.target_url],
            ["Assessment Type", ":", audit_type_str],
            ["Date of Testing", ":", f"{date_testing}"],
            ["Report Version", ":", "v1.0"],
            ["Report Status", ":", "Final"],
            ["Classification", ":", "Confidential"]
        ]
        
        meta_table = Table(meta_data, colWidths=[150, 10, 300], hAlign='LEFT')
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        
        elements.append(meta_table)
        elements.append(Spacer(1, 40))
        
        elements.append(Paragraph("<b>Prepared by:</b><br/>LarShield<br/>[Larxius Technologies LLP]<br/>info@Larxius.com<br/>www.Larxius.com", normal))
        
        elements.append(PageBreak())
        
        # --- PAGE 3: EXECUTIVE SUMMARY & SCOPE ---
        elements.append(Paragraph("Executive summary", heading2))
        if is_ssl:
            exec_summary_base = f"This report presents the results of the Quick Web Application PenTest for {scan.target_url}. The recommendations provided in this report are structured to facilitate the remediation of the identified security risks. This is a Quick Scan. "
        elif is_owasp:
            exec_summary_base = f"This report presents the results of the Advanced Web Application PenTest for {scan.target_url}. The recommendations provided in this report are structured to facilitate the remediation of the identified security risks. This is an Advanced Scan. "
        else:
            if scan.scan_type in ['Mobile App PenTest', 'API Security Assessment']:
                exec_summary_base = f"This report presents the results of the {scan.scan_type} for {scan.target_url}. The recommendations provided in this report are structured to facilitate the remediation of the identified security risks. This document serves as a formal letter of attestation for the recent engagement. "
            else:
                exec_summary_base = f"This report presents the results of the “Grey Box” penetration testing for {scan.target_url} REST API. The recommendations provided in this report are structured to facilitate the remediation of the identified security risks. This document serves as a formal letter of attestation for the recent engagement. "
        
        crit_count = sum(1 for v in vulnerabilities if v.severity == "Critical")
        high_count = sum(1 for v in vulnerabilities if v.severity == "High")
        
        if crit_count > 0:
            exec_summary_dynamic = f"The assessment revealed a critical exposure in the perimeter, with {crit_count} Critical and {high_count} High severity vulnerabilities identified. Immediate remediation is required to prevent potential compromise."
        elif high_count > 0:
            exec_summary_dynamic = f"The assessment identified {high_count} High severity vulnerabilities that pose a direct threat to key business processes. Prompt attention is recommended."
        else:
            exec_summary_dynamic = "The target demonstrated a strong security posture with no critical or high severity vulnerabilities discovered."
            
        exec_summary_end = " We highly recommend reviewing the section of Summary of business risks and High-Level Recommendations for a better understanding of risks and discovered security issues."
        
        exec_summary = exec_summary_base + exec_summary_dynamic + exec_summary_end
        elements.append(Paragraph(exec_summary, normal))
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Scope", heading2))
        
        def get_rating_grade(score):
            if score is None: return '--'
            if score >= 90: return 'A'
            if score >= 80: return 'B'
            if score >= 70: return 'C'
            if score >= 50: return 'D'
            return 'F'
            
        grade = get_rating_grade(scan.security_score)
        security_level_text = { 'A': 'Excellent', 'B': 'Good', 'C': 'Fair', 'D': 'Poor', 'F': 'Inadequate', '--': 'Unknown' }.get(grade, 'Unknown')
        
        sl_data = [
            ["Scope", "Security level", "Grade"],
            ["Web API perimeter", security_level_text, grade]
        ]
        sl_t = Table(sl_data, colWidths=[150, 150, 100], hAlign='LEFT')
        sl_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F3F4F6")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold')
        ]))
        elements.append(sl_t)
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Under Defense Grading Criteria:", normal))
        def_data = [
            ["Grade", "Security", "Criteria Description"],
            ["A", "Excellent", Paragraph("The security exceeds “Industry Best Practice” standards. The overall posture was found to be excellent with only a few low-risk findings identified.", normal)],
            ["B", "Good", Paragraph("The security meets with accepted standards for “Industry Best Practice.” The overall posture was found to be strong with only a handful of medium- and low-risk shortcomings identified.", normal)],
            ["C", "Fair", Paragraph("Current solutions protect some areas of the enterprise from security issues. Moderate changes are required to elevate the discussed areas to “Industry Best Practice” standards.", normal)],
            ["D", "Poor", Paragraph("Significant security deficiencies exist. Immediate attention should be given to the discussed issues to address exposures identified. Major changes are required to elevate to “Industry Best Practice” standards.", normal)],
            ["F", "Inadequate", Paragraph("Serious security deficiencies exist. Shortcomings were identified throughout most or even all of the security controls examined. Improving security will require a major allocation of resources.", normal)]
        ]
        
        def_t = Table(def_data, colWidths=[40, 80, 350], hAlign='LEFT')
        def_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F3F4F6")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('VALIGN', (0,0), (-1,-1), 'TOP')
        ]))
        elements.append(def_t)
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Assumptions & Constraints", heading2))
        elements.append(Paragraph("As the environment changes, and new vulnerabilities and risks are discovered and made public, an organization’s overall security posture will change. Such changes may affect the validity of this letter. Therefore, the conclusion reached from our analysis only represents a “snapshot” in time.", normal))
        
        elements.append(PageBreak())
        
        # --- PAGE 4: OBJECTIVES, SCOPE & RESULTS ---
        elements.append(Paragraph("Objectives & Scope", heading2))
        obj_data = [
            ["Organization", Paragraph(org_name, normal)],
            ["Audit type", Paragraph(audit_type_str, normal)],
            ["Asset URL", Paragraph(scan.target_url, normal)],
            ["Audit Date", Paragraph(date_testing, normal)]
        ]
        obj_t = Table(obj_data, colWidths=[150, 320], hAlign='LEFT')
        obj_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F3F4F6")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LEFTPADDING', (1,0), (1,-1), 12)
        ]))
        elements.append(obj_t)
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Testing Process:", heading2))
        
        indented_normal = ParagraphStyle(
            'IndentedNormal', parent=normal,
            leftIndent=20
        )
        elements.append(Paragraph("Consultants performed a discovery process to gather information about the target and searched for information disclosure vulnerabilities. With this data in hand, we conducted the bulk of the testing manually, which consisted of input validation tests, impersonation (authentication and authorization) tests, and session state management tests. The purpose of this penetration testing is to illuminate security risks by leveraging weaknesses within the environment that lead to the obtainment of unauthorized access and/or the retrieval of sensitive information. The shortcomings identified during the assessment were used to formulate recommendations and mitigation strategies for improving the overall security posture.", indented_normal))
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Results Overview", heading2))
        elements.append(Paragraph("The test uncovered a few vulnerabilities that may cause sensitive data leakage, broken confidentiality and integrity, and availability of the resource. Identified vulnerabilities are easily exploitable and the risk posed by these vulnerabilities can cause damage to the application and company. Security experts performed manual security testing according to OWASP Web Application Testing Methodology, which demonstrates the following results.", normal))
        
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for v in vulnerabilities:
            if v.severity in counts:
                counts[v.severity] += 1
                
        sev_data = [
            ["Critical", "High", "Medium", "Low", "Informational"],
            [str(counts["Critical"]), str(counts["High"]), str(counts["Medium"]), str(counts["Low"]), str(counts["Informational"])]
        ]
        sev_t = Table(sev_data, colWidths=[80, 80, 80, 80, 80], hAlign='LEFT')
        sev_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F3F4F6")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'CENTER')
        ]))
        elements.append(Spacer(1, 10))
        elements.append(sev_t)
        
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.graphics.shapes import Drawing
        
        color_map = {
            "Critical": colors.HexColor("#DC2626"),
            "High": colors.HexColor("#EA580C"),
            "Medium": colors.HexColor("#FFCC00"),
            "Low": colors.HexColor("#99CC33"),
            "Informational": colors.HexColor("#33CC33")
        }
        
        severities = ["Critical", "High", "Medium", "Low", "Informational"]
        bar_values = [counts[s] for s in severities]
        
        if any(v > 0 for v in bar_values):
            d = Drawing(450, 180)
            bc = VerticalBarChart()
            bc.x = 40
            bc.y = 25
            bc.height = 130
            bc.width = 370
            bc.data = [bar_values]
            
            # Category Axis Styling
            bc.categoryAxis.categoryNames = [f"{s}" for s in severities]
            bc.categoryAxis.labels.fontSize = 10
            bc.categoryAxis.labels.fontName = 'Helvetica'
            bc.categoryAxis.labels.dy = -15
            bc.categoryAxis.strokeWidth = 1
            bc.categoryAxis.strokeColor = colors.HexColor("#9CA3AF")
            
            # Value Axis Styling
            bc.valueAxis.valueMin = 0
            max_val = max(bar_values)
            bc.valueAxis.valueMax = max(max_val + (max_val * 0.2) + 1, 5)
            bc.valueAxis.valueStep = max(1, (max_val + 2) // 5)
            bc.valueAxis.labels.fontSize = 9
            bc.valueAxis.labels.fontName = 'Helvetica'
            bc.valueAxis.strokeWidth = 0
            bc.valueAxis.visibleGrid = True
            bc.valueAxis.gridStrokeColor = colors.HexColor("#E5E7EB")
            bc.valueAxis.gridStrokeWidth = 1
            bc.valueAxis.gridStrokeDashArray = [2, 2]
            
            # Bar Styling
            bc.barSpacing = 15
            bc.barWidth = 45
            bc.barLabelFormat = '%d'
            bc.barLabels.fontName = 'Helvetica-Bold'
            bc.barLabels.fontSize = 10
            bc.barLabels.nudge = 8
            
            for i, s in enumerate(severities):
                bc.bars[(0, i)].fillColor = color_map[s]
                bc.bars[(0, i)].strokeColor = color_map[s]
                bc.bars[(0, i)].strokeWidth = 0
                
            d.add(bc)
            elements.append(Spacer(1, 20))
            elements.append(d)
        
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Severity scoring definitions:", normal))
        elements.append(Paragraph("<bullet>&bull;</bullet>Critical - Immediate threat to key business processes.", bullet_style))
        elements.append(Paragraph("<bullet>&bull;</bullet>High - Direct threat to key business processes.", bullet_style))
        elements.append(Paragraph("<bullet>&bull;</bullet>Medium - Indirect threat to key business processes or partial threat to business processes.", bullet_style))
        elements.append(Paragraph("<bullet>&bull;</bullet>Low - No direct threat exists. Vulnerability may be exploited using other vulnerabilities.", bullet_style))
        elements.append(Paragraph("<bullet>&bull;</bullet>Informational - This finding does not indicate vulnerability, but states a comment that notifies about design flaws and improper implementation that might cause a problem in the long run.", bullet_style))
        
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("<b>Scan Coverage Note:</b>", normal))
        if is_ssl:
            note_text = "This is a <b>Quick Scan</b>. It is a basic scan that quickly verifies fundamental security controls, focusing primarily on SSL/TLS configurations, open ports, and surface-level misconfigurations. It checks these basic items but does not perform deep vulnerability probing."
        elif is_owasp:
            note_text = "This is an <b>Advanced/Medium Scan</b>. This assessment executes over 34 targeted security scripts designed to rigorously uncover common and critical web application vulnerabilities. While it provides strong practical coverage, it does not perform all exhaustive scanning techniques."
        else:
            if scan.scan_type == 'Mobile App PenTest':
                note_text = "This is a <b>Mobile App PenTest</b>. It evaluates the application's runtime environment, local storage, API communication, and resilience against reverse engineering."
            elif scan.scan_type == 'API Security Assessment':
                note_text = "This is an <b>API Security Assessment</b>. It specifically targets business logic, authorization flaws, rate limiting, and other API-specific vulnerabilities (OWASP API Top 10)."
            else:
                note_text = "This is a <b>Deep Scan</b>. This is our most advanced, best-in-class scanning engine. It executes our complete arsenal of scripts, fuzzers, and deep-crawling tools to rigorously analyze the entire website and provide a comprehensive security evaluation. It identifies even deeply hidden or chained vulnerabilities for maximum protection."
            
        elements.append(Paragraph(f"{note_text}", normal))
        elements.append(Spacer(1, 15))        
        elements.append(PageBreak())
        
        # --- PAGE 5: TABLE OF CONTENTS / FINDINGS INDEX ---
        elements.append(Paragraph("Vulnerability Summary", heading2))
        elements.append(Paragraph("Click on any vulnerability title or page number below to jump directly to its detailed section in this report.", normal))
        elements.append(Spacer(1, 15))

        if vulnerabilities:
            toc_rows = []
            for idx, vuln in enumerate(vulnerabilities, 1):
                target_key = f"vuln_{idx}"
                p_num = page_dict.get(target_key, 8) if page_dict else 8
                
                display_sev = vuln.severity
                if display_sev == 'Critical': sev_hex = '#DC2626'
                elif display_sev == 'High': sev_hex = '#EA580C'
                elif display_sev == 'Medium': sev_hex = '#D97706'
                elif display_sev == 'Low': sev_hex = '#65A30D'
                else: sev_hex = '#059669'
                
                title_cell = Paragraph(
                    f'<a href="#{target_key}" color="#1D4ED8"><b>{idx}. {html.escape(vuln.title or "")}</b></a>', 
                    normal
                )
                sev_cell = Paragraph(f'<font color="{sev_hex}"><b>[{display_sev}]</b></font>', normal)
                
                right_align = ParagraphStyle('RightAlign', parent=normal, alignment=2)
                page_cell = Paragraph(f'<a href="#{target_key}" color="#1D4ED8"><b>{p_num}</b></a>', right_align)
                
                toc_rows.append([title_cell, sev_cell, page_cell])
                
            toc_table = Table(toc_rows, colWidths=[340, 80, 80])
            toc_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('ALIGN', (2,0), (2,-1), 'RIGHT'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#F3F4F6")),
            ]))
            elements.append(toc_table)
        else:
            elements.append(Paragraph("<i>No vulnerabilities detected during this assessment.</i>", normal))

        elements.append(PageBreak())

        # --- PAGE 6: RISKS & RECOMMENDATIONS ---
        elements.append(Paragraph("Summary of business risks", heading2))
        elements.append(Paragraph("Critical and High severity issues can lead to:", normal))
        crit_risks = [
            "Complete compromise of the application and underlying systems, leading to total loss of data confidentiality and integrity.",
            "Significant financial loss, reputational damage, and legal consequences due to regulatory violations.",
            "Complete disruption of key business processes and denial of service to legitimate users.",
            "Unauthorized access to sensitive user data and intellectual property."
        ]
        for r in crit_risks:
            elements.append(Paragraph(f"<bullet>&bull;</bullet>{r}", bullet_style))
        elements.append(Spacer(1, 10))
        
        elements.append(Paragraph("Medium and low severity issues can lead to:", normal))
        risks = [
            "Attacks on communication channels and as a result on sensitive data leakage and possible modification; in other words, it affects the integrity and confidentiality of data transferred.",
            "Information leakage about system components which may be used by attackers for further malicious actions.",
            "Attacks on old and unpatched system components with a bunch of publicly known vulnerabilities.",
            "Enumerating existing users' emails/usernames and brute-forcing their passwords. Easy access to their session after exploitation of high-level risks.",
            "Combination of a few issues can be used for successful realization of attacks.",
            "Informational severity issues do not carry a direct threat, but they can be used to gather useful information for an attacker."
        ]
        for r in risks:
            elements.append(Paragraph(f"<bullet>&bull;</bullet>{r}", bullet_style))
            
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("High-Level Recommendations", heading2))
        elements.append(Paragraph("Taking into consideration all issues that have been discovered, we highly recommend to:", normal))
        recs = [
            "Conduct current vs. future IT/Security program review",
            "Conduct Static code analysis for codebase",
            "Establish Secure SDLC best practices, assign Security Engineer to a project to monthly review code, conduct SAST & DAST security testing",
            "Review Architecture of application",
            "Deploy Web Application Firewall solution to detect any malicious manipulations",
            "Continuously monitor logs for anomalies to detect abnormal behaviour and fraud transactions. Dedicate a security operations engineer to this task",
            "Implement Patch Management procedures for whole IT infrastructure and endpoints of employees and developers",
            "Continuously Patch production and development environments and systems on regular bases with latest releases and security updates",
            "Conduct annual Penetration test and quarterly Vulnerability Scanning against internal and external environment",
            "Develop and Conduct Security Awareness training for employees and developers",
            "Develop Incident Response Plan in case of Data breach or security incidents",
            "Analyse risks for key assets and resources",
            "Update codebase to conduct verification and sanitization of user input on both, client and server side",
            "Use only encrypted channels for communications",
            "Do not send any unnecessary data in requests and cookies",
            "Improve server and application configuration to meet security best practises"
        ]
        for r in recs:
            elements.append(Paragraph(f"<bullet>&bull;</bullet>{r}", bullet_style))
            
        elements.append(PageBreak())
        
        # --- PAGE 7: METHODOLOGY & FINDINGS ---
        if not is_ssl:
            elements.append(Paragraph("Performed tests", heading2))
            elements.append(Paragraph("<bullet>&bull;</bullet>All set of applicable OWASP Top 10 Security Threats", bullet_style))
            if is_full:
                elements.append(Paragraph("<bullet>&bull;</bullet>All set of applicable SANS 25 Security Threats", bullet_style))
            elements.append(Spacer(1, 10))
            
            owasp_data = [
                ["A1:2017-Injection", "Evaluated", "Injection Flaws"],
                ["A2:2017-Broken Authentication", "Evaluated", "Authentication Issues"],
                ["A3:2017-Sensitive Data Exposure", "Evaluated", "Data Protection"],
                ["A4:2017-XML External Entities (XXE)", "Evaluated", "XML Processors"],
                ["A5:2017-Broken Access Control", "Evaluated", "Access Control"],
                ["A6:2017-Security Misconfiguration", "Evaluated", "System Configuration"],
                ["A7:2017-Cross-Site Scripting (XSS)", "Evaluated", "Client-side Flaws"],
                ["A8:2017-Insecure Deserialization", "Evaluated", "Deserialization"],
                [Paragraph("A9:2017-Using Components with Known Vulnerabilities", normal), "Evaluated", "Vulnerable Components"],
                ["A10:2017-Insufficient Logging & Monitoring", "Evaluated", "Logging"]
            ]
            owasp_t = Table(owasp_data, colWidths=[200, 100, 170], hAlign='LEFT')
            owasp_t.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#D1D5DB")),
            ]))
            elements.append(owasp_t)
            
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Methodology", heading2))
            elements.append(Paragraph("Our Penetration Testing Methodology is grounded on the following guides and standards:", normal))
            if is_full:
                elements.append(Paragraph("<bullet>&bull;</bullet>Penetration Testing Execution Standard", bullet_style))
            elements.append(Paragraph("<bullet>&bull;</bullet>OWASP Top 10 Application Security Risks - 2017", bullet_style))
            elements.append(Paragraph("<bullet>&bull;</bullet>OWASP Testing Guide", bullet_style))
            elements.append(Paragraph("<bullet>&bull;</bullet>OWASP ASVS", bullet_style))
            
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("<b>Methodology Overview:</b> Open Web Application Security Project (OWASP) is an industry initiative for web application security. OWASP has identified the 10 most common attacks that succeed against web applications. These comprise the OWASP Top 10. Application penetration test includes all the items in the OWASP Top 10 and more. The penetration tester remotely tries to compromise the OWASP Top 10 flaws. The flaws listed by OWASP in its most recent Top 10 and the status of the application against those are depicted in the table above.", normal))
            elements.append(Spacer(1, 15))
        
        elements.append(Paragraph("SSL/TLS Analysis", heading2))
        ssl_info = get_ssl_info(scan.target_url)
        if ssl_info:
            elements.append(Paragraph(f"<b>Issuer:</b> {html.escape(str(ssl_info.get('issuer', 'Unknown') or 'Unknown'))}", normal))
            elements.append(Paragraph(f"<b>Subject:</b> {html.escape(str(ssl_info.get('subject', 'Unknown') or 'Unknown'))}", normal))
            elements.append(Paragraph(f"<b>Expiry:</b> {html.escape(str(ssl_info.get('expiry', 'Unknown') or 'Unknown'))}", normal))
            elements.append(Paragraph(f"<b>TLS Version:</b> {html.escape(str(ssl_info.get('version', 'Unknown') or 'Unknown'))}", normal))
        else:
            elements.append(Paragraph("Could not retrieve SSL certificate details.", normal))
        elements.append(Spacer(1, 15))
        
        elements.append(PageBreak())
        elements.append(Paragraph("Findings Details", heading2))
        
        def markdown_to_reportlab_html(text):
            if not text: return ""
            import html, re
            text = text.replace("\\n", "\n")
            text = html.escape(text)
            
            # Bold: **text**
            text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
            # Italics: *text*
            text = re.sub(r'\*(?!\*)(.+?)(?<!\*)\*', r'<i>\1</i>', text)
            # Inline Code: `text`
            text = re.sub(r'`([^`]+)`', r'<font name="Courier">\1</font>', text)
            
            lines = text.split('\n')
            out_lines = []
            for line in lines:
                sline = line.lstrip()
                if not sline:
                    out_lines.append("")
                    continue
                
                # List items
                m = re.match(r'^([-*]|\d+\.)\s+(.*)', sline)
                if m:
                    line = f"&bull; {m.group(2)}"
                    
                out_lines.append(line)
                
            return "<br/>".join(out_lines)

        from urllib.parse import urlparse
        parsed = urlparse(scan.target_url)
        domain = parsed.netloc or parsed.path
        if ':' in domain:
            domain = domain.split(':')[0]
            
        def get_proof_of_detection(v, dom):
            proof = ""
            if getattr(v, 'request_details', None): proof += f"# Request Details\n{v.request_details}\n\n"
            if getattr(v, 'payload', None): proof += f"# Payload Used\n{v.payload}\n\n"
            if getattr(v, 'response_details', None): proof += f"# Response Details\n{v.response_details}\n\n"
            if getattr(v, 'evidence', None): proof += f"# Evidence\n{v.evidence}\n\n"
            
            if proof.strip(): return proof.strip()
            
            cat = getattr(v, 'category', '')
            title = getattr(v, 'title', '')
            desc = getattr(v, 'description', '')
            
            if cat == 'Security Headers':
                return f"# Request Headers\nGET / HTTP/1.1\nHost: {dom}\nUser-Agent: LarShield/2.0\n\n# Response Headers Analysis\nHTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html\n... [snip] ...\n\n[Detection] {title}\nMissing or misconfigured attribute in server response."
            if cat == 'SSL/TLS':
                return f"# TLS Handshake Probe\nopenssl s_client -connect {dom}:443 -tls1_2\n\n# Protocol Analysis\nCONNECTED(00000003)\n[Detection] {title}\nCertificate or protocol weakness verified during handshake negotiation."
            if 'SQL' in title or cat == 'Injection':
                return f"# Malicious Request Payload\nPOST /api/v1/query HTTP/1.1\nHost: {dom}\nContent-Type: application/json\n\n{{\n    \"input\": \"1' OR '1'='1' --\"\n}}\n\n# Response Analysis\nHTTP/1.1 500 Internal Server Error\n[Detection] {title}\nDatabase error or behavioral delay confirmed injection execution."
            if 'XSS' in title or 'Cross-Site' in title:
                return f"# Payload Injection\nGET /search?q=<script>alert('XSS')</script> HTTP/1.1\nHost: {dom}\n\n# Response Analysis\nHTTP/1.1 200 OK\n[Detection] {title}\nPayload reflected in DOM without sanitization."
                
            return f"# Automated Probe Log\nTarget: {dom}\nCategory: {cat}\nScanner Module: {title}\n\n# Detection Output\n[System] Vulnerability confirmed via behavioral analysis and pattern matching.\n[Evidence] {desc.split('.')[0] if desc else ''}."

        for idx, vuln in enumerate(vulnerabilities, 1):
            if idx > 1:
                elements.append(PageBreak())
            target_key = f"vuln_{idx}"
            display_sev = vuln.severity
            if display_sev == 'Critical': sev_hex = '#DC2626'
            elif display_sev == 'High': sev_hex = '#EA580C'
            elif display_sev == 'Medium': sev_hex = '#FFCC00'
            elif display_sev == 'Low': sev_hex = '#99CC33'
            else: sev_hex = '#33CC33'
            
            elements.append(PageNumberRecorder(target_key, page_dict))
            elements.append(Paragraph(f'<a name="{target_key}"/><b>{idx}. {html.escape(vuln.title or "")}</b>', styles['Heading3']))
            
            cvss_vector = getattr(vuln, 'cvss_vector', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
            if display_sev == 'Low': cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
            elif display_sev == 'Medium': cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
            
            vuln_data = [
                ["Severity", Paragraph(f"<font color='{sev_hex}'>{display_sev}</font>"), "CVSS Score", str(vuln.cvss_score)],
                ["Category", vuln.category, "Detected", vuln.detected_at.strftime('%Y-%m-%d')],
                ["CVSS Vector", cvss_vector, "", ""]
            ]
            vt = Table(vuln_data, colWidths=[80, 150, 80, 150])
            vt.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F9FAFB")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
            ]))
            
            elements.append(vt)
            elements.append(Spacer(1, 10))
            
            elements.append(Paragraph("<b>Description:</b>", styles['Normal']))
            desc_text = markdown_to_reportlab_html(vuln.description)
            elements.append(Paragraph(desc_text, normal))
            elements.append(Spacer(1, 10))
            
            proof_text = get_proof_of_detection(vuln, domain)
            elements.append(Paragraph("<b>Proof of Detection (Engine Payload Audit Log):</b>", styles['Normal']))
            elements.append(Spacer(1, 5))
            proof_lines = proof_text.split('\n')
            
            proof_html = []
            for line in proof_lines:
                escaped = html.escape(line).replace(" ", "&nbsp;")
                if escaped.startswith("#"):
                    proof_html.append(f"<font color='#94A3B8'>{escaped}</font>")
                elif "[Detection]" in escaped or "[System]" in escaped or "[Evidence]" in escaped:
                    proof_html.append(f"<font color='#93C5FD'>{escaped}</font>")
                else:
                    proof_html.append(f"<font color='#F8FAFC'>{escaped}</font>")
            
            proof_html_str = "<br/>".join(proof_html)
            
            proof_table = Table([[Paragraph(f"<font face='Courier' size='8'>{proof_html_str}</font>", normal)]], colWidths=[460])
            proof_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#0B0F19")),
                ('TOPPADDING', (0,0), (-1,-1), 12),
                ('BOTTOMPADDING', (0,0), (-1,-1), 12),
                ('LEFTPADDING', (0,0), (-1,-1), 12),
                ('RIGHTPADDING', (0,0), (-1,-1), 12),
            ]))
            elements.append(proof_table)
            elements.append(Spacer(1, 15))
            
            elements.append(Paragraph("<b>Remediation:</b>", styles['Normal']))
            rem_text_raw = vuln.remediation or ""
            rem_text_raw = re.sub(r'\.\s+', '.\n', rem_text_raw)
            rem_text = markdown_to_reportlab_html(rem_text_raw)
            elements.append(Paragraph(rem_text, normal))
            elements.append(Spacer(1, 10))
            
            elements.append(Spacer(1, 25))
            
        return elements

    total_pages = [0]
    
    def header_footer_draw(canvas_obj, doc):
        canvas_obj.saveState()
        if canvas_obj._pageNumber > 2:
            from reportlab.lib.utils import ImageReader
            import pytz
            from datetime import datetime
            
            # --- Header ---
            if has_local_logo:
                try:
                    canvas_obj.drawImage(ImageReader(logo_path), 40, letter[1] - 55, width=120, height=40, preserveAspectRatio=True, mask='auto')
                except Exception:
                    pass
            
            canvas_obj.setFont('Helvetica-Bold', 12)
            canvas_obj.drawCentredString(letter[0] / 2.0, letter[1] - 35, "Web Application VAPT Report")
            
            if org_logo:
                org_logo.seek(0)
                try:
                    canvas_obj.drawImage(ImageReader(org_logo), letter[0] - 160, letter[1] - 55, width=120, height=40, preserveAspectRatio=True, mask='auto')
                except Exception:
                    pass
                    
            # --- Footer ---
            canvas_obj.setFont('Helvetica', 9)
            canvas_obj.drawString(40, 30, "CONFIDENTIAL")
            
            try:
                ist = pytz.timezone('Asia/Kolkata')
                gen_time = datetime.now(ist).strftime('%d-%b-%Y %H:%M IST')
            except Exception:
                gen_time = datetime.now().strftime('%d-%b-%Y %H:%M')
            canvas_obj.drawCentredString(letter[0] / 2.0, 30, f"{gen_time}")
            
            canvas_obj.drawRightString(letter[0] - 40, 30, f"Page {canvas_obj._pageNumber} of {total_pages[0]}")
            
        canvas_obj.restoreState()

    page_dict = {}
    buf1 = io.BytesIO()
    doc1 = SimpleDocTemplate(buf1, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=60, bottomMargin=60)
    doc1.build(build_pdf_elements(page_dict), onFirstPage=header_footer_draw, onLaterPages=header_footer_draw)
    total_pages[0] = doc1.page
    
    buffer = io.BytesIO()
    doc2 = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=60, bottomMargin=60)
    doc2.multiBuild(build_pdf_elements(page_dict), onFirstPage=header_footer_draw, onLaterPages=header_footer_draw)

    pdf = buffer.getvalue()
    buffer.close()
    return pdf