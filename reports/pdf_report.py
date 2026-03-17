from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib import colors
from datetime import datetime
import os

REPORT_FOLDER = "generated_reports"
os.makedirs(REPORT_FOLDER, exist_ok=True)


def generate_pdf(scan_data):
    filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(REPORT_FOLDER, filename)

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()
    elements = []

    # ================= PREMIUM STYLES =================
    header_style = ParagraphStyle(
        "Header",
        fontSize=24,
        alignment=TA_LEFT,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=12
    )
    
    subhead_style = ParagraphStyle(
        "Subhead",
        fontSize=10,
        alignment=TA_LEFT,
        fontName="Helvetica",
        textColor=colors.HexColor("#64748b"),
        spaceAfter=25,
        textTransform="uppercase",
        letterSpacing=1
    )
    
    section_head_style = ParagraphStyle(
        "SectionHead",
        parent=styles["Heading2"],
        fontSize=14,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=12,
        spaceBefore=24,
        borderPadding=(0, 0, 4, 0),
        borderWidth=1,
        borderColor=colors.HexColor("#cbd5e1"),
        borderRadius=0
    )

    normal_text = ParagraphStyle(
        "NormalText",
        parent=styles["Normal"],
        fontSize=10,
        fontName="Helvetica",
        textColor=colors.HexColor("#334155"),
        spaceAfter=6,
        leading=14
    )

    bullet_text = ParagraphStyle(
        "BulletText",
        parent=normal_text,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=8
    )

    bold_text = ParagraphStyle(
        "BoldText",
        parent=normal_text,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0f172a")
    )

    # ================= HEADER =================
    elements.append(Paragraph("SECURITY AUDIT REPORT", header_style))
    elements.append(Paragraph(f"METADATA SCAN • {datetime.now().strftime('%d %b %Y, %H:%M')}", subhead_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceAfter=20, spaceBefore=0, vAlign='CENTER'))

    # ================= FILE OVERVIEW =================
    elements.append(Paragraph("1. Document Overview", section_head_style))
    
    file_info = [
        [Paragraph("TARGET FILE", bold_text), Paragraph(scan_data.get("file_name", "Unknown Document"), normal_text)],
        [Paragraph("MIME FORMAT", bold_text), Paragraph(scan_data.get("file_type", "Unknown Format"), normal_text)]
    ]

    file_table = Table(file_info, colWidths=[140, 355])
    file_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 10),
    ]))

    elements.append(file_table)

    # ================= THREAT ASSESSMENT =================
    elements.append(Paragraph("2. Threat Assessment", section_head_style))
    
    risk_score = scan_data.get("risk_score", 0)
    risk_level = scan_data.get("risk_level", "Low")

    if risk_level == "High":
        r_col = "#dc2626"
        bg_col = "#fef2f2"
    elif risk_level == "Medium":
        r_col = "#d97706"
        bg_col = "#fffbeb"
    else:
        r_col = "#059669"
        bg_col = "#ecfdf5"

    risk_table = Table(
        [
            [Paragraph("THREAT SEVERITY", bold_text), Paragraph(f'<font color="{r_col}"><b>{risk_level.upper()}</b></font>', ParagraphStyle("RLevel", fontSize=12, fontName="Helvetica-Bold"))],
            [Paragraph("EXPOSURE INDEX", bold_text), Paragraph(f'<font color="{r_col}"><b>{risk_score}/100</b></font>', ParagraphStyle("RScore", fontSize=12, fontName="Helvetica-Bold"))]
        ],
        colWidths=[140, 355]
    )

    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("BACKGROUND", (1, 0), (1, -1), colors.HexColor(bg_col)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 10),
    ]))

    elements.append(risk_table)

    # ================= FORENSIC METADATA =================
    elements.append(Paragraph("3. Forensic Data Extraction", section_head_style))
    metadata = scan_data.get("metadata", {})
    
    if metadata:
        meta_data_table = [[Paragraph("IDENTIFIER", bold_text), Paragraph("EXTRACTED VALUE", bold_text)]]
        
        for key, value in metadata.items():
            formatted_val = Paragraph(str(value) if value else "<i>Redacted/Null</i>", normal_text)
            formatted_key = Paragraph(str(key), normal_text)
            meta_data_table.append([formatted_key, formatted_val])
            
        metadata_table_obj = Table(meta_data_table, colWidths=[140, 355], repeatRows=1)
        metadata_table_obj.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (-1, 0), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")])
        ]))
        elements.append(metadata_table_obj)
    else:
        elements.append(
            Table(
                [[Paragraph("<i>No exposed metadata anomalies detected in the file.</i>", ParagraphStyle("Clean", parent=normal_text, alignment=TA_CENTER))]],
                colWidths=[495],
                style=TableStyle([("BOX", (0,0), (-1,-1), 1, colors.HexColor("#059669")), ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#ecfdf5")), ("PADDING", (0,0), (-1,-1), 15)])
            )
        )

    # ================= MITIGATION STRATEGY =================
    elements.append(KeepTogether([
        Paragraph("4. Mitigation Guidelines", section_head_style),
        Paragraph("<b>• Sanitize Exports:</b> Strip embedded author IDs, creation dates, and tool versions prior to outbound sharing.", bullet_text),
        Paragraph("<b>• Network Obfuscation:</b> Eliminate internal file paths, UNC blocks, and printer nomenclature from source document properties.", bullet_text),
        Paragraph("<b>• Location Anonymity:</b> Ensure absolute scrub of EXIF GPS coordinates or regional metadata in media formats.", bullet_text),
        Paragraph("<b>• Policy Enforcement:</b> Mandate automated sanitization pipelines (e.g., ExifTool, MAT2) for all public-facing assets.", bullet_text)
    ]))

    elements.append(Spacer(1, 30))

    # ================= FOOTER =================
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#94a3b8")))
    elements.append(Spacer(1, 10))
    elements.append(
        Table(
            [[Paragraph("<b>CLASSIFICATION:</b> CONFIDENTIAL", ParagraphStyle("F1", fontSize=8, textColor=colors.HexColor("#64748b"))),
              Paragraph(f"REPORT ID: {scan_data.get('scan_id', 'AUTO')}-{int(datetime.now().timestamp())}", ParagraphStyle("F2", fontSize=8, alignment=TA_RIGHT, textColor=colors.HexColor("#64748b")))]],
            colWidths=[247, 248],
            style=TableStyle([("LEFTPADDING", (0,0), (-1,-1), 0), ("RIGHTPADDING", (0,0), (-1,-1), 0), ("VALIGN", (0,0), (-1,-1), "MIDDLE")])
        )
    )

    doc.build(elements)
    return path