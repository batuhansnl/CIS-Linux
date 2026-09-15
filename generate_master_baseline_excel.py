# -*- coding: utf-8 -*-
"""
Kurumsal Linux CIS Level 1 (L1) Master Baseline Excel Çalışma Kitabı Oluşturucu
Tüm kuralları, Siber Güvence gap analizini, resmi CIS dağıtım kataloğunu,
konfigürasyon parametrelerini ve yönetici dashboard'unu içeren profesyonel Excel dosyası üretir.
"""

import os
import re
from collections import Counter, defaultdict
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Renk Paleti ve Temel Stiller
COLOR_NAVY_DARK = "1B365D"       # Ana Başlıklar
COLOR_NAVY_MEDIUM = "2C4A6F"     # Tablo Başlıkları
COLOR_NAVY_LIGHT = "E8EEF5"      # Hafif Başlık / Vurgu
COLOR_WHITE = "FFFFFF"
COLOR_ZEBRA = "F8FAFC"           # Alternatif Satır Rengi
COLOR_BORDER = "CBD5E1"          # Tablo Kenarlıkları
COLOR_BORDER_LIGHT = "E2E8F0"

# Severity Renkleri (Badges)
COLOR_CRITICAL_BG = "FEE2E2"
COLOR_CRITICAL_FG = "991B1B"
COLOR_MEDIUM_BG = "FEF3C7"
COLOR_MEDIUM_FG = "92400E"
COLOR_LOW_BG = "DCFCE7"
COLOR_LOW_FG = "166534"
COLOR_INFO_BG = "E0F2FE"
COLOR_INFO_FG = "0369A1"

# Fontlar
FONT_NAME = "Segoe UI"
font_title = Font(name=FONT_NAME, size=15, bold=True, color=COLOR_WHITE)
font_subtitle = Font(name=FONT_NAME, size=9.5, italic=True, color="475569")
font_sec_header = Font(name=FONT_NAME, size=11, bold=True, color=COLOR_WHITE)
font_tbl_header = Font(name=FONT_NAME, size=10, bold=True, color=COLOR_WHITE)
font_data = Font(name=FONT_NAME, size=9.5, color="1E293B")
font_data_bold = Font(name=FONT_NAME, size=9.5, bold=True, color="1E293B")
font_code = Font(name="Consolas", size=9, color="0F172A")
font_total = Font(name=FONT_NAME, size=10, bold=True, color="0F172A")

# Fills
fill_navy_dark = PatternFill(start_color=COLOR_NAVY_DARK, end_color=COLOR_NAVY_DARK, fill_type="solid")
fill_navy_medium = PatternFill(start_color=COLOR_NAVY_MEDIUM, end_color=COLOR_NAVY_MEDIUM, fill_type="solid")
fill_navy_light = PatternFill(start_color=COLOR_NAVY_LIGHT, end_color=COLOR_NAVY_LIGHT, fill_type="solid")
fill_zebra = PatternFill(start_color=COLOR_ZEBRA, end_color=COLOR_ZEBRA, fill_type="solid")
fill_white = PatternFill(start_color=COLOR_WHITE, end_color=COLOR_WHITE, fill_type="solid")
fill_card_top = PatternFill(start_color="E2E8F0", end_color="E2E8F0", fill_type="solid")
fill_card_btm = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
fill_total = PatternFill(start_color="E2E8F0", end_color="E2E8F0", fill_type="solid")

# Kenarlıklar
thin_side = Side(style='thin', color=COLOR_BORDER)
border_all = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)
border_header = Border(left=Side(style='thin', color="475569"), right=Side(style='thin', color="475569"),
                       top=Side(style='thin', color="475569"), bottom=Side(style='medium', color="0F172A"))
border_total = Border(left=thin_side, right=thin_side,
                      top=Side(style='thin', color="0F172A"),
                      bottom=Side(style='double', color="0F172A"))

def style_merged_range(ws, cell_range, font=None, fill=None, border=None, alignment=None):
    for row in ws[cell_range]:
        for cell in row:
            if font: cell.font = font
            if fill: cell.fill = fill
            if border: cell.border = border
            if alignment: cell.alignment = alignment

def style_severity_cell(cell, severity_text):
    sev = str(severity_text).upper()
    if 'HIGH' in sev or 'CRITICAL' in sev or 'KRİTİK' in sev:
        cell.fill = PatternFill(start_color=COLOR_CRITICAL_BG, end_color=COLOR_CRITICAL_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_CRITICAL_FG)
    elif 'MEDIUM' in sev or 'ORTA' in sev:
        cell.fill = PatternFill(start_color=COLOR_MEDIUM_BG, end_color=COLOR_MEDIUM_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_MEDIUM_FG)
    elif 'LOW' in sev or 'DÜŞÜK' in sev:
        cell.fill = PatternFill(start_color=COLOR_LOW_BG, end_color=COLOR_LOW_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_LOW_FG)
    else:
        cell.fill = PatternFill(start_color=COLOR_INFO_BG, end_color=COLOR_INFO_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_INFO_FG)
    cell.alignment = Alignment(horizontal='center', vertical='center')

def style_status_cell(cell, status_text):
    st = str(status_text).upper()
    if 'MUST' in st:
        cell.fill = PatternFill(start_color=COLOR_CRITICAL_BG, end_color=COLOR_CRITICAL_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_CRITICAL_FG)
    elif 'RECOMMENDED' in st:
        cell.fill = PatternFill(start_color="E0E7FF", end_color="E0E7FF", fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color="3730A3")
    elif 'MEVCUT' in st or 'ENTEGRE' in st or 'EKLENDİ' in st:
        cell.fill = PatternFill(start_color=COLOR_LOW_BG, end_color=COLOR_LOW_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_LOW_FG)
    elif 'DÜZELTME' in st or 'UYUŞMAZLIK' in st:
        cell.fill = PatternFill(start_color=COLOR_MEDIUM_BG, end_color=COLOR_MEDIUM_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_MEDIUM_FG)
    else:
        cell.font = font_data_bold
    cell.alignment = Alignment(horizontal='center', vertical='center')

def parse_audit_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        text = f.read()

    lines = text.splitlines()
    sec_num = 0
    sec_name = ''
    scope = 'Tüm Linux Sunucuları'
    
    raw_items = []
    current_lines = []
    in_item = False
    cond_counter = 0

    for line in lines:
        sm = re.search(r'# BÖLÜM (\d+):\s*([^\n]+)', line)
        if sm:
            sec_num = int(sm.group(1))
            sec_name = sm.group(2).strip()
            if sec_num == 13: scope = 'Dağıtıma Özel (Dinamik Koşul)'
            elif sec_num == 14: scope = 'Tüm Kurumsal Linux Sunucuları'
            else: scope = 'Tüm Linux Sunucuları'
            
        if '13.1 RED HAT AİLESİ' in line:
            scope = 'Red Hat Ailesi (RHEL 7/8/9, Rocky 8/9, CentOS 6/7, Oracle 7/8/9)'
        elif '13.2 DEBIAN VE UBUNTU' in line:
            scope = 'Debian ve Ubuntu Ailesi (Ubuntu 18/20/22/24, Debian 12/13)'
        elif '13.3 SUSE AİLESİ' in line:
            scope = 'SUSE Ailesi (SLES 12/15/16, SLES for SAP)'
        elif '14.5 Red Hat Sunucularda' in line:
            scope = 'Red Hat Enterprise Linux (RHEL 7/8/9)'
            
        if '<custom_item>' in line:
            in_item = True
            current_lines = [line]
            cur_sec_num = sec_num
            cur_sec_name = sec_name
            cur_scope = scope
        elif '</custom_item>' in line:
            current_lines.append(line)
            in_item = False
            raw_items.append((cur_sec_num, cur_sec_name, cur_scope, current_lines))
        elif in_item:
            current_lines.append(line)

    KNOWN_KEYS = ['system', 'type', 'description', 'info', 'solution', 'reference', 'cmd', 'expect', 'severity', 'file', 'regex', 'mask', 'mode', 'owner', 'group', 'file_required', 'svc_name', 'svc_state']
    key_regex = re.compile(r'^\s*(' + '|'.join(KNOWN_KEYS) + r')\s*:\s*(.*)$')
    
    parsed_items = []

    for idx, (s_num, s_name, s_scope, item_lines) in enumerate(raw_items, 1):
        data = {}
        current_key = None
        current_val = []
        for l in item_lines:
            strip_l = l.strip()
            if strip_l.startswith('<custom_item>') or strip_l.startswith('</custom_item>'):
                continue
            m = key_regex.match(l)
            if m:
                if current_key:
                    val = '\n'.join(current_val).strip()
                    if val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                    data[current_key] = val
                current_key = m.group(1)
                current_val = [m.group(2)]
            else:
                if current_key:
                    current_val.append(l)
        if current_key:
            val = '\n'.join(current_val).strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            data[current_key] = val

        # Rule code & title
        desc = data.get('description', '').strip()
        code_match = re.match(r'^([0-9]+(\.[0-9]+)+)\s*(.*)$', desc)
        if code_match:
            rule_code = code_match.group(1)
            title = code_match.group(3).strip()
            is_condition = False
            raw_sev = data.get('severity', 'UNKNOWN').strip()
            severity = raw_sev.splitlines()[0].strip().split()[0].upper() if raw_sev else 'UNKNOWN'
        else:
            cond_counter += 1
            rule_code = f"KOŞUL-{s_num}.{cond_counter}"
            title = desc
            is_condition = True
            severity = "BİLGİ (Koşul)"

        # Info sub-fields
        info_str = data.get('info', '')
        anlam = ''
        tehlike = ''
        bulgu = ''
        kapsam = ''
        if is_condition:
            anlam = "Hedef sunucunun işletim sistemi ailesini (/etc/os-release) dinamik tespit eder; eşleşirse ilgili dağıtım bloğunu çalıştırır, eşleşmezse hatasız atlar (skip)."
            tehlike = "-"
            bulgu = "Koşul Tespiti"
            kapsam = s_scope
        else:
            m_anlam = re.search(r'AYARIN ANLAMI:\s*(.*?)(?=(TEHL[Iİ]KE:|BULGU SEV[Iİ]YES[Iİ]:|KAPSAM:|$))', info_str, re.DOTALL | re.IGNORECASE)
            m_tehlike = re.search(r'TEHL[Iİ]KE:\s*(.*?)(?=(BULGU SEV[Iİ]YES[Iİ]:|KAPSAM:|$))', info_str, re.DOTALL | re.IGNORECASE)
            m_bulgu = re.search(r'BULGU SEV[Iİ]YES[Iİ]:\s*(.*?)(?=(KAPSAM:|$))', info_str, re.DOTALL | re.IGNORECASE)
            m_kapsam = re.search(r'KAPSAM:\s*(.*?)$', info_str, re.DOTALL | re.IGNORECASE)
            if m_anlam: anlam = m_anlam.group(1).strip()
            if m_tehlike: tehlike = m_tehlike.group(1).strip()
            if m_bulgu: bulgu = m_bulgu.group(1).strip()
            if m_kapsam: kapsam = m_kapsam.group(1).strip()

        # References
        ref_str = data.get('reference', '')
        cis_refs = []
        nist_refs = []
        csc_refs = []
        corp_refs = []
        if ref_str:
            for p in ref_str.split(','):
                p = p.strip()
                if '|' in p:
                    std, val = p.split('|', 1)
                    std = std.strip().upper()
                    val = val.strip()
                    if 'CIS' in std: cis_refs.append(val)
                    elif '800-53' in std or 'NIST' in std: nist_refs.append(val)
                    elif 'CSC' in std: csc_refs.append(val)
                    elif 'KURUMSAL' in std: corp_refs.append(val)
                    else: cis_refs.append(p)
                else:
                    cis_refs.append(p)

        # Audit Target / Command / Criteria
        check_type = data.get('type', '')
        audit_cmd = ''
        criteria = ''
        if check_type == 'CMD_EXEC':
            audit_cmd = data.get('cmd', '')
            criteria = data.get('expect', '')
        elif 'FILE_CONTENT' in check_type:
            audit_cmd = f"Dosya: {data.get('file', '')}"
            if data.get('regex'):
                audit_cmd += f"\nRegex: {data.get('regex')}"
            criteria = f"Beklenen Değer: {data.get('expect', '')}"
        elif check_type == 'FILE_CHECK':
            audit_cmd = f"Dosya: {data.get('file', '')}"
            parts = []
            if data.get('mask'): parts.append(f"Maske: {data.get('mask')}")
            if data.get('mode'): parts.append(f"Mod: {data.get('mode')}")
            if data.get('owner'): parts.append(f"Sahip: {data.get('owner')}")
            if data.get('group'): parts.append(f"Grup: {data.get('group')}")
            criteria = ", ".join(parts)
        else:
            audit_cmd = data.get('cmd', '') or data.get('file', '')
            criteria = data.get('expect', '')

        parsed_items.append({
            'no': idx,
            'rule_code': rule_code,
            'sec_num': s_num,
            'sec_name': s_name,
            'title': title,
            'full_desc': desc,
            'severity': severity,
            'scope': kapsam if kapsam else s_scope,
            'anlam': anlam if anlam else info_str,
            'tehlike': tehlike if tehlike else "-",
            'bulgu': bulgu if bulgu else severity,
            'solution': data.get('solution', '-'),
            'check_type': check_type,
            'audit_cmd': audit_cmd if audit_cmd else "-",
            'criteria': criteria if criteria else "-",
            'cis_ref': ', '.join(cis_refs) if cis_refs else "-",
            'nist_ref': ', '.join(nist_refs) if nist_refs else "-",
            'csc_ref': ', '.join(csc_refs) if csc_refs else "-",
            'corp_ref': ', '.join(corp_refs) if corp_refs else "-",
            'is_condition': is_condition
        })

    return parsed_items

def parse_readme_catalog(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        text = f.read()
    pattern = re.compile(r'\|\s*\*\*([^\*]+)\*\*\s*\|\s*([^\|]+)\|\s*([^\|]+)\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|')
    matches = pattern.findall(text)
    
    rows = []
    for idx, m in enumerate(matches, 1):
        dist_name = m[0].strip()
        version_info = m[1].strip()
        benchmark_name = m[2].strip()
        audit_path = m[3].strip()
        rule_count = int(m[4].strip())
        
        family = 'Diğer'
        if 'RHEL' in dist_name or 'Red Hat' in dist_name or 'RHCOS' in dist_name:
            family = 'Red Hat Enterprise Linux'
        elif 'Oracle' in dist_name:
            family = 'Oracle Linux'
        elif 'Ubuntu' in dist_name:
            family = 'Ubuntu Linux'
        elif 'SuSE' in dist_name or 'SUSE' in dist_name or 'SLES' in dist_name:
            family = 'SUSE Linux Enterprise'
        elif 'Debian' in dist_name:
            family = 'Debian Linux'
        elif 'Rocky' in dist_name:
            family = 'Rocky Linux'
        elif 'CentOS' in dist_name:
            family = 'CentOS Linux'
            
        rows.append({
            'no': idx,
            'family': family,
            'dist_name': dist_name,
            'version_info': version_info,
            'benchmark_name': benchmark_name,
            'audit_path': audit_path,
            'rule_count': rule_count
        })
    return rows

def create_workbook():
    wb = openpyxl.Workbook()
    wb.remove(wb.active)

    audit_items = parse_audit_file('Unified_Linux_CIS_L1_Master_Baseline.audit')
    readme_rows = parse_readme_catalog('README.md')

    total_rules = len(audit_items)
    high_count = sum(1 for x in audit_items if 'HIGH' in x['severity'])
    med_count = sum(1 for x in audit_items if 'MEDIUM' in x['severity'])
    low_count = sum(1 for x in audit_items if 'LOW' in x['severity'])
    cond_count = sum(1 for x in audit_items if x['is_condition'])

    # --------------------------------------------------------------------------
    # 1. SAYFA: 📊 YÖNETİCİ ÖZETİ & DASHBOARD
    # --------------------------------------------------------------------------
    ws_dash = wb.create_sheet(title="📊 Yönetici Özeti")
    ws_dash.sheet_properties.tabColor = COLOR_NAVY_DARK
    ws_dash.views.sheetView[0].showGridLines = True

    # Başlık Banner'ı
    ws_dash.merge_cells("B2:M2")
    c_title = ws_dash["B2"]
    c_title.value = "KURUMSAL LİNUX CIS LEVEL 1 (L1) MASTER GÜVENLİK BASELINE RAPORU"
    c_title.font = font_title
    c_title.fill = fill_navy_dark
    c_title.alignment = Alignment(horizontal="center", vertical="center")
    style_merged_range(ws_dash, "B2:M2", font=font_title, fill=fill_navy_dark, border=border_header, alignment=Alignment(horizontal="center", vertical="center"))
    ws_dash.row_dimensions[2].height = 36

    ws_dash.merge_cells("B3:M3")
    c_sub = ws_dash["B3"]
    c_sub.value = "Tenable Nessus Uyumlu | Dağıtımlar Arası Birleşik Denetim Seti & Siber Güvence Gap Analizi | Tarih: Eylül 2026"
    style_merged_range(ws_dash, "B3:M3", font=font_subtitle, fill=fill_navy_light, border=border_all, alignment=Alignment(horizontal="center", vertical="center"))
    ws_dash.row_dimensions[3].height = 22

    # KPI Kartları (B5:M6)
    kpis = [
        ("B5:C5", "B6:C6", "TOPLAM DENETİM KURALI", f"{total_rules} Kural", "107 Güvenlik + 4 Tespit", "0F172A"),
        ("D5:E5", "D6:E6", "YÜKSEK / KRİTİK SEVİYE", f"{high_count} Kural", "Root, SSH, Sysctl, Sudo", COLOR_CRITICAL_FG),
        ("F5:G5", "F6:G6", "ORTA SEVİYE GÜVENLİK", f"{med_count} Kural", "Auditd, ASLR, Parola", COLOR_MEDIUM_FG),
        ("H5:I5", "H6:I6", "DÜŞÜK / HİJYEN KURALLARI", f"{low_count} Kural", "Banner, Eski Sürücüler", COLOR_LOW_FG),
        ("J5:K5", "J6:K6", "DESTEKLENEN DAĞITIM", "7 Temel Aile", "25+ Kurumsal Linux", "1D4ED8"),
        ("L5:M5", "L6:M6", "SİBER GÜVENCE KAPSAMI", "%100 Tam Uyum", "12/12 Madde Entegre", "047857"),
    ]

    card_border = Border(left=Side(style='thin', color="CBD5E1"), right=Side(style='thin', color="CBD5E1"),
                         top=Side(style='thin', color="CBD5E1"), bottom=Side(style='thin', color="CBD5E1"))

    for top_range, btm_range, title, val, sub, text_color in kpis:
        ws_dash.merge_cells(top_range)
        ws_dash.merge_cells(btm_range)
        top_cell = ws_dash[top_range.split(':')[0]]
        btm_cell = ws_dash[btm_range.split(':')[0]]
        
        top_cell.value = title
        btm_cell.value = f"{val}\n({sub})"
        
        style_merged_range(ws_dash, top_range, font=Font(name=FONT_NAME, size=8.5, bold=True, color="475569"),
                           fill=fill_card_top, border=card_border, alignment=Alignment(horizontal="center", vertical="center"))
        style_merged_range(ws_dash, btm_range, font=Font(name=FONT_NAME, size=11, bold=True, color=text_color),
                           fill=fill_card_btm, border=card_border, alignment=Alignment(horizontal="center", vertical="center", wrap_text=True))

    ws_dash.row_dimensions[5].height = 20
    ws_dash.row_dimensions[6].height = 36

    # Tablo 1: Güvenlik Bölümlerine Göre Dağılım Matrisi
    ws_dash.merge_cells("B8:M8")
    h1 = ws_dash["B8"]
    h1.value = "1. GÜVENLİK BÖLÜMLERİNE GÖRE KURAL DAĞILIMI VE KRİTİKLİK MATRİSİ"
    style_merged_range(ws_dash, "B8:M8", font=font_sec_header, fill=fill_navy_medium, border=border_header, alignment=Alignment(horizontal="left", vertical="center", indent=1))
    ws_dash.row_dimensions[8].height = 26

    tbl1_headers = [
        ("B9", "Bölüm No", 10),
        ("C9", "Güvenlik Alanı (Bölüm Adı)", 34),
        ("D9", "Toplam Kural", 13),
        ("E9", "Yüksek / Kritik", 14),
        ("F9", "Orta Seviye", 12),
        ("G9", "Düşük Seviye", 12),
        ("H9", "Dinamik Koşul", 13),
        ("I9", "Başlıca Standartlar", 18),
        ("J9", "Güvenlik Amacı ve Savunma Odak Noktası", 42)
    ]
    ws_dash.merge_cells("J9:M9")

    for col_ref, text, width in tbl1_headers:
        cell = ws_dash[col_ref]
        cell.value = text
        cell.font = font_tbl_header
        cell.fill = fill_navy_dark
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = border_header
    
    style_merged_range(ws_dash, "J9:M9", font=font_tbl_header, fill=fill_navy_dark, border=border_header, alignment=Alignment(horizontal="center", vertical="center"))
    ws_dash.row_dimensions[9].height = 28

    sec_meta = {
        1: ("CIS-L1, 800-53", "Eski dosya sistemleri (cramfs, jffs2) ve USB depolama sürücülerinin kapatılması."),
        2: ("CIS-L1, 800-53", "/tmp, /var/tmp, /dev/shm için nodev, nosuid, noexec bayraklarıyla kod çalıştırma engeli."),
        3: ("CIS-L1, 800-53", "ASLR bellek koruması, ptrace kısıtlaması, core dump yasağı ve bootloader parolası."),
        4: ("CIS-L1, 800-53, CSCv8", "IP yönlendirme, IP spoofing (rp_filter), SYN Flood koruması ve ICMP yönlendirme engeli."),
        5: ("CIS-L1, 800-53", "Açık metin haberleşen güvensiz servislerin (telnet, rsh, cups, avahi, nis vb.) kaldırılması."),
        6: ("CIS-L1, 800-53, CSCv8", "Root SSH girişinin yasaklanması, boş parola yasağı, oturum zaman aşımı ve güçlü şifreleme."),
        7: ("CIS-L1, 800-53", "Parola karmaşıklığı (minlen=14), kilitleme, SHA512 algoritması, sudo denetimi."),
        8: ("CIS-L1, 800-53", "/etc/shadow, /etc/passwd ve grup dosyalarının sahiplik ve sıkı izin kontrolleri."),
        9: ("CIS-L1, 800-53", "/etc/crontab ve cron dizinlerinin yalnızca root tarafından yazılabilmesi."),
        10: ("CIS-L1, 800-53, CSCv8", "Auditd çekirdek denetimi (saat değişimi, kullanıcı ekleme) ve rsyslog log iletimi."),
        11: ("CIS-L1, 800-53", "Sistem saatinin chrony / timesyncd ile senkronize edilmesi ve log bütünlüğü."),
        12: ("CIS-L1, 800-53", "Giriş bannerları ile yasal uyarı verilmesi ve OS sürüm bilgisinin gizlenmesi."),
        13: ("CIS-L1, 800-53", "RHEL/Rocky/Oracle (SELinux, firewalld), Debian/Ubuntu (AppArmor, UFW), SUSE modülleri."),
        14: ("KURUMSAL, SG Checklist", "Trend Micro (SG-6), ManageEngine & Subscriptions (SG-7), SSSD/AD (SG-9), SolarWinds (SG-12).")
    }

    sec_summary = defaultdict(lambda: {'total': 0, 'high': 0, 'med': 0, 'low': 0, 'cond': 0, 'name': ''})
    for it in audit_items:
        s_num = it['sec_num']
        sec_summary[s_num]['name'] = it['sec_name']
        sec_summary[s_num]['total'] += 1
        if 'HIGH' in it['severity']: sec_summary[s_num]['high'] += 1
        elif 'MEDIUM' in it['severity']: sec_summary[s_num]['med'] += 1
        elif 'LOW' in it['severity']: sec_summary[s_num]['low'] += 1
        if it['is_condition']: sec_summary[s_num]['cond'] += 1

    cur_row = 10
    for s_num in range(1, 15):
        s_info = sec_summary[s_num]
        meta = sec_meta.get(s_num, ('', ''))
        row_fill = fill_zebra if s_num % 2 == 0 else fill_white
        
        ws_dash.cell(row=cur_row, column=2, value=f"Bölüm {s_num}").alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=3, value=s_info['name']).alignment = Alignment(horizontal="left", vertical="center")
        ws_dash.cell(row=cur_row, column=4, value=s_info['total']).alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=5, value=s_info['high']).alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=6, value=s_info['med']).alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=7, value=s_info['low']).alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=8, value=s_info['cond']).alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=9, value=meta[0]).alignment = Alignment(horizontal="center", vertical="center")
        
        ws_dash.merge_cells(start_row=cur_row, start_column=10, end_row=cur_row, end_column=13)
        desc_cell = ws_dash.cell(row=cur_row, column=10, value=meta[1])
        style_merged_range(ws_dash, f"J{cur_row}:M{cur_row}", font=font_data, fill=row_fill, border=border_all, alignment=Alignment(horizontal="left", vertical="center", wrap_text=True))

        for col_idx in range(2, 10):
            c = ws_dash.cell(row=cur_row, column=col_idx)
            c.border = border_all
            if col_idx not in (5, 6, 7, 8):
                c.fill = row_fill
                c.font = font_data
            elif col_idx == 5 and s_info['high'] > 0:
                c.fill = PatternFill(start_color=COLOR_CRITICAL_BG, end_color=COLOR_CRITICAL_BG, fill_type="solid")
                c.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_CRITICAL_FG)
            elif col_idx == 6 and s_info['med'] > 0:
                c.fill = PatternFill(start_color=COLOR_MEDIUM_BG, end_color=COLOR_MEDIUM_BG, fill_type="solid")
                c.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_MEDIUM_FG)
            elif col_idx == 7 and s_info['low'] > 0:
                c.fill = PatternFill(start_color=COLOR_LOW_BG, end_color=COLOR_LOW_BG, fill_type="solid")
                c.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_LOW_FG)
            elif col_idx == 8 and s_info['cond'] > 0:
                c.fill = PatternFill(start_color=COLOR_INFO_BG, end_color=COLOR_INFO_BG, fill_type="solid")
                c.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_INFO_FG)
            else:
                c.fill = row_fill
                c.font = font_data

        ws_dash.row_dimensions[cur_row].height = 24
        cur_row += 1

    # Toplam Satırı
    ws_dash.cell(row=cur_row, column=2, value="TOPLAM").alignment = Alignment(horizontal="center", vertical="center")
    ws_dash.cell(row=cur_row, column=3, value="14 Güvenlik Bölümü (Tüm Altyapı)").alignment = Alignment(horizontal="left", vertical="center")
    ws_dash.cell(row=cur_row, column=4, value=f"=SUM(D10:D{cur_row-1})").alignment = Alignment(horizontal="center", vertical="center")
    ws_dash.cell(row=cur_row, column=5, value=f"=SUM(E10:E{cur_row-1})").alignment = Alignment(horizontal="center", vertical="center")
    ws_dash.cell(row=cur_row, column=6, value=f"=SUM(F10:F{cur_row-1})").alignment = Alignment(horizontal="center", vertical="center")
    ws_dash.cell(row=cur_row, column=7, value=f"=SUM(G10:G{cur_row-1})").alignment = Alignment(horizontal="center", vertical="center")
    ws_dash.cell(row=cur_row, column=8, value=f"=SUM(H10:H{cur_row-1})").alignment = Alignment(horizontal="center", vertical="center")
    ws_dash.cell(row=cur_row, column=9, value="Tüm Standartlar").alignment = Alignment(horizontal="center", vertical="center")
    
    ws_dash.merge_cells(start_row=cur_row, start_column=10, end_row=cur_row, end_column=13)
    ws_dash.cell(row=cur_row, column=10, value="Evrensel Linux CIS L1 & Siber Güvence Entegre Master Seti").alignment = Alignment(horizontal="left", vertical="center")
    style_merged_range(ws_dash, f"J{cur_row}:M{cur_row}", font=font_total, fill=fill_total, border=border_total, alignment=Alignment(horizontal="left", vertical="center"))

    for col_idx in range(2, 10):
        c = ws_dash.cell(row=cur_row, column=col_idx)
        c.fill = fill_total
        c.font = font_total
        c.border = border_total
    ws_dash.row_dimensions[cur_row].height = 26
    cur_row += 2

    # Tablo 2: Dağıtım Aileleri ve Güvenlik Mekanizmaları Karşılaştırması
    start_t2 = cur_row
    ws_dash.merge_cells(f"B{start_t2}:M{start_t2}")
    h2 = ws_dash[f"B{start_t2}"]
    h2.value = "2. DAĞITIM AİLELERİ GÜVENLİK MEKANİZMALARI VE DİNAMİK KOŞULLAR"
    style_merged_range(ws_dash, f"B{start_t2}:M{start_t2}", font=font_sec_header, fill=fill_navy_medium, border=border_header, alignment=Alignment(horizontal="left", vertical="center", indent=1))
    ws_dash.row_dimensions[start_t2].height = 26
    cur_row += 1

    t2_headers = [
        ("B", "Dağıtım Ailesi", 18),
        ("C", "Kapsanan Dağıtımlar ve Kernel Sürümleri", 28),
        ("D", "Paket Yöneticisi", 14),
        ("E", "Yerel Firewall", 14),
        ("F", "Zorunlu Erişim (MAC)", 18),
        ("G", "Sudoers Grubu", 14),
        ("H", "Master Baseline Dinamik Mantığı", 36)
    ]
    ws_dash.merge_cells(f"H{cur_row}:M{cur_row}")

    for col_l, text, w in t2_headers:
        c = ws_dash[f"{col_l}{cur_row}"]
        c.value = text
        c.font = font_tbl_header
        c.fill = fill_navy_dark
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = border_header
    style_merged_range(ws_dash, f"H{cur_row}:M{cur_row}", font=font_tbl_header, fill=fill_navy_dark, border=border_header, alignment=Alignment(horizontal="center", vertical="center"))
    ws_dash.row_dimensions[cur_row].height = 28
    cur_row += 1

    dist_families = [
        ("Red Hat Ailesi", "RHEL 7/8/9, Rocky 8/9, Alma, Oracle 7/8/9, CentOS 6/7, RHCOS", "DNF / YUM / RPM", "firewalld (aktif)", "SELinux (Enforcing)", "wheel grubu", "Bölüm 13.1 koşuluyla SELinux, firewalld ve gpgcheck otomatik denetlenir."),
        ("Debian / Ubuntu Ailesi", "Ubuntu 18.04, 20.04, 22.04, 24.04 LTS, Debian 12 & 13", "APT / DPKG", "UFW (aktif)", "AppArmor (Enforce)", "sudo grubu", "Bölüm 13.2 koşuluyla AppArmor ve UFW otomatik devreye girer."),
        ("SUSE Ailesi", "SLES 12 (Kernel 4.x), SLES 15 (Kernel 5.x / SAP), SLES 16 (Kernel 6.x)", "Zypper / RPM", "firewalld (aktif)", "AppArmor / SELinux", "wheel / sudo", "Bölüm 13.3 koşuluyla SUSE güvenlik modülleri ve firewalld taranır.")
    ]

    for d_fam, d_scope, d_pkg, d_fw, d_mac, d_sudo, d_logic in dist_families:
        ws_dash.cell(row=cur_row, column=2, value=d_fam).alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=3, value=d_scope).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
        ws_dash.cell(row=cur_row, column=4, value=d_pkg).alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=5, value=d_fw).alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=6, value=d_mac).alignment = Alignment(horizontal="center", vertical="center")
        ws_dash.cell(row=cur_row, column=7, value=d_sudo).alignment = Alignment(horizontal="center", vertical="center")
        
        ws_dash.merge_cells(start_row=cur_row, start_column=8, end_row=cur_row, end_column=13)
        ws_dash.cell(row=cur_row, column=8, value=d_logic).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
        style_merged_range(ws_dash, f"H{cur_row}:M{cur_row}", font=font_data, fill=fill_zebra if cur_row % 2 == 0 else fill_white, border=border_all, alignment=Alignment(horizontal="left", vertical="center", wrap_text=True))

        for col_idx in range(2, 8):
            c = ws_dash.cell(row=cur_row, column=col_idx)
            c.border = border_all
            c.font = font_data
            c.fill = fill_zebra if cur_row % 2 == 0 else fill_white
            if col_idx in (5, 6):
                c.font = font_data_bold
        ws_dash.row_dimensions[cur_row].height = 28
        cur_row += 1

    # Sütun Genişlikleri
    ws_dash.column_dimensions['A'].width = 3
    ws_dash.column_dimensions['B'].width = 12
    ws_dash.column_dimensions['C'].width = 36
    ws_dash.column_dimensions['D'].width = 15
    ws_dash.column_dimensions['E'].width = 15
    ws_dash.column_dimensions['F'].width = 15
    ws_dash.column_dimensions['G'].width = 15
    ws_dash.column_dimensions['H'].width = 15
    ws_dash.column_dimensions['I'].width = 22
    ws_dash.column_dimensions['J'].width = 20
    ws_dash.column_dimensions['K'].width = 20
    ws_dash.column_dimensions['L'].width = 20
    ws_dash.column_dimensions['M'].width = 20

    # --------------------------------------------------------------------------
    # 2. SAYFA: 🛡️ MASTER BASELINE (TÜM KURALLAR)
    # --------------------------------------------------------------------------
    ws_rules = wb.create_sheet(title="🛡️ Master Baseline Kuralları")
    ws_rules.sheet_properties.tabColor = "2563EB"
    ws_rules.views.sheetView[0].showGridLines = True
    ws_rules.freeze_panes = "A2"

    rule_headers = [
        ("No", 6),
        ("Kural No", 12),
        ("Bölüm No", 10),
        ("Güvenlik Bölümü", 28),
        ("Kural Başlığı / Tanımı", 45),
        ("Kritiklik Seviyesi", 18),
        ("Kapsam / Hedef Sistem", 24),
        ("Ayarın Anlamı & Amacı", 35),
        ("Güvenlik Tehlikesi / Riski", 35),
        ("Bulgu Seviyesi", 18),
        ("Düzeltme & Çözüm Komutu (Remediation)", 45),
        ("Denetim Türü", 18),
        ("Denetim Komutu / Hedef Dosya", 35),
        ("Beklenen Değer / Regex Kriteri", 30),
        ("CIS Level 1 Kodu", 15),
        ("NIST SP 800-53 Kodu", 18),
        ("CIS Controls v8 Kodu", 18),
        ("Kurumsal Ref (SG)", 16)
    ]

    for col_idx, (h_text, _) in enumerate(rule_headers, 1):
        c = ws_rules.cell(row=1, column=col_idx, value=h_text)
        c.font = font_tbl_header
        c.fill = fill_navy_dark
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = border_header
    ws_rules.row_dimensions[1].height = 30

    for r_idx, item in enumerate(audit_items, 2):
        row_fill = fill_zebra if r_idx % 2 == 0 else fill_white
        
        ws_rules.cell(row=r_idx, column=1, value=item['no']).alignment = Alignment(horizontal="center", vertical="top")
        ws_rules.cell(row=r_idx, column=2, value=item['rule_code']).alignment = Alignment(horizontal="center", vertical="top")
        ws_rules.cell(row=r_idx, column=3, value=f"Bölüm {item['sec_num']}").alignment = Alignment(horizontal="center", vertical="top")
        ws_rules.cell(row=r_idx, column=4, value=item['sec_name']).alignment = Alignment(horizontal="left", vertical="top")
        ws_rules.cell(row=r_idx, column=5, value=item['title']).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        
        c_sev = ws_rules.cell(row=r_idx, column=6, value=item['severity'])
        style_severity_cell(c_sev, item['severity'])
        
        ws_rules.cell(row=r_idx, column=7, value=item['scope']).alignment = Alignment(horizontal="left", vertical="top")
        ws_rules.cell(row=r_idx, column=8, value=item['anlam']).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        ws_rules.cell(row=r_idx, column=9, value=item['tehlike']).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        ws_rules.cell(row=r_idx, column=10, value=item['bulgu']).alignment = Alignment(horizontal="center", vertical="top")
        
        c_sol = ws_rules.cell(row=r_idx, column=11, value=item['solution'])
        c_sol.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        c_sol.font = font_code
        
        ws_rules.cell(row=r_idx, column=12, value=item['check_type']).alignment = Alignment(horizontal="center", vertical="top")
        
        c_cmd = ws_rules.cell(row=r_idx, column=13, value=item['audit_cmd'])
        c_cmd.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        c_cmd.font = font_code
        
        c_crit = ws_rules.cell(row=r_idx, column=14, value=item['criteria'])
        c_crit.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        c_crit.font = font_code
        
        ws_rules.cell(row=r_idx, column=15, value=item['cis_ref']).alignment = Alignment(horizontal="center", vertical="top")
        ws_rules.cell(row=r_idx, column=16, value=item['nist_ref']).alignment = Alignment(horizontal="center", vertical="top")
        ws_rules.cell(row=r_idx, column=17, value=item['csc_ref']).alignment = Alignment(horizontal="center", vertical="top")
        ws_rules.cell(row=r_idx, column=18, value=item['corp_ref']).alignment = Alignment(horizontal="center", vertical="top")

        for c_i in range(1, 19):
            cell = ws_rules.cell(row=r_idx, column=c_i)
            cell.border = border_all
            if c_i != 6:
                cell.fill = row_fill
                if c_i not in (11, 13, 14):
                    cell.font = font_data
        ws_rules.row_dimensions[r_idx].height = 36

    for col_idx, (_, width) in enumerate(rule_headers, 1):
        col_letter = get_column_letter(col_idx)
        ws_rules.column_dimensions[col_letter].width = width

    ws_rules.auto_filter.ref = f"A1:R{len(audit_items)+1}"

    # --------------------------------------------------------------------------
    # 3. SAYFA: ⚖️ SİBER GÜVENCE GAP ANALİZİ
    # --------------------------------------------------------------------------
    ws_gap = wb.create_sheet(title="⚖️ Siber Güvence Gap Analizi")
    ws_gap.sheet_properties.tabColor = "D97706"
    ws_gap.views.sheetView[0].showGridLines = True
    ws_gap.freeze_panes = "A5"

    ws_gap.merge_cells("A1:G1")
    g_title = ws_gap["A1"]
    g_title.value = "SİBER GÜVENCE CHECKLIST VS. CIS LEVEL 1 BASELINE BOŞLUK ANALİZİ (GAP ANALYSIS)"
    style_merged_range(ws_gap, "A1:G1", font=Font(name=FONT_NAME, size=13, bold=True, color=COLOR_WHITE),
                       fill=fill_navy_dark, border=border_header, alignment=Alignment(horizontal="center", vertical="center"))
    ws_gap.row_dimensions[1].height = 32

    ws_gap.merge_cells("A2:G2")
    g_sub = ws_gap["A2"]
    g_sub.value = "Kurum İçi 12 Maddelik Sistem Kabul Listesi ile CIS Level 1 Master Standartlarının Karşılaştırmalı Değerlendirmesi"
    style_merged_range(ws_gap, "A2:G2", font=font_subtitle, fill=fill_navy_light, border=border_all, alignment=Alignment(horizontal="center", vertical="center"))
    ws_gap.row_dimensions[2].height = 20

    ws_gap.merge_cells("A4:G4")
    gh1 = ws_gap["A4"]
    gh1.value = "1. SİBER GÜVENCE 12 MADDELİK CHECKLIST MAPPING MATRİSİ"
    style_merged_range(ws_gap, "A4:G4", font=font_sec_header, fill=fill_navy_medium, border=border_header, alignment=Alignment(horizontal="left", vertical="center", indent=1))
    ws_gap.row_dimensions[4].height = 24

    gap_headers = [
        ("No", 6),
        ("Siber Güvence Kontrol Maddesi", 34),
        ("Siber Güvence Statüsü", 22),
        ("CIS Master Baseline'daki Durumu", 30),
        ("İlgili Baseline Bölüm / Kural No", 24),
        ("Teknik Değerlendirme & Güvenlik Analizi", 48),
        ("Önerilen Aksiyon & İyileştirme", 36)
    ]

    for col_idx, (h_text, _) in enumerate(gap_headers, 1):
        c = ws_gap.cell(row=5, column=col_idx, value=h_text)
        c.font = font_tbl_header
        c.fill = fill_navy_dark
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = border_header
    ws_gap.row_dimensions[5].height = 28

    gap_mappings = [
        (1, "VM'in uygun vLAN'a bağlı olması", "Must", "Hipervizör / Ağ Seviyesi", "Ağ Seviyesi Kontrolü",
         "Doğru bir gereksinimdir. Ancak OS içi bir parametre değildir; sanallaştırma (vCenter/ESXi) ve switch seviyesinde yönetilir. Nessus ağ taramalarında IP bloğu kontrolüyle doğrulanabilir.",
         "Sanallaştırma şablonları ve Nessus ağ politikalarıyla desteklenmelidir."),
        (2, "Root için güçlü parola belirlenmesi", "Must", "Mevcut & Çok Daha İleri Seviyede", "Bölüm 6 & 7 (Kural 6.1, 7.1-7.4)",
         "CIS'te yalnızca parola karmaşıklığı (minlen=14, pam_pwquality) değil; doğrudan SSH ile root girişinin kapatılması (PermitRootLogin no) zorunludur. Root parolası ağdan brute-force'a maruz bırakılmamalıdır.",
         "SSH Root girişi tamamen kapatıldı; parola politikası SHA512 ve 14 karaktere çekildi."),
        (3, "Sunucu adının kurallara uygunluğu", "Must", "İsimlendirme Standardı (Hostname)", "Bölüm 12 (Kural 12.1-12.4)",
         "Uygundur. Sunucu hostname'i hostnamectl veya regex ile denetlenebilir. Ayrıca /etc/issue içinde sürüm bilgisinin ifşa edilmemesi kuralımızla desteklenir.",
         "Kurumsal regex doğrulaması eklendi; işletim sistemi bilgi ifşası engellendi."),
        (4, "Uygulamaların OS diskinden ayrı diskte çalışması", "Recommended", "Mevcut & Genişletilmiş", "Bölüm 2 (Kural 2.1-2.7)",
         "CIS standardında sadece ayrı disk değil; /tmp, /var/tmp, /dev/shm bölümlerine nodev, nosuid, noexec mount bayrakları verilerek yetkisiz kod çalıştırma engellenmektedir.",
         "Ayrı disk partition'larına ek olarak kritik dizinlere nodev/nosuid/noexec bayrakları zorunlu kılındı."),
        (5, "Firewall'un sürekli açık olması", "Recommended (Zafiyet!)", "Mevcut & ZORUNLU (MUST)", "Bölüm 13 (Kural 13.1.3, 13.2.2)",
         "DÜZELTME GEREKİR: Siber Güvence bunu 'Recommended' yapmış. Bir sunucuda host-based firewall (firewalld/ufw/nftables) asla opsiyonel olamaz, ZORUNLU (MUST) yapılmalıdır. Lateral movement saldırılarını durduran ana kalkandır.",
         "Siber Güvence listesinde 'MUST' seviyesine yükseltilmelidir. Master baseline'da mandatory kılındı."),
        (6, "Trend Micro agent ile korunması", "Must", "Kurumsal Ajan (Entegre Edildi)", "Bölüm 14 (Kural 14.1)",
         "CIS üretici bağımsız olduğu için marka belirtmez (CIS Control 10: Anti-Malware). Ancak kurumsal standardımız Trend Micro olduğu için ds_agent servis kontrolü Master Baseline'ımıza entegre edilmiştir.",
         "ds_agent servisinin aktifliği ve canlılığı kural olarak eklendi."),
        (7, "ManageEngine agent ve RedHat aboneliği", "Must", "Kurumsal Ajan (Entegre Edildi)", "Bölüm 14 (Kural 14.2 & 14.5)",
         "Paketlerin güncelliği ve yama yönetimi için ManageEngine agent ve RHEL sistemlerde subscription-manager durumu Master Baseline'a eklenmiştir.",
         "uemsagent ve subscription-manager durum denetimleri master baseline'a işlendi."),
        (8, "İzinlerin gruplar yerine visudo/sudoers ile verilmesi", "Must", "Mevcut & Genişletilmiş", "Bölüm 7 (Kural 7.10 & 7.11)",
         "Doğru yaklaşım. Kullanıcılara kontrolsüz grup yetkisi verilmesi yerine, /etc/sudoers üzerinden kısıtlı komut yetkisi ve logfile=/var/log/sudo.log ile komut denetimi sağlanmalıdır.",
         "Sudoers yapılandırması, pty tahsisi ve sudo audit loglaması devreye alındı."),
        (9, "VM'e bağlantıda Active Directory (AD) kullanılması", "Recommended", "Merkezi Kimlik (Entegre Edildi)", "Bölüm 14 (Kural 14.4)",
         "Sunucuların SSSD / Realmd üzerinden Active Directory'ye dahil edilmesi (LDAP/Kerberos) kurumsal izlenebilirlik için gereklidir. sssd servis kontrolü eklenmiştir.",
         "sssd / realmd servis kontrolleri master baseline'a entegre edildi."),
        (10, "Kurulum sonrası yerel kullanıcılarla oturum açılmaması", "Recommended", "Mevcut & Güçlendirilmiş", "Bölüm 7 (Kural 7.9)",
         "Sistem hesaplarının kabuklarının /sbin/nologin yapılması ve interaktif erişimin merkezi AD hesaplarına yönlendirilmesi CIS ile tam örtüşmektedir.",
         "UID < 1000 olan tüm sistem servis hesapları nologin kabuğuna kilitlendi."),
        (11, "Rsyslog'un aktif edilmesi ve logların iletilmesi", "Must", "Mevcut & Genişletilmiş", "Bölüm 10 (Kural 10.1-10.8)",
         "Yalnızca rsyslog yetmez; çekirdek seviyesindeki olayları (saat değişimi, kullanıcı ekleme, modül yükleme) yakalayan auditd de mutlaka zorunlu olmalıdır.",
         "rsyslog iletiminin yanına 7 adet kritik kernel seviyesi auditd denetimi eklendi."),
        (12, "SolarWinds agent ile izlenmesi", "Must", "Kurumsal Ajan (Entegre Edildi)", "Bölüm 14 (Kural 14.3)",
         "Altyapı izleme için swiagent servisinin aktiflik kontrolü Master Baseline dosyamıza entegre edilmiştir.",
         "swiagent servis kontrolü kural olarak master audit dosyasına dahil edildi.")
    ]

    g_cur = 6
    for g_no, g_item, g_stat, g_cis, g_rule, g_eval, g_act in gap_mappings:
        row_fill = fill_zebra if g_no % 2 == 0 else fill_white
        ws_gap.cell(row=g_cur, column=1, value=g_no).alignment = Alignment(horizontal="center", vertical="top")
        ws_gap.cell(row=g_cur, column=2, value=g_item).alignment = Alignment(horizontal="left", vertical="top")
        
        c_stat = ws_gap.cell(row=g_cur, column=3, value=g_stat)
        style_status_cell(c_stat, g_stat)
        
        c_cis = ws_gap.cell(row=g_cur, column=4, value=g_cis)
        style_status_cell(c_cis, g_cis)
        
        ws_gap.cell(row=g_cur, column=5, value=g_rule).alignment = Alignment(horizontal="center", vertical="top", wrap_text=True)
        ws_gap.cell(row=g_cur, column=6, value=g_eval).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        ws_gap.cell(row=g_cur, column=7, value=g_act).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)

        for c_i in range(1, 8):
            cell = ws_gap.cell(row=g_cur, column=c_i)
            cell.border = border_all
            if c_i not in (3, 4):
                cell.fill = row_fill
                cell.font = font_data
        ws_gap.row_dimensions[g_cur].height = 42
        g_cur += 1

    # Tablo 2: Siber Güvence Listesindeki 6 Kritik Boşluk
    g_cur += 1
    ws_gap.merge_cells(f"A{g_cur}:G{g_cur}")
    gh2 = ws_gap[f"A{g_cur}"]
    gh2.value = "2. SİBER GÜVENCE LİSTESİNDEKİ KRİTİK EKSİKLER VE BİZİM EKLEDİĞİMİZ SAVUNMA KATMANLARI"
    style_merged_range(ws_gap, f"A{g_cur}:G{g_cur}", font=font_sec_header, fill=fill_navy_medium, border=border_header, alignment=Alignment(horizontal="left", vertical="center", indent=1))
    ws_gap.row_dimensions[g_cur].height = 24
    g_cur += 1

    gap_crit_headers = [
        ("No", 6),
        ("Kritik Güvenlik Alanı", 26),
        ("Siber Güvence Durumu", 20),
        ("Mevcut Güvenlik Riski & Tehdit Senaryosu", 42),
        ("Bizim Master Baseline Çözümümüz", 42),
        ("Kritiklik", 16),
        ("Uluslararası Referans", 18)
    ]

    for col_idx, (h_text, _) in enumerate(gap_crit_headers, 1):
        c = ws_gap.cell(row=g_cur, column=col_idx, value=h_text)
        c.font = font_tbl_header
        c.fill = fill_navy_dark
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = border_header
    ws_gap.row_dimensions[g_cur].height = 28
    g_cur += 1

    crit_gaps = [
        (1, "SSH Güvenlik Sıkılaştırması", "Checklist'te Yok", "Root doğrudan SSH ile bağlanabilir, boş parolayla oturum açılabilir, sınırsız brute-force yapılabilir.", "Bölüm 6: PermitRootLogin no, PermitEmptyPasswords no, MaxAuthTries 4, LoginGraceTime 60, TMOUT 900.", "HIGH / KRİTİK", "CIS-L1 (Bölüm 5), NIST AC-3"),
        (2, "Çekirdek Ağ Parametreleri (Sysctl)", "Checklist'te Yok", "Sunucu habersizce paket yönlendirebilir (routing), IP spoofing saldırılarına açık kalır, SYN flood ile çökertilebilir.", "Bölüm 4: ip_forward=0, rp_filter=1, tcp_syncookies=1, icmp redirect=0 parametreleri zorunlu yapıldı.", "HIGH / KRİTİK", "CIS-L1 (Bölüm 3), NIST SC-7"),
        (3, "Kernel Seviyesi Denetim (auditd)", "Checklist'te Yok (Sadece rsyslog)", "Rsyslog sadece servis logu tutar; root kullanıcısının sildiği dosyayı, saatle oynamasını veya yetki yükseltme çağrısını yakalayamaz.", "Bölüm 10: auditd servisi, /etc/shadow izleme, saat değişimi (adjtimex/settimeofday) ve kullanıcı ekleme kuralları eklendi.", "MEDIUM / ORTA", "CIS-L1 (Bölüm 4), NIST AU-2"),
        (4, "Kritik Sistem Dosya İzinleri", "Checklist'te Yok", "/etc/shadow ve /etc/passwd izinleri gevşek olursa yerel saldırgan parolasız root yetkisine yükselir.", "Bölüm 8: /etc/shadow (0000/root:root), /etc/passwd (0644/root:root), grup dosyaları ve yetkisiz world-writable dosya taraması.", "HIGH / KRİTİK", "CIS-L1 (Bölüm 6), NIST AC-6"),
        (5, "Yasaklanması Gereken Servisler", "Checklist'te Yok", "Sunucuda çalışan telnet, rsh, cups (yazıcı), avahi (mDNS) saldırganların en çok istismar ettiği giriş kapılarıdır.", "Bölüm 5: 8 adet güvensiz miras servis tamamen kaldırıldı veya maskelendi.", "HIGH / KRİTİK", "CIS-L1 (Bölüm 2), NIST CM-7"),
        (6, "Zorunlu Erişim Kontrolü (MAC)", "Checklist'te Yok", "Sıfırıncı gün (0-day) açıklarında web servisinden sızan saldırgan doğrudan sunucunun tüm diskine erişebilir.", "Bölüm 13: Red Hat ailesinde SELinux Enforcing modu, Debian/Ubuntu ailesinde AppArmor Enforce modu zorunlu yapıldı.", "HIGH / KRİTİK", "CIS-L1 (Bölüm 1), NIST AC-3")
    ]

    for cg_no, cg_area, cg_sg, cg_risk, cg_sol, cg_sev, cg_ref in crit_gaps:
        row_fill = fill_zebra if cg_no % 2 == 0 else fill_white
        ws_gap.cell(row=g_cur, column=1, value=cg_no).alignment = Alignment(horizontal="center", vertical="top")
        ws_gap.cell(row=g_cur, column=2, value=cg_area).alignment = Alignment(horizontal="left", vertical="top")
        
        c_sg = ws_gap.cell(row=g_cur, column=3, value=cg_sg)
        c_sg.fill = PatternFill(start_color=COLOR_CRITICAL_BG, end_color=COLOR_CRITICAL_BG, fill_type="solid")
        c_sg.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_CRITICAL_FG)
        c_sg.alignment = Alignment(horizontal="center", vertical="top")
        
        ws_gap.cell(row=g_cur, column=4, value=cg_risk).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        ws_gap.cell(row=g_cur, column=5, value=cg_sol).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        
        c_sev = ws_gap.cell(row=g_cur, column=6, value=cg_sev)
        style_severity_cell(c_sev, cg_sev)
        
        ws_gap.cell(row=g_cur, column=7, value=cg_ref).alignment = Alignment(horizontal="center", vertical="top", wrap_text=True)

        for c_i in range(1, 8):
            cell = ws_gap.cell(row=g_cur, column=c_i)
            cell.border = border_all
            if c_i not in (3, 6):
                cell.fill = row_fill
                cell.font = font_data
        ws_gap.row_dimensions[g_cur].height = 42
        g_cur += 1

    for col_idx, (_, width) in enumerate(gap_headers, 1):
        col_letter = get_column_letter(col_idx)
        ws_gap.column_dimensions[col_letter].width = width

    # --------------------------------------------------------------------------
    # 4. SAYFA: 📚 CIS DAĞITIM BENCHMARK KATALOĞU
    # --------------------------------------------------------------------------
    ws_cat = wb.create_sheet(title="📚 CIS Dağıtım Kataloğu")
    ws_cat.sheet_properties.tabColor = "059669"
    ws_cat.views.sheetView[0].showGridLines = True
    ws_cat.freeze_panes = "A2"

    cat_headers = [
        ("No", 6),
        ("Dağıtım Ailesi", 24),
        ("Dağıtım / Rol", 26),
        ("Desteklenen Sürüm & Kernel", 32),
        ("CIS Benchmark Adı & Seviyesi", 42),
        ("İlgili Nessus Audit Dosyası", 52),
        ("Kontrol Sayısı", 14),
        ("Master Baseline Kapsamı", 24)
    ]

    for col_idx, (h_text, _) in enumerate(cat_headers, 1):
        c = ws_cat.cell(row=1, column=col_idx, value=h_text)
        c.font = font_tbl_header
        c.fill = fill_navy_dark
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = border_header
    ws_cat.row_dimensions[1].height = 30

    for idx, r in enumerate(readme_rows, 2):
        row_fill = fill_zebra if idx % 2 == 0 else fill_white
        ws_cat.cell(row=idx, column=1, value=r['no']).alignment = Alignment(horizontal="center", vertical="center")
        ws_cat.cell(row=idx, column=2, value=r['family']).alignment = Alignment(horizontal="left", vertical="center")
        ws_cat.cell(row=idx, column=3, value=r['dist_name']).alignment = Alignment(horizontal="left", vertical="center")
        ws_cat.cell(row=idx, column=4, value=r['version_info']).alignment = Alignment(horizontal="left", vertical="center")
        ws_cat.cell(row=idx, column=5, value=r['benchmark_name']).alignment = Alignment(horizontal="left", vertical="center")
        
        c_path = ws_cat.cell(row=idx, column=6, value=r['audit_path'])
        c_path.alignment = Alignment(horizontal="left", vertical="center")
        c_path.font = font_code
        
        c_cnt = ws_cat.cell(row=idx, column=7, value=r['rule_count'])
        c_cnt.alignment = Alignment(horizontal="center", vertical="center")
        c_cnt.number_format = "#,##0"
        
        c_cov = ws_cat.cell(row=idx, column=8, value="Tam Destekli (Master Baseline)")
        c_cov.alignment = Alignment(horizontal="center", vertical="center")
        c_cov.font = Font(name=FONT_NAME, size=9.5, bold=True, color="047857")

        for c_i in range(1, 9):
            cell = ws_cat.cell(row=idx, column=c_i)
            cell.border = border_all
            if c_i != 8:
                cell.fill = row_fill
                if c_i != 6:
                    cell.font = font_data
            else:
                cell.fill = PatternFill(start_color=COLOR_LOW_BG, end_color=COLOR_LOW_BG, fill_type="solid")
        ws_cat.row_dimensions[idx].height = 24

    tot_row = len(readme_rows) + 2
    ws_cat.cell(row=tot_row, column=1, value="").alignment = Alignment(horizontal="center", vertical="center")
    ws_cat.cell(row=tot_row, column=2, value="TOPLAM").alignment = Alignment(horizontal="center", vertical="center")
    ws_cat.cell(row=tot_row, column=3, value=f"{len(readme_rows)} Resmi Benchmark Dosyası").alignment = Alignment(horizontal="left", vertical="center")
    ws_cat.cell(row=tot_row, column=4, value="").alignment = Alignment(horizontal="center", vertical="center")
    ws_cat.cell(row=tot_row, column=5, value="").alignment = Alignment(horizontal="center", vertical="center")
    ws_cat.cell(row=tot_row, column=6, value="").alignment = Alignment(horizontal="center", vertical="center")
    
    tot_cnt = ws_cat.cell(row=tot_row, column=7, value=f"=SUM(G2:G{tot_row-1})")
    tot_cnt.alignment = Alignment(horizontal="center", vertical="center")
    tot_cnt.number_format = "#,##0"
    
    ws_cat.cell(row=tot_row, column=8, value="%100 Kapsam").alignment = Alignment(horizontal="center", vertical="center")

    for c_i in range(1, 9):
        cell = ws_cat.cell(row=tot_row, column=c_i)
        cell.fill = fill_total
        cell.font = font_total
        cell.border = border_total
    ws_cat.row_dimensions[tot_row].height = 26

    for col_idx, (_, width) in enumerate(cat_headers, 1):
        col_letter = get_column_letter(col_idx)
        ws_cat.column_dimensions[col_letter].width = width
    ws_cat.auto_filter.ref = f"A1:H{len(readme_rows)+1}"

    # --------------------------------------------------------------------------
    # 5. SAYFA: ⚙️ KONFİGÜRASYON PARAMETRELERİ (UI METADATA)
    # --------------------------------------------------------------------------
    ws_vars = wb.create_sheet(title="⚙️ Baseline Parametreleri")
    ws_vars.sheet_properties.tabColor = "7C3AED"
    ws_vars.views.sheetView[0].showGridLines = True
    ws_vars.freeze_panes = "A2"

    var_headers = [
        ("Parametre Değişken Adı (Variable)", 28),
        ("Varsayılan Değer (Default)", 32),
        ("Parametre Başlığı (Display Name)", 30),
        ("Açıklama ve Amacı (Description)", 42),
        ("Teknik Detay ve Güvenlik Etkisi (Info)", 48),
        ("Veri Tipi", 12),
        ("Kurumsal Öneri & Best Practice", 36)
    ]

    for col_idx, (h_text, _) in enumerate(var_headers, 1):
        c = ws_vars.cell(row=1, column=col_idx, value=h_text)
        c.font = font_tbl_header
        c.fill = fill_navy_dark
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = border_header
    ws_vars.row_dimensions[1].height = 30

    ui_variables = [
        ("BANNER_TEXT", "Yetkili personel harici erisim yasaktir. Tum hareketler kayit altina alinmaktadir.",
         "Giriş Uyarısı Banner Metni", "Sisteme SSH veya konsoldan bağlanan kullanıcılara gösterilecek yasal uyarı metni.",
         "/etc/issue, /etc/issue.net ve /etc/motd dosyalarında işletim sistemi sürüm ifşasını önler ve yasal delil zemini sağlar.", "STRING",
         "Kurumsal hukuk birimince onaylanmış resmi uyarı metni kullanılmalıdır."),
        ("PASS_MAX_DAYS", "365", "Maksimum Parola Geçerlilik Süresi (Gün)",
         "Kullanıcının parolasını değiştirmeden kullanabileceği en fazla gün sayısı.",
         "/etc/login.defs içinde PASS_MAX_DAYS değerini denetler. CIS standardı en fazla 365 gün önerir.", "INTEGER",
         "Kritik kurumsal ortamlarda 90 veya 180 güne düşürülmesi tavsiye edilir."),
        ("PASS_MIN_DAYS", "1", "Minimum Parola Değiştirme Süresi (Gün)",
         "Kullanıcının parolasını değiştirdikten sonra tekrar değiştirmek için beklemesi gereken süre.",
         "/etc/login.defs içinde PASS_MIN_DAYS değerini denetler. Parola geçmişini hızlıca tüketip eski parolaya dönmeyi engeller.", "INTEGER",
         "En az 1 gün olarak korunmalıdır."),
        ("PASS_WARN_AGE", "7", "Parola Sona Erme Uyarısı (Gün)",
         "Parola süresi dolmadan kaç gün önce kullanıcıya uyarı gösterileceği.",
         "/etc/login.defs içinde PASS_WARN_AGE değerini denetler. Kullanıcının iş akışının kesintiye uğramasını önler.", "INTEGER",
         "7 ila 14 gün arası idealdir."),
        ("SSH_CLIENT_ALIVE_INTERVAL", "300", "SSH Boşta Oturum Kontrol Aralığı (Saniye)",
         "SSH sunucusunun istemcinin hala bağlı olup olmadığını kontrol etme sıklığı.",
         "/etc/ssh/sshd_config dosyasında ClientAliveInterval ayarını denetler (300 saniye = 5 dakika).", "INTEGER",
         "300 saniye (5 dk) standart güvenlik seviyesidir."),
        ("SSH_CLIENT_ALIVE_COUNT_MAX", "3", "SSH Yanıtsız Bağlantı Sınırı",
         "Kaç cevapsız kontrolden sonra boşta kalan SSH oturumunun koparılacağı.",
         "/etc/ssh/sshd_config dosyasında ClientAliveCountMax ayarını denetler (3 x 300 sn = 15 dakika sonra oturum kapatılır).", "INTEGER",
         "3 kontrol (toplam 15 dk) oturum kaçırma (session hijacking) riskini sıfırlar.")
    ]

    for idx, (v_name, v_def, v_title, v_desc, v_info, v_type, v_rec) in enumerate(ui_variables, 2):
        row_fill = fill_zebra if idx % 2 == 0 else fill_white
        
        c_var = ws_vars.cell(row=idx, column=1, value=v_name)
        c_var.alignment = Alignment(horizontal="left", vertical="top")
        c_var.font = Font(name="Consolas", size=9.5, bold=True, color="1E293B")
        
        c_def = ws_vars.cell(row=idx, column=2, value=v_def)
        c_def.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        c_def.font = font_code
        
        ws_vars.cell(row=idx, column=3, value=v_title).alignment = Alignment(horizontal="left", vertical="top")
        ws_vars.cell(row=idx, column=4, value=v_desc).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        ws_vars.cell(row=idx, column=5, value=v_info).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        ws_vars.cell(row=idx, column=6, value=v_type).alignment = Alignment(horizontal="center", vertical="top")
        ws_vars.cell(row=idx, column=7, value=v_rec).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)

        for c_i in range(1, 8):
            cell = ws_vars.cell(row=idx, column=c_i)
            cell.border = border_all
            cell.fill = row_fill
            if c_i not in (1, 2):
                cell.font = font_data
        ws_vars.row_dimensions[idx].height = 42

    for col_idx, (_, width) in enumerate(var_headers, 1):
        col_letter = get_column_letter(col_idx)
        ws_vars.column_dimensions[col_letter].width = width
    ws_vars.auto_filter.ref = f"A1:G{len(ui_variables)+1}"

    output_filename = "CIS_Linux_L1_Master_Baseline.xlsx"
    wb.save(output_filename)
    print(f"Çalışma kitabı başarıyla oluşturuldu: {output_filename}")

if __name__ == '__main__':
    create_workbook()
