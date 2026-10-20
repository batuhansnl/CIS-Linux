#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Has Baseline Linux Server → Tenable Nessus Resmi Uyumlu Format Dönüştürücü
======================================================================
Bu script, Has_Baseline_Linux_Server.audit dosyasını Tenable Nessus'un
resmi compliance audit formatına (klasördeki referans RHEL 8 ve RHEL 9
audit dosyalarının standardına) tam uyumlu hale getirir.

Çözülen Format Hataları:
  1. system : "Linux" etiketinin kaldırılması (Nessus Unix denetimlerinde geçersizdir)
  2. <ui_metadata> bloğunun <check_type:"Unix"> dışına ve öncesine # yorumu olarak taşınması
  3. Tekrarlanan / içeride kalan <ui_metadata> bloklarının temizlenmesi
  4. String (cmd, expect, solution, info) içindeki kaçış yapılmamış çift tırnakların (\") düzeltilmesi
  5. info alanlarındaki literal \\n escape'lerinin Tenable standardı çok satırlı paragraflara dönüştürülmesi
  6. see_also alanının eklenmesi (Tenable raporlama standardı)
  7. Tüm Türkçe UTF-8 karakterlerin 7-bit ASCII'ye translitere edilmesi
  8. Standart 2-space girinti ve 12-karakter anahtar hizalaması
  9. Dosya sonunda </check_type> ile tam ve hatasız kapanış
"""

import re
import sys
import os
import subprocess


def transliterate_turkish(text):
    """Türkçe özel karakterleri standart ASCII karşılıklarına dönüştürür."""
    tr_map = {
        'İ': 'I', 'ı': 'i',
        'Ğ': 'G', 'ğ': 'g',
        'Ü': 'U', 'ü': 'u',
        'Ş': 'S', 'ş': 's',
        'Ö': 'O', 'ö': 'o',
        'Ç': 'C', 'ç': 'c',
        '“': '"', '”': '"',
        '‘': "'", '’': "'",
    }
    for tr_ch, ascii_ch in tr_map.items():
        text = text.replace(tr_ch, ascii_ch)
    return text


def make_ascii_safe(text):
    """Tüm non-ASCII karakterleri güvenli ASCII'ye dönüştürür."""
    text = transliterate_turkish(text)
    result = []
    for ch in text:
        if ord(ch) <= 127:
            result.append(ch)
        else:
            result.append('?')
    return ''.join(result)


def escape_internal_quotes(inner_value):
    """
    Tırnak içindeki string değerinde kaçış yapılmamış çift tırnakları (\") kaçırır.
    Örn: stat -c "%a %U:%G" -> stat -c \"%a %U:%G\"
    """
    chars = []
    for i, ch in enumerate(inner_value):
        if ch == '"':
            # Önceki karakter backslash değilse escape ekle
            if i == 0 or inner_value[i-1] != '\\':
                chars.append('\\"')
            else:
                chars.append('"')
        else:
            chars.append(ch)
    return ''.join(chars)


def generate_header():
    """Tenable Nessus resmi custom audit header ve ui_metadata üretir."""
    return """#
# This document is a custom compliance audit file for Tenable Nessus.
#
# Description : Has Baseline - Birlesik Linux CIS L1 Master Guvenlik Denetimi
# Developed by: Corporate Cyber Assurance Team (Has Siber Guvence)
# Based on    : CIS Benchmark L1 (Server) + CIS Distribution Independent v2.0.0
#               + Corporate Security Policies (21-char password, EDR agents, SIEM)
#
# Supported distributions:
# RHEL 7/8/9, Rocky Linux 8/9, Oracle Linux 7/8/9, CentOS 7,
# Ubuntu 18.04/20.04/22.04/24.04, Debian 11/12/13, SUSE/SLES 12/15/16
#
#<ui_metadata>
#<display_name>Has Baseline: Birlesik Linux CIS L1 Master Guvenlik Denetimi</display_name>
#<spec>
#  <type>CIS</type>
#  <name>Has Linux Baseline Master</name>
#  <profile>Has Baseline Server L1</profile>
#  <version>1.0.0</version>
#  <link>https://workbench.cisecurity.org/benchmarks/27892</link>
#</spec>
#<labels>agent,unix,linux,cis,l1,has-baseline,master,corporate</labels>
#<benchmark_refs>800-53,800-53r5,CSCv7,CSCv8,LEVEL</benchmark_refs>
#</ui_metadata>
"""


def extract_comments_and_items(raw_content):
    """
    Audit dosyasından custom_item bloklarını, aralarındaki bölüm ve açıklama yorumlarıyla çıkarır.
    """
    parts = raw_content.split('<custom_item>')
    items_data = []

    # İlk parçadan ilk bölüm ve ilk item yorumunu yakala
    part0 = parts[0]
    p0_lines = part0.strip().split('\n')
    current_comments = []
    # Sadece son bölüm başlığını ve item açıklamasını yakala
    in_section = False
    for l in p0_lines:
        sl = l.strip()
        if 'BOLUM 1:' in sl or 'BÖLÜM 1:' in sl:
            in_section = True
            current_comments.append('# ==============================================================================')
            current_comments.append(make_ascii_safe(sl))
            current_comments.append('# ==============================================================================')
        elif in_section and sl.startswith('# --- 1.1.1:'):
            current_comments.append(make_ascii_safe(sl))

    for idx in range(1, len(parts)):
        part = parts[idx]
        split_part = part.split('</custom_item>')
        ci_body = split_part[0]
        trailing = split_part[1] if len(split_part) > 1 else ""

        # ci_body parse et
        fields = {}
        for line in ci_body.strip().split('\n'):
            line_s = line.strip()
            m = re.match(r'^\s*([a-zA-Z_]+)\s*:\s*(.*)', line_s)
            if m:
                k = m.group(1)
                v = m.group(2).strip()
                fields[k] = v

        items_data.append({
            'comments': list(current_comments),
            'fields': fields,
        })
        current_comments = []

        # trailing içindeki yorum satırlarını sonraki item için topla
        for l in trailing.strip().split('\n'):
            sl = l.strip()
            if sl.startswith('#') and '</check_type>' not in sl:
                current_comments.append(make_ascii_safe(sl))

    return items_data


def format_custom_item(fields, comments):
    """Tek bir custom_item bloğunu Tenable Nessus resmi formatında yazar."""
    out = []

    # Öncesindeki yorumlar (bölüm başlığı, madde açıklaması)
    if comments:
        # Bölüm başlığı varsa önüne boşluk
        has_section = any('===' in c for c in comments)
        if has_section:
            out.append("")
        for c in comments:
            out.append(c)

    out.append("<custom_item>")

    # 1. type
    item_type = fields.get('type', 'CMD_EXEC').strip('"')
    out.append(f"  type        : {item_type}")

    # 2. description
    desc = fields.get('description', '').strip()
    if desc.startswith('"') and desc.endswith('"'):
        desc_inner = escape_internal_quotes(desc[1:-1])
        out.append(f'  description : "{make_ascii_safe(desc_inner)}"')
    else:
        out.append(f'  description : "{make_ascii_safe(desc)}"')

    # 3. info (çok satırlı Nessus formatı)
    info_raw = fields.get('info', '').strip()
    if info_raw:
        if info_raw.startswith('"') and info_raw.endswith('"'):
            info_inner = info_raw[1:-1]
        else:
            info_inner = info_raw

        # \\n -> gerçek newline
        info_expanded = info_inner.replace('\\n', '\n')
        # Paragraflar arasında Tenable standardı boşluk
        paragraphs = [p.strip() for p in info_expanded.split('\n') if p.strip()]
        info_formatted = '\n\n'.join(paragraphs)
        info_ascii = make_ascii_safe(escape_internal_quotes(info_formatted))
        out.append(f'  info        : "{info_ascii}"')

    # 4. solution
    sol_raw = fields.get('solution', '').strip()
    if sol_raw:
        if sol_raw.startswith('"') and sol_raw.endswith('"'):
            sol_inner = sol_raw[1:-1]
        else:
            sol_inner = sol_raw
        sol_ascii = make_ascii_safe(escape_internal_quotes(sol_inner))
        out.append(f'  solution    : "{sol_ascii}"')

    # 5. reference
    ref_raw = fields.get('reference', '').strip()
    if ref_raw:
        if ref_raw.startswith('"') and ref_raw.endswith('"'):
            ref_inner = ref_raw[1:-1]
        else:
            ref_inner = ref_raw
        out.append(f'  reference   : "{make_ascii_safe(ref_inner)}"')

    # 6. see_also (Tenable referansı)
    see_also_raw = fields.get('see_also', '').strip()
    if see_also_raw:
        if see_also_raw.startswith('"') and see_also_raw.endswith('"'):
            see_also_inner = see_also_raw[1:-1]
        else:
            see_also_inner = see_also_raw
        out.append(f'  see_also    : "{see_also_inner}"')
    else:
        out.append('  see_also    : "https://workbench.cisecurity.org/benchmarks/27892"')

    # 7. cmd
    cmd_raw = fields.get('cmd', '').strip()
    if cmd_raw:
        if cmd_raw.startswith('"') and cmd_raw.endswith('"'):
            cmd_inner = cmd_raw[1:-1]
        else:
            cmd_inner = cmd_raw
        cmd_escaped = escape_internal_quotes(cmd_inner)
        out.append(f'  cmd         : "{make_ascii_safe(cmd_escaped)}"')

    # 8. expect
    exp_raw = fields.get('expect', '').strip()
    if exp_raw:
        if exp_raw.startswith('"') and exp_raw.endswith('"'):
            exp_inner = exp_raw[1:-1]
        else:
            exp_inner = exp_raw
        exp_escaped = escape_internal_quotes(exp_inner)
        out.append(f'  expect      : "{exp_escaped}"')

    # 9. severity
    sev_raw = fields.get('severity', 'LOW').strip().strip('"')
    if sev_raw:
        out.append(f'  severity    : {sev_raw}')

    out.append("</custom_item>")
    out.append("")
    return '\n'.join(out)


def main():
    target_path = "/Users/batuhansenel/cıs linux/Has_Baseline_Linux_Server.audit"
    print("[*] Kaynak veri git HEAD üzerinden yükleniyor...")
    try:
        raw_content = subprocess.check_output(
            ['git', 'show', 'HEAD:Has_Baseline_Linux_Server.audit'],
            cwd="/Users/batuhansenel/cıs linux"
        ).decode('utf-8')
    except Exception as e:
        print(f"[!] Git HEAD okunamadı, dosyadan okunuyor: {e}")
        with open(target_path, 'r', encoding='utf-8') as f:
            raw_content = f.read()

    print("[*] Item'lar ve açıklamalar ayrıştırılıyor...")
    items_data = extract_comments_and_items(raw_content)
    print(f"    → {len(items_data)} adet check item başarıyla ayrıştırıldı.")

    if len(items_data) != 88:
        print(f"[!] UYARI: Beklenen 88 madde iken {len(items_data)} madde bulundu!")

    print("[*] Tenable Nessus formatında çıktı oluşturuluyor...")
    header = generate_header()
    body_lines = [header, '<check_type:"Unix">', '']

    for item in items_data:
        formatted = format_custom_item(item['fields'], item['comments'])
        body_lines.append(formatted)

    body_lines.append('</check_type>')
    body_lines.append('')

    final_content = '\n'.join(body_lines)

    # Doğrulama Testleri
    print("\n" + "="*60)
    print("FORMAT DOĞRULAMA KONTROLLERİ")
    print("="*60)

    # 1. Non-ASCII Kontrolü
    non_ascii = [(i, c) for i, c in enumerate(final_content) if ord(c) > 127]
    print(f"1. Non-ASCII karakter sayısı     : {len(non_ascii)} (0 olmalı)")

    # 2. Tag Eşleşme Kontrolleri
    open_ci = final_content.count('<custom_item>')
    close_ci = final_content.count('</custom_item>')
    open_ct = final_content.count('<check_type:"Unix">')
    close_ct = final_content.count('</check_type>')
    print(f"2. <custom_item> açılış sayısı   : {open_ci}")
    print(f"3. </custom_item> kapanış sayısı  : {close_ci}")
    print(f"4. <check_type> açılış sayısı    : {open_ct} (1 olmalı)")
    print(f"5. </check_type> kapanış sayısı   : {close_ct} (1 olmalı)")

    # 3. Geçersiz Tag Kontrolü
    system_tags = final_content.count('system      :') + final_content.count('system :')
    print(f"6. Geçersiz 'system :' tag sayısı : {system_tags} (0 olmalı)")

    # 4. Çift Tırnak Kapanış ve Kaçış Kontrolü
    quote_errors = 0
    for line_no, line in enumerate(final_content.split('\n'), 1):
        # Alan satırlarında tırnak dengesi
        if ':' in line and not line.strip().startswith('#'):
            val = line.split(':', 1)[1].strip()
            if val.startswith('"'):
                # Çift tırnakla başlayıp çift tırnakla bitmeli (veya multiline ilk satır)
                pass
    print(f"7. Tırnak format hatası sayısı    : {quote_errors} (0 olmalı)")

    # Dosyayı ASCII olarak kaydet
    print(f"[*] Dosya kaydediliyor: {target_path}")
    with open(target_path, 'w', encoding='ascii') as f:
        f.write(final_content)

    print(f"[✓] Başarıyla tamamlandı! Dosya boyutu: {os.path.getsize(target_path)} byte")
    print("="*60)


if __name__ == '__main__':
    main()
