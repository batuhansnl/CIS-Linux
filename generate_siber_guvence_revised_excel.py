# -*- coding: utf-8 -*-
"""
Siber Güvence Configuration Baseline Checklist (LinuxServer) - Revize ve Genişletilmiş Sürüm
Bu betik, Siber Güvence ekibinin 12 maddelik başlangıç listesini alıp kurumsal tüm Linux sunucular
için geçerli, eksik kritik güvenlik katmanlarını ve somut ayar değerlerini içeren 25 maddelik
resmi bir Excel çalışma kitabı haline getirir.
"""

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Renkler
COLOR_NAVY_DARK = "1B365D"
COLOR_NAVY_MEDIUM = "2C4A6F"
COLOR_NAVY_LIGHT = "E8EEF5"
COLOR_WHITE = "FFFFFF"
COLOR_ZEBRA = "F8FAFC"
COLOR_BORDER = "CBD5E1"

# Severity / Status
COLOR_CRITICAL_BG = "FEE2E2"
COLOR_CRITICAL_FG = "991B1B"
COLOR_AMBER_BG = "FEF3C7"
COLOR_AMBER_FG = "92400E"
COLOR_GREEN_BG = "DCFCE7"
COLOR_GREEN_FG = "166534"
COLOR_BLUE_BG = "E0F2FE"
COLOR_BLUE_FG = "0369A1"
COLOR_INDIGO_BG = "E0E7FF"
COLOR_INDIGO_FG = "3730A3"

FONT_NAME = "Segoe UI"
font_title = Font(name=FONT_NAME, size=14, bold=True, color=COLOR_WHITE)
font_subtitle = Font(name=FONT_NAME, size=9.5, italic=True, color="475569")
font_tbl_header = Font(name=FONT_NAME, size=10, bold=True, color=COLOR_WHITE)
font_sec_header = Font(name=FONT_NAME, size=11, bold=True, color=COLOR_WHITE)
font_data = Font(name=FONT_NAME, size=9.5, color="1E293B")
font_data_bold = Font(name=FONT_NAME, size=9.5, bold=True, color="1E293B")
font_code = Font(name="Consolas", size=9, color="0F172A")
font_total = Font(name=FONT_NAME, size=10, bold=True, color="0F172A")

fill_navy_dark = PatternFill(start_color=COLOR_NAVY_DARK, end_color=COLOR_NAVY_DARK, fill_type="solid")
fill_navy_medium = PatternFill(start_color=COLOR_NAVY_MEDIUM, end_color=COLOR_NAVY_MEDIUM, fill_type="solid")
fill_navy_light = PatternFill(start_color=COLOR_NAVY_LIGHT, end_color=COLOR_NAVY_LIGHT, fill_type="solid")
fill_zebra = PatternFill(start_color=COLOR_ZEBRA, end_color=COLOR_ZEBRA, fill_type="solid")
fill_white = PatternFill(start_color=COLOR_WHITE, end_color=COLOR_WHITE, fill_type="solid")
fill_total = PatternFill(start_color="E2E8F0", end_color="E2E8F0", fill_type="solid")

thin_side = Side(style='thin', color=COLOR_BORDER)
border_all = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)
border_header = Border(left=Side(style='thin', color="475569"), right=Side(style='thin', color="475569"),
                       top=Side(style='thin', color="475569"), bottom=Side(style='medium', color="0F172A"))

def style_merged_range(ws, cell_range, font=None, fill=None, border=None, alignment=None):
    for row in ws[cell_range]:
        for cell in row:
            if font: cell.font = font
            if fill: cell.fill = fill
            if border: cell.border = border
            if alignment: cell.alignment = alignment

def style_priority_cell(cell, priority_text):
    p = str(priority_text).upper()
    if 'MUST' in p:
        cell.fill = PatternFill(start_color=COLOR_CRITICAL_BG, end_color=COLOR_CRITICAL_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_CRITICAL_FG)
    else:
        cell.fill = PatternFill(start_color=COLOR_INDIGO_BG, end_color=COLOR_INDIGO_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_INDIGO_FG)
    cell.alignment = Alignment(horizontal='center', vertical='top')

def style_note_cell(cell, note_text):
    nt = str(note_text).upper()
    if 'YENİ EKLENDİ' in nt:
        cell.fill = PatternFill(start_color=COLOR_GREEN_BG, end_color=COLOR_GREEN_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_GREEN_FG)
    elif 'DÜZELTİLDİ' in nt:
        cell.fill = PatternFill(start_color=COLOR_AMBER_BG, end_color=COLOR_AMBER_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_AMBER_FG)
    elif 'GÜÇLENDİRİLDİ' in nt:
        cell.fill = PatternFill(start_color=COLOR_BLUE_BG, end_color=COLOR_BLUE_BG, fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9.5, bold=True, color=COLOR_BLUE_FG)
    else:
        cell.fill = PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid")
        cell.font = Font(name=FONT_NAME, size=9, bold=False, color="475569")
    cell.alignment = Alignment(horizontal='center', vertical='top', wrap_text=True)

def create_revised_baseline():
    wb = openpyxl.Workbook()
    wb.remove(wb.active)

    # --------------------------------------------------------------------------
    # 1. SEKME: 📋 Configuration Baseline Checklist (LinuxServer)
    # --------------------------------------------------------------------------
    ws_main = wb.create_sheet(title="📋 Baseline Checklist (Revize)")
    ws_main.sheet_properties.tabColor = COLOR_NAVY_DARK
    ws_main.views.sheetView[0].showGridLines = True
    ws_main.freeze_panes = "A2"

    headers = [
        ("No", 6),
        ("Bölüm (Section)", 22),
        ("Gereksinim (Requirement)", 38),
        ("Yapılması Gereken Ayar & Parametre Değeri (Exact Configuration)", 45),
        ("İlgili Dosya / Servis / Komut (Target Component)", 32),
        ("Statü (Priority)", 16),
        ("Güvenlik Gerekçesi & Engellenen Tehdit (Security Rationale)", 48),
        ("Değişiklik Durumu (Revision Note)", 26)
    ]

    for col_idx, (h_text, width) in enumerate(headers, 1):
        c = ws_main.cell(row=1, column=col_idx, value=h_text)
        c.font = font_tbl_header
        c.fill = fill_navy_dark
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = border_header
        col_letter = get_column_letter(col_idx)
        ws_main.column_dimensions[col_letter].width = width
    ws_main.row_dimensions[1].height = 30

    checklist_items = [
        # --- MEVCUT 12 MADDENİN GÜÇLENDİRİLMİŞ HALLERİ ---
        (
            1, "Installation",
            "Ensure the virtual machine is connected to the appropriate vLAN.",
            "Sunucu ağ arayüzü, şirket ağ topolojisindeki DMZ, Yönetim veya Uygulama vLAN kurallarına uygun subnet IP'sine atanmalıdır.",
            "Hipervizör (vCenter/ESXi) & Ağ Arayüzü",
            "Must",
            "Farklı güvenlik seviyelerindeki sunucuların mantıksal olarak izole edilmesi ve yetkisiz ağ erişimlerinin engellenmesi.",
            "Mevcut Madde (Onaylandı)"
        ),
        (
            2, "Access & Authentication",
            "Have a strong password for root account and enforce password complexity.",
            "minlen=14, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1, SHA512 algoritması. Root parolası asla e-posta/sohbet üzerinden paylaşılmamalıdır.",
            "/etc/security/pwquality.conf & /etc/login.defs",
            "Must",
            "Kaba kuvvet (brute-force) ve sözlük saldırılarıyla en yetkili işletim sistemi hesabının ele geçirilmesini engeller.",
            "Mevcut Madde (Güçlendirildi: Değerler Eklendi)"
        ),
        (
            3, "Installation",
            "The name of server must meet relevant naming rules and prevent OS information disclosure.",
            "Sunucu adı kurumsal hostname formatına uygun olmalı. /etc/issue, /etc/issue.net ve /etc/motd dosyalarından OS sürüm bilgileri silinmeli, yasal uyarı banner'ı eklenmelidir.",
            "/etc/hostname, /etc/issue, /etc/motd",
            "Must",
            "Saldırganların sunucuya bağlanır bağlanmaz işletim sistemi ve çekirdek sürümünü öğrenerek hedefe yönelik exploit aramasını engeller.",
            "Mevcut Madde (Güçlendirildi: Banner/Sürüm Gizleme)"
        ),
        (
            4, "Installation & Storage",
            "Server should be partitioned correctly; temporary directories must have restrictive mount options.",
            "Uygulamalar ve loglar (/var/log) OS diskinden ayrı olmalı. /tmp, /var/tmp ve /dev/shm bölümleri 'nodev, nosuid, noexec' bayraklarıyla mount edilmelidir.",
            "/etc/fstab",
            "Must",
            "Saldırganların /tmp veya bellek alanlarına zararlı script/binary yükleyip doğrudan çalıştırmasını (arbitrary code execution) engeller.",
            "Mevcut Madde (Güçlendirildi: nodev,nosuid,noexec Eklendi)"
        ),
        (
            5, "Network & Security",
            "Host-based firewall has to be enabled and enforcing default deny incoming at all times.",
            "RHEL/Oracle/Rocky/SUSE: 'systemctl enable --now firewalld', Ubuntu/Debian: 'ufw enable'. Varsayılan gelen (incoming) tüm trafik DROP/REJECT olmalı, sadece izinli servis portları açılmalıdır.",
            "firewalld / ufw / nftables",
            "Must",
            "DÜZELTME: Siber Güvence bunu 'Recommended' yapmıştı. Sunucularda yerel güvenlik duvarı ASLA opsiyonel olamaz. Yanal hareket (Lateral Movement) saldırılarını durduran ana kalkandır.",
            "DÜZELTİLDİ (Recommended -> MUST Yapıldı!)"
        ),
        (
            6, "Corporate Agents",
            "The machines are secured with the Trend Micro Deep Security / Apex One agent.",
            "'ds_agent' servisi aktif ve çalışır durumda olmalıdır (systemctl is-active ds_agent). Güncel imza/pattern'lar otomatik güncellenmelidir.",
            "ds_agent servisi (Trend Micro)",
            "Must",
            "Zararlı yazılım, fidye yazılımı (ransomware) ve yetkisiz işlem girişimlerinin merkezi SOC tarafından anında tespiti ve engellenmesi.",
            "Mevcut Madde (Servis Doğrulaması Eklendi)"
        ),
        (
            7, "Corporate Agents & Patching",
            "All the packages must be up to date. Keep updated via ManageEngine and official repositories.",
            "'uemsagent' (ManageEngine) servisi aktif olmalı. RHEL sunucularda 'subscription-manager status' Current olmalı; paket güncellemeleri düzenli uygulanmalıdır.",
            "ManageEngine (uemsagent) & subscription-manager",
            "Must",
            "Bilinen CVE güvenlik zafiyetlerinin hızlıca kapatılması ve sunucunun resmi depolardan dijital imzalı güvenli paket alması.",
            "Mevcut Madde (Servis Doğrulaması Eklendi)"
        ),
        (
            8, "Access & Authentication",
            "Permissions must be assigned strictly via visudo/sudoers with logging enabled, not uncontrolled group membership.",
            "/etc/sudoers dosyasına 'Defaults logfile=\"/var/log/sudo.log\"' ve 'Defaults requiretty' eklenmeli. Kullanıcılara sınırsız 'ALL' yerine kısıtlı komut yetkisi tanımlanmalıdır.",
            "/etc/sudoers, /etc/sudoers.d/*",
            "Must",
            "Kullanıcıların kontrolsüz root yetkisi almasını önler; çalıştırılan her süper kullanıcı komutunu denetim kaydı altına alır.",
            "Mevcut Madde (Güçlendirildi: Loglama & TTY Eklendi)"
        ),
        (
            9, "Access & Authentication",
            "Use Active Directory user accounts via SSSD/Realmd for administrative and interactive access.",
            "'sssd' servisi aktif olmalı (systemctl is-active sssd). Sunucu Active Directory alan adına dahil edilmeli (realm join), erişimler merkezi kurumsal AD gruplarıyla sınırlandırılmalıdır.",
            "sssd servisi & /etc/sssd/sssd.conf",
            "Must",
            "Personel işten ayrıldığında tek noktadan erişim kapatma, parola politikasını merkezileştirme ve merkezi SIEM izlenebilirliği sağlar.",
            "Mevcut Madde (Must yapıldı, SSSD Kriteri Eklendi)"
        ),
        (
            10, "Access & Authentication",
            "Interactive login must be disabled for local system and service accounts.",
            "UID < 1000 olan tüm sistem/hizmet hesaplarının (daemon, bin, sys, adm, sync vb.) kabukları (shell) '/sbin/nologin' veya '/bin/false' olarak ayarlanmalıdır.",
            "/etc/passwd",
            "Must",
            "Saldırganların servis hesaplarını kullanarak sunucu üzerinde interaktif oturum açmasını veya komut çalıştırmasını engeller.",
            "Mevcut Madde (Must yapıldı, Shell Kriteri Eklendi)"
        ),
        (
            11, "Logging & Auditing",
            "Enable Rsyslog to collect and forward all system logs to the central SIEM / Log server.",
            "'rsyslog' servisi aktif ve çalışır olmalı. /etc/rsyslog.conf içinde merkezi log sunucusu IP/FQDN hedefi '*.* @log-server.kurum.local:514' tanımlı olmalıdır.",
            "rsyslog servisi & /etc/rsyslog.conf",
            "Must",
            "Sunucu ele geçirilse dahi saldırganın yerel logları silerek izini kaybettirmesini önler; 5651 ve KVKK yasal uyumluluğunu sağlar.",
            "Mevcut Madde (Log İletim Hedefi Eklendi)"
        ),
        (
            12, "Corporate Agents & Monitoring",
            "All machines are monitored with the SolarWinds agent.",
            "'swiagent' servisi aktif ve çalışır durumda olmalıdır (systemctl is-active swiagent).",
            "swiagent servisi (SolarWinds Orion)",
            "Must",
            "Kaynak tüketimi (CPU, RAM, Disk doluluğu), kesinti ve yetkisiz servis durdurmalarının anlık olarak SOC/NOC tarafından izlenmesi.",
            "Mevcut Madde (Servis Doğrulaması Eklendi)"
        ),

        # --- ŞİRKETTEKİ TÜM LİNUX'LAR İÇİN EKLENEN YENİ KRİTİK AYARLAR ---
        (
            13, "SSH & Remote Access",
            "Direct SSH login for the root account must be strictly prohibited.",
            "PermitRootLogin no (Root kullanıcısı doğrudan ağdan SSH ile bağlanamamalı, önce yetkili AD/yerel kullanıcı girmeli, gerekiyorsa sudo kullanılmalıdır).",
            "/etc/ssh/sshd_config",
            "Must",
            "YENİ KRİTİK: Kaba kuvvet (brute-force) saldırılarının %99'u doğrudan 'root' hesabını hedefler. Root'un SSH'a kapatılması en hayati savunma adımıdır.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 5.2.10)"
        ),
        (
            14, "SSH & Remote Access",
            "SSH authentication attempts and empty passwords must be restricted.",
            "PermitEmptyPasswords no, MaxAuthTries 4, LoginGraceTime 60, X11Forwarding no",
            "/etc/ssh/sshd_config",
            "Must",
            "YENİ KRİTİK: Boş parolalı hesapların girişini engeller; başarısız denemeyi 4 ile sınırlayarak parola tahmin saldırılarını durdurur; askıda bağlantıyı 60 sn'de koparır.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 5.2.5)"
        ),
        (
            15, "SSH & Remote Access",
            "Inactive terminal and SSH sessions must automatically terminate after 15 minutes.",
            "SSH: ClientAliveInterval 300 & ClientAliveCountMax 3. Shell: /etc/profile.d/timeout.sh içine 'export TMOUT=900' ve 'readonly TMOUT'.",
            "/etc/ssh/sshd_config & /etc/profile.d/timeout.sh",
            "Must",
            "YENİ KRİTİK: Yöneticinin bilgisayar başından ayrıldığı durumlarda açık unutulan konsol veya SSH oturumlarının ele geçirilmesini (Session Hijacking) engeller.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 5.2.19)"
        ),
        (
            16, "Network & Kernel (Sysctl)",
            "IP forwarding must be disabled and IP spoofing protections must be enabled.",
            "net.ipv4.ip_forward = 0, net.ipv4.conf.all.rp_filter = 1, net.ipv4.conf.default.rp_filter = 1, net.ipv4.conf.all.accept_redirects = 0",
            "/etc/sysctl.d/99-security.conf",
            "Must",
            "YENİ KRİTİK: Sunucunun saldırgan tarafından yetkisiz bir router/gateway gibi kullanılarak kurumsal trafiği gizlice iletmesini ve sahte (spoofed) IP paketlerini engeller.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 3.1.1, 3.2.1)"
        ),
        (
            17, "Network & Kernel (Sysctl)",
            "TCP SYN cookies must be enabled to mitigate Denial of Service (DoS) attacks.",
            "net.ipv4.tcp_syncookies = 1",
            "/etc/sysctl.d/99-security.conf",
            "Must",
            "YENİ KRİTİK: Sunucu bellek tablosunu sahte bağlantı istekleriyle doldurarak hizmeti durdurmayı hedefleyen SYN Flood DoS saldırılarına karşı çekirdek koruması sağlar.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 3.2.8)"
        ),
        (
            18, "File System & Integrity",
            "Critical authentication and identity files must have strict ownership and restrictive permissions.",
            "/etc/shadow: chmod 0000 (veya 0640), chown root:root (veya root:shadow). /etc/passwd: chmod 0644, chown root:root. /etc/gshadow: chmod 0000. /etc/group: chmod 0644.",
            "/etc/shadow, /etc/passwd, /etc/gshadow, /etc/group",
            "Must",
            "YENİ KRİTİK: Parola özetlerinin (hash) yetkisiz kullanıcılar tarafından okunup offline kırılmasını veya değiştirilerek root yetkisi kazanılmasını (privilege escalation) engeller.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 6.1.2 - 6.1.9)"
        ),
        (
            19, "Logging & Auditing",
            "Kernel audit daemon (auditd) must be active and record critical security events.",
            "'auditd' servisi aktif olmalı. /etc/shadow değişiklikleri, sistem saati değişiklikleri (adjtimex/settimeofday), kullanıcı ekleme-silme ve yetki yükseltme çağrıları denetlenmelidir.",
            "auditd servisi & /etc/audit/rules.d/audit.rules",
            "Must",
            "YENİ KRİTİK: Rsyslog sadece çalışan servis logunu tutar; root kullanıcısının sildiği bir dosyayı, saatle oynamasını veya yetkisiz sistem çağrısını ancak 'auditd' yakalar.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 4.1.1 - 4.1.17)"
        ),
        (
            20, "Access & Authentication",
            "Accounts must be locked after consecutive failed authentication attempts.",
            "pam_faillock (veya pam_tally2): deny=5, unlock_time=900, even_deny_root. 5 hatalı parola denemesinden sonra hesap 15 dakika kilitlenmelidir.",
            "/etc/pam.d/password-auth & /etc/pam.d/system-auth",
            "Must",
            "YENİ KRİTİK: Sunucu üzerindeki yerel ve servis hesaplarına yönelik otomatik sözlük ve kaba kuvvet parola denemelerini hesabı geçici kilitleyerek engeller.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 5.4.2)"
        ),
        (
            21, "Services & Daemons",
            "Unencrypted legacy services and unnecessary listening daemons must be removed.",
            "telnet, rsh, rlogin, ypserv (nis), tftp, cups (yazıcı), avahi-daemon (mDNS) servisleri kaldırılmalı veya maskelenmelidir (systemctl mask).",
            "systemd servisleri & paket yöneticisi",
            "Must",
            "YENİ KRİTİK: Şifresiz açık metin haberleşen protokolleri ve sunucuda gereksiz port açarak saldırı yüzeyi yaratan miras servisleri tamamen yok eder.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 2.1.1 - 2.2.17)"
        ),
        (
            22, "System Hardening & MAC",
            "Mandatory Access Control (MAC) must be active and enforcing at boot.",
            "Red Hat / Oracle / Rocky: /etc/selinux/config içinde 'SELINUX=enforcing'. Debian / Ubuntu / SUSE: 'apparmor.service' aktif ve enforce modda olmalıdır.",
            "/etc/selinux/config & apparmor.service",
            "Must",
            "YENİ KRİTİK: Sıfırıncı gün (0-day) açıklarında bir web sunucusu veya servis hacklense bile saldırganın işletim sisteminin geri kalanına ve diskine erişmesini engeller.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 1.6.1)"
        ),
        (
            23, "System Hardening & Scheduling",
            "Cron daemon configuration and directories must be restricted to root only.",
            "/etc/crontab ve /etc/cron.* dizinleri: chmod 0700 (veya 0600), chown root:root. /etc/cron.allow mevcut olmalı, cron.deny kaldırılmalıdır.",
            "/etc/crontab & /etc/cron.*",
            "Must",
            "YENİ KRİTİK: Linux sistemlerde saldırganların arka kapı (persistence) bırakmak ve root olmak için en çok istismar ettiği zamanlanmış görev manipülasyonunu engeller.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 5.1.1 - 5.1.8)"
        ),
        (
            24, "System Hardening & Memory",
            "Address Space Layout Randomization (ASLR) enabled and core dumps disabled.",
            "kernel.randomize_va_space = 2, fs.suid_dumpable = 0. /etc/security/limits.conf içine '* hard core 0' eklenmelidir.",
            "/etc/sysctl.d/99-security.conf & /etc/security/limits.conf",
            "Must",
            "YENİ KRİTİK: Bellek taşması (Buffer Overflow) exploitlerini zorlaştırır; çöken servislerin bellek dökümlerinden (core dump) şifre ve sertifika anahtarı sızmasını engeller.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 1.5.1, 1.5.3)"
        ),
        (
            25, "Access & Authentication",
            "Root must be the only account in the system with UID 0.",
            "awk -F: '($3 == 0) { print $1 }' /etc/passwd komutu yalnızca tek bir satır olarak 'root' çıktısını vermelidir.",
            "/etc/passwd",
            "Must",
            "YENİ KRİTİK: Saldırganların yetki yükselttikten sonra sisteme kalıcılık sağlamak için eklediği gizli ikinci root yetkili (UID 0 backdoor) hesapları tespit eder ve engeller.",
            "YENİ EKLENDİ (Kritik Savunma - CIS 5.4.3)"
        )
    ]

    for idx, item in enumerate(checklist_items, 2):
        row_fill = fill_zebra if idx % 2 == 0 else fill_white
        
        ws_main.cell(row=idx, column=1, value=item[0]).alignment = Alignment(horizontal="center", vertical="top")
        ws_main.cell(row=idx, column=2, value=item[1]).alignment = Alignment(horizontal="left", vertical="top")
        ws_main.cell(row=idx, column=3, value=item[2]).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        
        c_val = ws_main.cell(row=idx, column=4, value=item[3])
        c_val.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        c_val.font = font_code if ("=" in item[3] or "chmod" in item[3] or "systemctl" in item[3]) else font_data_bold
        
        c_comp = ws_main.cell(row=idx, column=5, value=item[4])
        c_comp.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        c_comp.font = font_data
        
        c_stat = ws_main.cell(row=idx, column=6, value=item[5])
        style_priority_cell(c_stat, item[5])
        
        c_rat = ws_main.cell(row=idx, column=7, value=item[6])
        c_rat.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        c_rat.font = font_data
        
        c_note = ws_main.cell(row=idx, column=8, value=item[7])
        style_note_cell(c_note, item[7])

        for col_i in range(1, 9):
            cell = ws_main.cell(row=idx, column=col_i)
            cell.border = border_all
            if col_i not in (6, 8):
                cell.fill = row_fill
                if col_i not in (4,):
                    cell.font = font_data
        ws_main.row_dimensions[idx].height = 46

    ws_main.auto_filter.ref = f"A1:H{len(checklist_items)+1}"

    # --------------------------------------------------------------------------
    # 2. SEKME: 🔍 Yönetici Bilgi Notu & Gerekçe Özeti
    # --------------------------------------------------------------------------
    ws_memo = wb.create_sheet(title="🔍 Yönetici Bilgi Notu & Analiz")
    ws_memo.sheet_properties.tabColor = "059669"
    ws_memo.views.sheetView[0].showGridLines = True

    ws_memo.merge_cells("B2:G2")
    m_title = ws_memo["B2"]
    m_title.value = "SİBER GÜVENCE CHECKLIST REVİZYONU - YÖNETİCİ BİLGİ NOTU"
    style_merged_range(ws_memo, "B2:G2", font=font_title, fill=fill_navy_dark, border=border_header, alignment=Alignment(horizontal="center", vertical="center"))
    ws_memo.row_dimensions[2].height = 36

    ws_memo.merge_cells("B3:G3")
    m_sub = ws_memo["B3"]
    m_sub.value = "Konu: Kurumsal Linux Baseline Değerlendirmesi ve Kritik Güvenlik Eklentileri | Tarih: Eylül 2026"
    style_merged_range(ws_memo, "B3:G3", font=font_subtitle, fill=fill_navy_light, border=border_all, alignment=Alignment(horizontal="center", vertical="center"))
    ws_memo.row_dimensions[3].height = 22

    memo_paragraphs = [
        ("1. Neden Bu Revizyon Yapıldı?",
         "Siber Güvence ekibi tarafından paylaşılan 12 maddelik liste, temel devreye alma (commissioning) ve kurumsal ajan gereksinimlerini çok iyi karşılamaktadır. Ancak bir Linux işletim sisteminin çekirdek (Kernel), SSH, ağ ve yetki güvenliğini sağlayan en kritik savunma mekanizmaları bu listede bulunmamaktaydı. Bu revizyonla hem mevcut 12 madde net parametrelerle güçlendirilmiş hem de 13 adet evrensel kritik güvenlik kuralı eklenerek toplam 25 maddelik eksiksiz bir kurumsal standart oluşturulmuştur."),
        
        ("2. En Kritik Düzeltme: Güvenlik Duvarı (Firewall) Statüsü",
         "Mevcut listenin 5. maddesinde yerel güvenlik duvarı 'Recommended (Tavsiye)' olarak tanımlanmıştır. Siber güvenlik standartlarında (CIS, NIST SP 800-53, PCI-DSS) sunucu içi güvenlik duvarı ASLA opsiyonel olamaz. Ağdaki bir saldırganın diğer sunuculara sıçramasını (Lateral Movement) engelleyen ana mekanizma host-based firewall'dur. Bu nedenle statüsü kesinlikle 'MUST' yapılmalıdır."),
        
        ("3. Eklenen 13 Kritik Savunma Katmanı ve Amacı",
         "Eklenen maddeler kurumsal filodaki TÜM Linux dağıtımlarında (RHEL, Ubuntu, SUSE, Debian, Rocky, Oracle, CentOS) istisnasız uygulanabilen standartlardır:\n"
         "• SSH Root Kapatma & Brute-Force Engeli (Madde 13, 14, 15): Dış/iç saldırıların ilk hedefi olan root SSH girişini ve açık kalan sahipsiz oturumları engeller.\n"
         "• Çekirdek Ağ Güvenliği (Madde 16, 17): Sunucunun yetkisiz yönlendirici (router) gibi davranmasını, IP spoofing ve SYN Flood DoS saldırılarını çekirdek seviyesinde durdurur.\n"
         "• Dosya İzinleri ve Çekirdek Denetimi (Madde 18, 19): /etc/shadow dosyası izinlerini kilitler; rsyslog'un yakalayamadığı dosya silme ve saat müdahalelerini 'auditd' ile yakalar.\n"
         "• Zorunlu Erişim Denetimi & Bellek Koruması (Madde 22, 24): SELinux/AppArmor ve ASLR ile sıfırıncı gün (0-day) açıklarında sistemin tamamen ele geçirilmesini önler.\n"
         "• Miras Servisler ve Arka Kapı Engeli (Madde 21, 23, 25): Telnet gibi güvensiz servisleri, izinsiz cron manipülasyonunu ve gizli UID 0 backdoor hesaplarını temizler."),
         
        ("4. Sonuç ve Öneri",
         "Bu 25 maddelik revize checklist, şirketimizdeki tüm Linux sunucularda operasyonel kesinti yaratmadan uygulanabilecek en rasyonel, yüksek etkili ve uluslararası CIS Level 1 uyumlu güvenlik zeminini oluşturmaktadır.")
    ]

    m_row = 5
    for title, text in memo_paragraphs:
        ws_memo.merge_cells(f"B{m_row}:G{m_row}")
        c_t = ws_memo[f"B{m_row}"]
        c_t.value = title
        style_merged_range(ws_memo, f"B{m_row}:G{m_row}", font=font_sec_header, fill=fill_navy_medium, border=border_header, alignment=Alignment(horizontal="left", vertical="center", indent=1))
        ws_memo.row_dimensions[m_row].height = 24
        m_row += 1

        ws_memo.merge_cells(f"B{m_row}:G{m_row}")
        c_b = ws_memo[f"B{m_row}"]
        c_b.value = text
        style_merged_range(ws_memo, f"B{m_row}:G{m_row}", font=font_data, fill=fill_white, border=border_all, alignment=Alignment(horizontal="left", vertical="top", wrap_text=True))
        # Yüksekliği satır sayısına göre hesapla
        line_count = len(text.split('\n')) + (len(text) // 95)
        ws_memo.row_dimensions[m_row].height = max(line_count * 18, 45)
        m_row += 2

    ws_memo.column_dimensions['A'].width = 4
    ws_memo.column_dimensions['B'].width = 20
    ws_memo.column_dimensions['C'].width = 20
    ws_memo.column_dimensions['D'].width = 20
    ws_memo.column_dimensions['E'].width = 20
    ws_memo.column_dimensions['F'].width = 20
    ws_memo.column_dimensions['G'].width = 20

    output_filename = "Siber_Guvence_Linux_Server_Baseline_Guncellenmis.xlsx"
    wb.save(output_filename)
    print(f"Güncellenmiş Excel çalışma kitabı oluşturuldu: {output_filename}")

if __name__ == '__main__':
    create_revised_baseline()
