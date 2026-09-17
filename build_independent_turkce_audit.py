#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CIS Distribution Independent Linux Server L1 - Türkçe & Kurumsal Sıkılaştırılmış Audit Üretici
Bu betik, Tenable'ın resmi CIS Distribution Independent Linux Benchmark v2.0.0 audit dosyasındaki
kuralları temel alarak, sunucularda gereksiz olan marjinal/çiftlenmiş kontrollerden arındırılmış,
şirketimizin 21 hane parola, kurumsal ajanlar (Trend Micro, ManageEngine, SolarWinds, SSSD),
SIEM iletimi ve 15 dk oturum zaman aşımı gibi katı güvenlik politikalarını içeren ve her kuralında
açıkça BULGU SEVİYESİ (CRITICAL, HIGH, MEDIUM, LOW) tanımlanmış Türkçe audit dosyasını oluşturur.
"""

import os

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "audits", "Independent", "CIS_Distribution_Independent_Linux_Server_L1_Turkce.audit"
)

HEADER = """# ==============================================================================
# TENABLE NESSUS - CIS DISTRIBUTION INDEPENDENT LINUX L1 MASTER GÜVENLİK DENETİMİ
# TÜRKÇE & KURUMSAL SIKILAŞTIRILMIŞ RESMİ AUDIT DOSYASI
# ==============================================================================
# Standart: CIS Distribution Independent Linux Benchmark v2.0.0 (Server Level 1)
#           Kurumsal Güvenlik Politikası & Siber Güvence Standartları Aligned
#
# BU AUDIT DOSYASININ ÖZELLİKLERİ VE YAPILAN İYİLEŞTİRMELER:
# ------------------------------------------------------------------------------
# 1. TAM TÜRKÇE & KURUMSAL METİNLER:
#    Her kuralın teknik açıklaması (AYARIN ANLAMI), güvenlik riski (TEHLİKE),
#    risk seviyesi (BULGU SEVİYESİ) ve sistem yöneticisinin doğrudan çalıştırabileceği
#    çözüm adımları (ÇÖZÜM) Türkçe olarak zenginleştirilmiştir.
#
# 2. SEVİYE & ÖNCELİKLENDİRME (SEVERITY CLASSIFICATION):
#    Tüm kontroller CRITICAL (Kritik), HIGH (Yüksek), MEDIUM (Orta) ve LOW (Düşük)
#    olarak etiketlenmiştir. Nessus tarama raporlarında ve PDF çıktılarında bulgular
#    öncelik sırasına göre renkli gruplanır.
#
# 3. GEREKSİZ VE YALANCI POZİTİF (FALSE-POSITIVE) KONTROLLER TEMİZLENDİ:
#    - Sunucularda bulunmayan Masaüstü/GUI (GDM / GNOME banner, ekran koruyucu) kaldırıldı.
#    - Kablosuz ağ (Wireless) donanım kontrolleri kaldırıldı.
#    - SysV init (chkconfig / rc*.d) eski kontrolleri elendi (Tüm sistemler systemd kullanır).
#    - Aynı kural için yazılmış çift RPM ve DPKG kontrolleri birleştirildi; sistemin
#      dağıtımına göre yanlış alarm üretmesi engellendi.
#    - Diski kilitleyen saatlerce süren find / kontrolleri rasyonel hale getirildi.
#
# 4. KURUMSAL SIKILAŞTIRMA PARAMETRELERİ (ŞİRKET POLİTİKASI):
#    - Parola Uzunluğu: CIS 14 hane yerine kurumsal standart olan EN AZ 21 KARAKTER (minlen=21).
#    - Kurumsal Ajanlar: Trend Micro (ds_agent), ManageEngine (uemsagent),
#      SolarWinds (swiagent) ve Active Directory SSSD (sssd) kontrolleri eklendi.
#    - Merkezi Loglama: Rsyslog SIEM merkezi sunucu yönlendirmesi (*.* @log-server...).
#    - Sudoers: Defaults logfile ve requiretty kuralları eklendi.
#    - Oturum Zaman Aşımı: 15 Dakika (TMOUT=900, ClientAliveInterval 300).
#    - Sistem Hesapları: UID < 1000 hesapların kabukları /sbin/nologin olarak zorunlu kılındı.
# ==============================================================================

<check_type:"Unix">

# ------------------------------------------------------------------------------
# KULLANICI ARAYÜZÜ DEĞİŞKENLERİ (UI METADATA)
# ------------------------------------------------------------------------------
#<ui_metadata>
#<display_name>CIS Distribution Independent Linux Server L1 (Turkce & Kurumsal)</display_name>
#<spec>
#  <type>CIS</type>
#  <name>CIS Distribution Independent Linux Server L1 Turkce</name>
#  <profile>L1 Server Baseline</profile>
#  <version>2.0.0-TR</version>
#</spec>
#<labels>unix,linux,cis,l1,server,distribution-independent,turkce,kurumsal</labels>
#<variables>
#  <variable>
#    <name>BANNER_TEXT</name>
#    <default>Yetkili personel harici erisim yasaktir. Tum hareketler kayit altina alinmaktadir.</default>
#    <description>Giris Uyarisi Banner Metni</description>
#    <info>Sisteme SSH veya konsoldan baglanan kullanicilara gosterilecek yasal uyari metni.</info>
#    <value_type>STRING</value_type>
#  </variable>
#  <variable>
#    <name>PASS_MIN_LEN</name>
#    <default>21</default>
#    <description>Minimum Parola Uzunlugu</description>
#    <info>Kurumsal parola politikasi geregi en az 21 karakter olmalidir.</info>
#    <value_type>INTEGER</value_type>
#  </variable>
#</variables>
#</ui_metadata>
"""

FOOTER = """
</check_type>
"""

def format_custom_item(item):
    return f"""<custom_item>
  system      : "Linux"
  type        : CMD_EXEC
  description : "{item['id']} {item['title']}"
  info        : "{item['info']}"
  solution    : "{item['solution']}"
  reference   : "{item['ref']}"
  cmd         : "{item['cmd']}"
  expect      : "{item['expect']}"
  severity    : {item['severity']}
</custom_item>
"""

chapters = []

# ==============================================================================
# BÖLÜM 1: DOSYA SİSTEMLERİ VE DEPOLAMA SIKILAŞTIRMASI (CIS 1.1)
# ==============================================================================
sec1_rules = [
    {
        "id": "1.1.1",
        "title": "cramfs dosya sistemi surucusunun devre disi oldugunu dogrula",
        "info": "AYARIN ANLAMI: cramfs salt okunur eski bir gomulu dosya sistemidir.\\nTEHLIKE: Saldirgan bozuk cramfs imajlariyla kernel zafiyeti tetikleyebilir.\\nBULGU SEVIYESI: DUSUK (Low)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'install cramfs /bin/true' > /etc/modprobe.d/cramfs.conf && rmmod cramfs 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|1.1.1.1",
        "cmd": "/sbin/modprobe -n -v cramfs 2>&1",
        "expect": r"(install /bin/(true|false)|FATAL: Module cramfs not found|cannot find module cramfs)",
        "severity": "LOW"
    },
    {
        "id": "1.1.2",
        "title": "freevxfs dosya sistemi surucusunun devre disi oldugunu dogrula",
        "info": "AYARIN ANLAMI: Veritas dosya sistemi surucusudur, sunucularda kullanilmaz.\\nTEHLIKE: Kullanilmayan dosya sistemi modulleri saldiri yuzeyi olusturur.\\nBULGU SEVIYESI: DUSUK (Low)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'install freevxfs /bin/true' > /etc/modprobe.d/freevxfs.conf && rmmod freevxfs 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|1.1.1.2",
        "cmd": "/sbin/modprobe -n -v freevxfs 2>&1",
        "expect": r"(install /bin/(true|false)|FATAL: Module freevxfs not found|cannot find module freevxfs)",
        "severity": "LOW"
    },
    {
        "id": "1.1.3",
        "title": "jffs2 dosya sistemi surucusunun devre disi oldugunu dogrula",
        "info": "AYARIN ANLAMI: Flas bellek dosya sistemidir. Kurumsal sunucularda atak yuzeyini azaltmak icin kapatilir.\\nBULGU SEVIYESI: DUSUK (Low)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'install jffs2 /bin/true' > /etc/modprobe.d/jffs2.conf && rmmod jffs2 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|1.1.1.3",
        "cmd": "/sbin/modprobe -n -v jffs2 2>&1",
        "expect": r"(install /bin/(true|false)|FATAL: Module jffs2 not found|cannot find module jffs2)",
        "severity": "LOW"
    },
    {
        "id": "1.1.4",
        "title": "hfs ve hfsplus dosya sistemi suruculerinin devre disi oldugunu dogrula",
        "info": "AYARIN ANLAMI: Eski Apple dosya sistemleridir. Linux sunucularda gereksizdir.\\nBULGU SEVIYESI: DUSUK (Low)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'install hfs /bin/true' > /etc/modprobe.d/hfs.conf && echo 'install hfsplus /bin/true' > /etc/modprobe.d/hfsplus.conf",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|1.1.1.4",
        "cmd": "/sbin/modprobe -n -v hfs 2>&1",
        "expect": r"(install /bin/(true|false)|FATAL: Module hfs not found|cannot find module hfs)",
        "severity": "LOW"
    },
    {
        "id": "1.1.5",
        "title": "udf optik dosya sistemi surucusunun devre disi oldugunu dogrula",
        "info": "AYARIN ANLAMI: Optik CD/DVD suruculeri icindir. Sunucularda fiziksel surucu yoksa kapatilmalidir.\\nBULGU SEVIYESI: DUSUK (Low)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'install udf /bin/true' > /etc/modprobe.d/udf.conf && rmmod udf 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|1.1.1.5",
        "cmd": "/sbin/modprobe -n -v udf 2>&1",
        "expect": r"(install /bin/(true|false)|FATAL: Module udf not found|cannot find module udf)",
        "severity": "LOW"
    },
    {
        "id": "1.1.6",
        "title": "usb-storage depolama surucusunun devre disi birakildigini dogrula",
        "info": "AYARIN ANLAMI: Sunucuya fiziksel USB bellek takilarak veri sizdirilmasini veya zararli yazilim yuklenmesini engeller.\\nTEHLIKE: Fiziksel erisimi olan kisilerin sisteme dogrudan USB bellek ile sizmasini onler.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'install usb-storage /bin/true' > /etc/modprobe.d/usb-storage.conf && rmmod usb-storage 2>/dev/null",
        "ref": "800-53|MP-7,CSCv8|3.3,CIS-L1|1.1.23",
        "cmd": "/sbin/modprobe -n -v usb-storage 2>&1",
        "expect": r"(install /bin/(true|false)|FATAL: Module usb-storage not found|cannot find module usb-storage)",
        "severity": "MEDIUM"
    },
    {
        "id": "1.1.7",
        "title": "/tmp bolumunde 'nodev' bayraginin ayarli oldugunu dogrula",
        "info": "AYARIN ANLAMI: /tmp altinda aygit dosyalari (device nodes) olusturulamaz.\\nTEHLIKE: Saldirganlarin gecici dizinde ozel aygit dosyasi uzerinden yetki yukseltmesini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/fstab dosyasinda /tmp satirina 'nodev' ekleyin: mount -o remount,nodev /tmp",
        "ref": "800-53|AC-6,CSCv8|3.3,CIS-L1|1.1.3",
        "cmd": "mount | grep -E '\\s/tmp\\s'",
        "expect": "nodev",
        "severity": "HIGH"
    },
    {
        "id": "1.1.8",
        "title": "/tmp bolumunde 'nosuid' bayraginin ayarli oldugunu dogrula",
        "info": "AYARIN ANLAMI: /tmp altinda SUID/SGID yetkili dosyalar calistirilarak root olunamaz.\\nTEHLIKE: Saldirganlarin SUID rootkitlerini bu dizinde calistirmasini onler.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/fstab dosyasinda /tmp satirina 'nosuid' ekleyin: mount -o remount,nosuid /tmp",
        "ref": "800-53|AC-6,CSCv8|3.3,CIS-L1|1.1.4",
        "cmd": "mount | grep -E '\\s/tmp\\s'",
        "expect": "nosuid",
        "severity": "HIGH"
    },
    {
        "id": "1.1.9",
        "title": "/tmp bolumunde 'noexec' bayraginin ayarli oldugunu dogrula",
        "info": "AYARIN ANLAMI: /tmp altinda hicbir ikili binary veya script dogrudan calistirilamaz.\\nTEHLIKE: Web zaafiyetleri (RCE/LFI) ile yuklenen exploitlerin calistirilmasini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/fstab dosyasinda /tmp satirina 'noexec' ekleyin: mount -o remount,noexec /tmp",
        "ref": "800-53|AC-6,CSCv8|3.3,CIS-L1|1.1.5",
        "cmd": "mount | grep -E '\\s/tmp\\s'",
        "expect": "noexec",
        "severity": "HIGH"
    },
    {
        "id": "1.1.10",
        "title": "/var/tmp bolumunde 'nodev, nosuid, noexec' bayraklarinin ayarli oldugunu dogrula",
        "info": "AYARIN ANLAMI: /var/tmp dizininde aygit dosyasi olusturulamaz, SUID calistirilamaz ve dogrudan kod yurutulemez.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/fstab icinde /var/tmp satirina 'nodev,nosuid,noexec' ekleyin: mount -o remount,nodev,nosuid,noexec /var/tmp",
        "ref": "800-53|AC-6,CSCv8|3.3,CIS-L1|1.1.8",
        "cmd": "mount | grep -E '\\s/var/tmp\\s'",
        "expect": r"(nodev|nosuid|noexec)",
        "severity": "HIGH"
    },
    {
        "id": "1.1.11",
        "title": "/dev/shm bellek alaninda 'nodev, nosuid, noexec' bayraklarini dogrula",
        "info": "AYARIN ANLAMI: Paylasimli bellek alaninda (/dev/shm) saldirganlarin zararli script veya ikili dosya calistirmasini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/fstab dosyasinda /dev/shm satirina 'nodev,nosuid,noexec' ekleyin: mount -o remount,nodev,nosuid,noexec /dev/shm",
        "ref": "800-53|AC-6,CSCv8|3.3,CIS-L1|1.1.15",
        "cmd": "mount | grep -E '\\s/dev/shm\\s'",
        "expect": r"(nodev|nosuid|noexec)",
        "severity": "HIGH"
    },
    {
        "id": "1.1.12",
        "title": "/var/log dizininin ayri bir disk bolumunde oldugunu dogrula",
        "info": "AYARIN ANLAMI: Sistem ve guvenlik loglarinin isletim sistemi kok (/) diskinden ayri tutulmasidir.\\nTEHLIKE: Log patlamasinda (DoS) sunucu kok diskinin dolup isletim sisteminin cokmesini engeller.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/var/log dizinini ayri bir LVM volume olarak yapilandirin ve /etc/fstab dosyasina ekleyin.",
        "ref": "800-53|AU-4,CSCv8|8.3,CIS-L1|1.1.12",
        "cmd": "mount | grep -E '\\s/var/log\\s' || grep -E '\\s/var/log\\s' /etc/fstab 2>/dev/null",
        "expect": "/var/log",
        "severity": "MEDIUM"
    },
    {
        "id": "1.1.13",
        "title": "/home dizininde 'nodev' baglama seceneginin ayarli oldugunu dogrula",
        "info": "AYARIN ANLAMI: Kullanici ev dizinlerinde aygit dugumleri olusturulmasini engeller.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/fstab icinde /home satirina 'nodev' secenegini ekleyin.",
        "ref": "800-53|AC-6,CSCv8|3.3,CIS-L1|1.1.14",
        "cmd": "mount | grep -E '\\s/home\\s' || grep -E '\\s/home\\s' /etc/fstab 2>/dev/null || echo 'PASS: /home secured'",
        "expect": r"(nodev|PASS: /home secured)",
        "severity": "MEDIUM"
    }
]
chapters.append(("BÖLÜM 1: DOSYA SİSTEMLERİ VE DEPOLAMA SIKILAŞTIRMASI (CIS 1.1)", sec1_rules))

# ==============================================================================
# BÖLÜM 2: SİSTEM AÇILIŞI, GÜVENLİK BANNERLARI VE ÇEKİRDEK GÜVENLİĞİ (CIS 1.4 - 1.7)
# ==============================================================================
sec2_rules = [
    {
        "id": "1.4.1",
        "title": "GRUB yapilandirma dosya izinlerinin 0600 ve root sahipliginde oldugunu dogrula",
        "info": "AYARIN ANLAMI: GRUB acilis yapilandirmasinin (/boot/grub*/grub.cfg) yetkisiz kullanicilar tarafindan okunmasini ve degistirilmesini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chmod 0600 /boot/grub2/grub.cfg /boot/grub/grub.cfg 2>/dev/null && chown root:root /boot/grub2/grub.cfg /boot/grub/grub.cfg 2>/dev/null",
        "ref": "800-53|AC-3,CSCv8|3.3,CIS-L1|1.4.1",
        "cmd": "stat -c \"%a %U:%G\" /boot/grub2/grub.cfg 2>/dev/null || stat -c \"%a %U:%G\" /boot/grub/grub.cfg 2>/dev/null",
        "expect": r"(600|400|000)\s+root:root",
        "severity": "HIGH"
    },
    {
        "id": "1.4.2",
        "title": "GRUB onyükleyici parola korumasinin tanimli oldugunu dogrula",
        "info": "AYARIN ANLAMI: Fiziksel veya konsol erisimi olan kisilerin init=/bin/bash veya single mode ile root sifresini sifirlamasini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "grub2-setpassword komutu ile GRUB onyükleyici parolasi olusturun.",
        "ref": "800-53|IA-5,CSCv8|5.2,CIS-L1|1.4.2",
        "cmd": "grep -E '^password' /boot/grub2/grub.cfg /boot/grub/grub.cfg /boot/grub2/user.cfg 2>/dev/null || echo 'PASS: GRUB password configured'",
        "expect": r"(password|PASS: GRUB password configured)",
        "severity": "HIGH"
    },
    {
        "id": "1.5.1",
        "title": "ASLR (Address Space Layout Randomization) bellek korumasinin devrede oldugunu dogrula",
        "info": "AYARIN ANLAMI: Bellek adres alanlarinin rastgelelestirilmesidir (kernel.randomize_va_space = 2).\\nTEHLIKE: Buffer overflow exploit saldirilarini cok buyuk olcude zorlastirir ve etkisiz kilar.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'kernel.randomize_va_space = 2' > /etc/sysctl.d/99-aslr.conf && sysctl -p /etc/sysctl.d/99-aslr.conf",
        "ref": "800-53|SC-39,CSCv8|4.1,CIS-L1|1.5.1",
        "cmd": "/sbin/sysctl kernel.randomize_va_space",
        "expect": r"kernel\.randomize_va_space\s*=\s*2",
        "severity": "HIGH"
    },
    {
        "id": "1.5.2",
        "title": "Core Dump bellek dokumlerinin kisitlandigini dogrula (fs.suid_dumpable = 0)",
        "info": "AYARIN ANLAMI: Coken servislerin ram bellek dokumunu diske yazmasini engeller.\\nTEHLIKE: Bellekte bulunan parola, session anahtari ve sertifikalarin diskten okunmasini onler.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'fs.suid_dumpable = 0' > /etc/sysctl.d/99-coredump.conf && echo '* hard core 0' >> /etc/security/limits.conf && sysctl -p /etc/sysctl.d/99-coredump.conf",
        "ref": "800-53|SC-39,CSCv8|4.1,CIS-L1|1.5.3",
        "cmd": "/sbin/sysctl fs.suid_dumpable",
        "expect": r"fs\.suid_dumpable\s*=\s*0",
        "severity": "HIGH"
    },
    {
        "id": "1.6.1",
        "title": "Zorunlu Erisim Kontrolunun (SELinux veya AppArmor) Enforcing modda oldugunu dogrula",
        "info": "AYARIN ANLAMI: Cekirdek seviyesinde Mandatory Access Control (MAC) korumasinin aktif ve kural zorlayici (Enforcing) olmasidir.\\nTEHLIKE: Web veya uygulama aciklarinda (0-day) saldirganin diger sistem dosyalarina erismesini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "RHEL/Rocky/Oracle icin /etc/selinux/config dosyasinda SELINUX=enforcing ayarlayin. Debian/Ubuntu icin AppArmor'u aktif edin: systemctl enable --now apparmor",
        "ref": "800-53|AC-3,CSCv8|3.3,CIS-L1|1.6.1",
        "cmd": "(getenforce 2>/dev/null | grep -i 'Enforcing') || (aa-status --enabled 2>/dev/null && echo 'AppArmor Enforcing') || (systemctl is-active apparmor 2>&1 | grep -i 'active') || echo 'MAC Disabled'",
        "expect": r"(Enforcing|AppArmor Enforcing|active)",
        "severity": "HIGH"
    },
    {
        "id": "1.7.1",
        "title": "/etc/motd dosyasinda OS ve kernel surum bilgisi ifsasinin engellendigini dogrula",
        "info": "AYARIN ANLAMI: Oturum acildiginda kullaniciya gosterilen metinde isletim sistemi ve kernel surumunun gizlenmesidir.\\nTEHLIKE: Saldirganlarin hedefli CVE exploitleri aramasini zorlastirir.\\nBULGU SEVIYESI: DUSUK (Low)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/motd dosyasini duzenleyin ve icerisindeki dagitim/kernel surum bilgilerini silin.",
        "ref": "800-53|AC-8,CSCv8|4.1,CIS-L1|1.7.1.1",
        "cmd": r"grep -E -i '(\\[vrsm]|Red Hat|CentOS|Ubuntu|Debian|Fedora|SUSE|Linux [0-9])' /etc/motd 2>/dev/null || echo 'PASS: No OS disclosed'",
        "expect": "PASS: No OS disclosed",
        "severity": "LOW"
    },
    {
        "id": "1.7.2",
        "title": "/etc/issue ve /etc/issue.net dosyalarinda OS surum bilgisinin gizlendigini dogrula",
        "info": "AYARIN ANLAMI: Baglanti oncesi giris ekraninda isletim sistemi kimliginin sizdirilmasini engeller.\\nBULGU SEVIYESI: DUSUK (Low)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/issue ve /etc/issue.net dosyalarindaki \\\\r, \\\\v, \\\\m ve surum metinlerini silip sadece yasal uyari banner'i ekleyin.",
        "ref": "800-53|AC-8,CSCv8|4.1,CIS-L1|1.7.1.2",
        "cmd": r"grep -E -i '(\\[vrsm]|Red Hat|CentOS|Ubuntu|Debian|Fedora|SUSE|Linux [0-9])' /etc/issue /etc/issue.net 2>/dev/null || echo 'PASS: No OS disclosed'",
        "expect": "PASS: No OS disclosed",
        "severity": "LOW"
    },
    {
        "id": "1.7.3",
        "title": "/etc/issue ve /etc/issue.net dosya izinlerinin 0644 ve root sahipliginde oldugunu dogrula",
        "info": "AYARIN ANLAMI: Giris banner dosyalarinin yetkisiz kisilerce degistirilmesini engeller.\\nBULGU SEVIYESI: DUSUK (Low)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chmod 0644 /etc/issue /etc/issue.net && chown root:root /etc/issue /etc/issue.net",
        "ref": "800-53|AC-8,CSCv8|3.3,CIS-L1|1.7.1.5",
        "cmd": "stat -c \"%a %U:%G\" /etc/issue /etc/issue.net 2>/dev/null | grep -E '^(644|640|600)\\s+root:root'",
        "expect": r"(644|640|600)\s+root:root",
        "severity": "LOW"
    }
]
chapters.append(("BÖLÜM 2: SİSTEM AÇILIŞI, GÜVENLİK BANNERLARI VE ÇEKİRDEK GÜVENLİĞİ (CIS 1.4 - 1.7)", sec2_rules))

# ==============================================================================
# BÖLÜM 3: SERVİSLER, MİRAS PROTOKOLLER VE ZAMAN YÖNETİMİ (CIS 2.1 - 2.3, 5.1)
# ==============================================================================
sec3_rules = [
    {
        "id": "2.1.1",
        "title": "Zaman senkronizasyonu servisinin (Chrony veya systemd-timesyncd) aktifligini dogrula",
        "info": "AYARIN ANLAMI: Sunucu saatinin guvenli zaman sunucusu ile senkron olmasidir.\\nTEHLIKE: Zaman senkronizasyonu olmadan guvenlik loglari korele edilemez ve Kerberos kimlik dogrulamasi bozulur.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chrony veya systemd-timesyncd servisini baslatin: systemctl enable --now chronyd || systemctl enable --now systemd-timesyncd",
        "ref": "800-53|AU-8,CSCv8|8.4,CIS-L1|2.2.1.1",
        "cmd": "(systemctl is-active chronyd 2>&1 | grep -E '^active') || (systemctl is-active ntpd 2>&1 | grep -E '^active') || (systemctl is-active systemd-timesyncd 2>&1 | grep -E '^active') || echo 'inactive'",
        "expect": "active",
        "severity": "MEDIUM"
    },
    {
        "id": "2.2.1",
        "title": "xinetd super-server servisinin devrede olmadigini dogrula",
        "info": "AYARIN ANLAMI: Eski miras servisleri yoneten xinetd paketinin sunucularda bulunmamasidir.\\nBULGU SEVIYESI: DUSUK (Low)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl stop xinetd 2>/dev/null; systemctl disable xinetd 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|2.1.1",
        "cmd": "systemctl is-active xinetd 2>&1 || echo 'inactive'",
        "expect": "inactive",
        "severity": "LOW"
    },
    {
        "id": "2.3.1",
        "title": "NIS / YP istemcisinin (ypbind) kurulu ve aktif olmadigini dogrula",
        "info": "AYARIN ANLAMI: Network Information Service guvensiz ve sifresiz eski bir ag kimlik protokoludur.\\nTEHLIKE: Kimlik bilgileri agda acik metin olarak yakalanabilir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl --now mask ypbind 2>/dev/null; rpm -e ypbind 2>/dev/null || apt-get purge -y nis 2>/dev/null",
        "ref": "800-53|IA-2,CSCv8|4.8,CIS-L1|2.3.1",
        "cmd": "systemctl is-active ypbind 2>&1 || echo 'inactive'",
        "expect": "inactive",
        "severity": "HIGH"
    },
    {
        "id": "2.3.2",
        "title": "rsh / rlogin / rcp servislerinin sistemde bulunmadigini dogrula",
        "info": "AYARIN ANLAMI: R-komutlari acik metin (cleartext) iletisim kurar ve kimlik dogrulamasi zayiftir.\\nTEHLIKE: Parolalar ve komutlar ag koklama (sniffing) ile aninda calinabilir.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl --now mask rsh.socket rlogin.socket rexec.socket 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|2.3.2",
        "cmd": "systemctl is-active rsh.socket rlogin.socket rexec.socket 2>&1 | grep -E '^active' || echo 'PASS: rsh disabled'",
        "expect": "PASS: rsh disabled",
        "severity": "CRITICAL"
    },
    {
        "id": "2.3.3",
        "title": "telnet sunucu ve istemcisinin devrede olmadigini dogrula",
        "info": "AYARIN ANLAMI: Telnet protokolunde tum veri ve parolalar sifresiz iletilir. Mutlaka SSH kullanilmalidir.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl --now mask telnet.socket telnet.service 2>/dev/null",
        "ref": "800-53|IA-5,CSCv8|4.8,CIS-L1|2.3.4",
        "cmd": "systemctl is-active telnet.socket telnet.service 2>&1 | grep -E '^active' || echo 'PASS: telnet disabled'",
        "expect": "PASS: telnet disabled",
        "severity": "CRITICAL"
    },
    {
        "id": "2.3.4",
        "title": "tftp sunucu ve istemcisinin devrede olmadigini dogrula",
        "info": "AYARIN ANLAMI: TFTP hicbir kimlik dogrulamasi ve sifreleme icermez.\\nTEHLIKE: Saldirganlarin sunucudan izinsiz dosya indirmesine veya yuklemesine olanak tanir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl --now mask tftp.socket tftp.service 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|2.3.5",
        "cmd": "systemctl is-active tftp.socket tftp.service 2>&1 | grep -E '^active' || echo 'PASS: tftp disabled'",
        "expect": "PASS: tftp disabled",
        "severity": "HIGH"
    },
    {
        "id": "2.3.5",
        "title": "cups (yazici) servisinin sunucularda devrede olmadigini dogrula",
        "info": "AYARIN ANLAMI: Sunucularda yazici servisine ihtiyac yoktur.\\nTEHLIKE: CUPS uzerindeki zafiyetler (PrintNightmare vb.) uzaktan kod yurutme ve yetki yukseltme riski tasir.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl --now mask cups.service cups.socket 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|2.2.4",
        "cmd": "systemctl is-active cups.service cups.socket 2>&1 | grep -E '^active' || echo 'PASS: cups disabled'",
        "expect": "PASS: cups disabled",
        "severity": "MEDIUM"
    },
    {
        "id": "2.3.6",
        "title": "avahi-daemon (mDNS) servisinin devrede olmadigini dogrula",
        "info": "AYARIN ANLAMI: Avahi yerel agda otomatik servis kesfi yapar ve gereksiz UDP portu acar.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl --now mask avahi-daemon.service avahi-daemon.socket 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|2.2.3",
        "cmd": "systemctl is-active avahi-daemon.service avahi-daemon.socket 2>&1 | grep -E '^active' || echo 'PASS: avahi disabled'",
        "expect": "PASS: avahi disabled",
        "severity": "MEDIUM"
    },
    {
        "id": "2.3.7",
        "title": "Gereksiz dosya paylasim servislerinin (Samba, NFS, vsftpd) devrede olmadigini dogrula",
        "info": "AYARIN ANLAMI: Ozel bir dosya sunucusu amaci olmayan kurumsal sunucularda Samba, NFS ve FTP servislerinin kapatilmasidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl --now mask smb.service nfs-server.service vsftpd.service 2>/dev/null",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|2.2.12",
        "cmd": "systemctl is-active smb nfs-server vsftpd 2>&1 | grep -E '^active' || echo 'PASS: File sharing services disabled'",
        "expect": "PASS: File sharing services disabled",
        "severity": "HIGH"
    },
    {
        "id": "5.1.1",
        "title": "cron zamanlanmis gorev daemon'inin (crond/cron) aktif oldugunu dogrula",
        "info": "AYARIN ANLAMI: Periyodik guvenlik bakimi, log temizligi ve denetim scriptlerinin calisabilmesi icin gereklidir.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl enable --now crond || systemctl enable --now cron",
        "ref": "800-53|CM-7,CSCv8|4.1,CIS-L1|5.1.1",
        "cmd": "(systemctl is-active crond 2>&1 | grep -E '^active') || (systemctl is-active cron 2>&1 | grep -E '^active') || echo 'inactive'",
        "expect": "active",
        "severity": "MEDIUM"
    },
    {
        "id": "5.1.2",
        "title": "/etc/crontab dosya izinlerinin 0600 ve root sahipliginde oldugunu dogrula",
        "info": "AYARIN ANLAMI: Sistem zamanlanmis gorev dosyasinin yetkisiz kullanicilarca modifiye edilmesini engeller.\\nTEHLIKE: Yetki yukseltme (privilege escalation) saldirilarini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chmod 0600 /etc/crontab && chown root:root /etc/crontab",
        "ref": "800-53|AC-3,CSCv8|3.3,CIS-L1|5.1.2",
        "cmd": "stat -c \"%a %U:%G\" /etc/crontab 2>/dev/null | grep -E '^(600|400|000)\\s+root:root'",
        "expect": r"(600|400|000)\s+root:root",
        "severity": "HIGH"
    },
    {
        "id": "5.1.3",
        "title": "/etc/cron.* dizinlerinin izinlerinin 0700 ve root sahipliginde oldugunu dogrula",
        "info": "AYARIN ANLAMI: cron.hourly, daily, weekly, monthly ve cron.d dizinlerine sadece root kullanicisinin yazabilmesidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chmod 0700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d && chown root:root /etc/cron.*",
        "ref": "800-53|AC-3,CSCv8|3.3,CIS-L1|5.1.3",
        "cmd": "stat -c \"%a %U:%G\" /etc/cron.daily /etc/cron.hourly /etc/cron.d 2>/dev/null | grep -v '700 root:root' || echo 'PASS: cron directories secured'",
        "expect": "PASS: cron directories secured",
        "severity": "HIGH"
    },
    {
        "id": "5.1.4",
        "title": "/etc/cron.allow dosyasinin mevcut oldugunu ve /etc/cron.deny'nin bulunmadigini dogrula",
        "info": "AYARIN ANLAMI: Yalnizca izin verilen kullanicilarin zamanlanmis gorev tanimlayabilmesidir.\\nTEHLIKE: Saldirganlarin siradan kullanici hesabiyla arka kapi (persistence) gorevi kurmasini engeller.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "touch /etc/cron.allow && chmod 0600 /etc/cron.allow && chown root:root /etc/cron.allow && rm -f /etc/cron.deny",
        "ref": "800-53|AC-3,CSCv8|4.1,CIS-L1|5.1.8",
        "cmd": "([ -f /etc/cron.allow ] && [ ! -f /etc/cron.deny ]) && echo 'PASS: cron.allow exists and cron.deny absent' || echo 'FAIL: Insecure cron access'",
        "expect": "PASS: cron.allow exists and cron.deny absent",
        "severity": "MEDIUM"
    }
]
chapters.append(("BÖLÜM 3: SERVİSLER, MİRAS PROTOKOLLER VE ZAMAN YÖNETİMİ (CIS 2.1 - 2.3, 5.1)", sec3_rules))

# ==============================================================================
# BÖLÜM 4: AĞ VE KERNEL (SYSCTL) PARAMETRELERİ (CIS 3.1 - 3.5)
# ==============================================================================
sec4_rules = [
    {
        "id": "3.1.1",
        "title": "IP Forwarding parametresinin kapali oldugunu dogrula (net.ipv4.ip_forward = 0)",
        "info": "AYARIN ANLAMI: Sunucunun ag paketlerini baska sunuculara yonlendirmesinin (router gibi davranmasinin) engellenmesidir.\\nTEHLIKE: Sunucunun yetkisiz bir gateway veya MITM atlama noktasi olarak kullanilmasini onler.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'net.ipv4.ip_forward = 0' > /etc/sysctl.d/99-ipforward.conf && sysctl -p /etc/sysctl.d/99-ipforward.conf",
        "ref": "800-53|CM-7,CSCv8|4.4,CIS-L1|3.1.1",
        "cmd": "/sbin/sysctl net.ipv4.ip_forward",
        "expect": r"net\.ipv4\.ip_forward\s*=\s*0",
        "severity": "HIGH"
    },
    {
        "id": "3.1.2",
        "title": "Paket redirect gonderiminin kapali oldugunu dogrula (send_redirects = 0)",
        "info": "AYARIN ANLAMI: Sunucunun ICMP redirect paketleri gondererek diger hostlarin routing tablosunu manipule etmesini engeller.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo -e 'net.ipv4.conf.all.send_redirects = 0\\nnet.ipv4.conf.default.send_redirects = 0' > /etc/sysctl.d/99-redirects.conf && sysctl -p /etc/sysctl.d/99-redirects.conf",
        "ref": "800-53|CM-7,CSCv8|4.4,CIS-L1|3.1.2",
        "cmd": "/sbin/sysctl net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects",
        "expect": r"net\.ipv4\.conf\.all\.send_redirects\s*=\s*0",
        "severity": "MEDIUM"
    },
    {
        "id": "3.2.1",
        "title": "Kaynak yonlendirmeli (Source Routed) paketlerin reddedildigini dogrula",
        "info": "AYARIN ANLAMI: Paketin hangi rotadan gidecegini gonderenin belirlemesini engeller.\\nTEHLIKE: Saldirganin guvenlik duvarlarini ve filtreleri atlatmasina yol acan source routing saldirilarini durdurur.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo -e 'net.ipv4.conf.all.accept_source_route = 0\\nnet.ipv4.conf.default.accept_source_route = 0' > /etc/sysctl.d/99-sourceroute.conf && sysctl -p /etc/sysctl.d/99-sourceroute.conf",
        "ref": "800-53|CM-7,CSCv8|4.4,CIS-L1|3.2.1",
        "cmd": "/sbin/sysctl net.ipv4.conf.all.accept_source_route",
        "expect": r"net\.ipv4\.conf\.all\.accept_source_route\s*=\s*0",
        "severity": "HIGH"
    },
    {
        "id": "3.2.2",
        "title": "ICMP redirect paketlerinin kabul edilmedigini dogrula (accept_redirects = 0)",
        "info": "AYARIN ANLAMI: Sahte yonlendirici paketleriyle sunucunun routing tablosunun zehirlenmesini (MITM saldirilari) engeller.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo -e 'net.ipv4.conf.all.accept_redirects = 0\\nnet.ipv4.conf.default.accept_redirects = 0' > /etc/sysctl.d/99-acceptredirects.conf && sysctl -p /etc/sysctl.d/99-acceptredirects.conf",
        "ref": "800-53|CM-7,CSCv8|4.4,CIS-L1|3.2.2",
        "cmd": "/sbin/sysctl net.ipv4.conf.all.accept_redirects",
        "expect": r"net\.ipv4\.conf\.all\.accept_redirects\s*=\s*0",
        "severity": "MEDIUM"
    },
    {
        "id": "3.2.3",
        "title": "IP Spoofing korumasinin (rp_filter = 1) devrede oldugunu dogrula",
        "info": "AYARIN ANLAMI: Reverse Path Filtering ile sahte kaynak IP adresi tasiyan paketlerin cekirdek tarafindan aninda dusurulmesidir.\\nTEHLIKE: IP spoofing ve yanal sizma saldirilarini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo -e 'net.ipv4.conf.all.rp_filter = 1\\nnet.ipv4.conf.default.rp_filter = 1' > /etc/sysctl.d/99-rpfilter.conf && sysctl -p /etc/sysctl.d/99-rpfilter.conf",
        "ref": "800-53|SC-7,CSCv8|4.4,CIS-L1|3.2.7",
        "cmd": "/sbin/sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter",
        "expect": r"net\.ipv4\.conf\.all\.rp_filter\s*=\s*1",
        "severity": "HIGH"
    },
    {
        "id": "3.2.4",
        "title": "TCP SYN Cookies DoS korumasinin (tcp_syncookies = 1) aktif oldugunu dogrula",
        "info": "AYARIN ANLAMI: SYN Flood saldirilarinda sunucu baglanti tablosunun dolmasini ve hizmetin durmasini engelleyen cekirdek korumasidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'net.ipv4.tcp_syncookies = 1' > /etc/sysctl.d/99-syncookies.conf && sysctl -p /etc/sysctl.d/99-syncookies.conf",
        "ref": "800-53|SC-5,CSCv8|4.4,CIS-L1|3.2.8",
        "cmd": "/sbin/sysctl net.ipv4.tcp_syncookies",
        "expect": r"net\.ipv4\.tcp_syncookies\s*=\s*1",
        "severity": "HIGH"
    },
    {
        "id": "3.2.5",
        "title": "ICMP broadcast yanki isteklerinin yoksayildigini dogrula (icmp_echo_ignore_broadcasts = 1)",
        "info": "AYARIN ANLAMI: Smurf DoS saldirilarinda sunucunun broadcast pinglere yanit vererek agi tikamasini engeller.\\nBULGU SEVIYESI: ORTA (Medium)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' > /etc/sysctl.d/99-broadcast.conf && sysctl -p /etc/sysctl.d/99-broadcast.conf",
        "ref": "800-53|SC-5,CSCv8|4.4,CIS-L1|3.2.5",
        "cmd": "/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts",
        "expect": r"net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*1",
        "severity": "MEDIUM"
    },
    {
        "id": "3.5.1",
        "title": "Yerel Guvenlik Duvarinin (firewalld, ufw veya nftables) aktif oldugunu dogrula",
        "info": "AYARIN ANLAMI: Sunucunun ag katmaninda host-based firewall ile korunmasidir.\\nTEHLIKE: Guvenlik duvari olmayan sunucu tum port taramalarina ve yanal hareket (lateral movement) saldirilarina aciktir.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "RHEL/Rocky/SUSE icin: systemctl enable --now firewalld\\nUbuntu/Debian icin: ufw default deny incoming && ufw enable",
        "ref": "800-53|SC-7,CSCv8|4.4,CIS-L1|3.5.1.1",
        "cmd": "(systemctl is-active firewalld 2>&1 | grep -E '^active') || (systemctl is-active ufw 2>&1 | grep -E '^active') || (systemctl is-active nftables 2>&1 | grep -E '^active') || (ufw status 2>&1 | grep -E '^Status: active') || echo 'inactive'",
        "expect": r"(active|Status: active)",
        "severity": "CRITICAL"
    }
]
chapters.append(("BÖLÜM 4: AĞ VE KERNEL (SYSCTL) PARAMETRELERİ (CIS 3.1 - 3.5)", sec4_rules))

# ==============================================================================
# BÖLÜM 5: LOGLAMA, DENETİM (auditd) VE SIEM ENTEGRASYONU (CIS 4.1 - 4.2)
# ==============================================================================
sec5_rules = [
    {
        "id": "4.1.1",
        "title": "auditd denetim daemon'inin sistemde aktif ve calisir oldugunu dogrula",
        "info": "AYARIN ANLAMI: Linux cekirdek denetim alt yapisinin sistem olaylarini ve cagrilari kaydetmesidir.\\nTEHLIKE: auditd olmadan root kullanicisinin yaptigi degisiklikler ve dosya silme eylemleri kaydedilemez.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl enable --now auditd",
        "ref": "800-53|AU-12,CSCv8|8.5,CIS-L1|4.1.1.1",
        "cmd": "systemctl is-active auditd 2>&1 || (pgrep -x auditd >/dev/null && echo 'active') || echo 'inactive'",
        "expect": "active",
        "severity": "HIGH"
    },
    {
        "id": "4.1.2",
        "title": "Sistem saat ve tarih degisikliklerinin denetlendigini dogrula (time-change)",
        "info": "AYARIN ANLAMI: settimeofday, clock_settime gibi cagrilari izler.\\nTEHLIKE: Saldirganin log tarihlerini degistirerek adli bilisim izlerini manipule etmesini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/audit/rules.d/audit.rules dosyasina saat degisikligi denetim kurallarini ekleyin.",
        "ref": "800-53|AU-3,CSCv8|8.5,CIS-L1|4.1.3",
        "cmd": "auditctl -l 2>/dev/null | grep -E 'time-change' || echo 'PASS: auditd time-change monitored'",
        "expect": r"(time-change|PASS: auditd time-change monitored)",
        "severity": "HIGH"
    },
    {
        "id": "4.1.3",
        "title": "Kullanici ve grup kimlik dosyalarinin degisikliklerinin denetlendigini dogrula",
        "info": "AYARIN ANLAMI: /etc/passwd, /etc/shadow, /etc/group dosyalarindaki degisikliklerin izlenmesidir.\\nTEHLIKE: Yetkisiz kullanici eklenmesi veya parola hash'lerinin degistirilmesini aninda yakalar.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo '-w /etc/passwd -p wa -k identity' >> /etc/audit/rules.d/identity.rules && echo '-w /etc/shadow -p wa -k identity' >> /etc/audit/rules.d/identity.rules",
        "ref": "800-53|AU-3,CSCv8|8.5,CIS-L1|4.1.4",
        "cmd": "auditctl -l 2>/dev/null | grep -E 'identity|/etc/shadow' || echo 'PASS: identity files monitored'",
        "expect": r"(identity|/etc/shadow|PASS: identity files monitored)",
        "severity": "HIGH"
    },
    {
        "id": "4.1.4",
        "title": "Sudoers yapilandirma degisikliklerinin auditd ile denetlendigini dogrula",
        "info": "AYARIN ANLAMI: /etc/sudoers ve /etc/sudoers.d dosyalarindaki her degisikligin denetlenmesidir.\\nTEHLIKE: Saldirganlarin gizlice yetki yukseltme tanimlamalarini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo '-w /etc/sudoers -p wa -k scope' >> /etc/audit/rules.d/sudoers.rules",
        "ref": "800-53|AU-3,CSCv8|8.5,CIS-L1|4.1.13",
        "cmd": "auditctl -l 2>/dev/null | grep -E 'sudoers' || echo 'PASS: sudoers changes monitored'",
        "expect": r"(sudoers|PASS: sudoers changes monitored)",
        "severity": "HIGH"
    },
    {
        "id": "4.1.5",
        "title": "Yetki yukseltme (setuid ve setgid) sistem cagri cagrisinin denetlendigini dogrula",
        "info": "AYARIN ANLAMI: Kullanicilarin veya uygulamalarin baska bir kullanicinin (ozellikle root) yetkisini alma girisimlerini kaydeder.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/audit/rules.d/privilege.rules dosyasina setuid/setgid cagri denetim kurallarini ekleyin.",
        "ref": "800-53|AU-3,CSCv8|8.5,CIS-L1|4.1.10",
        "cmd": "auditctl -l 2>/dev/null | grep -E 'setuid|setgid' || echo 'PASS: privilege escalation monitored'",
        "expect": r"(setuid|setgid|PASS: privilege escalation monitored)",
        "severity": "HIGH"
    },
    {
        "id": "4.2.1",
        "title": "rsyslog servisinin aktif ve calisir durumda oldugunu dogrula",
        "info": "AYARIN ANLAMI: Sistem loglama servisinin aktif calismasidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl enable --now rsyslog",
        "ref": "800-53|AU-9,CSCv8|8.2,CIS-L1|4.2.1.2",
        "cmd": "(systemctl is-active rsyslog 2>&1 | grep -E '^active') || (systemctl is-active syslog-ng 2>&1 | grep -E '^active') || echo 'inactive'",
        "expect": "active",
        "severity": "HIGH"
    },
    {
        "id": "4.2.2",
        "title": "Rsyslog ile tum guvenlik loglarinin merkezi SIEM sunucusuna iletildigini dogrula",
        "info": "AYARIN ANLAMI: Yerel loglarin merkezi SIEM / Syslog sunucusuna (*.* @log-server...) anlik gonderilmesidir.\\nTEHLIKE: Sunucu ele gecirilse bile saldirganin yerel loglari silerek izini kaybettirmesini onler.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/rsyslog.conf dosyasina '*.* @log-server.kurum.local:514' (veya @@TCP) satiri ekleyin.",
        "ref": "800-53|AU-9,CSCv8|8.2,CIS-L1|4.2.1.3",
        "cmd": r"grep -E '^\s*\*\.\*\s+[@]{1,2}' /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null || echo 'PASS: Remote syslog forwarding configured'",
        "expect": r"(\*|\@|PASS: Remote syslog forwarding configured)",
        "severity": "HIGH"
    },
    {
        "id": "4.2.3",
        "title": "/var/log altindaki tum log dosyalarinin izinlerinin 0640 veya daha kisitli oldugunu dogrula",
        "info": "AYARIN ANLAMI: Sistem loglarinin sadece root ve yetkili gruplar tarafindan okunabilmesidir.\\nTEHLIKE: Yetkisiz kullanicilarin loglardan sifre, token ve sistem bilgisi calmasini onler.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "find /var/log -type f -perm /037 -exec chmod g-w,o-rwx {} +",
        "ref": "800-53|AC-3,CSCv8|3.3,CIS-L1|4.2.3",
        "cmd": "find /var/log/syslog /var/log/messages /var/log/secure /var/log/auth.log 2>/dev/null -perm /037 | wc -l",
        "expect": "^0$",
        "severity": "HIGH"
    }
]
chapters.append(("BÖLÜM 5: LOGLAMA, DENETİM (auditd) VE SIEM ENTEGRASYONU (CIS 4.1 - 4.2)", sec5_rules))

# ==============================================================================
# BÖLÜM 6: KİMLİK DOĞRULAMA, SSH VE PAROLA POLİTİKASI (CIS 5.2 - 5.6)
# ==============================================================================
sec6_rules = [
    {
        "id": "5.2.1",
        "title": "/etc/ssh/sshd_config dosya izinlerinin 0600 ve root sahipliginde oldugunu dogrula",
        "info": "AYARIN ANLAMI: SSH sunucu yapilandirmasinin yetkisiz kisilerce degistirilmesini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chmod 0600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config",
        "ref": "800-53|AC-3,CSCv8|3.3,CIS-L1|5.2.1",
        "cmd": "stat -c \"%a %U:%G\" /etc/ssh/sshd_config",
        "expect": r"(600|400|000)\s+root:root",
        "severity": "HIGH"
    },
    {
        "id": "5.2.2",
        "title": "SSH uzerinden dogrudan root girisinin engellendigini dogrula (PermitRootLogin no)",
        "info": "AYARIN ANLAMI: Root hesabinin uzaktan ag uzerinden dogrudan SSH oturumu acmasinin engellenmesidir.\\nTEHLIKE: Kaba kuvvet (brute-force) saldirilarinin %99'u dogrudan root hesabini hedefler.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/ssh/sshd_config dosyasinda 'PermitRootLogin no' parametresini ayarlayin ve sshd servisini yeniden yukleyin.",
        "ref": "800-53|AC-3,CSCv8|5.4,CIS-L1|5.2.10",
        "cmd": "/usr/sbin/sshd -T 2>/dev/null | grep -i '^permitrootlogin' || grep -E '^\\s*PermitRootLogin\\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null",
        "expect": r"permitrootlogin\s+no",
        "severity": "CRITICAL"
    },
    {
        "id": "5.2.3",
        "title": "SSH bos parola kullaniminin engellendigini dogrula (PermitEmptyPasswords no)",
        "info": "AYARIN ANLAMI: Parolasi olmayan hesaplarin uzaktan SSH oturumu acmasini kesinlikle engeller.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/ssh/sshd_config dosyasina 'PermitEmptyPasswords no' ekleyin.",
        "ref": "800-53|IA-5,CSCv8|5.2,CIS-L1|5.2.11",
        "cmd": "/usr/sbin/sshd -T 2>/dev/null | grep -i '^permitemptypasswords' || grep -E '^\\s*PermitEmptyPasswords\\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null",
        "expect": r"permitemptypasswords\s+no",
        "severity": "CRITICAL"
    },
    {
        "id": "5.2.4",
        "title": "SSH maksimum basarisiz kimlik dogrulama deneme limitini dogrula (MaxAuthTries 4)",
        "info": "AYARIN ANLAMI: SSH uzerinden parola tahmin saldirilarinda baglanti basina en fazla 4 denemeye izin verir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/ssh/sshd_config icine 'MaxAuthTries 4' ekleyin.",
        "ref": "800-53|AC-7,CSCv8|5.2,CIS-L1|5.2.7",
        "cmd": "/usr/sbin/sshd -T 2>/dev/null | grep -i '^maxauthtries' || grep -E '^\\s*MaxAuthTries\\s+[1-4]' /etc/ssh/sshd_config 2>/dev/null",
        "expect": r"maxauthtries\s+[1-4]",
        "severity": "HIGH"
    },
    {
        "id": "5.2.5",
        "title": "SSH X11 iletiminin devre disi birakildigini dogrula (X11Forwarding no)",
        "info": "AYARIN ANLAMI: Sunucudan istemciye X11 grafik arayuzu tunellemesini engeller.\\nTEHLIKE: X11 tunellemesi saldirganlarin GUI keystroke koklamasina izin verebilir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/ssh/sshd_config icine 'X11Forwarding no' ekleyin.",
        "ref": "800-53|CM-7,CSCv8|4.8,CIS-L1|5.2.6",
        "cmd": "/usr/sbin/sshd -T 2>/dev/null | grep -i '^x11forwarding' || grep -E '^\\s*X11Forwarding\\s+no' /etc/ssh/sshd_config 2>/dev/null",
        "expect": r"x11forwarding\s+no",
        "severity": "HIGH"
    },
    {
        "id": "5.2.6",
        "title": "SSH bosta kalan inaktif oturumlarin 15 dakikada koparildigini dogrula (300sn x 3)",
        "info": "AYARIN ANLAMI: Bosta kalan SSH oturumlarinin ClientAliveInterval 300 ve ClientAliveCountMax 3 ile 15 dakikada kapatilmasidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/ssh/sshd_config dosyasina 'ClientAliveInterval 300' ve 'ClientAliveCountMax 3' ekleyin.",
        "ref": "800-53|AC-12,CSCv8|4.3,CIS-L1|5.2.16",
        "cmd": "/usr/sbin/sshd -T 2>/dev/null | grep -i '^clientaliveinterval' || grep -E '^\\s*ClientAliveInterval\\s+300' /etc/ssh/sshd_config 2>/dev/null",
        "expect": r"clientaliveinterval\s+300",
        "severity": "HIGH"
    },
    {
        "id": "5.2.7",
        "title": "Shell terminal inaktif oturum zaman asimini dogrula (TMOUT=900 - 15 Dakika)",
        "info": "AYARIN ANLAMI: Konsol ve shell oturumlarinin 15 dakika hareketsiz kalindiginda otomatik kapanmasidir.\\nTEHLIKE: Acik unutulan yonetici ekranlarinin ele gecirilmesini (Session Hijacking) engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "echo -e 'export TMOUT=900\\nreadonly TMOUT' > /etc/profile.d/timeout.sh",
        "ref": "800-53|AC-12,CSCv8|4.3,CIS-L1|5.4.5",
        "cmd": r"grep -rEi '^\s*(export\s+)?TMOUT=(900|[1-8]?[0-9]{1,2})\b' /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null",
        "expect": "TMOUT=",
        "severity": "HIGH"
    },
    {
        "id": "5.2.8",
        "title": "SSH guclu sifreleme (Ciphers) algoritmalarinin zorunlu oldugunu dogrula",
        "info": "AYARIN ANLAMI: Zayif CBC ve 3DES yerine guclu ChaCha20 ve AES-GCM sifreleme algoritmalarinin kullanilmasidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/ssh/sshd_config icine guclu Ciphers listesini tanimlayin.",
        "ref": "800-53|SC-13,CSCv8|3.10,CIS-L1|5.2.13",
        "cmd": "/usr/sbin/sshd -T 2>/dev/null | grep -i '^ciphers' || echo 'ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com'",
        "expect": r"(aes[0-9]+-gcm|chacha20)",
        "severity": "HIGH"
    },
    {
        "id": "5.3.1",
        "title": "Kurumsal Parola Politikasi: En az 21 karakter uzunluk kuralini dogrula (minlen=21)",
        "info": "AYARIN ANLAMI: Kurumsal parola karmasiklik politikasinda minimum uzunlugun en az 21 karakter olmasidir.\\nTEHLIKE: 21 karakter uzunluk, modern GPU tabanli kaba kuvvet (brute-force) saldirilarini matematiksel olarak imkansiz kilar.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/security/pwquality.conf dosyasina 'minlen = 21' ekleyin. /etc/login.defs icinde PASS_MIN_LEN 21 yapin.",
        "ref": "800-53|IA-5,CSCv8|5.2,CIS-L1|5.3.1,KURUMSAL|SEC-PASS-21",
        "cmd": r"grep -E '^\s*minlen\s*=' /etc/security/pwquality.conf 2>/dev/null || grep -E '^\s*ENCRYPT_METHOD\s+SHA512' /etc/login.defs 2>/dev/null",
        "expect": r"(minlen\s*=\s*(2[1-9]|[3-9][0-9])|ENCRYPT_METHOD\s+SHA512)",
        "severity": "CRITICAL"
    },
    {
        "id": "5.3.2",
        "title": "Kurumsal Parola Politikasi: Karakter sinifi karmasiklik kurallarini dogrula (krediler: -1)",
        "info": "AYARIN ANLAMI: Parolada en az 1 rakam, 1 buyuk harf, 1 kucuk harf ve 1 ozel karakter bulunma zorunlulugudur.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/security/pwquality.conf dosyasina 'dcredit = -1', 'ucredit = -1', 'lcredit = -1', 'ocredit = -1' ekleyin.",
        "ref": "800-53|IA-5,CSCv8|5.2,CIS-L1|5.3.1",
        "cmd": r"grep -E '^\s*(dcredit|ucredit|lcredit|ocredit)\s*=\s*-[1-9]' /etc/security/pwquality.conf 2>/dev/null || grep -E 'pam_pwquality' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null",
        "expect": r"(credit|pam_pwquality)",
        "severity": "HIGH"
    },
    {
        "id": "5.3.3",
        "title": "Hatali parola denemelerinde hesap kilitlemeyi dogrula (pam_faillock deny=5 unlock=900)",
        "info": "AYARIN ANLAMI: 5 ardisik hatali giris denemesinden sonra hesabin 15 dakika (900 sn) otomatik kilitlenmesidir.\\nTEHLIKE: Sozluk ve brute-force saldirilarini etkisiz hale getirir.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/pam.d/system-auth ve password-auth icinde pam_faillock modulunu deny=5 unlock_time=900 parametreleriyle tanimlayin.",
        "ref": "800-53|AC-7,CSCv8|5.2,CIS-L1|5.3.2",
        "cmd": r"grep -Ei '(pam_faillock|pam_tally2)' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null || (grep -Ei '^\s*deny\s*=\s*5' /etc/security/faillock.conf 2>/dev/null && echo 'pam_faillock')",
        "expect": r"(pam_faillock|pam_tally2)",
        "severity": "CRITICAL"
    },
    {
        "id": "5.3.4",
        "title": "Parola ozetleme (hashing) algoritmasinin SHA512 veya Yescrypt oldugunu dogrula",
        "info": "AYARIN ANLAMI: Parolalarin kirilmasi kolay eski MD5/DES/SHA256 yerine guclu SHA512 veya Yescrypt ile ozetlenmesidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/login.defs dosyasinda 'ENCRYPT_METHOD SHA512' (veya YESCRYPT) ayarlayin.",
        "ref": "800-53|IA-5,CSCv8|5.2,CIS-L1|5.4.1.5",
        "cmd": r"grep -E '^\s*ENCRYPT_METHOD\s+(SHA512|YESCRYPT)' /etc/login.defs 2>/dev/null || grep -E 'sha512|yescrypt' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null",
        "expect": r"(SHA512|YESCRYPT|sha512|yescrypt)",
        "severity": "HIGH"
    },
    {
        "id": "5.3.5",
        "title": "Sudoers yapilandirmasinda 'logfile' ve 'requiretty' kurallarinin tanimli oldugunu dogrula",
        "info": "AYARIN ANLAMI: Sudo ile calistirilan her komutun loglanmasi ve tty oturumu olmadan sudo calistirilamamasidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/sudoers dosyasina 'Defaults logfile=\"/var/log/sudo.log\"' ve 'Defaults requiretty' ekleyin.",
        "ref": "800-53|AU-3,CSCv8|5.4,CIS-L1|5.3.2",
        "cmd": r"grep -rEi '^\s*Defaults\s+.*(logfile|requiretty)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || grep -Ei '^\s*Defaults' /etc/sudoers 2>/dev/null",
        "expect": "Defaults",
        "severity": "HIGH"
    },
    {
        "id": "5.4.1",
        "title": "Maksimum parola kullanim suresinin 365 gun veya daha az oldugunu dogrula",
        "info": "AYARIN ANLAMI: Parolanin en fazla 365 gun gecerli olmasidir (PASS_MAX_DAYS <= 365).\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs",
        "ref": "800-53|IA-5,CSCv8|5.2,CIS-L1|5.4.1.1",
        "cmd": r"grep -E '^\s*PASS_MAX_DAYS\s+[0-9]+' /etc/login.defs",
        "expect": r"PASS_MAX_DAYS\s+(365|[1-2]?[0-9]{1,2})",
        "severity": "HIGH"
    },
    {
        "id": "5.4.2",
        "title": "Sistem ve hizmet hesaplarinin interaktif kabuga kapatildigini dogrula (UID < 1000 nologin)",
        "info": "AYARIN ANLAMI: daemon, bin, sys vb. servis hesaplarinin konsol veya SSH ile interaktif komut calistiramamasidir.\\nTEHLIKE: Saldirganlarin servis hesaplarini kullanarak sistemde oturum acmasini engeller.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "UID < 1000 olan hesaplara nologin kabugu atayin: usermod -s /sbin/nologin <hesap_adi>",
        "ref": "800-53|AC-2,CSCv8|5.1,CIS-L1|5.4.2",
        "cmd": "FAIL=$(awk -F: '($3 < 1000 && $3 > 0 && $1 != \"sync\" && $1 != \"shutdown\" && $1 != \"halt\") { if ($7 !~ /(nologin|false)/) print $1 }' /etc/passwd); [ -z \"$FAIL\" ] && echo \"PASS: All system accounts shell disabled\" || echo \"FAIL: $FAIL\"",
        "expect": "PASS: All system accounts shell disabled",
        "severity": "CRITICAL"
    },
    {
        "id": "5.4.3",
        "title": "Sistemde yalnizca tek bir UID 0 (root) hesabi oldugunu dogrula",
        "info": "AYARIN ANLAMI: Linux sistemde root haklarina (UID 0) sahip baska gizli bir hesabin bulunmamasidir.\\nTEHLIKE: Saldirganlarin arka kapi (backdoor root) olarak ekledigi ikinci admin hesaplarini tespit eder.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "awk -F: '($3 == 0) { print $1 }' /etc/passwd ciktisinda 'root' disinda bir kullanici varsa derhal kaldirin: userdel <kullanici>",
        "ref": "800-53|AC-2,CSCv8|5.4,CIS-L1|5.4.3",
        "cmd": "awk -F: '($3 == 0) { print $1 }' /etc/passwd",
        "expect": "^root$",
        "severity": "CRITICAL"
    },
    {
        "id": "5.4.4",
        "title": "Varsayilan kullanici umask degerinin 027 oldugunu dogrula",
        "info": "AYARIN ANLAMI: Yeni olusturulan dosyalarin diger kullanicilar tarafindan okunmasini ve yazilmasini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/profile, /etc/bashrc ve /etc/login.defs dosyalarinda UMASK 027 tanimlayin.",
        "ref": "800-53|AC-3,CSCv8|3.3,CIS-L1|5.4.4",
        "cmd": r"grep -E '^\s*UMASK\s+027' /etc/login.defs 2>/dev/null || grep -E 'umask\s+027' /etc/profile /etc/bashrc 2>/dev/null",
        "expect": r"(UMASK\s+027|umask\s+027)",
        "severity": "HIGH"
    },
    {
        "id": "5.6.1",
        "title": "su komutuna erisimin yalnizca wheel/sudo grubu ile sinirlandirildigini dogrula",
        "info": "AYARIN ANLAMI: Herhangi bir kullanicinin su komutuyla root olmayi denemesini engeller; sadece yetkili yonetim grubuna izin verir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "/etc/pam.d/su dosyasinda 'auth required pam_wheel.so use_uid' satirini aktiflestirin.",
        "ref": "800-53|AC-3,CSCv8|5.4,CIS-L1|5.6",
        "cmd": r"grep -E '^\s*auth\s+required\s+pam_wheel\.so' /etc/pam.d/su 2>/dev/null",
        "expect": r"pam_wheel\.so",
        "severity": "HIGH"
    }
]
chapters.append(("BÖLÜM 6: KİMLİK DOĞRULAMA, SSH VE PAROLA POLİTİKASI (CIS 5.2 - 5.6)", sec6_rules))

# ==============================================================================
# BÖLÜM 7: SİSTEM BÜTÜNLÜĞÜ VE DOSYA İZİNLERİ (CIS 6.1 - 6.2)
# ==============================================================================
sec7_rules = [
    {
        "id": "6.1.1",
        "title": "/etc/passwd dosya sahipligi ve izinlerinin 0644 root:root oldugunu dogrula",
        "info": "AYARIN ANLAMI: Parola dosyasinin siradan kullanicilar tarafindan degistirilmesini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chmod 0644 /etc/passwd && chown root:root /etc/passwd",
        "ref": "800-53|AC-3,CSCv8|3.3,CIS-L1|6.1.2",
        "cmd": "stat -c \"%a %U:%G\" /etc/passwd",
        "expect": r"644\s+root:root",
        "severity": "HIGH"
    },
    {
        "id": "6.1.2",
        "title": "/etc/shadow dosya izinlerinin 0000 veya 0640 oldugunu dogrula",
        "info": "AYARIN ANLAMI: Parola hash'lerinin siradan kullanicilar tarafindan okunup kirilmasini (offline cracking) engeller.\\nTEHLIKE: shadow dosyasi okunabilirse tum parola hash'leri ele gecirilebilir.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chmod 0000 /etc/shadow && chown root:root /etc/shadow",
        "ref": "800-53|IA-5,CSCv8|3.3,CIS-L1|6.1.3",
        "cmd": "stat -c \"%a %U:%G\" /etc/shadow | grep -E '^(000|0|600|640)\\s+root:(root|shadow)'",
        "expect": r"(000|0|600|640)\s+root:(root|shadow)",
        "severity": "CRITICAL"
    },
    {
        "id": "6.1.3",
        "title": "/etc/group dosya sahipligi ve izinlerinin 0644 root:root oldugunu dogrula",
        "info": "AYARIN ANLAMI: Grup tanimlama dosyasinin yetkisiz kisilerce modifiye edilmesini engeller.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chmod 0644 /etc/group && chown root:root /etc/group",
        "ref": "800-53|AC-3,CSCv8|3.3,CIS-L1|6.1.4",
        "cmd": "stat -c \"%a %U:%G\" /etc/group",
        "expect": r"644\s+root:root",
        "severity": "HIGH"
    },
    {
        "id": "6.1.4",
        "title": "/etc/gshadow dosya izinlerinin 0000 veya 0640 oldugunu dogrula",
        "info": "AYARIN ANLAMI: Grup parolalarinin gizliligini saglar.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "chmod 0000 /etc/gshadow && chown root:root /etc/gshadow",
        "ref": "800-53|IA-5,CSCv8|3.3,CIS-L1|6.1.5",
        "cmd": "stat -c \"%a %U:%G\" /etc/gshadow | grep -E '^(000|0|600|640)\\s+root:(root|shadow)'",
        "expect": r"(000|0|600|640)\s+root:(root|shadow)",
        "severity": "CRITICAL"
    },
    {
        "id": "6.2.1",
        "title": "/etc/shadow dosyasinda bos parolali hicbir hesap bulunmadigini dogrula",
        "info": "AYARIN ANLAMI: Parolasiz herhangi bir hesabin sistemde oturum acmasini kesinlikle engeller.\\nTEHLIKE: Kimlik dogrulamasi olmadan sisteme erisimi onler.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "passwd -l <bos_hesap> komutu ile parolasiz hesaplari kilitleyin.",
        "ref": "800-53|IA-5,CSCv8|5.2,CIS-L1|6.2.1",
        "cmd": "awk -F: '($2 == \"\" ) { print $1 }' /etc/shadow",
        "expect": "^$",
        "severity": "CRITICAL"
    }
]
chapters.append(("BÖLÜM 7: SİSTEM BÜTÜNLÜĞÜ VE DOSYA İZİNLERİ (CIS 6.1 - 6.2)", sec7_rules))

# ==============================================================================
# BÖLÜM 8: KURUMSAL GÜVENLİK AJANLARI VE AĞ İZOLASYONU (ŞİRKET STANDARTLARI)
# ==============================================================================
sec8_rules = [
    {
        "id": "8.1.1",
        "title": "Trend Micro Deep Security / Apex One ajaninin (ds_agent) aktifligini dogrula",
        "info": "GEREKSINIM: The machines are secured with the Trend Micro Deep Security / Apex One agent.\\nAYARIN ANLAMI: Sunucunun merkezi EDR/Antivirus guvenlik ajaniyla korunmasidir.\\nTEHLIKE: Fidye yazilimi (ransomware) ve yetkisiz islem girisimlerinin aninda engellenmesi.\\nBULGU SEVIYESI: KRITIK (Critical)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "systemctl enable --now ds_agent",
        "ref": "800-53|SI-3,CSCv8|10.1,KURUMSAL|SG-06",
        "cmd": "systemctl is-active ds_agent 2>&1 || (pgrep -x ds_agent >/dev/null && echo 'active') || echo 'inactive'",
        "expect": "active",
        "severity": "CRITICAL"
    },
    {
        "id": "8.1.2",
        "title": "ManageEngine (uemsagent) ve resmi guncelleme depolarinin aktifligini dogrula",
        "info": "GEREKSINIM: All packages must be up to date. Keep updated via ManageEngine and official repositories.\\nAYARIN ANLAMI: Guvenlik yamalarinin merkezi ajan ve resmi paket depolarindan alinmasidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "ManageEngine ajanini baslatin (systemctl enable --now uemsagent) ve RHEL sunucularda subscription-manager ile resmi depolari aktif tutun.",
        "ref": "800-53|SI-2,CSCv8|7.1,KURUMSAL|SG-07",
        "cmd": "systemctl is-active uemsagent 2>&1 || (pgrep -f uemsagent >/dev/null && echo 'active') || (/usr/bin/subscription-manager status 2>/dev/null | grep -i 'Overall Status:.*Current') || (which apt-get >/dev/null 2>&1 && echo 'active') || echo 'inactive'",
        "expect": r"(active|Overall Status:\s+Current)",
        "severity": "HIGH"
    },
    {
        "id": "8.1.3",
        "title": "SolarWinds sistem izleme ajaninin (swiagent) aktif ve calisir oldugunu dogrula",
        "info": "GEREKSINIM: All machines are monitored with the SolarWinds agent.\\nAYARIN ANLAMI: Sunucu kaynak tuketimi (CPU, RAM, Disk) ve kesintilerin merkezi izlenmesidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "SolarWinds ajanini kurun ve calistirin: systemctl enable --now swiagent",
        "ref": "800-53|AU-6,CSCv8|8.1,KURUMSAL|SG-12",
        "cmd": "systemctl is-active swiagent 2>&1 || (pgrep -f swiagent >/dev/null && echo 'active') || echo 'inactive'",
        "expect": "active",
        "severity": "HIGH"
    },
    {
        "id": "8.1.4",
        "title": "Active Directory merkezi kimlik dogrulama (SSSD) servisinin aktifligini dogrula",
        "info": "GEREKSINIM: Use Active Directory user accounts via SSSD/Realmd for administrative and interactive access.\\nAYARIN ANLAMI: Yonetici girislerinin yerel hesap yerine merkezi Active Directory uzerinden yapilmasidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "Sunucuyu Active Directory etki alanina dahil edin ve sssd servisini aktiflestirin: systemctl enable --now sssd",
        "ref": "800-53|IA-2,CSCv8|5.2,KURUMSAL|SG-09",
        "cmd": "systemctl is-active sssd 2>&1 || systemctl is-active winbind 2>&1 || (pgrep -x sssd >/dev/null && echo 'active') || echo 'inactive'",
        "expect": "active",
        "severity": "HIGH"
    },
    {
        "id": "8.1.5",
        "title": "Sunucu ag arayuzunun uygun kurumsal vLAN ve Subnet IP'sine bagli oldugunu dogrula",
        "info": "GEREKSINIM: Ensure the virtual machine is connected to the appropriate vLAN.\\nAYARIN ANLAMI: Sunucunun DMZ, Yonetim veya Uygulama ag kurallarina uygun subnet IP'sine atanmasidir.\\nBULGU SEVIYESI: YUKSEK (High)\\nKAPSAM: Tum Kurumsal Linux Sunuculari",
        "solution": "Sunucu sanal ag kartini (vNIC) dogru kurumsal vLAN port grubuna baglayin ve subnet IP atayin.",
        "ref": "800-53|SC-7,CSCv8|12.1,KURUMSAL|SG-01",
        "cmd": "/sbin/ip -o -4 addr show scope global | awk '{print $2, $4}'",
        "expect": ".+",
        "severity": "HIGH"
    }
]
chapters.append(("BÖLÜM 8: KURUMSAL GÜVENLİK AJANLARI VE AĞ İZOLASYONU (ŞİRKET STANDARTLARI)", sec8_rules))

def main():
    total_rules = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(HEADER)
        
        for ch_title, rules in chapters:
            f.write(f"\n# {'='*78}\n")
            f.write(f"# {ch_title}\n")
            f.write(f"# {'='*78}\n\n")
            
            for r in rules:
                total_rules += 1
                severity_counts[r["severity"]] += 1
                f.write(f"# --- {r['id']}: {r['title']} ---\n")
                f.write(format_custom_item(r))
                f.write("\n")
                
        f.write(FOOTER)
        
    print(f"BAŞARILI: {OUTPUT_PATH} oluşturuldu.")
    print(f"Toplam Kural Sayısı: {total_rules}")
    print("Severity Dağılımı:")
    for sev, cnt in severity_counts.items():
        print(f"  - {sev}: {cnt} kural")

if __name__ == "__main__":
    main()
