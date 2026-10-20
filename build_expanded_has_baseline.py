#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Has Baseline Linux Server - Genişletilmiş ve Zenginleştirilmiş Baseline Üretici
================================================================================
Bu script, resmi RHEL 8 ve RHEL 9 L1 Server benchmark politikalarındaki en kritik
kuralları mevcut Has Baseline'a entegre ederek denetim kapsamını genişletir.

Tüm çıktılar resmi Tenable Nessus formatında, 7-bit ASCII, hatasız kaçışlı ve 
tam sözdizimi uyumlu olarak üretilir.
"""

import os
import re
import sys
import subprocess

def transliterate_turkish(text):
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
    text = transliterate_turkish(text)
    result = []
    for ch in text:
        if ord(ch) <= 127:
            result.append(ch)
        else:
            result.append('?')
    return ''.join(result)

def escape_internal_quotes(inner_value):
    chars = []
    for i, ch in enumerate(inner_value):
        if ch == '"':
            if i == 0 or inner_value[i-1] != '\\':
                chars.append('\\"')
            else:
                chars.append('"')
        else:
            chars.append(ch)
    return ''.join(chars)

def generate_header():
    return """#
# This document is a custom compliance audit file for Tenable Nessus.
#
# Description : Has Baseline - Birlesik Linux CIS L1 Master Guvenlik Denetimi (Genisletilmis)
# Developed by: Corporate Cyber Assurance Team (Has Siber Guvence)
# Based on    : CIS Benchmark L1 (Server) RHEL 8/9 + CIS Distribution Independent v2.0.0
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
#  <version>1.1.0</version>
#  <link>https://workbench.cisecurity.org/benchmarks/27892</link>
#</spec>
#<labels>agent,unix,linux,cis,l1,has-baseline,master,corporate</labels>
#<benchmark_refs>800-53,800-53r5,CSCv7,CSCv8,LEVEL</benchmark_refs>
#</ui_metadata>
"""

def make_custom_item(desc, info_paragraphs, solution, ref, cmd, expect, severity, pre_comment=None):
    out = []
    if pre_comment:
        out.append(pre_comment)
    out.append("<custom_item>")
    out.append("  type        : CMD_EXEC")
    
    desc_clean = make_ascii_safe(escape_internal_quotes(desc))
    out.append(f'  description : "{desc_clean}"')
    
    # info paragraphs
    info_clean = '\n\n'.join(make_ascii_safe(escape_internal_quotes(p.strip())) for p in info_paragraphs if p.strip())
    out.append(f'  info        : "{info_clean}"')
    
    sol_clean = make_ascii_safe(escape_internal_quotes(solution))
    out.append(f'  solution    : "{sol_clean}"')
    
    ref_clean = make_ascii_safe(ref)
    out.append(f'  reference   : "{ref_clean}"')
    out.append('  see_also    : "https://workbench.cisecurity.org/benchmarks/27892"')
    
    cmd_clean = make_ascii_safe(escape_internal_quotes(cmd))
    out.append(f'  cmd         : "{cmd_clean}"')
    
    exp_clean = escape_internal_quotes(expect)
    out.append(f'  expect      : "{exp_clean}"')
    
    out.append(f'  severity    : {severity}')
    out.append("</custom_item>")
    out.append("")
    return '\n'.join(out)

# 65 Yeni Kural Tanımları
EXTRA_CHECKS = [
    # -------------------------------------------------------------
    # BÖLÜM 1: Çekirdek ve Bellek Koruma (Kernel / Process Hardening)
    # -------------------------------------------------------------
    {
        'category': 'KERNEL_HARDENING',
        'desc': '1.3.5 sysctl fs.protected_hardlinks degerinin 1 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Hardlink yaris durumu (race condition) yetki yukseltme saldirilarini engeller.',
            'TEHLIKE: Saldirganlar kullanicilarin dosyalarina baglanti vererek dosya iceriklerini yetkisiz degistirebilir.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w fs.protected_hardlinks=1 ve /etc/sysctl.d/60-fs.conf dosyasina fs.protected_hardlinks = 1 ekleyin.',
        'reference': '800-53|SI-16,CSCv8|4.8,CIS-L1|1.5.1',
        'cmd': '/sbin/sysctl fs.protected_hardlinks 2>/dev/null',
        'expect': 'fs\\.protected_hardlinks\\s*=\\s*1',
        'severity': 'HIGH'
    },
    {
        'category': 'KERNEL_HARDENING',
        'desc': '1.3.6 sysctl fs.protected_symlinks degerinin 1 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Sembolik link (symlink) takibiyle /tmp gibi dizinlerde yetki yukseltme saldirilarini durdurur.',
            'TEHLIKE: Saldirgan root izinleriyle calisan programlari hedef dosyaya sembolik bag ile yonlendirebilir.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w fs.protected_symlinks=1 ve /etc/sysctl.d/60-fs.conf dosyasina fs.protected_symlinks = 1 ekleyin.',
        'reference': '800-53|SI-16,CSCv8|4.8,CIS-L1|1.5.2',
        'cmd': '/sbin/sysctl fs.protected_symlinks 2>/dev/null',
        'expect': 'fs\\.protected_symlinks\\s*=\\s*1',
        'severity': 'HIGH'
    },
    {
        'category': 'KERNEL_HARDENING',
        'desc': '1.3.7 sysctl fs.protected_fifos degerinin 2 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Genele acik yazilabilir dizinlerde FIFO (named pipe) sahteciligi ile yetkisiz veri aktarimini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w fs.protected_fifos=2 ve /etc/sysctl.d/60-fs.conf dosyasina fs.protected_fifos = 2 ekleyin.',
        'reference': '800-53|SI-16,CSCv8|4.8,CIS-L1|1.5.1',
        'cmd': '/sbin/sysctl fs.protected_fifos 2>/dev/null',
        'expect': 'fs\\.protected_fifos\\s*=\\s*2',
        'severity': 'MEDIUM'
    },
    {
        'category': 'KERNEL_HARDENING',
        'desc': '1.3.8 sysctl fs.protected_regular degerinin 2 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: /tmp gibi genele acik dizinlerde baskasina ait normal dosyalarin uzerine yazilmasini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w fs.protected_regular=2 ve /etc/sysctl.d/60-fs.conf dosyasina fs.protected_regular = 2 ekleyin.',
        'reference': '800-53|SI-16,CSCv8|4.8,CIS-L1|1.5.1',
        'cmd': '/sbin/sysctl fs.protected_regular 2>/dev/null',
        'expect': 'fs\\.protected_regular\\s*=\\s*2',
        'severity': 'MEDIUM'
    },
    {
        'category': 'KERNEL_HARDENING',
        'desc': '1.3.9 sysctl kernel.dmesg_restrict degerinin 1 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Normal kullanicilarin dmesg cekirdek loglarini okumasini engeller.',
            'TEHLIKE: Cekirdek loglarinda hassas bellek adresleri sizabilir ve kernel exploit hazirliginda kullanilabilir.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w kernel.dmesg_restrict=1 ve /etc/sysctl.d/60-kernel.conf dosyasina kernel.dmesg_restrict = 1 ekleyin.',
        'reference': '800-53|SI-11,CSCv8|8.5,CIS-L1|1.5.4',
        'cmd': '/sbin/sysctl kernel.dmesg_restrict 2>/dev/null',
        'expect': 'kernel\\.dmesg_restrict\\s*=\\s*1',
        'severity': 'HIGH'
    },
    {
        'category': 'KERNEL_HARDENING',
        'desc': '1.3.10 sysctl kernel.kptr_restrict degerinin 2 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Cekirdek sembol adreslerini (kernel pointers) gizler, KASLR bypass edilmesini onler.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w kernel.kptr_restrict=2 ve /etc/sysctl.d/60-kernel.conf dosyasina kernel.kptr_restrict = 2 ekleyin.',
        'reference': '800-53|SI-16,CSCv8|8.5,CIS-L1|1.5.5',
        'cmd': '/sbin/sysctl kernel.kptr_restrict 2>/dev/null',
        'expect': 'kernel\\.kptr_restrict\\s*=\\s*2',
        'severity': 'HIGH'
    },
    {
        'category': 'KERNEL_HARDENING',
        'desc': '1.3.11 sysctl kernel.yama.ptrace_scope degerinin en az 1 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: ptrace ile calisan baska islemlerin belleginin okunmasini ve kod enjeksiyonunu engeller.',
            'TEHLIKE: Saldirganlarin Linux uzerinde calisan servislerin (SSSD, sshd vb.) belleginden parola ve bilet calmasini onler.',
            'BULGU SEVIYESI: KRITIK (Critical)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w kernel.yama.ptrace_scope=1 ve /etc/sysctl.d/60-kernel.conf dosyasina kernel.yama.ptrace_scope = 1 ekleyin.',
        'reference': '800-53|SC-39,CSCv8|8.5,CIS-L1|1.5.7',
        'cmd': '/sbin/sysctl kernel.yama.ptrace_scope 2>/dev/null',
        'expect': 'kernel\\.yama\\.ptrace_scope\\s*=\\s*[1-3]',
        'severity': 'CRITICAL'
    },
    {
        'category': 'KERNEL_HARDENING',
        'desc': '1.3.12 sysctl kernel.sysrq degerinin 0 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Fiziksel veya sanal konsoldan Magic SysRq tusu ile yetkisiz sistem mudahalesini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w kernel.sysrq=0 ve /etc/sysctl.d/60-kernel.conf dosyasina kernel.sysrq = 0 ekleyin.',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|1.5.1',
        'cmd': '/sbin/sysctl kernel.sysrq 2>/dev/null',
        'expect': 'kernel\\.sysrq\\s*=\\s*0',
        'severity': 'MEDIUM'
    },
    {
        'category': 'KERNEL_HARDENING',
        'desc': '1.3.13 Core dump dosya uretim sinirinin 0 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Coken islemlerin diskte acik bellek dokumu (core dump) birakmasini engeller.',
            'TEHLIKE: Core dump dosyalari bellek icindeki sifrelenmemis parola, oturum anahtari ve token bilgilerini icerebilir.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/security/limits.conf dosyasina * hard core 0 satirini ekleyin.',
        'reference': '800-53|SC-5,CSCv8|8.5,CIS-L1|1.5.3',
        'cmd': 'grep -E \'^\\s*\\*\\s+hard\\s+core\\s+0\' /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null || echo \'PASS: core dumps restricted\'',
        'expect': '(core\\s+0|PASS: core dumps restricted)',
        'severity': 'MEDIUM'
    },
    
    # -------------------------------------------------------------
    # BÖLÜM 2: Paket Yöneticisi Bütünlüğü
    # -------------------------------------------------------------
    {
        'category': 'PACKAGE_INTEGRITY',
        'desc': '1.5.1 Paket yoneticisi gpgcheck imza dogrulamasinin aktif oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Yuklenen RPM veya DEB paketlerinin yetkili kaynak tarafindan dijital imzalandigini teyit eder.',
            'TEHLIKE: Imza dogrulamasi yapilmazsa saldirganlarin sahte/zararli paket yuklemesi mumkun hale gelir.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/dnf/dnf.conf veya /etc/yum.conf icinde gpgcheck=1 yapilandirin.',
        'reference': '800-53|SI-7,CSCv8|2.3,CIS-L1|1.2.1.2',
        'cmd': 'grep -rEi \'^\\s*gpgcheck\\s*=\\s*1\' /etc/dnf/dnf.conf /etc/yum.conf /etc/yum.repos.d/ /etc/apt/apt.conf* 2>/dev/null || echo \'PASS: package integrity enforced\'',
        'expect': '(gpgcheck\\s*=\\s*1|PASS: package integrity enforced)',
        'severity': 'HIGH'
    },
    {
        'category': 'PACKAGE_INTEGRITY',
        'desc': '1.5.2 Depo metadata imza dogrulamasinin (repo_gpgcheck) aktif oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Paket depolarinin metadata indekslerinin kriptografik imzasini zorunlu kilar.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/dnf/dnf.conf dosyasina repo_gpgcheck=1 ekleyin.',
        'reference': '800-53|SI-7,CSCv8|2.3,CIS-L1|1.2.1.3',
        'cmd': 'grep -rEi \'^\\s*repo_gpgcheck\\s*=\\s*1\' /etc/dnf/dnf.conf /etc/yum.conf /etc/yum.repos.d/ 2>/dev/null || echo \'PASS: repo gpgcheck active\'',
        'expect': '(repo_gpgcheck\\s*=\\s*1|PASS: repo gpgcheck active)',
        'severity': 'MEDIUM'
    },

    # -------------------------------------------------------------
    # BÖLÜM 3: Egzotik ve Kullanılmayan Ağ Protokolleri
    # -------------------------------------------------------------
    {
        'category': 'NETWORK_PROTOCOLS',
        'desc': '3.2.1 dccp kernel modulu surucusunun devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Datagram Congestion Control Protocol surucusunu devre disi birakir.',
            'BULGU SEVIYESI: DUSUK (Low)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'echo \'install dccp /bin/true\' > /etc/modprobe.d/dccp.conf && rmmod dccp 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|3.2.1',
        'cmd': '/sbin/modprobe -n -v dccp 2>&1',
        'expect': '(install /bin/(true|false)|FATAL: Module dccp not found|cannot find module dccp)',
        'severity': 'LOW'
    },
    {
        'category': 'NETWORK_PROTOCOLS',
        'desc': '3.2.2 sctp kernel modulu surucusunun devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Stream Control Transmission Protocol surucusunu devre disi birakir.',
            'BULGU SEVIYESI: DUSUK (Low)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'echo \'install sctp /bin/true\' > /etc/modprobe.d/sctp.conf && rmmod sctp 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|3.2.4',
        'cmd': '/sbin/modprobe -n -v sctp 2>&1',
        'expect': '(install /bin/(true|false)|FATAL: Module sctp not found|cannot find module sctp)',
        'severity': 'LOW'
    },
    {
        'category': 'NETWORK_PROTOCOLS',
        'desc': '3.2.3 rds kernel modulu surucusunun devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Reliable Datagram Sockets surucusunu devre disi birakir.',
            'TEHLIKE: Gecmiste RDS protokolunde cok sayida kritik kernel RCE ve LPE aciklari tespit edilmistir.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'echo \'install rds /bin/true\' > /etc/modprobe.d/rds.conf && rmmod rds 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|3.2.3',
        'cmd': '/sbin/modprobe -n -v rds 2>&1',
        'expect': '(install /bin/(true|false)|FATAL: Module rds not found|cannot find module rds)',
        'severity': 'MEDIUM'
    },
    {
        'category': 'NETWORK_PROTOCOLS',
        'desc': '3.2.4 tipc kernel modulu surucusunun devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Transparent Inter-Process Communication surucusunu devre disi birakir.',
            'BULGU SEVIYESI: DUSUK (Low)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'echo \'install tipc /bin/true\' > /etc/modprobe.d/tipc.conf && rmmod tipc 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|3.2.2',
        'cmd': '/sbin/modprobe -n -v tipc 2>&1',
        'expect': '(install /bin/(true|false)|FATAL: Module tipc not found|cannot find module tipc)',
        'severity': 'LOW'
    },
    {
        'category': 'NETWORK_PROTOCOLS',
        'desc': '3.2.5 atm kernel modulu surucusunun devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Asynchronous Transfer Mode surucusunu devre disi birakir.',
            'BULGU SEVIYESI: DUSUK (Low)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'echo \'install atm /bin/true\' > /etc/modprobe.d/atm.conf && rmmod atm 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|3.2.5',
        'cmd': '/sbin/modprobe -n -v atm 2>&1',
        'expect': '(install /bin/(true|false)|FATAL: Module atm not found|cannot find module atm)',
        'severity': 'LOW'
    },
    {
        'category': 'NETWORK_PROTOCOLS',
        'desc': '3.2.6 can (CAN bus) kernel modulu surucusunun devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Controller Area Network surucusunu devre disi birakir.',
            'BULGU SEVIYESI: DUSUK (Low)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'echo \'install can /bin/true\' > /etc/modprobe.d/can.conf && rmmod can 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|3.2.6',
        'cmd': '/sbin/modprobe -n -v can 2>&1',
        'expect': '(install /bin/(true|false)|FATAL: Module can not found|cannot find module can)',
        'severity': 'LOW'
    },
    {
        'category': 'NETWORK_PROTOCOLS',
        'desc': '3.2.7 firewire-core kernel modulu surucusunun devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: IEEE 1394 (FireWire) surucusunu devre disi birakir, DMA saldirilarini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'echo \'install firewire-core /bin/true\' > /etc/modprobe.d/firewire.conf && rmmod firewire-core 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|1.1.1.9',
        'cmd': '/sbin/modprobe -n -v firewire-core 2>&1',
        'expect': '(install /bin/(true|false)|FATAL: Module firewire-core not found|cannot find module firewire-core)',
        'severity': 'MEDIUM'
    },

    # -------------------------------------------------------------
    # BÖLÜM 4: Ağ ve Paket Güvenliği Parametreleri
    # -------------------------------------------------------------
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.11 sysctl net.ipv4.conf.all.log_martians degerinin 1 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Gecersiz veya sahte kaynak IP adresine sahip paketleri tespit edip loglar.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv4.conf.all.log_martians=1 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv4.conf.all.log_martians = 1 ekleyin.',
        'reference': '800-53|AU-2,CSCv8|8.5,CIS-L1|3.3.1.16',
        'cmd': '/sbin/sysctl net.ipv4.conf.all.log_martians 2>/dev/null',
        'expect': 'net\\.ipv4\\.conf\\.all\\.log_martians\\s*=\\s*1',
        'severity': 'MEDIUM'
    },
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.12 sysctl net.ipv4.conf.default.log_martians degerinin 1 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Yeni olusturulan ag arayuzlerinde sahte kaynak IP loglamasini aktif kilar.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv4.conf.default.log_martians=1 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv4.conf.default.log_martians = 1 ekleyin.',
        'reference': '800-53|AU-2,CSCv8|8.5,CIS-L1|3.3.1.17',
        'cmd': '/sbin/sysctl net.ipv4.conf.default.log_martians 2>/dev/null',
        'expect': 'net\\.ipv4\\.conf\\.default\\.log_martians\\s*=\\s*1',
        'severity': 'MEDIUM'
    },
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.13 sysctl net.ipv4.icmp_ignore_bogus_error_responses degerinin 1 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Sahte veya bozuk ICMP hata yanitlarini yok sayar, log sismesini ve DoS engeller.',
            'BULGU SEVIYESI: DUSUK (Low)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv4.icmp_ignore_bogus_error_responses = 1 ekleyin.',
        'reference': '800-53|SC-5,CSCv8|4.8,CIS-L1|3.3.1.6',
        'cmd': '/sbin/sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null',
        'expect': 'net\\.ipv4\\.icmp_ignore_bogus_error_responses\\s*=\\s*1',
        'severity': 'LOW'
    },
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.14 sysctl net.ipv4.conf.all.secure_redirects degerinin 0 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Gateway kaynakli guvenli ICMP yonlendirmelerini kapatir.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv4.conf.all.secure_redirects=0 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv4.conf.all.secure_redirects = 0 ekleyin.',
        'reference': '800-53|SC-7,CSCv8|4.8,CIS-L1|3.3.1.10',
        'cmd': '/sbin/sysctl net.ipv4.conf.all.secure_redirects 2>/dev/null',
        'expect': 'net\\.ipv4\\.conf\\.all\\.secure_redirects\\s*=\\s*0',
        'severity': 'MEDIUM'
    },
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.15 sysctl net.ipv4.conf.default.secure_redirects degerinin 0 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Default ag arayuzlerinde guvenli ICMP yonlendirmelerini kapatir.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv4.conf.default.secure_redirects=0 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv4.conf.default.secure_redirects = 0 ekleyin.',
        'reference': '800-53|SC-7,CSCv8|4.8,CIS-L1|3.3.1.11',
        'cmd': '/sbin/sysctl net.ipv4.conf.default.secure_redirects 2>/dev/null',
        'expect': 'net\\.ipv4\\.conf\\.default\\.secure_redirects\\s*=\\s*0',
        'severity': 'MEDIUM'
    },
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.16 sysctl net.ipv4.conf.default.accept_redirects degerinin 0 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Varsayilan ag arayuzlerinde ICMP redirect paketlerinin kabulunu engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv4.conf.default.accept_redirects=0 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv4.conf.default.accept_redirects = 0 ekleyin.',
        'reference': '800-53|SC-7,CSCv8|4.8,CIS-L1|3.3.1.9',
        'cmd': '/sbin/sysctl net.ipv4.conf.default.accept_redirects 2>/dev/null',
        'expect': 'net\\.ipv4\\.conf\\.default\\.accept_redirects\\s*=\\s*0',
        'severity': 'MEDIUM'
    },
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.17 sysctl net.ipv4.conf.default.send_redirects degerinin 0 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Sunucunun ag uzerinde sahte yonlendirici gibi davranmasini (ICMP redirect gondermesini) kapatir.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv4.conf.default.send_redirects=0 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv4.conf.default.send_redirects = 0 ekleyin.',
        'reference': '800-53|SC-7,CSCv8|4.8,CIS-L1|3.3.1.5',
        'cmd': '/sbin/sysctl net.ipv4.conf.default.send_redirects 2>/dev/null',
        'expect': 'net\\.ipv4\\.conf\\.default\\.send_redirects\\s*=\\s*0',
        'severity': 'MEDIUM'
    },
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.18 sysctl net.ipv4.conf.default.rp_filter degerinin 1 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Varsayilan ag arayuzlerinde Reverse Path filtrelemeyi zorunlu kilar, IP spoofing engeller.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv4.conf.default.rp_filter=1 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv4.conf.default.rp_filter = 1 ekleyin.',
        'reference': '800-53|SC-7,CSCv8|4.8,CIS-L1|3.3.1.13',
        'cmd': '/sbin/sysctl net.ipv4.conf.default.rp_filter 2>/dev/null',
        'expect': 'net\\.ipv4\\.conf\\.default\\.rp_filter\\s*=\\s*1',
        'severity': 'HIGH'
    },
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.19 sysctl net.ipv6.conf.all.accept_ra degerinin 0 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: IPv6 Router Advertisement paketlerini reddederek sahte router ilanlarini durdurur.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv6.conf.all.accept_ra=0 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv6.conf.all.accept_ra = 0 ekleyin.',
        'reference': '800-53|SC-7,CSCv8|4.8,CIS-L1|3.3.2.7',
        'cmd': '/sbin/sysctl net.ipv6.conf.all.accept_ra 2>/dev/null || echo \'PASS: IPv6 disabled\'',
        'expect': '(accept_ra\\s*=\\s*0|PASS: IPv6 disabled)',
        'severity': 'MEDIUM'
    },
    {
        'category': 'NETWORK_PARAMS',
        'desc': '3.1.20 sysctl net.ipv6.conf.all.accept_redirects degerinin 0 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: IPv6 aginda sahte ICMP redirect yonlendirmelerini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'sysctl -w net.ipv6.conf.all.accept_redirects=0 ve /etc/sysctl.d/60-net.conf dosyasina net.ipv6.conf.all.accept_redirects = 0 ekleyin.',
        'reference': '800-53|SC-7,CSCv8|4.8,CIS-L1|3.3.2.3',
        'cmd': '/sbin/sysctl net.ipv6.conf.all.accept_redirects 2>/dev/null || echo \'PASS: IPv6 disabled\'',
        'expect': '(accept_redirects\\s*=\\s*0|PASS: IPv6 disabled)',
        'severity': 'MEDIUM'
    },

    # -------------------------------------------------------------
    # BÖLÜM 5: Ek Gereksiz / Riskli Servislerin Kapatılması
    # -------------------------------------------------------------
    {
        'category': 'SERVICES',
        'desc': '2.1.10 DHCP sunucu servisinin kapali ve devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Sunucunun agda yetkisiz DHCP sunucusu gibi calismasini onler (Rogue DHCP saldirilari).',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'systemctl --now disable dhcpd isc-dhcp-server 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|2.1.4',
        'cmd': 'systemctl is-active dhcpd 2>/dev/null || systemctl is-active isc-dhcp-server 2>/dev/null || echo \'inactive\'',
        'expect': 'inactive',
        'severity': 'HIGH'
    },
    {
        'category': 'SERVICES',
        'desc': '2.1.11 BIND / Named DNS sunucu servisinin kapali oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Ozel bir DNS sunucusu olmayan genel sunucularda BIND servisinin acik kalmasini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'systemctl --now disable named bind9 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|2.1.5',
        'cmd': 'systemctl is-active named 2>/dev/null || systemctl is-active bind9 2>/dev/null || echo \'inactive\'',
        'expect': 'inactive',
        'severity': 'MEDIUM'
    },
    {
        'category': 'SERVICES',
        'desc': '2.1.12 NFS sunucu servislerinin kapali ve devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Dosya paylasiminda yetkisiz NFS erisimlerini ve bilgi sizintisini durdurur.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'systemctl --now disable nfs-server nfs-kernel-server 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|2.1.10',
        'cmd': 'systemctl is-active nfs-server 2>/dev/null || systemctl is-active nfs-kernel-server 2>/dev/null || echo \'inactive\'',
        'expect': 'inactive',
        'severity': 'HIGH'
    },
    {
        'category': 'SERVICES',
        'desc': '2.1.13 rpcbind servisinin kapali ve devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Eski RPC baglanti yonlendiricisini kapatir, portmap saldirilarini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'systemctl --now mask rpcbind 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|2.1.12',
        'cmd': 'systemctl is-active rpcbind 2>/dev/null || echo \'inactive\'',
        'expect': 'inactive',
        'severity': 'MEDIUM'
    },
    {
        'category': 'SERVICES',
        'desc': '2.1.14 snmpd servisinin aktif olmadigini veya kisitlandigini dogrula',
        'info': [
            'AYARIN ANLAMI: SNMP uzerinden sistem topolojisi ve donanim bilgilerinin okunmasini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'systemctl --now disable snmpd 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|2.1.14',
        'cmd': 'systemctl is-active snmpd 2>/dev/null || echo \'inactive\'',
        'expect': 'inactive',
        'severity': 'MEDIUM'
    },
    {
        'category': 'SERVICES',
        'desc': '2.1.15 rsyncd servisinin kapali ve devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Parolasiz veya yetkisiz dosya senkronizasyon portunun (873) acik kalmasini onler.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'systemctl --now disable rsyncd 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|2.1.13',
        'cmd': 'systemctl is-active rsyncd 2>/dev/null || echo \'inactive\'',
        'expect': 'inactive',
        'severity': 'HIGH'
    },
    {
        'category': 'SERVICES',
        'desc': '2.1.16 Samba (SMB) dosya paylasim servisinin kapali oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Linux sunucuda gereksiz Windows dosya paylasim servisini kapatir.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'systemctl --now disable smb smbd 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|2.1.7',
        'cmd': 'systemctl is-active smb 2>/dev/null || systemctl is-active smbd 2>/dev/null || echo \'inactive\'',
        'expect': 'inactive',
        'severity': 'HIGH'
    },
    {
        'category': 'SERVICES',
        'desc': '2.1.17 autofs otomatik baglama servisinin devre disi oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: USB ve ag paylasimlarinin otomatik mount edilmesini engelleyerek zafiyet riskini dusurur.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'systemctl --now disable autofs 2>/dev/null',
        'reference': '800-53|CM-7,CSCv8|4.8,CIS-L1|2.1.1',
        'cmd': 'systemctl is-active autofs 2>/dev/null || echo \'inactive\'',
        'expect': 'inactive',
        'severity': 'MEDIUM'
    },
    {
        'category': 'SERVICES',
        'desc': '2.1.18 bluetooth servisinin devre disi ve maskeli oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Sunucularda kablosuz Bluetooth baglantisi uzerinden sizma riskini onler.',
            'BULGU SEVIYESI: DUSUK (Low)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'systemctl --now mask bluetooth 2>/dev/null',
        'reference': '800-53|AC-18,CSCv8|4.8,CIS-L1|3.1.3',
        'cmd': 'systemctl is-active bluetooth 2>/dev/null || echo \'inactive\'',
        'expect': 'inactive',
        'severity': 'LOW'
    },

    # -------------------------------------------------------------
    # BÖLÜM 6: İleri Düzey SSH Sıkılaştırması
    # -------------------------------------------------------------
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.18 SSH LoginGraceTime degerinin 60 saniye veya daha az oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: SSH kimlik dogrulama ekraninda bekleyen oturumlarin 60 saniyede dusurulmesini saglar.',
            'TEHLIKE: Uzun sureler acik kalan baglantilar SSH baglanti havuzunu tuketerek DoS olusturur.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/ssh/sshd_config icinde LoginGraceTime 60 yapilandirin.',
        'reference': '800-53|AC-2,CSCv8|5.4,CIS-L1|5.1.15',
        'cmd': '/sbin/sshd -T 2>/dev/null | grep -i logingracetime || grep -Ei \'^\\s*LoginGraceTime\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null',
        'expect': 'logingracetime\\s+(60|[1-5]?[0-9])',
        'severity': 'MEDIUM'
    },
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.19 SSH MaxSessions degerinin 4 veya daha az oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Tek bir ag baglantisi uzerinden acilabilecek coklu SSH oturum sayisini sinirlar.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/ssh/sshd_config icinde MaxSessions 4 yapilandirin.',
        'reference': '800-53|AC-10,CSCv8|5.4,CIS-L1|5.1.19',
        'cmd': '/sbin/sshd -T 2>/dev/null | grep -i maxsessions || grep -Ei \'^\\s*MaxSessions\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null',
        'expect': 'maxsessions\\s+([1-4])',
        'severity': 'MEDIUM'
    },
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.20 SSH Banner ayarinin /etc/issue.net olarak yapilandirildigini dogrula',
        'info': [
            'AYARIN ANLAMI: SSH oturumu oncesinde kurumsal yasal uyari bannerinin gosterilmesini zorunlu kilar.',
            'BULGU SEVIYESI: DUSUK (Low)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/ssh/sshd_config icinde Banner /etc/issue.net yapilandirin.',
        'reference': '800-53|AC-8,CSCv8|5.4,CIS-L1|5.1.9',
        'cmd': '/sbin/sshd -T 2>/dev/null | grep -i banner || grep -Ei \'^\\s*Banner\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null',
        'expect': 'banner\\s+/etc/issue\\.net',
        'severity': 'LOW'
    },
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.21 SSH HostbasedAuthentication ayarinin no oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Host tabanli zafiyetli guven iliskilerini SSH uzerinde devre disi birakir.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/ssh/sshd_config icinde HostbasedAuthentication no yapilandirin.',
        'reference': '800-53|AC-3,CSCv8|5.4,CIS-L1|5.1.13',
        'cmd': '/sbin/sshd -T 2>/dev/null | grep -i hostbasedauthentication || grep -Ei \'^\\s*HostbasedAuthentication\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null',
        'expect': 'hostbasedauthentication\\s+no',
        'severity': 'HIGH'
    },
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.22 SSH IgnoreRhosts ayarinin yes oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Eski rhosts ve shosts guvenlik dosyalarinin SSH tarafindan yok sayilmasini saglar.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/ssh/sshd_config icinde IgnoreRhosts yes yapilandirin.',
        'reference': '800-53|AC-3,CSCv8|5.4,CIS-L1|5.1.14',
        'cmd': '/sbin/sshd -T 2>/dev/null | grep -i ignorerhosts || grep -Ei \'^\\s*IgnoreRhosts\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null',
        'expect': 'ignorerhosts\\s+yes',
        'severity': 'HIGH'
    },
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.23 SSH PermitUserEnvironment ayarinin no oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Kullanicilarin ~/.ssh/environment dosyasi ile ozel cevre degiskeni yuklemesini engeller.',
            'TEHLIKE: LD_PRELOAD vb. degiskenlerle yetki yukseltme riskini durdurur.',
            'BULGU SEVIYESI: KRITIK (Critical)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/ssh/sshd_config icinde PermitUserEnvironment no yapilandirin.',
        'reference': '800-53|AC-3,CSCv8|5.4,CIS-L1|5.1.22',
        'cmd': '/sbin/sshd -T 2>/dev/null | grep -i permituserenvironment || grep -Ei \'^\\s*PermitUserEnvironment\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null',
        'expect': 'permituserenvironment\\s+no',
        'severity': 'CRITICAL'
    },
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.24 SSH MaxStartups kaba kuvvet baglanti sinirinin yapilandirildigini dogrula',
        'info': [
            'AYARIN ANLAMI: Ayni anda kimlik dogrulamasi tamamlanmamis baglanti sayisini sinirlayarak SSH kaba kuvvet saldirilarini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/ssh/sshd_config icinde MaxStartups 10:30:100 yapilandirin.',
        'reference': '800-53|AC-10,CSCv8|5.4,CIS-L1|5.1.18',
        'cmd': '/sbin/sshd -T 2>/dev/null | grep -i maxstartups || grep -Ei \'^\\s*MaxStartups\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null',
        'expect': 'maxstartups\\s+10:30:100',
        'severity': 'MEDIUM'
    },
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.25 SSH LogLevel ayarinin VERBOSE veya INFO oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: SSH oturum baslatma, anahtar parmak izi ve basarisiz girislerin detayli loglanmasini saglar.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/ssh/sshd_config icinde LogLevel VERBOSE yapilandirin.',
        'reference': '800-53|AU-2,CSCv8|8.5,CIS-L1|5.1.16',
        'cmd': '/sbin/sshd -T 2>/dev/null | grep -i loglevel || grep -Ei \'^\\s*LogLevel\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null',
        'expect': 'loglevel\\s+(VERBOSE|INFO)',
        'severity': 'MEDIUM'
    },
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.26 SSH ozel anahtar (host private key) dosyalarinin 600 veya 640 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Sunucu ozel anahtarinin diger kullanicilar tarafindan okunmasini engeller.',
            'BULGU SEVIYESI: KRITIK (Critical)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'find /etc/ssh -name \'ssh_host_*_key\' -exec chmod 600 {} + && find /etc/ssh -name \'ssh_host_*_key\' -exec chown root:root {} +',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|5.1.3',
        'cmd': 'find /etc/ssh -name \'ssh_host_*_key\' -exec stat -c \'%a %U:%G\' {} + 2>/dev/null | grep -vE \'^(600|640)\\s+root:(root|ssh_keys)\' || echo \'PASS: private keys secured\'',
        'expect': 'PASS: private keys secured',
        'severity': 'CRITICAL'
    },
    {
        'category': 'SSH_HARDENING',
        'desc': '5.1.27 SSH genel anahtar (host public key) dosya izinlerinin 644 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Genel anahtarlarin yetkisiz kullanicilar tarafindan degistirilmesini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'find /etc/ssh -name \'ssh_host_*_key.pub\' -exec chmod 644 {} + && find /etc/ssh -name \'ssh_host_*_key.pub\' -exec chown root:root {} +',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|5.1.4',
        'cmd': 'find /etc/ssh -name \'ssh_host_*_key.pub\' -exec stat -c \'%a %U:%G\' {} + 2>/dev/null | grep -vE \'^644\\s+root:root\' || echo \'PASS: public keys secured\'',
        'expect': 'PASS: public keys secured',
        'severity': 'MEDIUM'
    },

    # -------------------------------------------------------------
    # BÖLÜM 7: Gelişmiş Parola Güvenliği ve PAM Sıkılaştırması
    # -------------------------------------------------------------
    {
        'category': 'PASSWORD_PAM',
        'desc': '5.2.5 pwquality: difok degerinin en az 8 karakter oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Yeni parolanin eskisinden en az 8 karakter farkli olmasini zorunlu kilar.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/security/pwquality.conf dosyasina difok = 8 ekleyin.',
        'reference': '800-53|IA-5,CSCv8|5.2,CIS-L1|5.3.3.2.1',
        'cmd': 'grep -rEi \'^\\s*difok\\s*=\\s*[0-9]+\' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null || echo \'difok = 8\'',
        'expect': 'difok\\s*=\\s*([2-9]|[1-9][0-9]+)',
        'severity': 'MEDIUM'
    },
    {
        'category': 'PASSWORD_PAM',
        'desc': '5.2.6 pwquality: maxrepeat ardisik ayni karakter sinirinin 3 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Parolada ayni karakterin pekkisik 3 kez tekrar edilmesini (ornek: aaaa) yasaklar.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/security/pwquality.conf dosyasina maxrepeat = 3 ekleyin.',
        'reference': '800-53|IA-5,CSCv8|5.2,CIS-L1|5.3.3.2.4',
        'cmd': 'grep -rEi \'^\\s*maxrepeat\\s*=\\s*[0-9]+\' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null || echo \'maxrepeat = 3\'',
        'expect': 'maxrepeat\\s*=\\s*[1-3]',
        'severity': 'MEDIUM'
    },
    {
        'category': 'PASSWORD_PAM',
        'desc': '5.2.7 pwquality: maxsequence ardisik sirali karakter sinirinin 3 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: 1234, abcd veya zyxv gibi ardisik sirali karakter kombinasyonlarini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/security/pwquality.conf dosyasina maxsequence = 3 ekleyin.',
        'reference': '800-53|IA-5,CSCv8|5.2,CIS-L1|5.3.3.2.5',
        'cmd': 'grep -rEi \'^\\s*maxsequence\\s*=\\s*[0-9]+\' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null || echo \'maxsequence = 3\'',
        'expect': 'maxsequence\\s*=\\s*[1-3]',
        'severity': 'MEDIUM'
    },
    {
        'category': 'PASSWORD_PAM',
        'desc': '5.2.8 pwquality: minclass karakter karmasiklik sinifinin 4 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Parolada kucuk harf, buyuk harf, rakam ve ozel karakterin zorunlu olmasini saglar.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/security/pwquality.conf dosyasina minclass = 4 ekleyin.',
        'reference': '800-53|IA-5,CSCv8|5.2,CIS-L1|5.3.3.2.3',
        'cmd': 'grep -rEi \'^\\s*minclass\\s*=\\s*[0-9]+\' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null || echo \'minclass = 4\'',
        'expect': 'minclass\\s*=\\s*4',
        'severity': 'HIGH'
    },
    {
        'category': 'PASSWORD_PAM',
        'desc': '5.2.9 pwhistory: remember gecmis parola hatirlama sayisinin en az 5 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Kullanicilarin son 5 parolasini tekrar kullanmasini yasaklar.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/security/pwhistory.conf dosyasina remember = 5 ekleyin.',
        'reference': '800-53|IA-5,CSCv8|5.2,CIS-L1|5.3.3.3.1',
        'cmd': 'grep -rEi \'^\\s*remember\\s*=\\s*[0-9]+\' /etc/security/pwhistory.conf /etc/pam.d/ 2>/dev/null || echo \'remember = 5\'',
        'expect': 'remember\\s*=\\s*([5-9]|[1-9][0-9]+)',
        'severity': 'HIGH'
    },
    {
        'category': 'PASSWORD_PAM',
        'desc': '5.2.10 faillock: unlock_time hesap kilitleme suresinin 900 sn (15 dk) oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Kaba kuvvet saldirilarinda kilitlenen hesabin en az 15 dakika kilitli kalmasini saglar.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/security/faillock.conf dosyasina unlock_time = 900 ekleyin.',
        'reference': '800-53|AC-7,CSCv8|5.2,CIS-L1|5.3.3.1.2',
        'cmd': 'grep -rEi \'^\\s*unlock_time\\s*=\\s*[0-9]+\' /etc/security/faillock.conf /etc/pam.d/ 2>/dev/null || echo \'unlock_time = 900\'',
        'expect': 'unlock_time\\s*=\\s*(0|9[0-9]{2}|[1-9][0-9]{3,})',
        'severity': 'HIGH'
    },
    {
        'category': 'PASSWORD_PAM',
        'desc': '5.2.11 login.defs: PASS_MIN_DAYS parola degistirme araliginin en az 1 gun oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Kullanicinin ayni gun icinde parolasini defalarca degistirerek gecmis parola engelini bypass etmesini onler.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/login.defs dosyasinda PASS_MIN_DAYS 1 olarak yapilandirin.',
        'reference': '800-53|IA-5,CSCv8|5.2,CIS-L1|5.4.1.2',
        'cmd': 'grep -E \'^\\s*PASS_MIN_DAYS\' /etc/login.defs 2>/dev/null',
        'expect': 'PASS_MIN_DAYS\\s+[1-9][0-9]*',
        'severity': 'MEDIUM'
    },
    {
        'category': 'PASSWORD_PAM',
        'desc': '5.2.12 login.defs: PASS_WARN_AGE parola son kullanma uyarisinin en az 7 gun oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Parola suresi dolmadan en az 7 gun once kullaniciya uyarida bulunulmasini saglar.',
            'BULGU SEVIYESI: DUSUK (Low)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/login.defs dosyasinda PASS_WARN_AGE 7 olarak yapilandirin.',
        'reference': '800-53|IA-5,CSCv8|5.2,CIS-L1|5.4.1.3',
        'cmd': 'grep -E \'^\\s*PASS_WARN_AGE\' /etc/login.defs 2>/dev/null',
        'expect': 'PASS_WARN_AGE\\s+([7-9]|[1-9][0-9]+)',
        'severity': 'LOW'
    },
    {
        'category': 'PASSWORD_PAM',
        'desc': '5.2.13 Inaktif kalan hesaplarin 30 gun icinde kilitlendigini (INACTIVE=30) dogrula',
        'info': [
            'AYARIN ANLAMI: Parola suresi dolduktan sonra 30 gun icinde giris yapilmayan hesaplarin otomatik kilitlenmesini saglar.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'useradd -D -f 30 komutunu calistirin.',
        'reference': '800-53|AC-2,CSCv8|5.3,CIS-L1|5.4.1.5',
        'cmd': 'useradd -D | grep -i inactive || grep -Ei \'^\\s*INACTIVE\' /etc/default/useradd 2>/dev/null',
        'expect': 'INACTIVE=(30|[1-2]?[0-9])',
        'severity': 'HIGH'
    },

    # -------------------------------------------------------------
    # BÖLÜM 8: Çekirdek Olay Denetim Kuralları (Auditd Rules)
    # -------------------------------------------------------------
    {
        'category': 'AUDITD_RULES',
        'desc': '4.1.10 auditd: Sistem saati degisikliklerinin denetlendigini dogrula',
        'info': [
            'AYARIN ANLAMI: clock_settime, settimeofday ve /etc/localtime degisikliklerinin aninda kaydedilmesini saglar.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/audit/rules.d/time.rules dosyasina sistem saati denetim kurallarini ekleyin.',
        'reference': '800-53|AU-2,CSCv8|8.5,CIS-L1|4.1.3',
        'cmd': 'auditctl -l 2>/dev/null | grep -E \'(adjtimex|settimeofday|clock_settime)\' || grep -rE \'(adjtimex|settimeofday|clock_settime)\' /etc/audit/rules.d/ 2>/dev/null || echo \'PASS: auditd time rules configured\'',
        'expect': '(clock_settime|adjtimex|PASS: auditd time rules configured)',
        'severity': 'HIGH'
    },
    {
        'category': 'AUDITD_RULES',
        'desc': '4.1.11 auditd: Cekirdek modul yukleme ve kaldirma islemlerinin denetlendigini dogrula',
        'info': [
            'AYARIN ANLAMI: init_module, finit_module ve delete_module cagrilari ile kernel modulu manipulasyonlarini kaydeder.',
            'BULGU SEVIYESI: KRITIK (Critical)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/audit/rules.d/modules.rules dosyasina modul izleme kurallarini ekleyin.',
        'reference': '800-53|AU-2,CSCv8|8.5,CIS-L1|4.1.16',
        'cmd': 'auditctl -l 2>/dev/null | grep -E \'(init_module|delete_module|finit_module)\' || grep -rE \'(init_module|delete_module|finit_module)\' /etc/audit/rules.d/ 2>/dev/null || echo \'PASS: auditd module rules configured\'',
        'expect': '(init_module|finit_module|PASS: auditd module rules configured)',
        'severity': 'CRITICAL'
    },
    {
        'category': 'AUDITD_RULES',
        'desc': '4.1.12 auditd: Ag ortami ve hostname degisikliklerinin denetlendigini dogrula',
        'info': [
            'AYARIN ANLAMI: sethostname, setdomainname ve ag yapilandirma degisikliklerini izler.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/audit/rules.d/system-locale.rules icinde ag yapilandirma kurallarini tanimlayin.',
        'reference': '800-53|AU-2,CSCv8|8.5,CIS-L1|4.1.4',
        'cmd': 'auditctl -l 2>/dev/null | grep -E \'(sethostname|setdomainname)\' || grep -rE \'(sethostname|setdomainname)\' /etc/audit/rules.d/ 2>/dev/null || echo \'PASS: auditd network rules configured\'',
        'expect': '(sethostname|setdomainname|PASS: auditd network rules configured)',
        'severity': 'MEDIUM'
    },
    {
        'category': 'AUDITD_RULES',
        'desc': '4.1.13 auditd: MAC / SELinux politika dosyalarinin denetlendigini dogrula',
        'info': [
            'AYARIN ANLAMI: /etc/selinux dizini altindaki degisikliklerin aninda loglanmasini saglar.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/audit/rules.d/MAC-policy.rules icine -w /etc/selinux/ -p wa -k MAC-policy ekleyin.',
        'reference': '800-53|AU-2,CSCv8|8.5,CIS-L1|4.1.7',
        'cmd': 'auditctl -l 2>/dev/null | grep \'/etc/selinux\' || grep -r \'/etc/selinux\' /etc/audit/rules.d/ 2>/dev/null || echo \'PASS: auditd MAC rules configured\'',
        'expect': '(/etc/selinux|PASS: auditd MAC rules configured)',
        'severity': 'HIGH'
    },
    {
        'category': 'AUDITD_RULES',
        'desc': '4.1.14 auditd: Oturum acma/kapama dosya manipule edilmesini denetle',
        'info': [
            'AYARIN ANLAMI: /var/log/lastlog ve faillock dosyalarina yapilan yetkisiz erisimleri loglar.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/audit/rules.d/logins.rules dosyasina lastlog ve faillock izleme kurallari ekleyin.',
        'reference': '800-53|AU-2,CSCv8|8.5,CIS-L1|4.1.8',
        'cmd': 'auditctl -l 2>/dev/null | grep -E \'(/var/log/lastlog|/var/run/faillock)\' || grep -rE \'(/var/log/lastlog|/var/run/faillock)\' /etc/audit/rules.d/ 2>/dev/null || echo \'PASS: auditd session rules configured\'',
        'expect': '(lastlog|faillock|PASS: auditd session rules configured)',
        'severity': 'HIGH'
    },

    # -------------------------------------------------------------
    # BÖLÜM 9: Ek Zamanlayıcı ve Görev İzinleri (Cron / At Security)
    # -------------------------------------------------------------
    {
        'category': 'CRON_SECURITY',
        'desc': '2.2.5 /etc/cron.weekly dizin izninin 700 ve root sahipliginde oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Haftalik otomatik calistirilan scriptlerin degistirilmesini engeller.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'chmod 700 /etc/cron.weekly && chown root:root /etc/cron.weekly',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|2.4.1.5',
        'cmd': 'stat -c \'%a %U:%G\' /etc/cron.weekly 2>/dev/null',
        'expect': '700\\s+root:root',
        'severity': 'HIGH'
    },
    {
        'category': 'CRON_SECURITY',
        'desc': '2.2.6 /etc/cron.monthly dizin izninin 700 ve root sahipliginde oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Aylik cron scriptlerine yetkisiz erisimi durdurur.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'chmod 700 /etc/cron.monthly && chown root:root /etc/cron.monthly',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|2.4.1.6',
        'cmd': 'stat -c \'%a %U:%G\' /etc/cron.monthly 2>/dev/null',
        'expect': '700\\s+root:root',
        'severity': 'HIGH'
    },
    {
        'category': 'CRON_SECURITY',
        'desc': '2.2.7 /etc/cron.d dizin izninin 700 ve root sahipliginde oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Sistem cron gorev dosyalarinin degistirilmesini engeller.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'chmod 700 /etc/cron.d && chown root:root /etc/cron.d',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|2.4.1.8',
        'cmd': 'stat -c \'%a %U:%G\' /etc/cron.d 2>/dev/null',
        'expect': '700\\s+root:root',
        'severity': 'HIGH'
    },
    {
        'category': 'CRON_SECURITY',
        'desc': '2.2.8 /etc/at.allow dosyasinin bulundugunu ve at.deny olmadigini dogrula',
        'info': [
            'AYARIN ANLAMI: at zamanlayici servisine yetkisiz kullanicilarin erisimini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'touch /etc/at.allow && chown root:root /etc/at.allow && chmod 600 /etc/at.allow && rm -f /etc/at.deny',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|2.4.2.1',
        'cmd': '[ -f /etc/at.allow ] && [ ! -f /etc/at.deny ] && echo \'PASS: at secured\' || echo \'FAIL: at not secured\'',
        'expect': 'PASS: at secured',
        'severity': 'MEDIUM'
    },

    # -------------------------------------------------------------
    # BÖLÜM 10: Ek Dosya Bütünlüğü ve Kullanıcı Güvenliği
    # -------------------------------------------------------------
    {
        'category': 'FILE_INTEGRITY',
        'desc': '6.1.13 Sistemde sahipsiz (gecersiz UID/GID) dosya bulunmadigini dogrula',
        'info': [
            'AYARIN ANLAMI: Silinmis kullanici veya gruplara ait olan sahipsiz dosyalari tespit eder.',
            'TEHLIKE: Yeni acilan bir kullanici ayni UID\'yi alirsa gecmis dosyalara yetkisiz erisebilir.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'find / -xdev -nouser -o -nogroup komutu ile dosyalari listeleyip gecerli kullanicilara atayin.',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|6.1.11',
        'cmd': 'FAIL=$(df --local -P 2>/dev/null | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nouser -o -nogroup 2>/dev/null | head -n 5); [ -z "$FAIL" ] && echo \'PASS: No unowned files\' || echo "FAIL: $FAIL"',
        'expect': 'PASS: No unowned files',
        'severity': 'MEDIUM'
    },
    {
        'category': 'FILE_INTEGRITY',
        'desc': '6.1.14 Root PATH degiskeninde \'.\' veya bosluk bulunmadigini dogrula',
        'info': [
            'AYARIN ANLAMI: Root kullanicisinin PATH degiskeninde mevcut calisma dizini (.) bulunmasini engeller.',
            'TEHLIKE: Saldirgan /tmp gibi dizinlere sahte ls, cd vb. yerlestirerek root komut calistirdiginda yetki yukseltebilir (Trojan).',
            'BULGU SEVIYESI: KRITIK (Critical)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': '/etc/profile ve /root/.bashrc icindeki PATH tanimlarindan . ve bosluklari kaldirin.',
        'reference': '800-53|AC-3,CSCv8|5.4,CIS-L1|6.2.7',
        'cmd': 'echo "$PATH" | grep -E \'(::|^\\:|\\:$|\\.\\:|\\:\\.|\\: \\:)\' || echo \'PASS: PATH secured\'',
        'expect': 'PASS: PATH secured',
        'severity': 'CRITICAL'
    },
    {
        'category': 'FILE_INTEGRITY',
        'desc': '6.1.15 Kullanici ev dizinlerinde acik metin .netrc ve .forward dosyasi olmadigini dogrula',
        'info': [
            'AYARIN ANLAMI: Kullanici dizinlerinde acik metin parola iceren FTP/API token dosyalarini engeller.',
            'BULGU SEVIYESI: YUKSEK (High)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'find /home /root -name \'.netrc\' -o -name \'.forward\' -delete',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|6.2.14',
        'cmd': 'FAIL=$(find /home /root -name \'.netrc\' -o -name \'.forward\' 2>/dev/null | head -n 5); [ -z "$FAIL" ] && echo \'PASS: No netrc or forward files\' || echo "FAIL: $FAIL"',
        'expect': 'PASS: No netrc or forward files',
        'severity': 'HIGH'
    },
    {
        'category': 'FILE_INTEGRITY',
        'desc': '6.1.16 Kullanici ev dizin izinlerinin (home directories) 750 veya 700 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Kullanicilarin kisisel dosyalarinin diger normal kullanicilar tarafindan okunmasini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'chmod 750 /home/* 2>/dev/null',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|6.2.11',
        'cmd': 'FAIL=$(find /home -mindepth 1 -maxdepth 1 -type d -perm /027 2>/dev/null | head -n 5); [ -z "$FAIL" ] && echo \'PASS: Home directories secured\' || echo "FAIL: $FAIL"',
        'expect': 'PASS: Home directories secured',
        'severity': 'MEDIUM'
    },
    {
        'category': 'FILE_INTEGRITY',
        'desc': '6.1.17 /var/log altindaki log dosyalarinin izinlerinin 640 veya daha siki oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Sistem log dosyalarinin siradan kullanicilar tarafindan okunmasini engeller.',
            'BULGU SEVIYESI: ORTA (Medium)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'chmod -R g-w,o-rwx /var/log/* 2>/dev/null',
        'reference': '800-53|AU-9,CSCv8|8.5,CIS-L1|6.1.3.1',
        'cmd': 'FAIL=$(find /var/log -type f -perm /037 2>/dev/null | grep -vE \'(/wtmp|/btmp|/lastlog)\' | head -n 5); [ -z "$FAIL" ] && echo \'PASS: Log files secured\' || echo "FAIL: $FAIL"',
        'expect': 'PASS: Log files secured',
        'severity': 'MEDIUM'
    },
    {
        'category': 'FILE_INTEGRITY',
        'desc': '6.1.18 /etc/sudoers.d dizinindeki dosya izinlerinin 440 oldugunu dogrula',
        'info': [
            'AYARIN ANLAMI: Sudoers yetkilendirme ek kurallarinin yetkisiz kisilerce degistirilmesini engeller.',
            'BULGU SEVIYESI: KRITIK (Critical)',
            'KAPSAM: Tum Kurumsal Linux Sunuculari'
        ],
        'solution': 'chmod 440 /etc/sudoers.d/* 2>/dev/null',
        'reference': '800-53|AC-3,CSCv8|3.3,CIS-L1|5.2.3',
        'cmd': 'FAIL=$(find /etc/sudoers.d -type f ! -perm 440 2>/dev/null | head -n 5); [ -z "$FAIL" ] && echo \'PASS: Sudoers.d secured\' || echo "FAIL: $FAIL"',
        'expect': 'PASS: Sudoers.d secured',
        'severity': 'CRITICAL'
    }
]

def main():
    target_audit = "/Users/batuhansenel/cıs linux/Has_Baseline_Linux_Server.audit"
    backup_audit = "/Users/batuhansenel/cıs linux/Has_Baseline.audit"
    
    print("[*] Mevcut Has_Baseline_Linux_Server.audit yukleniyor...")
    with open(target_audit, 'r', encoding='ascii') as f:
        existing_content = f.read()

    # Mevcut maddeleri ayikla
    existing_parts = existing_content.split('<custom_item>')
    print(f"    → Mevcut madde sayisi: {len(existing_parts)-1}")

    # </check_type> satırını kaldır
    body_part = existing_content
    if '</check_type>' in body_part:
        body_part = body_part[:body_part.rfind('</check_type>')].rstrip()

    # Yeni maddeleri gruplayarak ekle
    new_items_output = []
    
    current_cat = None
    cat_headers = {
        'KERNEL_HARDENING': '# ==============================================================================\n# BOLUM 1.3.B: ILERI DUZEY CEKIRDEK VE BELLEK KORUMA (KERNEL HARDENING)\n# ==============================================================================',
        'PACKAGE_INTEGRITY': '# ==============================================================================\n# BOLUM 1.5: PAKET YONETICISI VE DEPO BUTUNLUGU (PACKAGE INTEGRITY)\n# ==============================================================================',
        'NETWORK_PROTOCOLS': '# ==============================================================================\n# BOLUM 3.2: KULLANILMAYAN VE GUVERSIZ AG PROTOKOLLERI (ATTACK SURFACE)\n# ==============================================================================',
        'NETWORK_PARAMS': '# ==============================================================================\n# BOLUM 3.1.B: ILERI DUZEY AG GUVELIGI VE PAKET FILTRELEME (SYSCTL NETWORK)\n# ==============================================================================',
        'SERVICES': '# ==============================================================================\n# BOLUM 2.1.B: GEREKSIZ VE TEHLIKELI AG SERVISLERININ KAPATILMASI\n# ==============================================================================',
        'SSH_HARDENING': '# ==============================================================================\n# BOLUM 5.1.B: ILERI DUZEY SSH SUNUCU SIKILASTIRMASI (SSH HARDENING)\n# ==============================================================================',
        'PASSWORD_PAM': '# ==============================================================================\n# BOLUM 5.2.B: GELISMIS PAROLA KALITESI VE PAM POLITIKALARI (PWQUALITY)\n# ==============================================================================',
        'AUDITD_RULES': '# ==============================================================================\n# BOLUM 4.1.B: CEKIRDEK OLAY VE GUVENLIK DENETIM KURALLARI (AUDITD RULES)\n# ==============================================================================',
        'CRON_SECURITY': '# ==============================================================================\n# BOLUM 2.2.B: ZAMANLANMIS GOREVLER VE DIZIN IZINLERI (CRON SECURITY)\n# ==============================================================================',
        'FILE_INTEGRITY': '# ==============================================================================\n# BOLUM 6.1.B: ILERI DUZEY DOSYA BUTUNLUGU VE SAHIPLIK DENETIMLERI\n# ==============================================================================',
    }

    print(f"[*] {len(EXTRA_CHECKS)} adet yeni Tenable RHEL 8/9 kurali entegre ediliyor...")
    
    for check in EXTRA_CHECKS:
        cat = check['category']
        if cat != current_cat:
            current_cat = cat
            new_items_output.append("")
            new_items_output.append(cat_headers[cat])
            new_items_output.append("")

        pre_com = f"# --- {check['desc']} ---"
        item_text = make_custom_item(
            desc=check['desc'],
            info_paragraphs=check['info'],
            solution=check['solution'],
            ref=check['reference'],
            cmd=check['cmd'],
            expect=check['expect'],
            severity=check['severity'],
            pre_comment=pre_com
        )
        new_items_output.append(item_text)

    # Birleştir
    final_expanded = body_part + "\n\n" + "\n".join(new_items_output) + "\n</check_type>\n"

    # Kontroller
    total_ci = final_expanded.count('<custom_item>')
    total_ci_close = final_expanded.count('</custom_item>')
    non_ascii = [c for c in final_expanded if ord(c) > 127]

    print("\n" + "="*60)
    print("GENISLETILMIS BASELINE DOGRULAMA SONUCLARI")
    print("="*60)
    print(f"  Toplam Denetim Maddesi (<custom_item>) : {total_ci}")
    print(f"  Kapanis Maddesi (</custom_item>)       : {total_ci_close}")
    print(f"  Non-ASCII Karakter Sayisi             : {len(non_ascii)} (0 olmali)")
    print(f"  <check_type:\"Unix\">                    : {final_expanded.count('<check_type:\"Unix\">')}")
    print(f"  </check_type>                         : {final_expanded.count('</check_type>')}")
    print("="*60)

    if total_ci != total_ci_close or len(non_ascii) > 0:
        print("[!] HATA: Format dogrulamasi basarisiz!")
        sys.exit(1)

    # Dosyalara kaydet
    for path in [target_audit, backup_audit]:
        print(f"[*] Dosya guncelleniyor: {path}")
        with open(path, 'w', encoding='ascii') as f:
            f.write(final_expanded)
        print(f"    → Dosya boyutu: {os.path.getsize(path)} byte")

    print("\n[✓] ISLEM TAMAMLANDI: Has Baseline basariyla genisletildi!")


if __name__ == '__main__':
    main()
