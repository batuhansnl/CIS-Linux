# CIS Linux Level 1 (L1) Dağıtımlar Arası Karşılaştırmalı Analiz Raporu

Bu rapor, kurumsal altyapınızda bulunan **RHEL (7, 8, 9, CoreOS/OpenShift)**, **Oracle Linux (7, 8, 9)**, **Ubuntu (18.04, 20.04, 22.04, 24.04)**, **SUSE (12, 15/SAP, 16)**, **Debian (12, 13)**, **Rocky Linux (8, 9)** ve **CentOS (6, 7)** dağıtımları için Nessus resmi audit deposundaki 39 adet CIS L1 Benchmark dosyasının analizi sonucunda hazırlanmıştır.

---

## 1. Yönetici Özeti (Executive Summary)

- **İncelenen Toplam Resmi CIS L1 Dosyası:** 39 Adet
- **İncelenen Dağıtım Ailesi Sayısı:** 7 Temel Aile (RHEL, Oracle, Ubuntu, SUSE, Debian, Rocky, CentOS)
- **Tespit Edilen Tekil Kural Sayısı:** 1,325 Kural
- **7 Dağıtım Ailesinin Tamamında (%100) Ortak Kurallar:** 148 Kural
- **En Az 5 Dağıtım Ailesinde (%70+) Ortak Kurallar:** 406 Kural
- **Yalnızca Belirli Bir Dağıtıma/Paket Yöneticisine Özel Kurallar:** 394 Kural (Örn. `apt` vs `rpm` paket denetimleri, `ufw` vs `firewalld`, `apparmor` vs `selinux`)

> [!IMPORTANT]
> **Temel Çıkarım:** Linux işletim sistemlerinin çekirdek (Kernel), SSH protokolü, dosya hiyerarşisi (FHS), PAM mimarisi ve temel GNU yardımcı araçları ortak olduğu için, **güvenlik zafiyetlerinin ve sıkılaştırma gereksinimlerinin %70'inden fazlası evrenseldir.** Bu nedenle, her dağıtım için ayrı scan audit dosyası kullanmak yerine, ortak çekirdeği doğrudan denetleyen ve dağıtıma özel farkları Nessus'un `<if><condition>` mantığıyla dinamik çözen **tek bir Master Audit Dosyası (`Unified_Linux_CIS_L1_Master_Baseline.audit`)** kullanmak operasyonel yönetilebilirliği en üst düzeye çıkarır.

---

## 2. Dağıtımlar Arası Kural Ortaklık Dağılımı

| Kapsam Seviyesi | Dağıtım Ailesi Sayısı | Tekil Kural Sayısı | Oran (%) | Açıklama |
|---|---|---|---|---|
| **Evrensel Çekirdek (Tier 1)** | 7 Ailenin Tümü | 148 Kural | %11.2 | Her Linux makinede harfiyen aynı çalışan kurallar (SSH, sysctl, shadow izinleri vb.) |
| **Geniş Ortaklık (Tier 2)** | 5 - 6 Aile | 258 Kural | %19.5 | Çoğu dağıtımda aynı olup sadece minör sürüm/paket farkı olan kurallar |
| **Aile Bazlı Ortaklık (Tier 3)** | 2 - 4 Aile | 525 Kural | %39.6 | Red Hat ailesi (RPM) veya Debian ailesi (DEB) içinde paylaşılan kurallar |
| **Dağıtıma Özel (Tier 4)** | Yalnızca 1 Dağıtım | 394 Kural | %29.7 | Spesifik paket adı kontrolleri, OS-release sürüm bayrakları |
| **TOPLAM** | - | **1,325 Kural** | **%100** | - |

---

## 3. Güvenlik Alanlarına Göre Ortaklık ve Kritiklik Analizi

| Güvenlik Alanı (Domain) | Toplam Kural | Evrensel/Ortak Kurallar (>=5 Dağıtım) | Dağıtıma Özel Kurallar | Kritiklik Seviyesi |
|---|---|---|---|---|
| **Sistem & Dosya** | 716 | 201 | 515 | `LOW` |
| **Ağ & Kernel (Sysctl)** | 119 | 53 | 66 | `HIGH / CRITICAL` |
| **Kimlik & Parola & Erişim** | 108 | 49 | 59 | `HIGH / CRITICAL` |
| **Güvenlik Duvarı (Firewall)** | 93 | 4 | 89 | `MEDIUM` |
| **Loglama & Denetim (Auditd)** | 72 | 30 | 42 | `MEDIUM` |
| **SSH Güvenliği** | 68 | 24 | 44 | `HIGH / CRITICAL` |
| **Protokol & Dosya Sistemi Karaliste** | 58 | 5 | 53 | `LOW` |
| **Zamanlanmış Görevler (Cron/At)** | 36 | 21 | 15 | `LOW` |
| **Güvensiz Eski Servisler** | 32 | 16 | 16 | `LOW` |
| **Zorunlu Erişim Kontrolü (MAC)** | 23 | 3 | 20 | `MEDIUM` |

---

## 4. Kritiklik Seviyeleri ve Tehdit Modeli (Severity Classification)

Tüm kurallar Nessus ve CIS metodolojisine göre 3 kritiklik seviyesine ayrılmıştır:

### 🔴 YÜKSEK / KRİTİK (High / Critical Severity)
Saldırganın uzaktan doğrudan sisteme girmesine veya yetkisiz bir kullanıcının anında root yetkisi kazanmasına yol açabilecek zaafiyetler:
1. **SSH Root Girişi:** `PermitRootLogin yes` olması (Brute-force saldırıları doğrudan root kullanıcısını hedefler).
2. **Boş Parolalar:** `/etc/shadow` içinde parolasız hesap bulunması veya SSH'ta `PermitEmptyPasswords yes` olması.
3. **Dosya İzin Zafiyetleri:** `/etc/shadow` ve `/etc/gshadow` dosyalarının dünya tarafından okunabilir olması (`000` veya `0640` olmalı).
4. **World-Writable Dosyalar:** Herhangi bir kullanıcının içine zararlı kod enjekte edebileceği sistem dosyaları.
5. **Güvensiz Eski Servisler:** Telnet, rsh, rlogin, talk servislerinin açık olması (Ağ trafiği açık metin gider, şifreler sniff edilebilir).
6. **UID 0 Tekliği:** Sistemde `root` dışında UID'si `0` olan ikinci bir gizli yönetici hesabının bulunması.

### 🟡 ORTA (Medium Severity)
Ağ saldırılarına karşı sistemin mukavemetini artıran ve sistem bütünlüğünü sağlayan parametreler:
1. **Sysctl Ağ Parametreleri:** `net.ipv4.ip_forward = 0` (sunucunun yetkisiz router gibi davranması engellenir), `rp_filter = 1` (IP spoofing engelleme), `tcp_syncookies = 1` (SYN Flood DoS koruması).
2. **Auditd & Günlük Kayıt:** Sistem çağrılarının (saat değişimi, kullanıcı ekleme, sudo çalıştırma) denetlenmesi ve saklanması.
3. **Parola Politikası:** `PASS_MAX_DAYS <= 365`, `PASS_MIN_DAYS >= 1`, `PASS_WARN_AGE >= 7` ve SHA512/yescrypt algoritması.
4. **Cron/At İzinleri:** `/etc/crontab` ve cron dizinlerinin yalnızca root tarafından yazılabilir olması (yetki yükseltme engellenir).
5. **Core Dump Kısıtlaması:** Bellek dökümlerinin (`fs.suid_dumpable = 0`, `limits.conf * hard core 0`) engellenmesi (bellekteki şifrelerin sızması önlenir).
6. **ASLR (Address Space Layout Randomization):** `kernel.randomize_va_space = 2` (Buffer overflow exploitlerini zorlaştırır).

### 🟢 DÜŞÜK / BİLGİ (Low / Info Severity)
Kurumsal farkındalık, yasal bildirim ve gereksiz atak yüzeyini küçültme adımları:
1. **Uyarı Bannerları:** `/etc/issue`, `/etc/issue.net` ve `/etc/motd` üzerinde yasal uyarı metinleri ve OS sürüm bilgisinin gizlenmesi.
2. **Eski Dosya Sistemleri:** `cramfs`, `freevxfs`, `jffs2`, `hfs`, `udf` gibi kullanılmayan dosya sistemi sürücülerinin kara listeye alınması.
3. **Shell Zaman Aşımı:** `TMOUT=900` ayarı ile açık kalan sahipsiz oturumların 15 dakikada otomatik sonlandırılması.

---

## 5. Dağıtım Ailelerinin Ayrıştığı Kritik Noktalar

| Özellik | Red Hat Ailesi (RHEL, Rocky, CentOS, Oracle) | Debian Ailesi (Ubuntu, Debian) | SUSE Ailesi (SLES, SLES for SAP) |
|---|---|---|---|
| **Paket Yöneticisi** | DNF / YUM / RPM (`rpm -q`) | APT / DPKG (`dpkg-query`) | Zypper / RPM (`rpm -q`) |
| **Güvenlik Duvarı** | `firewalld` veya `nftables` | `ufw` veya `nftables` | `firewalld` veya `SuSEfirewall2` |
| **Zorunlu Erişim Kontrolü (MAC)** | `SELinux` (Enforcing) | `AppArmor` (Enforce mode) | `AppArmor` / `SELinux` |
| **Sudo & Yetki Grubu** | `wheel` grubu | `sudo` grubu | `wheel` veya `sudo` grubu |
| **Servis Başlatma (Init)** | systemd (`systemctl`) [CentOS 6: SysV] | systemd (`systemctl`) | systemd (`systemctl`) [SLES 11: SysV] |

