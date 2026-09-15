# Siber Güvence Checklist vs. CIS Level 1 Baseline Karşılaştırma ve Boşluk Analizi (Gap Analysis)

**Tarih:** 15 Eylül 2026  
**Konu:** Linux Sunucular için Configuration Baseline Checklist Değerlendirmesi  
**Hazırlayan:** Sistem / Güvenlik Mühendisliği  

---

## 1. Yönetici Özeti (Executive Summary)

Siber Güvence ekibi tarafından paylaşılan 12 maddelik **"Configuration Baseline Checklist (LinuxServer)"**, geleneksel anlamda bir **"Sistem Devreye Alma / Operasyonel Kabul Listesi (Commissioning & Provisioning Checklist)"** niteliğindedir. 

Hazırlamış olduğumuz **CIS Level 1 Master Server Baseline (105 Kural)** ile karşılaştırıldığında:
1. **Tamamlayıcı Rol:** Siber Güvence'nin listesindeki kurumsal ajanlar (Trend Micro, SolarWinds, ManageEngine) ve vLAN/AD gereksinimleri, işletim sistemi sıkılaştırmasının (Hardening) üzerindeki kurumsal yönetim katmanını temsil etmektedir.
2. **Kritik Güvenlik Boşlukları:** Siber Güvence listesi; çekirdek (kernel) güvenliği, ağ katmanı (sysctl), SSH sıkılaştırması, yetki yükseltme engelleri, dosya bütünlüğü ve SELinux/AppArmor gibi işletim sistemini ayakta tutan temel güvenlik katmanlarını içermemektedir.
3. **Seviye Uyuşmazlığı:** Listenin 5. maddesinde yer alan **Güvenlik Duvarı (Firewall)** gereksiniminin *"Recommended (Tavsiye)"* olarak sınıflandırılması ciddi bir güvenlik zafiyetidir. Modern siber güvenlik standartlarında (CIS, NIST 800-53, PCI-DSS) sunucu yerel güvenlik duvarı **"MUST (Zorunlu)"** olmak zorundadır.

---

## 2. Madde Madde Karşılaştırma Matrisi (Mapping Matrix)

| No | Siber Güvence Maddesi | Statü | Bizim CIS L1 Baseline'daki Durumu | Değerlendirme & Teknik Yorum |
|---|---|---|---|---|
| **1** | VM'in uygun vLAN'a bağlı olması | Must | Hipervizör / Ağ Seviyesi | **Doğru bir gereksinimdir.** Ancak OS içi bir parametre değildir; sanallaştırma (vCenter/ESXi) ve ağ anahtarı (Switch) seviyesinde yönetilir. Nessus ağ taramalarında IP bloğu kontrolüyle doğrulanabilir. |
| **2** | Root için güçlü parola belirlenmesi | Must | **Mevcut & Çok Daha İleri Seviyede (Bölüm 6 & 7)** | CIS'te yalnızca parola karmaşıklığı (`minlen=14`, `pam_pwquality`) değil; doğrudan SSH ile root girişinin kapatılması (`PermitRootLogin no`) zorunludur. Root parolası ağdan brute-force'a maruz bırakılmamalıdır. |
| **3** | Sunucu adının kurallara uygunluğu | Must | İsimlendirme Standardı (Hostname) | **Uygundur.** Sunucu hostname'i `hostnamectl` veya regex kontrolü ile denetlenebilir. Ayrıca `/etc/issue` içinde sürüm bilgisinin ifşa edilmemesi kuralımızla desteklenir. |
| **4** | Uygulamaların OS diskinden ayrı diskte çalışması | Recommended | **Mevcut & Genişletilmiş (Bölüm 2)** | CIS standardında sadece ayrı disk değil; `/tmp`, `/var/tmp`, `/dev/shm` bölümlerine `nodev, nosuid, noexec` mount bayrakları verilerek yetkisiz kod çalıştırma engellenmektedir. |
| **5** | Firewall'un sürekli açık olması | **Recommended** | **Mevcut & ZORUNLU (Bölüm 13 - MUST)** | **DÜZELTME GEREKİR:** Siber Güvence bunu *Recommended* yapmış. Bir sunucuda host-based firewall (firewalld/ufw/nftables) **asla opsiyonel olamaz, MUST yapılmalıdır.** Lateral movement saldırılarını durduran ana kalkandır. |
| **6** | Trend Micro agent ile korunması | Must | **Kurumsal Ajan (Baseline'a Eklendi)** | CIS üretici bağımsız olduğu için marka belirtmez (CIS Control 10: Anti-Malware). Ancak kurumsal standardımız Trend Micro olduğu için `ds_agent` servis kontrolü Master Baseline'ımıza entegre edilmiştir. |
| **7** | ManageEngine agent ve RedHat aboneliği | Must | **Kurumsal Ajan (Baseline'a Eklendi)** | Paketlerin güncelliği ve yama yönetimi için ManageEngine agent ve RHEL sistemlerde `subscription-manager` durumu Master Baseline'a eklenmiştir. |
| **8** | İzinlerin gruplar yerine visudo/sudoers ile verilmesi | Must | **Mevcut (Bölüm 7 - Kural 7.10 & 7.11)** | **Doğru yaklaşım.** Kullanıcılara kontrolsüz grup yetkisi verilmesi yerine, `/etc/sudoers` üzerinden kısıtlı komut yetkisi ve `logfile=/var/log/sudo.log` ile komut denetimi sağlanmalıdır. |
| **9** | VM'e bağlantıda Active Directory (AD) kullanılması | Recommended | **Merkezi Kimlik (Baseline'a Eklendi)** | Sunucuların SSSD / Realmd üzerinden Active Directory'ye dahil edilmesi (LDAP/Kerberos) kurumsal izlenebilirlik için gereklidir. `sssd` servis kontrolü eklenmiştir. |
| **10** | Kurulum sonrası yerel kullanıcılarla oturum açılmaması | Recommended | **Mevcut (Bölüm 7 - Kural 7.9)** | Sistem hesaplarının kabuklarının `/sbin/nologin` yapılması ve interaktif erişimin merkezi AD hesaplarına yönlendirilmesi CIS ile tam örtüşmektedir. |
| **11** | Rsyslog'un aktif edilmesi ve logların iletilmesi | Must | **Mevcut & Genişletilmiş (Bölüm 10 - Kural 10.2)** | Yalnızca rsyslog yetmez; çekirdek seviyesindeki olayları (saat değişimi, kullanıcı ekleme, modül yükleme) yakalayan **auditd** de mutlaka zorunlu olmalıdır. |
| **12** | SolarWinds agent ile izlenmesi | Must | **Kurumsal Ajan (Baseline'a Eklendi)** | Altyapı izleme için `swiagent` servisinin aktiflik kontrolü Master Baseline dosyamıza entegre edilmiştir. |

---

## 3. Siber Güvence Listesindeki Kritik Eksikler (Bizim Ekleyeceğimiz Değer)

Siber Güvence ekibinin listesi yalnızca 12 maddeden ibarettir ve işletim sisteminin **iç savunma mekanizmalarının neredeyse tamamı açıkta kalmıştır**. Siber Güvence ekibine sunulacak geri bildirimde şu başlıkların önemi vurgulanmalıdır:

1. **SSH Güvenlik Sıkılaştırması Yok:** Root doğrudan SSH ile bağlanabilir mi? Boş parolayla girilebilir mi? Maksimum deneme sayısı kaç? Session timeout var mı? (Bunların hepsi bizim baseline'da çözülmüştür).
2. **Çekirdek Ağ Parametreleri (Sysctl) Yok:** IP Forwarding kapalı mı? IP Spoofing koruması (`rp_filter`) açık mı? SYN Flood koruması (`tcp_syncookies`) devrede mi?
3. **Kernel Seviyesi Denetim (auditd) Yok:** Rsyslog yalnızca servis loglarını tutar; root kullanıcısının hangi dosyayı sildiğini, saatle oynayıp oynamadığını veya yetkisiz `open/creat` çağrılarını ancak `auditd` yakalar.
4. **Dosya İzin Korumaları Yok:** `/etc/shadow` ve `/etc/passwd` dosyalarının izinleri kontrol edilmezse yerel yetki yükseltmeler önlenemez.
5. **Sunucuda Olmaması Gereken Servisler Belirtilmemiş:** Sunucularda CUPS (yazıcı servisi), Avahi (mDNS yayın), Telnet, RSH gibi saldırganların en çok kullandığı servislerin yasaklanması gerekir.
6. **Zorunlu Erişim Kontrolü (SELinux / AppArmor) Yok:** Sıfırıncı gün (0-day) açıklarına karşı en büyük kalkan olan SELinux Enforcing modu checklist'te yer almamaktadır.

---

## 4. Sonuç ve Eylem Planı

- Siber Güvence'nin 12 maddelik checklist'i **doğru yöndedir ancak yetersizdir**.
- Bizim hazırladığımız CIS L1 Master Baseline, onların 12 maddesini **%100 kapsamakta** ve üzerine **93 adet kritik teknik işletim sistemi savunma kuralı** eklemektedir.
- Master audit dosyamıza kurumunuza özel **Trend Micro, SolarWinds, ManageEngine, SSSD/AD ve RedHat Subscription** kontrolleri dahil edilmiştir.
