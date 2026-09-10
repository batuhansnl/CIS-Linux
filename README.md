# Nessus CIS Level 1 (L1) Linux Audit Dosyaları ve Kılavuzları

Bu dizin, Tenable Nessus'un resmi uyumluluk denetim deposundan (Tenable Compliance Audits) temin edilmiş, kurumsal Linux altyapısında bulunan dağıtımlar için güncel **CIS Level 1 (L1)** benchmark audit dosyalarını ve referans rehberlerini içermektedir.

---

## Dizin Yapısı

```text
cıs linux/
├── Unified_Linux_CIS_L1_Master_Baseline.audit   # Tüm Linux filosu için birleşik Master CIS L1 Audit dosyası
├── reports/
│   └── CIS_Linux_L1_Karsilastirmali_Analiz_Raporu.md # Dağıtımlar arası kural sıklığı ve kritiklik analiz raporu
├── guides/
│   └── Tenable_Nessus_Compliance_Checks_Reference_Guide.pdf # Tenable resmi audit rehberi
├── audits/
│   ├── RHEL/              # Red Hat Enterprise Linux 9, 8, 7 ve RHCOS / OpenShift
│   ├── Oracle_Linux/      # Oracle Linux 9, 8, 7 (RHEL uyumlu)
│   ├── Ubuntu/            # Ubuntu 24.04, 22.04, 20.04, 18.04 LTS
│   ├── SUSE/              # SLES 16 (Kernel 6.x), SLES 15 (Kernel 5.x / SAP), SLES 12 (Kernel 4.x)
│   ├── Debian/            # Debian 12 & 13 (Kernel 6.x) ve Debian Family
│   ├── Rocky_Linux/       # Rocky Linux 8 (Kernel 4.x) ve Rocky Linux 9
│   └── CentOS/            # CentOS 7 (Kernel 3.x) ve CentOS 6 (Kernel 2.x)
└── README.md              # Dağıtım ve benchmark eşleştirme kataloğu
```

---

## Dağıtım & CIS Benchmark Eşleştirme Tablosu

| Dağıtım / İstek | Dağıtım Versiyonu & Kernel | CIS Benchmark Adı & Seviye | İlgili Audit Dosyası | Kontrol Sayısı |
|---|---|---|---|---|
| **RHEL 9** | 9.0 - 9.8 (9.3, 9.4, 9.6, 9.7, 9.8) | CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 (L1 Server) | `audits/RHEL/CIS_Red_Hat_Enterprise_Linux_9_v2.0.0_L1_Server.audit` | 622 |
| **RHEL 9 (Workstation)** | 9.0 - 9.8 | CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 (L1 Workstation) | `audits/RHEL/CIS_Red_Hat_Enterprise_Linux_9_v2.0.0_L1_Workstation.audit` | 603 |
| **RHEL 8** | 8.0 - 8.10 | CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0 (L1 Server) | `audits/RHEL/CIS_Red_Hat_Enterprise_Linux_8_v4.0.0_L1_Server.audit` | 766 |
| **RHEL 8 (Workstation)** | 8.0 - 8.10 | CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0 (L1 Workstation) | `audits/RHEL/CIS_Red_Hat_Enterprise_Linux_8_v4.0.0_L1_Workstation.audit` | 742 |
| **RHEL 7** | 7.0 - 7.9 | CIS Red Hat Enterprise Linux 7 Benchmark v4.0.0 (L1 Server) | `audits/RHEL/CIS_Red_Hat_Enterprise_Linux_7_v4.0.0_L1_Server.audit` | 752 |
| **RHEL 7 (Workstation)** | 7.0 - 7.9 | CIS Red Hat Enterprise Linux 7 Benchmark v4.0.0 (L1 Workstation) | `audits/RHEL/CIS_Red_Hat_Enterprise_Linux_7_v4.0.0_L1_Workstation.audit` | 735 |
| **Red Hat CoreOS (RHCOS)** | OpenShift Node OS (RHCOS) | CIS Red Hat OpenShift Container Platform v1.9.0 (L1) | `audits/RHEL/CIS_Red_Hat_OpenShift_Container_Platform_v1.9.0_L1.audit` | 118 |
| **Oracle Linux 8** | 8.0 - 8.10 (RHEL Tabanlı) | CIS Oracle Linux 8 Benchmark v4.0.0 (L1 Server) | `audits/Oracle_Linux/CIS_Oracle_Linux_8_v4.0.0_L1_Server.audit` | 766 |
| **Oracle Linux 8 (Workstation)** | 8.0 - 8.10 | CIS Oracle Linux 8 Benchmark v4.0.0 (L1 Workstation) | `audits/Oracle_Linux/CIS_Oracle_Linux_8_v4.0.0_L1_Workstation.audit` | 742 |
| **Oracle Linux (Genel)** | Oracle Linux 9.x | CIS Oracle Linux 9 Benchmark v2.0.0 (L1 Server) | `audits/Oracle_Linux/CIS_Oracle_Linux_9_v2.0.0_L1_Server.audit` | 622 |
| **Oracle Linux (Genel)** | Oracle Linux 7.x | CIS Oracle Linux 7 Benchmark v4.0.0 (L1 Server) | `audits/Oracle_Linux/CIS_Oracle_Linux_7_v4.0.0_L1_Server.audit` | 752 |
| **Ubuntu 24.04 LTS** | Noble Numbat (Kernel 6.8) | CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0 (L1 Server) | `audits/Ubuntu/CIS_Ubuntu_Linux_24.04_LTS_v2.0.0_L1_Server.audit` | 757 |
| **Ubuntu 24.04 LTS (Workstation)** | Noble Numbat | CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0 (L1 Workstation) | `audits/Ubuntu/CIS_Ubuntu_Linux_24.04_LTS_v2.0.0_L1_Workstation.audit` | 724 |
| **Ubuntu 22.04 LTS** | Jammy Jellyfish (Kernel 5.15 / 6.x HWE) | CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 (L1 Server) | `audits/Ubuntu/CIS_Ubuntu_Linux_22.04_LTS_v3.0.0_L1_Server.audit` | 737 |
| **Ubuntu 22.04 LTS (Workstation)** | Jammy Jellyfish | CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 (L1 Workstation) | `audits/Ubuntu/CIS_Ubuntu_Linux_22.04_LTS_v3.0.0_L1_Workstation.audit` | 709 |
| **Ubuntu 18.04 LTS** | Bionic Beaver (Kernel 4.15 / 5.4) | CIS Ubuntu Linux 18.04 LTS Benchmark v2.2.0 (L1 Server) | `audits/Ubuntu/CIS_Ubuntu_Linux_18.04_LTS_v2.2.0_L1_Server.audit` | 600 |
| **Ubuntu 18.04 LTS (Workstation)** | Bionic Beaver | CIS Ubuntu Linux 18.04 LTS Benchmark v2.2.0 (L1 Workstation) | `audits/Ubuntu/CIS_Ubuntu_Linux_18.04_LTS_v2.2.0_L1_Workstation.audit` | 593 |
| **Ubuntu Linux (Genel / 20.04)** | Focal Fossa (Kernel 5.4 / 5.15) | CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 (L1 Server) | `audits/Ubuntu/CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L1_Server.audit` | 804 |
| **SuSE (Kernel 6.x)** | SLES 16 / SLES 15 SP5+ (Kernel 6.x) | CIS SUSE Linux Enterprise 16 Benchmark v1.0.0 (L1 Server) | `audits/SUSE/CIS_SUSE_Linux_Enterprise_16_v1.0.0_L1_Server.audit` | 703 |
| **SuSE / SLES_SAP (Kernel 5.x)** | SLES 15 (Kernel 5.x: 5.3, 5.14) / SLES for SAP | CIS SUSE Linux Enterprise 15 Benchmark v2.0.1 (L1 Server) | `audits/SUSE/CIS_SUSE_Linux_Enterprise_15_v2.0.1_L1_Server.audit` | 592 |
| **SuSE (Kernel 4.x)** | SLES 12 (Kernel 4.4 / 4.12) | CIS SUSE Linux Enterprise 12 Benchmark v3.2.1 (L1 Server) | `audits/SUSE/CIS_SUSE_Linux_Enterprise_12_v3.2.1_L1_Server.audit` | 399 |
| **Debian (Kernel 6.x)** | Debian 12 Bookworm (Kernel 6.1) | CIS Debian Linux 12 Benchmark v2.0.0 (L1 Server) | `audits/Debian/CIS_Debian_Linux_12_v2.0.0_L1_Server.audit` | 754 |
| **Debian (Kernel 6.x)** | Debian 13 Trixie (Kernel 6.x) | CIS Debian Linux 13 Benchmark v1.0.0 (L1 Server) | `audits/Debian/CIS_Debian_Linux_13_v1.0.0_L1_Server.audit` | 782 |
| **Debian (Genel)** | Debian Family Genel | CIS Debian Family Linux Benchmark v1.0.0 (L1 Server) | `audits/Debian/CIS_Debian_Family_Linux_v1.0.0_L1_Server.audit` | 444 |
| **Rocky Linux (Kernel 4.x)** | Rocky Linux 8 (Kernel 4.18) | CIS Rocky Linux 8 Benchmark v3.0.0 (L1 Server) | `audits/Rocky_Linux/CIS_Rocky_Linux_8_v3.0.0_L1_Server.audit` | 766 |
| **Rocky Linux (Kernel 4.x Workstation)** | Rocky Linux 8 | CIS Rocky Linux 8 Benchmark v3.0.0 (L1 Workstation) | `audits/Rocky_Linux/CIS_Rocky_Linux_8_v3.0.0_L1_Workstation.audit` | 742 |
| **Rocky Linux (Kernel 5.x)** | Rocky Linux 9 (Kernel 5.14) | CIS Rocky Linux 9 Benchmark v2.0.0 (L1 Server) | `audits/Rocky_Linux/CIS_Rocky_Linux_9_v2.0.0_L1_Server.audit` | 622 |
| **CentOS (Kernel 3.x)** | CentOS 7 (Kernel 3.10) | CIS CentOS Linux 7 Benchmark v4.0.0 (L1 Server) | `audits/CentOS/CIS_CentOS_Linux_7_v4.0.0_L1_Server.audit` | 752 |
| **CentOS (Kernel 3.x Workstation)** | CentOS 7 | CIS CentOS Linux 7 Benchmark v4.0.0 (L1 Workstation) | `audits/CentOS/CIS_CentOS_Linux_7_v4.0.0_L1_Workstation.audit` | 735 |
| **CentOS (Kernel 2.x)** | CentOS 6 (Kernel 2.6.32) | CIS CentOS 6 Benchmark v3.0.0 (L1 Server) | `audits/CentOS/CIS_CentOS_6_v3.0.0_Server_L1.audit` | 389 |
| **CentOS (Kernel 2.x Workstation)** | CentOS 6 | CIS CentOS 6 Benchmark v3.0.0 (L1 Workstation) | `audits/CentOS/CIS_CentOS_6_v3.0.0_Workstation_L1.audit` | 381 |

---

## Hariç Tutulan Dağıtımlar Hakkında Notlar

1. **VMware Photon OS**:
   - CIS organizasyonu bağımsız bir "CIS Photon OS Benchmark" yayımlamamaktadır. Photon OS genellikle VMware vCenter Server Appliance (VCSA) veya ESXi embedded bileşeni olarak çalışır ve Tenable üzerinde VMware vCenter/ESXi API denetimleri (`AUDIT_ESX`, `AUDIT_VCENTER`) veya VMware Photon STIG denetimleri üzerinden taranmaktadır. Talimat doğrultusunda kapsam dışı tutulmuştur.
2. **FreeBSD (12.1 ve 13.0)**:
   - FreeBSD teknik olarak Unix/BSD ailesindedir. Talimat doğrultusunda bu Linux tarama setinin dışında tutulmuştur.

---

## Tenable Nessus'ta Kullanım Kılavuzu

1. **Nessus Web UI Girişi**: Nessus'a giriş yaptıktan sonra **Policies** veya doğrudan **New Scan** > **Policy Compliance Auditing** şablonunu seçin.
2. **Compliance Sekmesi**: Scan / Policy ayarlarında **Compliance** sekmesine gidin.
3. **Upload Audit File**: **Add Audit File** seçeneğini kullanarak hedef sunucunuzun dağıtımına uygun `.audit` dosyasını (örneğin RHEL 9 sunucular için `CIS_Red_Hat_Enterprise_Linux_9_v2.0.0_L1_Server.audit`) yükleyin.
4. **Kimlik Bilgileri (Credentials)**: **SSH** sekmesinden hedef sistemde yeterli yetkiye sahip (root veya sudo yetkili) kullanıcı bilgilerinizi girin.
5. **Tarama Başlatma**: Taramayı başlatın; sonuçlar raporda CIS kural kodları, Pass/Fail/Warning durumları ve çözüm adımlarıyla birlikte görüntülenecektir.
