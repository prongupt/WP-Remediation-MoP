# 🛰️ Cisco IOS-XR Automation Suite – Consistency Verification

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey)
![Cisco](https://img.shields.io/badge/Cisco-IOS--XR-orange)

---

## 📑 Table of Contents
1. [Overview](#-overview)
2. [Structure at a Glance](#-structure-at-a-glance)
3. [Installation & Setup](#-installation--setup)
4. [Scripts functionality](#-scripts-functionality)

---

## 🚀 Overview

The **Cisco IOS-XR Automation Suite** provides the framework to install Fabric Cards and remediate any LC-FC link issues.  
It is divided into seven key parts:

- **Part I:** Device health assessment and baseline establishment *(Used for both 7.3.5 and 7.3.6+)*
- **Part II:** Python-based execution and validation *(Used for both 7.3.5 and 7.3.6+)*
- **Part III:** Post-check automation with dataplane monitoring *(Used for 7.3.6+ only)*
- **Part IIIa:** Post-check Phase 1 health checks *(Used for 7.3.5 only)*
- **Part IIIb:** Post-check Phase 2 health checks *(Used for 7.3.5 only)*
- **Part IIIc:** Post-check Phase 3 health checks *(Used for 7.3.5 only)*
- **Part IV:** File upload utility for monitor scripts *(Used for both 7.3.5 and 7.3.6+)*

All parts operate together to form a **comprehensive automation and testing framework** for Fabric Card Link remediation.

---

## 📦 Structure at a Glance
| Part          | Script | Purpose |
|:--------------|:--|:--|
| **Part I**    | `step_01_all_xr_health_check_script_v2_0.py` | CLI pre-check (device health + baseline comparison) |
| **Part II**   | `step_02_all_XR_python_pre_check_v2_0.py` | Python pre-check (two-phase script execution) |
| **Part III**  | `step_03_7_3_6+_post_checks_v2_0.py` | Post-check with dataplane monitoring (IOS-XR 7.3.6+) |
| **Part IIIa** | `step_03a_7_3_5_post_checks_phase_1_v2_0.py` | Post-check Phase 1 (IOS-XR 7.3.5) - Steps a-e |
| **Part IIIb** | `step_03b_7_3_5_post_checks_phase_2_v2_0.py` | Post-check Phase 2 (IOS-XR 7.3.5) - Steps f-j |
| **Part IIIc** | `step_03c_7_3_5_post_checks_phase_3_v2_0.py` | Post-check Phase 3 (IOS-XR 7.3.5) - Steps k-q |
| **Part IV**   | `step_04_degradation_detect_file_upload_v2_0.py` | File upload utility (monitor scripts) |

---

## 📥 Installation & Setup

### **Downloading to Jump Server/SAW Machine**

Follow these steps to get the automation suite onto your Jump Server or SAW machine:

#### **Step 1: Access GitHub**
1. **🌐 Login to GitHub** from your Jump Server/SAW machine
2. **✅ Verify access** - GitHub is accessible and works correctly on SAW machines

#### **Step 2: Navigate to Repository**
1. **🔗 Open Internet Explorer** or your preferred browser
2. **🌍 Navigate via HTTPS/GUI** to the repository:
[WP Remediation MoP Repository](https://github.com/prongupt/WP-Remediation-MoP.git)

#### **Step 3: Download Options**

   **Option A: GUI Download**

   1. **⬇️ Click the green "Code" button** on the repository main page
   2. **📦 Select "Download ZIP"** to get the complete automation suite
   3. **📁 Extract** the ZIP file to your working directory on SAW machine

   **Option B: CLI Clone (if GitHub CLI available)**
```bash
   gh repo clone prongupt/WP-Remediation-MoP
```

   **Option C: Git Clone (standard)**

   I normally use PyCharm to modify code and upload to GitHub. In effect, it is doing the same thing with the command below:
```bash
   git clone github.com/prongupt/WP-Remediation-MoP.git
```

#### **Step 4: Transfer to Jump Server**

1. 🖥️ Open SSH session to jump host (e.g., netjb-westus2-1 - 10.20.39.42)
2. 🔧 Configure SFTP options using SecureCRT
3. 📚 Reference guide: [SecureCRT SFTP Setup Tutorial](https://www.youtube.com/watch?v=X_d9uXGbSvc)
4. 📡 Connect to SFTP session through the Jump Server
5. 📤 Upload the files to the Jump Server


#### **Step 5: Organize Files**

For ease of use, organize into separate folders by IOS-XR version:
```bash
/your-working-directory/
├── 7_3_5/                                          # For IOS-XR 7.3.5 devices
│   ├── step_01_all_xr_health_check_script_v2_0.py
│   ├── step_02_all_XR_python_pre_check_v2_0.py
│   ├── step_03a_7_3_5_post_checks_phase_1_v2_0.py
│   ├── step_03b_7_3_5_post_checks_phase_2_v2_0.py
│   ├── step_03c_7_3_5_post_checks_phase_3_v2_0.py
│   └── step_04_degradation_detect_file_upload_v2_0.py
└── 7_3_6+/                                         # For IOS-XR 7.3.6+ devices
    ├── step_01_all_xr_health_check_script_v2_0.py
    ├── step_02_all_XR_python_pre_check_v2_0.py
    ├── step_03_7_3_6+_post_checks_v2_0.py
    └── step_04_degradation_detect_file_upload_v2_0.py
```
---

## 📋 Summary of MoP Steps Between 7.3.5 and 7.3.6+

| **Script Name** | **Functionality** |
|:----------------|:------------------|
| **step_01** | **CLI Health Checks**<br>• Platform status and serial numbers verification<br>• Fabric reachability assessment<br>• NPU link information and statistics check<br>• ASIC errors detection<br>• Interface status monitoring<br>• Active alarms verification<br>• Fan tray status and field notice compliance<br>• Environment monitoring (temperature, voltage, power)<br>• Baseline comparison for optics/hardware changes |
| **step_02** | **Python Pre-Checks**<br>• Phase 1: Execute dummy scripts with '--dummy' yes<br>• 20-minute countdown timer<br>• Phase 2: Execute dummy scripts with '--dummy' no<br>• Link degradation analysis and baseline establishment<br>• Error detection and reporting for faulty links |
| **step_03** | **Post-Checks for 7.3.6+ (8-Step Workflow)**<br>• Step 1: Execute dummy scripts '--dummy' yes<br>• Step 2: First dataplane monitor (polling mode)<br>• Step 3: 15-minute countdown<br>• Step 4: Execute dummy scripts '--dummy' no (Phase 2)<br>• Step 5: Second dataplane monitor<br>• Step 6: Concurrent countdown + show tech collection<br>• Step 7: Execute dummy scripts '--dummy' no (Phase 3)<br>• Step 8: ASIC error clearing |
| **step_03a** | **Post-Checks for 7.3.5 Phase 1 (Steps a-e)**<br>• Step a: Execute dummy scripts '--dummy' yes<br>• Step b: First dataplane monitor (foreground mode)<br>• Step c: 20-minute wait time<br>• Step d: Execute dummy scripts '--dummy' no<br>• Step e: Manual intervention (reload instructions) |
| **step_03b** | **Post-Checks for 7.3.5 Phase 2 (Steps f-j)**<br>• Step f: Second dataplane monitor<br>• Step g: 20-minute wait time<br>• Step h: Third dataplane monitor<br>• Step i: Show tech collection<br>• Step j: Clear ASIC counters |
| **step_03c** | **Post-Checks for 7.3.5 Phase 3 (Steps k-q)**<br>• Step k: Execute dummy scripts '--dummy' yes (Part 3)<br>• Step l: Fourth dataplane monitor<br>• Step m: 20-minute wait time<br>• Step n: Execute dummy scripts '--dummy' no (First time)<br>• Step o: Fifth dataplane monitor<br>• Step p: 20-minute wait time<br>• Step q: Execute dummy scripts '--dummy' no (Second time) |
| **step_04** | **Upload Python Monitor Files to IOS-XR DUT**<br>• SFTP file transfer to device hard disk (/misc/disk1/)<br>• Multi-host support for bulk uploads<br>• Automatic directory navigation<br>• Upload verification and status reporting |

---