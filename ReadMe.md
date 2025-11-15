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
4. [Consistency Score](#-consistency-score)
5. [Deployment Status](#-deployment-status)
6. [Code Examples](#-code-examples)
   - [CLI Sample](#cli-sample)
   - [Python Sample](#python-sample)
7. [Author](#-author)

---

## 🚀 Overview

The **Cisco IOS-XR Automation Suite** provides an end-to-end consistency verification and validation workflow for IOS-XR devices.  
It is divided into four key parts:

- **Part I:** Device health assessment and baseline establishment  
- **Part II:** Python-based execution and validation  
- **Part III:** Post-check automation with dataplane monitoring
- **Part IV:** File upload utility for monitor scripts

All four parts operate together to form a **comprehensive automation and testing framework** for Cisco network environments.

---

## 📦 Structure at a Glance

| Part | Script | Purpose |
|:--|:--|:--|
| **Part I** | `step_01_all_xr_health_check_script_v2_0.py` | CLI pre-check (device health + baseline comparison) |
| **Part II** | `step_02_all_XR_python_pre_check_v2_0.py` | Python pre-check (two-phase script execution) |
| **Part III** | `step_03_7_3_6+_post_checks_v2_0.py` | Post-check with dataplane monitoring |
| **Part IV** | `step_04_degradation_detect_file_upload_v2_0.py` | File upload utility (monitor scripts) |

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
https://github.com/prongupt/WP-Remediation-MoP.git

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
3. 📚 Reference guide: SecureCRT SFTP Setup Tutorial
4. 📡 Connect to SFTP session through the Jump Server
5. 📤 Upload the files to the Jump Server


#### **Step 5: Organize Files**

For ease of use, organize into separate folders by IOS-XR version:
```bash
/your-working-directory/
├── 7_3_5/          # For IOS-XR 7.3.5 devices
└── 7_3_6+/         # For IOS-XR 7.3.6+ devices
    ├── step_01_all_xr_health_check_script_v2_0.py
    ├── step_02_all_XR_python_pre_check_v2_0.py
    ├── step_03_7_3_6+_post_checks_v2_0.py
    └── step_04_degradation_detect_file_upload_v2_0.py
```
