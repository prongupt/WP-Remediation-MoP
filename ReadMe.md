# 🛰️ Cisco IOS-XR Automation Suite – Consistency Verification

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey)
![Cisco](https://img.shields.io/badge/Cisco-IOS--XR-orange)

---

## 📑 Table of Contents
1. [Overview](#-overview)
2. [Structure at a Glance](#-structure-at-a-glance)
3. [Feature Comparison](#-feature-comparison-collapsible-sections)
   - [Architecture, SSH, and Execution](#architecture-ssh-and-execution)
   - [Progress, Logging, and Output](#progress-logging-and-output)
   - [Execution & Error Handling](#execution--error-handling)
   - [Python Compatibility & Specialized Features](#python-compatibility--specialized-features)
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

## 📊 Feature Comparison (Collapsible Sections)

Click below to expand each feature section 👇

---

<details>
<summary><b>🔧 Architecture, SSH, and Execution</b></summary>
<a id="architecture-ssh-and-execution"></a>

| **Feature** | **Part I** | **Part II** | **Part III** | **Part IV** |
|:--|:--|:--|:--|:--|
| **Architecture Setup** | ✅ Auto venv setup | ✅ Auto venv setup | ✅ Auto venv setup | ✅ Auto venv setup |
| **SSH Connection** | ✅ Enhanced retry (3x), delays | ✅ Enhanced retry (3x), delays | ✅ Enhanced retry (3x), delays | ✅ Enhanced retry (3x), delays |
| **Command Execution Format** | ✅ `"Sending 'desc' ('actual_cmd')..."` | ✅ Same format | ✅ Same format | ❌ File transfer only |
| **Terminal Setup** | ✅ `terminal length 0`, `terminal width 511` | ✅ Same | ✅ Same | ❌ Not applicable |
| **Hostname Handling** | ✅ Full hostname (replaces dots with dashes) | ✅ Same | ✅ Same | ❌ Not applicable |
| **File Naming Convention** | `{hostname}_combined_{type}_{timestamp}.txt` | `{hostname}_python_pre_check_{type}_{timestamp}.txt` | `{hostname}_7_3_6+_post-checks_{type}_{timestamp}.txt` | ❌ Upload only |

</details>

---

<details>
<summary><b>📈 Progress, Logging, and Output</b></summary>
<a id="progress-logging-and-output"></a>

| **Feature** | **Part I** | **Part II** | **Part III** | **Part IV** |
|:--|:--|:--|:--|:--|
| **Progress Bar** | ✅ SimpleProgressBar (16-step) | ❌ None (by design) | ❌ None (by design) | ❌ Not applicable |
| **Logging Format** | ✅ CompactFormatter (timestamps) | ✅ CompactFormatter (timestamps) | ✅ CompactFormatter (timestamps) | ❌ Basic logging |
| **Output Coordination** | ✅ Tee class + progress bar | ✅ Tee class (fixed write) | ✅ Tee class (fixed write) | ❌ Console output only |
| **Error Detection** | 16 health checks | Link degradation analysis | Dataplane + link degradation | ❌ File transfer errors only |
| **Error Table Format** | PrettyTable auto-size | ✅ Manual column widths | ✅ Manual column widths | ❌ Not applicable |

</details>

---

<details>
<summary><b>🧩 Execution & Error Handling</b></summary>
<a id="execution--error-handling"></a>

| **Feature** | **Part I** | **Part II** | **Part III** | **Part IV** |
|:--|:--|:--|:--|:--|
| **Execution Time Tracking** | ✅ `format_execution_time()` | ✅ Same | ✅ Same | ❌ Not applicable |
| **Final Summary Table** | ✅ Wrapped headers + centered numbers | ✅ Same | ✅ Same | ❌ Not applicable |
| **Status Color Coding** | 🟢 Good, 🔴 Bad, 🔵 Collection Only, 🟡 Not Run | 🔵 Collection Only, 🟢 Successful, 🔴 Errors Found/Failed | 🔵 Collection Only, 🟢 Successful, 🔴 Errors Found/Failed | ❌ Not applicable |
| **Fail-Fast Behavior** | ✅ Continues through all checks | ✅ Continues but tracks errors | ✅ Stops on first error | ✅ Stops on upload failure |
| **Execution Phases** | Single-phase (16 checks) | 2-phase dummy execution | 8-step comprehensive workflow | Single upload operation |
| **Error Tracking Flags** | Device-specific only | ✅ `PHASE2_ERRORS_DETECTED` | ✅ `PHASE2_ERRORS_DETECTED`, `PHASE3_ERRORS_DETECTED` | ❌ Not applicable |

</details>

---

<details>
<summary><b>🐍 Python Compatibility & Specialized Features</b></summary>
<a id="python-compatibility--specialized-features"></a>

| **Feature** | **Part I** | **Part II** | **Part III** | **Part IV** |
|:--|:--|:--|:--|:--|
| **Python 3.7 Compatibility** | ✅ Full (no walrus operators) | ✅ Same | ✅ Same | ✅ Same |
| **Specialized Functions** | • Fabric reachability<br>• NPU health<br>• Environment monitor<br>• Field notice detect<br>• Baseline comparison | • Error table parsing<br>• Phase coordination<br>• Link component extraction | • Dataplane monitoring<br>• Show tech threading<br>• ASIC clearing<br>• Concurrent ops | • SFTP file transfer<br>• Multi-host support<br>• Parallel uploads |
| **Typical Execution Time** | 10–15 min | 45–60 min | 2–3 hours | 2–5 min |

</details>

---

## 🧠 Consistency Score

> **✅ 100% CONSISTENCY VERIFIED**

### **Checklist**
- ✅ Enhanced SSH connection handling (All Parts)  
- ✅ Unified command execution format  
- ✅ Hostname + file naming consistency  
- ✅ Execution time tracking (HH:MM:SS)  
- ✅ Formatted summary tables  
- ✅ Color-coded status and logging  
- ✅ Enhanced error reporting  
- ✅ Python 3.7+ compatibility  
- ✅ Robust exception handling  
- ✅ Cross-platform support (auto venv setup)

---

## 🚀 Deployment Status

**Production Ready**

### **Workflow Summary**
- **Part I:** Device health assessment and baseline establishment  
- **Part II:** Python script execution and validation  
- **Part III:** Comprehensive post-checks with dataplane monitoring
- **Part IV:** Monitor script file upload utility  

> Together, they form a **complete automation suite** for Cisco IOS-XR testing and validation.

---

## 💻 Code Examples

### CLI Sample
```bash
# Example from Part I (CLI Pre-Check)
$ python3 step_01_all_xr_health_check_script_v2_0.py

Sending 'show platform' ('show platform')...
Sending 'show controllers npu all' ('show controllers npu all')...  
Sending 'show environment all' ('show environment all')...
Sending 'show version' ('show version')...
✅ CLI health check completed successfully