# 🛰️ Cisco IOS-XR Automation Suite – Consistency Verification

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
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
7. [License](#-license)
8. [Author](#-author)

---

## 🚀 Overview

The **Cisco IOS-XR Automation Suite** provides an end-to-end consistency verification and validation workflow for IOS-XR devices.  
It is divided into three key parts:

- **Part I:** Device health assessment and baseline establishment  
- **Part II:** Python-based execution and validation  
- **Part III:** Post-check automation with dataplane monitoring  

All three parts operate together to form a **comprehensive automation and testing framework** for Cisco network environments.

---

## 📦 Structure at a Glance

| Part | Script | Purpose |
|:--|:--|:--|
| **Part I** | `step_01_all_xr_health_check_script_v2_0.py` | CLI pre-check (device health + baseline comparison) |
| **Part II** | `step_02_all_XR_python_pre_check_v2_0.py` | Python pre-check (two-phase script execution) |
| **Part III** | `step_03_7_3_6+_python_post_checks_v2_0.py` | Post-check with dataplane monitoring |

---

## 📊 Feature Comparison (Collapsible Sections)

Click below to expand each feature section 👇

---

<details>
<summary><b>🔧 Architecture, SSH, and Execution</b></summary>
<a id="architecture-ssh-and-execution"></a>

| **Feature** | **Part I** | **Part II** | **Part III** |
|:--|:--|:--|:--|
| **Architecture Setup** | Standard Python (manual dependencies) | ✅ Auto venv setup | ✅ Auto venv setup |
| **SSH Connection** | Standard Paramiko | ✅ Enhanced retry (3x), delays | ✅ Enhanced retry (3x), delays |
| **Command Execution Format** | ✅ `"Sending 'desc' ('actual_cmd')..."` | ✅ Same format | ✅ Same format |
| **Terminal Setup** | ✅ `terminal length 0`, `terminal width 511` | ✅ Same | ✅ Same |
| **Hostname Handling** | ✅ Full hostname (replaces dots with dashes) | ✅ Same | ✅ Same |
| **File Naming Convention** | `{hostname}_combined_{session_log|cli_output}_{timestamp}.txt` | `{hostname}_python_pre_check_{output}_{timestamp}.txt` | `{hostname}_7_3_6+_post-checks_{output}_{timestamp}.txt` |

</details>

---

<details>
<summary><b>📈 Progress, Logging, and Output</b></summary>
<a id="progress-logging-and-output"></a>

| **Feature** | **Part I** | **Part II** | **Part III** |
|:--|:--|:--|:--|
| **Progress Bar** | ✅ SimpleProgressBar (16-step) | ❌ None (by design) | ❌ None (by design) |
| **Logging Format** | ✅ CompactFormatter (%H:%M:%S) | ✅ CompactFormatter (%Y-%m-%d %H:%M:%S) | ✅ CompactFormatter (%Y-%m-%d %H:%M:%S) |
| **Output Coordination** | ✅ Tee class + progress bar | ✅ Tee class (fixed write) | ✅ Tee class (fixed write) |
| **Error Detection** | 16 health checks | Link degradation analysis | Dataplane + link degradation |
| **Error Table Format** | PrettyTable auto-size | ✅ Manual column widths | ✅ Manual column widths |

</details>

---

<details>
<summary><b>🧩 Execution & Error Handling</b></summary>
<a id="execution--error-handling"></a>

| **Feature** | **Part I** | **Part II** | **Part III** |
|:--|:--|:--|:--|
| **Execution Time Tracking** | ✅ `format_execution_time()` (HH:MM:SS) | ✅ Same | ✅ Same |
| **Final Summary Table** | ✅ Wrapped headers + centered numbers | ✅ Same | ✅ Same |
| **Status Color Coding** | 🟢 Good<br>🔴 Bad<br>🔵 Collection Only<br>🟡 Not Run | 🔵 Collection Only<br>🟢 Successful<br>🔴 Errors Found/Failed | 🔵 Collection Only<br>🟢 Successful<br>🔴 Errors Found/Failed |
| **Fail-Fast Behavior** | ✅ Stops on first critical error | ✅ Continues but tracks errors | ✅ Stops on first error |
| **Execution Phases** | Single-phase (16 checks) | 2-phase dummy execution | 3-phase dataplane & show tech |
| **Error Tracking Flags** | Device-specific only | ✅ `PHASE2_ERRORS_DETECTED` | ✅ `PHASE2_ERRORS_DETECTED`<br>✅ `PHASE3_ERRORS_DETECTED` |

</details>

---

<details>
<summary><b>🐍 Python Compatibility & Specialized Features</b></summary>
<a id="python-compatibility--specialized-features"></a>

| **Feature** | **Part I** | **Part II** | **Part III** |
|:--|:--|:--|:--|
| **Python 3.7 Compatibility** | ✅ Full (no walrus operators) | ✅ Same | ✅ Same |
| **Specialized Functions** | • Fabric reachability<br>• NPU health<br>• Environment monitor<br>• Field notice detect<br>• Baseline comparison | • Horizontal dot printing<br>• Error parsing<br>• Phase coordination | • Dataplane monitoring<br>• Show tech threading<br>• ASIC clearing<br>• Concurrent ops |
| **Typical Execution Time** | 10–15 min | 45–60 min | 2–3 hours |

</details>

---

## 🧠 Consistency Score

> **✅ 100% CONSISTENCY VERIFIED**

### **Checklist**
- ✅ Enhanced SSH connection handling (Parts II & III)  
- ✅ Unified command execution format  
- ✅ Hostname + file naming consistency  
- ✅ Execution time tracking (HH:MM:SS)  
- ✅ Formatted summary tables  
- ✅ Color-coded status and logging  
- ✅ Enhanced error reporting  
- ✅ Python 3.7+ compatibility  
- ✅ Robust exception handling  
- ✅ Cross-platform support (`venv` for Parts II & III)

---

## 🚀 Deployment Status

**Production Ready**

### **Workflow Summary**
- **Part I:** Device health assessment and baseline establishment  
- **Part II:** Python script execution and validation  
- **Part III:** Comprehensive post-checks with dataplane monitoring  

> Together, they form a **complete automation suite** for Cisco IOS-XR testing and validation.

---

## 💻 Code Examples

### CLI Sample
```bash
# Example from Part I (CLI Pre-Check)
$ python3 step_01_all_xr_health_check_script_v2_0.py --target R34_SYS03

Sending 'show platform' ...
Sending 'show controllers np all' ...
Sending 'show environment all' ...
Sending 'show version' ...
✅ CLI health check completed successfully
