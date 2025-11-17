# 🔧 Steps for IOS-XR version 7.3.6 and above

Use the following sequence of steps for any Cisco 8818 and 8808 running IOS-XR version 7.3.6 and above

## 📑 Table of Contents
1. [Scripts Functionality](#-scripts-functionality)
2. [Process Flow and Steps to Follow](#-process-flow-and--steps-to-follow)
3. [CLI Samples for All Scripts](#-cli-samples-for-all-scripts)
4. [Execution Times](#️-execution-times)
5. [Support](#-support)

---

### 📋 Scripts Functionality

| **Script Name** | **Functionality** |
|:----------------|:------------------|
| **step_01** | **CLI Health Checks + File Upload**<br>• **Automatic monitor file upload** (checks if files exist first)<br>• Platform status and serial numbers verification<br>• Fabric reachability assessment<br>• NPU link information and statistics check<br>• ASIC errors detection<br>• Interface status monitoring<br>• Active alarms verification<br>• Fan tray status and field notice compliance<br>• Environment monitoring (temperature, voltage, power)<br>• Baseline comparison for optics/hardware changes |
| **step_02** | **Python Pre-Checks**<br>• Phase 1: Execute dummy scripts with '--dummy' yes<br>• 20-minute countdown timer<br>• Phase 2: Execute dummy scripts with '--dummy' no<br>• Link degradation analysis and baseline establishment<br>• Error detection and reporting for faulty links |
| **step_03** | **Post-Checks for 7.3.6+ (8-Step Workflow)**<br>• Step 1: Execute dummy scripts '--dummy' yes<br>• Step 2: First dataplane monitor (polling mode)<br>• Step 3: 15-minute countdown<br>• Step 4: Execute dummy scripts '--dummy' no (Phase 2)<br>• Step 5: Second dataplane monitor<br>• Step 6: Concurrent countdown + show tech collection<br>• Step 7: Execute dummy scripts '--dummy' no (Phase 3)<br>• Step 8: ASIC error clearing |

---

### 📊 Process Flow and 🚀 Steps to Follow

```mermaid
graph TD
    subgraph Pre-Checks
        A[🏁 Start] --> D[🔍 Run step_01_all_xr_health_check_script_v2_0.py<br>📤 Includes automatic file upload + health checks];
        D --> E[🐍 Run step_02_all_XR_python_pre_check_v2_0.py - gather baseline];
    end

    subgraph Remediation
        E --> F[⚡ Power off device];
        F --> G[🔧 Installation];
        G --> H[⚡ Power on device];
    end

    subgraph Post-Checks
        H --> J_node[🔍 Run step_01_all_xr_health_check_script_v2_0.py];
        J_node --> K{✅ Post-install status OK?};
        K -- No --> K_Remediate_Step[🔧 Remediate issues];
        K_Remediate_Step --> J_node;
        K -- Yes --> L[🔄 Perform first reload];
        L --> L1[⏰ Wait 20 minutes];
        L1 --> L2[🔍 Run CLI pre-check<br>verify optics/interfaces];
        L2 --> L3{✅ Optics/interfaces OK?};
        L3 -- No --> L3_Fix[🔧 Fix optics/interface issues];
        L3_Fix --> L2;
        L3 -- Yes --> M1[🔄 Perform second reload];
        M1 --> M2[⏰ Wait 20 minutes];
        M2 --> M3[🔍 Run CLI pre-check<br>verify optics/interfaces];
        M3 --> M4{✅ Optics/interfaces OK?};
        M4 -- No --> M4_Fix[🔧 Fix optics/interface issues];
        M4_Fix --> M3;
        M4 -- Yes --> M[✅ Run step_03_7_3_6+_post_checks_v2_0.py];
        M --> N{🎯 All checks passed?};
        N -- Yes --> P[🎉 Hand device to customer];
        N -- No --> O[🔧 Remediate problems];
        O --> M;
        P --> Q[🏁 End];
    end

    %% Styling
    style A fill:#D4EDDA,stroke:#28A745,stroke-width:3px,color:#212529
    style Q fill:#D4EDDA,stroke:#28A745,stroke-width:3px,color:#212529
    style K fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style L3 fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style M4 fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style N fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style P fill:#D1ECF1,stroke:#17A2B8,stroke-width:2px,color:#212529
```
---


### 💻 CLI Samples for All Scripts

1. **Run CLI Pre-Check + File Upload (if needed)**
```bash
# Example from Part I (CLI Pre-Check + Automatic File Upload)
$ python3 step_01_all_xr_health_check_script_v2_0.py

📁 Monitor files detected on device: group0.py, group1.py, group2.py, group3.py
✅ Files already on hard drive...skipping upload
Sending 'show platform' ('show platform')...
Sending 'show controllers npu all' ('show controllers npu all')...  
✅ CLI health check with integrated file upload completed successfully
```

2. **Run Python Pre-Check (step02)**
```bash
# Example from Part II (Python Pre-Check)
$ python3 step_02_all_XR_python_pre_check_v2_0.py

Phase 1: Execute dummy scripts with '--dummy' yes
Phase 2: Execute dummy scripts with '--dummy' no
✅ Python script validation completed successfully
```

3. **Run Post-Checks (step03)**
```bash
# Example from Part III (Post-Check 7.3.6+)
$ python3 step_03_7_3_6+_post_checks_v2_0.py

Step 1: Phase 1 - Execute dummy scripts '--dummy' yes
Step 2: First Dataplane Monitor (7.3.6+ polling mode)
Step 3: Sequential 15-minute countdown
Step 4: Phase 2 - Execute dummy scripts '--dummy' no
Step 5: Second Dataplane Monitor (7.3.6+ polling mode)
Step 6: Concurrent countdown + show tech collection
Step 7: Phase 3 - Execute dummy scripts '--dummy' no
Step 8: ASIC Error Clearing Command
✅ 8-step post-check workflow completed successfully
```

---   

### ⏱️ Execution Times

| Script           | Typical Duration  | Purpose                                                  |
|------------------|-------------------|----------------------------------------------------------|
| Pre-Check        | **10-15 minutes** | Device health assessment + monitor file management       |
| Python Pre-Check | **45-60 minutes** | Script validation (includes 20min wait)                  |
| Post-Check       | **2-3 hours**     | Comprehensive validation (includes dataplane monitoring) |

---

### 📞 Support
- **Author**: Pronoy Dasgupta (prongupt@cisco.com)
- **Version**: 2.0.0
- **Status**: Production Ready

---

**🚀 Ready to automate your Cisco IOS-XR device commissioning process!**

