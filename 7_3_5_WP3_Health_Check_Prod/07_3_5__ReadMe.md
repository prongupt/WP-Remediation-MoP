# 🔧 Steps for IOS-XR version 7.3.5

Use the following sequence of steps for any Cisco 8818 and 8808 running IOS-XR version 7.3.5.

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
| **step_01** | **CLI Health Checks**<br>• Platform status and serial numbers verification<br>• Fabric reachability assessment<br>• NPU link information and statistics check<br>• ASIC errors detection<br>• Interface status monitoring<br>• Active alarms verification<br>• Fan tray status and field notice compliance<br>• Environment monitoring (temperature, voltage, power)<br>• Baseline comparison for optics/hardware changes |
| **step_02** | **Python Pre-Checks**<br>• Phase 1: Execute dummy scripts with '--dummy' yes<br>• 20-minute countdown timer<br>• Phase 2: Execute dummy scripts with '--dummy' no<br>• Link degradation analysis and baseline establishment<br>• Error detection and reporting for faulty links |
| **step_03a** | **Post-Checks Phase 1 for 7.3.5 (Steps a-e)**<br>• Step a: Execute dummy scripts '--dummy' yes<br>• Step b: First dataplane monitor (foreground mode)<br>• Step c: 20-minute wait time<br>• Step d: Execute dummy scripts '--dummy' no<br>• Step e: Manual intervention (reload instructions) |
| **step_03b** | **Post-Checks Phase 2 for 7.3.5 (Steps f-j)**<br>• Step f: Second dataplane monitor<br>• Step g: 20-minute wait time<br>• Step h: Third dataplane monitor<br>• Step i: Show tech collection<br>• Step j: Clear ASIC counters |
| **step_03c** | **Post-Checks Phase 3 for 7.3.5 (Steps k-q)**<br>• Step k: Execute dummy scripts '--dummy' yes (Part 3)<br>• Step l: Fourth dataplane monitor<br>• Step m: 20-minute wait time<br>• Step n: Execute dummy scripts '--dummy' no (First time)<br>• Step o: Fifth dataplane monitor<br>• Step p: 20-minute wait time<br>• Step q: Execute dummy scripts '--dummy' no (Second time) |
| **step_04** | **Upload Python Monitor Files to IOS-XR DUT**<br>• SFTP file transfer to device hard disk (/misc/disk1/)<br>• Multi-host support for bulk uploads<br>• Automatic directory navigation<br>• Upload verification and status reporting |

---

### 📊 Process Flow and 🚀 Steps to Follow

```mermaid
graph TD
    subgraph Pre-Checks
        A[🏁 Start] --> B{📁 Check if .py files exist on device?};
        B -- No --> C[📤 Run step_04_degradation_detect_file_upload_v2_0.py];
        C --> D[🔍 Run step_01_all_xr_health_check_script_v2_0.py];
        B -- Yes --> D;
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
        M4 -- Yes --> P1[✅ Run step_03a_7_3_5_post_checks_phase_1_v2_0.py];
        P1 --> P1_Check{🎯 Step 03a passed?};
        P1_Check -- No --> P1_Fix[🔧 Remediate step 03a issues];
        P1_Fix --> P1;
        P1_Check -- Yes --> P2[✅ Run step_03b_7_3_5_post_checks_phase_2_v2_0.py];
        P2 --> P2_Check{🎯 Step 03b passed?};
        P2_Check -- No --> P2_Fix[🔧 Remediate step 03b issues];
        P2_Fix --> P1;  %% Re-run from step 03a
        P2_Check -- Yes --> P3[✅ Run step_03c_7_3_5_post_checks_phase_3_v2_0.py];
        P3 --> P3_Check{🎯 Step 03c passed?};
        P3_Check -- No --> P3_Fix[🔧 Remediate step 03c issues];
        P3_Fix --> P3;  %% Re-run only step 03c
        P3_Check -- Yes --> P[🎉 Hand device to customer];
        P --> Q[🏁 End];
    end

    %% Styling
    style A fill:#D4EDDA,stroke:#28A745,stroke-width:3px,color:#212529
    style Q fill:#D4EDDA,stroke:#28A745,stroke-width:3px,color:#212529
    style B fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style K fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style L3 fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style M4 fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style P1_Check fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style P2_Check fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style P3_Check fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style P fill:#D1ECF1,stroke:#17A2B8,stroke-width:2px,color:#212529
    style L3_Fix fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
    style M4_Fix fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
    style P1_Fix fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
    style P2_Fix fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
    style P3_Fix fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
```
### 💻 CLI Samples for All Scripts

1. **Upload files (if needed)**
```bash
# Example from Part IV (File Upload)
# Type 'step_04_degradation_detect_file_upload_v2_0.py' for help
$ python3 step_04_degradation_detect_file_upload_v2_0.py --hosts router1.example.com --username admin

Uploading monitor scripts to router1.example.com:/misc/disk1/
✅ File upload completed successfully
```

2. **Run CLI Pre-Check (step01)**
```bash
# Example from Part I (CLI Pre-Check)
$ python3 step_01_all_xr_health_check_script_v2_0.py

Sending 'show platform' ('show platform')...
Sending 'show controllers npu all' ('show controllers npu all')...  
Sending 'show environment all' ('show environment all')...
Sending 'show version' ('show version')...
✅ CLI health check completed successfully
```

3. **Run Python Pre-Check (step02)**
```bash
# Example from Part II (Python Pre-Check)
$ python3 step_02_all_XR_python_pre_check_v2_0.py

Phase 1: Execute dummy scripts with '--dummy' yes
Phase 2: Execute dummy scripts with '--dummy' no
✅ Python script validation completed successfully
```

4. **Run Post-Checks Phase 1 (step03a)**
```bash
# Example from Part 3a (Post-Check 7.3.5 Phase 1)
$ python3 step_03a_7_3_5_post_checks_phase_1_v2_0.py

Step a: Execute dummy scripts '--dummy' yes
Step b: First dataplane monitor (foreground mode)
Step c: 20-minute wait time
Step d: Execute dummy scripts '--dummy' no
Step e: Manual intervention (reload instructions)
✅ Phase 1 post-check completed successfully
```

5. **Run Post-Checks Phase 2 (step03b)**
```bash
# Example from Part 3b (Post-Check 7.3.5 Phase 2)
$ python3 step_03b_7_3_5_post_checks_phase_2_v2_0.py

Step f: Second dataplane monitor
Step g: 20-minute wait time
Step h: Third dataplane monitor
Step i: Show tech collection
Step j: Clear ASIC counters
✅ Phase 2 post-check completed successfully
```

6. **Run Post-Checks Phase 3 (step03c)**
```bash
# Example from Part 3c (Post-Check 7.3.5 Phase 3)
$ python3 step_03c_7_3_5_post_checks_phase_3_v2_0.py

Step k: Execute dummy scripts '--dummy' yes (Part 3)
Step l: Fourth dataplane monitor
Step m: 20-minute wait time
Step n: Execute dummy scripts '--dummy' no (First time)
Step o: Fifth dataplane monitor
Step p: 20-minute wait time
Step q: Execute dummy scripts '--dummy' no (Second time)
✅ Phase 3 post-check completed successfully
```
---

### ⏱️ Execution Times

| Script                        | Typical Duration   | Purpose                                                  |
|-------------------------------|:------------------:|----------------------------------------------------------|
| Pre-Check (step01)            | **10-15 minutes**  | Device health assessment                                 |
| Python Pre-Check (step02)     | **45-60 minutes**  | Script validation (includes 20min wait)                 |
| Post-Check Phase 1 (step03a)  | **45-60 minutes**  | Phase 1 workflow (includes 20min wait)                  |
| Post-Check Phase 2 (step03b)  | **60-90 minutes**  | Phase 2 workflow (includes dataplane + show tech)      |
| Post-Check Phase 3 (step03c)  | **90-120 minutes** | Phase 3 workflow (includes dual dummy no phases)       |
| File Upload (step04)          | **2-5 minutes**    | File transfer utility                                    |

---

### 📞 Support
- **Author**: Pronoy Dasgupta (prongupt@cisco.com)
- **Version**: 2.0.0
- **Status**: Production Ready

---

**🚀 Ready to automate your Cisco IOS-XR device commissioning process!**