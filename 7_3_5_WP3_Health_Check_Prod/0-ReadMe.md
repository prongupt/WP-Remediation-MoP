# Process Flowchart

This document outlines the steps and scripts involved in the device commissioning process.

# Process Flowchart

This document outlines the steps and scripts involved in the device commissioning process.

## Script Descriptions

| Script Name                            | Description                                                                                                                                                                                                        |
|:---------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `1-all_XR_pre_check_and_comparison.py` | <ol type="a"><li>Performs CLI pre-check commands.</li><li>Captures baseline for optics / FPD / Serial Number change and comparison after bootup.</li><li>First file captures is considered the baseline.</li></ol> |
| `2-all_XR_python_pre_check.py`         | Provides a baseline of degraded links.                                                                                                                                                                             |
| `3a_7_3_5_phase_1.py`                  | <ol type="a"><li>Monitor dummy yes.</li><li>Monitor dataplane.</li><li>Wait 20 minutes.</li><li>Monitor dummy no.</li><li>Asks to perform the two reloads at the end.</li></ol>                                    |
| `3b_7_3_5_phase_2.py`                  | <ol type="a"><li>Monitoring dataplane.</li><li>Wait 20 minutes.</li><li>Monitor dataplane.</li><li>Wait 20 minutes.</li><li>Show tech file.</li><li>ASIC counters clearing.</li></ol>                              |
| `3c_7_3_5_phase_3.py`                  | <ol type="a"><li>Monitor dummy yes.</li><li>Monitor dataplane.</li><li>Wait 20 minutes.</li><li>Monitor dummy no.</li><li>Monitor dataplane.</li><li>Wait 20 minutes.</li><li>Monitor dummy no.</li></ol>          |
| `4-file_upload.py`                     | Uploads the monitorxx.xx.py files to the device's hard disk.                                                                                                                                                       |

## Process Flow
```mermaid
graph TD
    subgraph Initialization
        A[Start] --> B{Check for dummy yes/no scripts?};
        B -- No --> C[Run 4-file_upload.py <br> Upload files to hard disk];
        
    end

    subgraph Pre-Checks and Remediation
        C --> D[Run 1-all_XR_pre_check_and_comparison.py];
        B -- Yes --> D;
        D --> E[Run 2-all_XR_python_pre_check.py <br> Provides baseline of degraded links];
        E --> F[Get baseline for faulty / degraded links];
        F --> G[Perform installation on the chassis / <br> remediation of fabric cards];
        G --> H[Device powered back on]
    end

    subgraph Post-check Phases
        H --> I[Run 1-all_XR_pre_check_and_comparison.py <br> compares optics/interfaces, FPD, serial numbers];
        I --> J[Run 3a_7_3_5_phase_1.py <br> Asks for manual reloads at end];
        J --> K{Errors in Phase 1?};
        K -- Yes --> L[Remediate Phase 1 errors];
        L --> J;
        K -- No --> M[Perform 2 reloads <br> 30 minutes wait after each];

        M --> N[Run 3b_7_3_5_phase_2.py <br> Monitor dataplanes, show tech, clear ASIC counters];
        N --> O{Errors in Phase 2?};
        O -- Yes --> P[Remediate Phase 2 errors];
        P --> N;
        O -- No --> Q[Run 3c_7_3_5_phase_3.py <br> Last round of dummy yes/no, monitor dataplanes];

        Q --> R{Errors in Phase 3?};
        R -- Yes --> S[Remediate Phase 3 errors];
        S --> Q;
    end

    subgraph Finalization
        R -- No --> T[Clean up and handoff to MSFT];
        T --> U[End];
    end

    %% Styling for better readability
    style A fill:#D4EDDA,stroke:#28A745,stroke-width:2px,color:#212529
    style U fill:#D4EDDA,stroke:#28A745,stroke-width:2px,color:#212529
    style B fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style K fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style O fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style R fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style C fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style D fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style E fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style F fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style G fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style H fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style I fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style J fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style M fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style N fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style Q fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style T fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style L fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
    style P fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
    style S fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
```