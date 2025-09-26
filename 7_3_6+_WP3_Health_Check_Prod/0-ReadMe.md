```mermaid
graph TD
    subgraph Initialization
        A[Start] --> B{Check if .py files exist?};
        B -- No --> C[Run 4-file_upload.py];

    end

    subgraph Pre-Checks and Remediation
        C --> D[Run 1-all_XR_pre_check_and_comparison.py];
        B -- Yes --> D; 
        D --> E[Run 2-all_XR_python_pre_check.py, gather baseline];
        E --> F[Perform installation on the chassis / <br> remediation of fabric cards];
        F --> I[Power on device];
        J_node[Run 1-all_XR_pre_check_and_comparison.py <br> re-check optics, interfaces];
        I --> J_node;
        J_node --> K{Post install status ok-optics/interfaces etc?};
        K -- No --> K_Remediate_Step[Remediate post-install issues];
        K_Remediate_Step --> J_node;
    end

    subgraph Post-check Phases
        K -- Yes --> L[Reload device twice <br> 20 min wait each];
        L --> M[Run 3-7_3_6+_python_post_checks.py];
        M --> N{Problems after post-checks?};
        N -- Yes --> O[Remediate post-check problems];
        O --> M;
    end
    
    subgraph Finalization
        N -- No --> P[Clean up and hand device to MSFT];
        P --> Q[End];
    end

    %% Styling for better readability
    style A fill:#D4EDDA,stroke:#28A745,stroke-width:2px,color:#212529
    style Q fill:#D4EDDA,stroke:#28A745,stroke-width:2px,color:#212529
    style B fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style K fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style N fill:#FFF3CD,stroke:#FFC107,stroke-width:2px,color:#212529
    style C fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style D fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style E fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style F fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style I fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style J_node fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style L fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style M fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style P fill:#E0F7FA,stroke:#17A2B8,stroke-width:1px,color:#212529
    style O fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
    style K_Remediate_Step fill:#F8D7DA,stroke:#DC3545,stroke-width:1px,color:#212529
```
