MITRE_ATTACK_MAPPING = {
    "LOG-SSH-001": {
        "framework": "MITRE ATT&CK",
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
    },
    "LOG-SSH-002": {
        "framework": "MITRE ATT&CK",
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "description": "Invalid user attempts may indicate username guessing or credential attacks.",
    },
    "LOG-SSH-003": {
        "framework": "MITRE ATT&CK",
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "description": "Root login attempts may indicate privileged account targeting.",
    },
    "HOST-PORT-21": {
        "framework": "MITRE ATT&CK",
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "description": "Open FTP service discovered during host exposure analysis.",
    },
    "HOST-PORT-22": {
        "framework": "MITRE ATT&CK",
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "description": "Open SSH service discovered during host exposure analysis.",
    },
    "HOST-PORT-23": {
        "framework": "MITRE ATT&CK",
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "description": "Open Telnet service discovered during host exposure analysis.",
    },
    "HOST-PORT-80": {
        "framework": "MITRE ATT&CK",
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "description": "Open HTTP service discovered during host exposure analysis.",
    },
    "HOST-PORT-443": {
        "framework": "MITRE ATT&CK",
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "description": "Open HTTPS service discovered during host exposure analysis.",
    },
    "HOST-PORT-445": {
        "framework": "MITRE ATT&CK",
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "description": "Open SMB service discovered during host exposure analysis.",
    },
    "HOST-PORT-3389": {
        "framework": "MITRE ATT&CK",
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "description": "Open RDP service discovered during host exposure analysis.",
    },
}