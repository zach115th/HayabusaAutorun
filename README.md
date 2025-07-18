# Hayabusa Autorun

**Modular PowerShell automation for streamlined Hayabusa & Takajo workflows.**  

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Workflow](#workflow)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Profiles & Output](#profiles--output)

---

## Overview

Hayabusa Autorun is a PowerShell automation wrapper that simplifies and accelerates forensic timeline generation using [Hayabusa](https://github.com/Yamato-Security/hayabusa) and optional deep artifact extraction with [Takajo](https://github.com/Yamato-Security/takajo).  
It's designed for rapid, repeatable workflows in digital forensics, incident response, and threat hunting.

---

## Features

- Interactive prompts for event log source and output format
- Automated, timestamped results folder creation
- Automatic update check for Hayabusa & Takajo (with easy download links if outdated)
- Rule-set update prior to scanning
- Supports Hayabusa CSV timeline, Timesketch format, and Takajo-compatible JSONL output
- Optional Takajo deep artifact parsing (if selected)
- Clean status messages and workflow summary at completion
- Results ready for [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) visualization

---

## Workflow

1. **Prompt for input:**  
   User provides path to local EVTX event logs and selects output profile (CSV, Timesketch, or JSONL for Takajo).

2. **Create results directory:**  
   Output is stored in a unique, timestamped folder under `.\Results\`.

3. **Update detection rules:**  
   Hayabusa's rules are updated before each run.

4. **Run Hayabusa scan:**  
   - **CSV**: Standard timeline, rich verbosity.
   - **Timesketch**: For ingestion into [Timesketch](https://github.com/google/timesketch).
   - **Takajo (JSONL)**: Optimized for subsequent Takajo deep artifact parsing.

5. **(Optional) Run Takajo:**  
   If Takajo output is chosen, Takajo parses JSONL results for advanced Windows artifact extraction.

6. **Completion & Next Steps:**  
   Script shows results location and links for MITRE ATT&CK visualization.

---

## Requirements

- **PowerShell 5.1+** (Windows recommended)
- **Hayabusa**: Download [latest release](https://github.com/Yamato-Security/hayabusa/releases) and place the EXE in the script directory
- **Takajo** (optional, for profile `P`): Download [latest release](https://github.com/Yamato-Security/takajo/releases) and place the EXE in the script directory
- Sufficient disk space for results (event logs, CSVs, JSONL, parsed artifacts)

---

## Quick Start

1. **Clone or Download this Repository**

2. **Download the Required Binaries:**
   - [Hayabusa](https://github.com/Yamato-Security/hayabusa/releases)
   - [Takajo](https://github.com/Yamato-Security/takajo/releases) _(optional, for deep parsing)_

3. **Place Binaries in Script Folder**

4. **Run the Script:**

   ```powershell
   .\HayabusaAutorun.ps1
   ```

---

## Profiles & Output

| Option | Output Type         | Description                                           |
| ------ | ------------------- | ----------------------------------------------------- |
| C      | CSV Timeline        | Full-featured timeline with maximum verbosity         |
| T      | Timesketch Timeline | CSV timeline tailored for Timesketch ingestion        |
| P      | Takajo JSONL        | JSONL timeline, for deep artifact parsing with Takajo |

---

