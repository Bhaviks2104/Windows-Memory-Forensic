# 🧠 Volatility Automation and Analysis Framework

A powerful and flexible framework for automating memory dump analysis using the **Volatility Framework**. This tool streamlines the detection of suspicious processes and anomalous activities by combining Volatility plugin output with custom analysis logic and heuristic checks.

---

## 📌 How It Works

The core of this framework is the `automate.py` script, which orchestrates the full memory analysis pipeline.

### 🧪 Step-by-Step Workflow

1. **🧬 Profile Detection**  
   - Begins with `imageinfo` to suggest the appropriate Volatility profile.
   - Prompts user to accept or manually specify the profile.

2. **⚙️ Plugin Execution**  
   - Executes a series of critical Volatility plugins in parallel to collect system artifacts:  
     `pslist`, `pstree`, `psscan`, `cmdline`, `dlllist`, `hollowfind`,  
     `handles`, `ldrmodules`, `netscan`, `ssdt`, `modules`, `modscan`

3. **📊 Data Aggregation & Analysis**  
   - Plugin output is parsed into structured **pandas DataFrames** for correlation and scoring.

4. **🧠 Suspicion Heuristics**  
   Heuristic modules analyze plugin results to detect anomalies and malware indicators:

   - 🔍 **`NPIP_Verify.py` (Name, Parent, Instance, Path)**  
     - Detects **typosquatted or fake process names**  
     - Verifies **parent-child process relationships**  
     - Flags **unusual process counts**  
     - Checks for **invalid or suspicious executable paths**

   - 🧪 **`DNH_Verify.py` (DLLs, Network, Handles)**  
     - Identifies **DLL injection** or DLLs in suspicious paths  
     - Discovers **hidden or unauthorized network connections**  
     - Inspects **handles** to suspicious files, mutexes, events, or pipes

5. **📄 Reporting**  
   - Generates **detailed reports** summarizing suspicious behavior.  
   - Supports output formats:  
     - 📟 Console  
     - 📝 TXT  
     - 🌐 HTML  
     - 📄 PDF  
   - Each finding is **scored and categorized** to aid prioritization.

---

## ✨ Key Features

- ⚡ **Automated Analysis:**  
  Cuts down manual effort in forensic memory analysis.

- ⚙️ **Parallel Plugin Execution:**  
  Boosts performance by running multiple plugins concurrently.

- 🎯 **Comprehensive Heuristics:**  
  Built-in checks identify common malware behaviors and anomalies.

- 🧾 **Flexible Reporting:**  
  Outputs results in human-readable formats—TXT, HTML, PDF.

- 🔌 **Extensible Framework:**  
  Easily add custom Volatility plugins or analysis modules.

---


## 🏗️ Installation

### Prerequisites

- Python 2.7
- Volatility Framework 2.6

### Step 1: Clone Volatility 2

```
cd volatility
git clone https://github.com/volatilityfoundation/volatility.git

```

### Step 2: Install Dependencies
```
pip2 -r requriments.txt
```

### Step 3: VirusTotal Integration (Optional)

### In parent_child_process.py
```
VTSCANX_API_KEY = "YOUR_API_KEY_HERE"
```
## Usage
The primary script to execute is automate.py. Below are the command-line arguments it accepts:
```
python2 automate.py --help
```
Use code with caution.
Bash
## 🛠️ Command-Line Arguments

| **Argument**                  | **Description**                                                                                                                                      | 
|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-f`, `--file`               | **(Required)** Path to the memory dump file.                                                                                                          |
| `-p`, `--profile`            | Specify the Volatility profile to use. If not provided, the script will run the `imageinfo` plugin to suggest profiles and prompt the user.           |
| `--scan-procdump`            | Dump all processes and scan them with VTScanX.                                                                                                         |
| `--scan-dlldump`             | Dump all DLLs and scan them with VTScanX.                                                                                                              |
| `--scan-suspicious-proc`     | Dump only processes flagged as suspicious and scan them with VTScanX.                                                                                  |
| `--scan-suspicious-dll`      | Dump only DLLs from suspicious processes and scan them with VTScanX.                                                                                   |
| `--generate-txt`             | Generate a report in TXT format.                                                                                                                       |
| `--generate-html`            | Generate a report in HTML format.                                                                                                                      |
| `--generate-pdf`             | Generate a report in PDF format.                                                                                                                       |
| `--report-name`              | The name for the generated report file (without extension). Defaults to `memory_report`.                                                               |
| `--report-dir`               | The directory where the report will be saved. Defaults to `reports`.                                                                                   |
| `--include-plugins`          | A space-separated list of additional Volatility plugins to include in the report.                                                                      |
| `--all-include-plugins`      | Include all supported Volatility plugins in the report.                                                                                                |

## 🧪 Usage Examples

#### 🔹 Basic Analysis (Auto Profile Suggestion)
```
python2 automate.py -f wanncry.vmem
```
Runs a complete analysis on wanncry.vmem. The tool will suggest a Volatility profile automatically.

#### 🔹 Custom Profile Usage
```
python2 automate.py -f wanncry.vmem -p Win7SP1x64
```
Runs analysis using a manually specified profile (Win7SP1x64).

#### 🔹Dump All Processes & Scan with VTScanX
```
python2 automate.py -f wanncry.vmem --scan-procdump
```
Dumps all processes and scans their hashes using VTScanX (requires API key).  

#### 🔹Dump All DLLs & Scan with VTScanX
```
python2 automate.py -f wanncry.vmem --scan-dlldump

```
Dumps all loaded DLLs and scans them using VTScanX.
 

#### 🔹 Dump All Processes & DLLs + Scan via VTScanX
```
python2 automate.py -f wanncry.vmem -scan-suspicious-proc
```
Dump only processes flagged as suspicious and scan them with VTScanX.


#### 🔹 Generate HTML Report
```
python2 automate.py -f wanncry.vmem --scan-procdump --generate-html
```
Performs a full scan, dumps all processes, and generates an HTML report.

#### 🔹 Generate Report with Custom Name
```
python2 automate.py -f wanncry.vmem --generate-html --report-name=case001_report

```

#### 🔹Generate Report with Custom Name and Specfic Path
```
python2 automate.py -f wanncry.vmem --generate-html --report-name=case001_report --report-dir 
 ```

#### 🔹Include Specific Plugins in a Report

```
python2 automate.py -f memory.dmp --profile Win10x64_19041 --generate-html --include-plugins pstree malfind

```
Runs analysis and appends the raw output of pstree and malfind to the end of the generated HTML report

#### 🔹Include All Plugins in Report

```
python2 automate.py -f memory.dmp --profile Win10x64_19041 --generate-html --all-include-plugins

```
Includes the output of all supported Volatility plugins in the generated report.


## 🧩 Customizing Detection Logic

The framework is highly customizable to support specific environments, use cases, and organizational policies. Two key components of this logic are:

1. **Parent-Child Process Relationship Validation**
2. **Suspicion Category Prioritization**

---

#### 🔗 Parent-Child Process Relationships

A core part of behavioral detection in this framework is the validation of **parent-child process relationships**. These rules are defined in `parent_child_process.py` within the `windows_processes` dictionary.

Each process entry includes:

| Key              | Description                                                                                  |
|------------------|----------------------------------------------------------------------------------------------|
| `parent`         | List of legitimate parent processes.                                                         |
| `children`       | List of expected child processes.                                                            |
| `can_be_orphan`  | Boolean indicating whether the process can legitimately run without a parent.               |
| `instances`      | Expected number of running instances. Accepts: a number, `-1` (any), or a version-dependent dict. |
| `path`           | Full, expected path of the process binary on disk.                                           |

---

##### 🛠️ Adding a Custom Process Rule

To enhance detection accuracy or adapt to internal tools, you can add custom entries. For example:

```python
"monitoring_agent.exe": {
    "parent": ["services.exe"],
    "children": [],
    "can_be_orphan": False,
    "instances": 1,
    "path": r"C:\Program Files\Monitoring Agent\monitoring_agent.exe"
},
```
### 🎯 Category Priorities

The framework assigns a priority score to each type of suspicious activity. These are defined in the CATEGORY_PRIORITIES dictionary in parent_child_process.py.

A higher score indicates greater forensic significance. This scoring system ensures the final report is risk-ranked to help analysts focus on the most critical findings first.


### 🧪 Example: Adjusting Priorities

#### Original:

```python
CATEGORY_PRIORITIES = {
    ...
    "DLLIllegitimatePath": 8,
    ...
}
```
#### Modified:
```python
CATEGORY_PRIORITIES = {
    ...
    "DLLIllegitimatePath": 10,  # Elevated from 8 to 10
    ...
}
