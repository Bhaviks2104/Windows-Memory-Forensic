# -*- coding: utf-8 -*-
import subprocess
import sys
import argparse
import os
import StringIO
import io
import threading
import json
from tabulate import tabulate
import pandas as pd
import re
import hashlib
import requests
from datetime import datetime
from NPIP_Verify import is_suspicious_name, check_instance_count, check_parent, check_path
from DNH_Verify import *
from parent_child_process import profiles, CACHE_FILE, VTSCANX_URL, VTSCANX_API_KEY, VT_SCAN_THRESHOLD, CATEGORY_PRIORITIES
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
from xml.sax.saxutils import escape
import cgi 

reload(sys)
sys.setdefaultencoding('utf-8')  

plugins = ["pslist", "pstree", "psscan", "cmdline", "dlllist", "hollowfind", "handles", "ldrmodules", "networkscan", "ssdt", "modules", "modscan", "malfind"]
results = {}
suspicious_processes = {}
suggested_profiles = []
profile=""
psscan_df = pd.DataFrame()
memory_file = None
plugin_list = None

scan_procdump = False
scan_dlldump = False
scan_suspicious_only = False
scan_suspicious_dll_only = False

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)

def run_plugin(memory_file, profile, plugin, results):
    """Run a Volatility plugin and store the output in a dictionary. Retry with other suggested profiles if results are empty.
       If all profiles fail, store the blank result at the end.
    """
    final_output_data = None
    final_profile_used = profile  # Default to initial profile

    def execute_plugin(p):
        cmd = "python2 vol.py -f {} --profile={} {}".format(memory_file, p, plugin)
        if plugin == "procdump" or plugin == "dlldump":
            memfile_base = os.path.splitext(os.path.basename(memory_file))[0]
            dump_dir = os.path.join("dump", memfile_base)
            
            ensure_directory_exists(dump_dir)
            cmd += " -D {}".format(dump_dir)

        if plugin not in ['pstree', 'hollowfind']:
            cmd += " --output=json"
        
        print("Running command: {}\n".format(cmd))
        
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        output, error = process.communicate()
        if process.returncode != 0:
            print("[!] Error running {}: {}".format(plugin, error))
            return None, p

        # Filter out non-critical errors
        error_lines = error.strip().split("\n")
        filtered_errors = [line for line in error_lines if "Volatility Foundation" not in line]
        if filtered_errors:
            print("Warnings/Info:\n" + "\n".join(filtered_errors))

        if plugin in ['pstree', 'hollowfind']:
            return output, p  # These are text plugins, return raw
        else:
            try:
                # Find the start of the JSON output
                json_start_index = output.find('{')
                if json_start_index == -1:
                    print("[-] No JSON object found for plugin: {}".format(plugin))
                    return None, p
                
                json_output = output[json_start_index:]
                parsed = json.loads(json_output)
                
                if parsed.get("rows", []):  # If rows not empty
                    return parsed, p
                else:
                    print("[!] No data found with profile: {}".format(p))
                    return parsed, p  # Still return parsed (empty), not None
            except (json.JSONDecodeError, ValueError):
                print("[-] Failed to parse JSON for plugin: {}".format(plugin))
                return None, p

    # Try original profile
    output_data, used_profile = execute_plugin(profile)
    final_output_data = output_data
    final_profile_used = used_profile

    # Try other suggested profiles if needed
    if (output_data is None or (isinstance(output_data, dict) and not output_data.get("rows"))) and suggested_profiles:
        for alt_profile in suggested_profiles:
            if alt_profile == profile:
                continue
            print("[*] Trying alternative profile: {}".format(alt_profile))
            output_data, used_profile = execute_plugin(alt_profile)
            if output_data and (not isinstance(output_data, dict) or output_data.get("rows")):
                final_output_data = output_data
                final_profile_used = used_profile
                break
            elif output_data is not None:
                # Keep the last valid empty result if parsing succeeded
                final_output_data = output_data
                final_profile_used = used_profile

    if final_output_data is not None:
        results[plugin] = final_output_data
        print("[+] {} completed using profile: {}".format(plugin, final_profile_used))
    else:
        results[plugin] = None  # Store explicitly as None
        print("[-] Plugin '{}' returned no valid output with any profile.".format(plugin))

def extract_hollowfind_paths(hollowfind_output):
    if not hollowfind_output:
        return pd.DataFrame([])
    process_paths = []  # List to store process information
    
    # Split the output into blocks for each process
    process_blocks = hollowfind_output.strip().split("Hollowed Process Information:")
    
    for block in process_blocks[1:]:  # Skip the first empty split
        pid_match = re.search(r"PID:\s*(\d+)", block)
        vad_match = re.search(r"Process Path\(VAD\):\s*(.+)", block)
        peb_match = re.search(r"Process Path\(PEB\):\s*(.+)", block)

        pid = pid_match.group(1) if pid_match else None
        vad_path = vad_match.group(1).strip() if vad_match else "NA"
        peb_path = peb_match.group(1).strip() if peb_match else "NA"
        
        if pid:
            process_paths.append({
                "PID": pid,
                "VAD Path": vad_path,
                "PEB Path": peb_path
            })

    # Convert to DataFrame for better handling
    return pd.DataFrame(process_paths)

def get_priority(category):
    return CATEGORY_PRIORITIES.get(category, 1)

def NPIP_check():
    psscan_df = pd.DataFrame(results["psscan"]["rows"], columns=["Offset(P)", "Process Name", "PID", "PPID", "PDB", "Time Created", "Time Exited"])

    # Convert results to DataFrames
    dlllist_df = pd.DataFrame(results["dlllist"]["rows"], columns=["Pid", "Base", "Size", "LoadCount", "LoadTime", "Path"])

    # Remove NaN values from the "Path" column before applying string operations
    dlllist_df = dlllist_df.dropna(subset=["Path"])

    # Filter only .exe files (case insensitive)
    exe_paths = dlllist_df[dlllist_df["Path"].str.lower().str.endswith(".exe", na=False)]

    # Keep only "Pid" and "Path" columns, remove duplicates
    exe_paths = exe_paths[["Pid", "Path"]].drop_duplicates()

    # Rename columns to match "PID" format for merging
    exe_paths.rename(columns={"Pid": "PID", "Path": "Executable Path"}, inplace=True)

    # Perform the merge (only keeps processes that have an associated .exe)
    dlllist_path = psscan_df.merge(exe_paths, on="PID", how="inner")  # Use "inner" to remove unmatched PIDs
    
    cmdline_path = pd.DataFrame(results["cmdline"]["rows"], columns=["Process", "PID", "CommandLine"])
    handles = pd.DataFrame(results["handles"]["rows"], columns=["Offset(V)", "Pid", "Handle", "Access", "Type", "Details"])
    
    try:
        if "hollowfind" in results and results["hollowfind"]:
            hollowfind_path = extract_hollowfind_paths(results["hollowfind"])
        else:
            hollowfind_path = pd.DataFrame([])
    except Exception as e:
        hollowfind_path = pd.DataFrame([])

    process_counts = psscan_df["Process Name"].value_counts().to_dict()
    pid_to_name = dict(zip(psscan_df["PID"], psscan_df["Process Name"]))
    for _, row in psscan_df.iterrows():
        process_name = row["Process Name"]
        pid = row["PID"]
        # Get expected instance count (default 1 if not found in known processes)
        actual_count = process_counts.get(process_name, 0)

        # Initialize a dictionary to hold reasons for the current process
        reasons_dict = {}

        # Check for suspicious name modifications
        is_suspicious, reasons = is_suspicious_name(process_name)

        if is_suspicious:
            reasons_dict["name_reasons"] = reasons

        # Check for unusual instance count
        is_instance_suspicious, reasons = check_instance_count(process_name, actual_count, profile)
        
        if is_instance_suspicious:
            reasons_dict["instance_reasons"] = reasons
        
        parent_name = pid_to_name.get(row["PPID"], "Unknown")
        is_reason_suspicious, reasons = check_parent(process_name, parent_name)

        if is_reason_suspicious:
            reasons_dict["parent_reasons"] = reasons

        pid_specific_dll = dlllist_path[dlllist_path["PID"] == pid]["Executable Path"].values
        pid_specific_cmd = cmdline_path[cmdline_path["PID"] == pid]["CommandLine"].values
        pid_specific_peb = (
            hollowfind_path[hollowfind_path["PID"] == str(pid)]["PEB Path"].values
            if "hollowfind" in results and not hollowfind_path.empty 
            else []
        )

        pid_specific_vad = (
            hollowfind_path[hollowfind_path["PID"] == str(pid)]["VAD Path"].values
            if "hollowfind" in results and not hollowfind_path.empty 
            else []
        )


        if row["Process Name"] != "System" and row["Time Exited"].strip() == "":
            is_path_suspicious, reasons = check_path(
                process_name,
                pid_specific_dll[0] if len(pid_specific_dll) > 0 else None, 
                pid_specific_cmd[0] if len(pid_specific_cmd) > 0 else None, 
                pid_specific_peb[0] if len(pid_specific_peb) > 0 else None, 
                pid_specific_vad[0] if len(pid_specific_vad) > 0 else None
            )

            if is_path_suspicious:
                reasons_dict["path_reasons"] = reasons

        process_dll_path = pid_specific_dll[0] if len(pid_specific_dll) > 0 else None
        if process_dll_path != None and pid != 4:
            is_dll_suspicious, reasons = check_dll(process_dll_path, dlllist_df[dlllist_df["Pid"] == pid]["Path"].tolist())

            if is_dll_suspicious:
                reasons_dict["dll_reasons"] = reasons

        is_handles_suspicious, reasons = check_handles(handles[handles["Pid"] == pid])
        
        if is_handles_suspicious:
            reasons_dict["handles_reasons"] = reasons

        # If there are any reasons collected, store them in the suspicious_processes dictionary
        if reasons_dict:
            add_reasons(pid, process_name, reasons_dict)

def add_reasons(pid, process_name, new_reasons):
    global suspicious_processes
    if pid not in suspicious_processes:
        suspicious_processes[pid] = {
            "process_name": process_name,
            "reasons": {}
        }
    for key, reason in new_reasons.iteritems():
        # Ensure vtscanx_reasons is always in the correct format (list of dicts)
        if key == "vtscanx_reasons":
            if isinstance(reason, (str, unicode)):
                # If it's a string, convert it to the proper format
                # Try to extract score for proper categorization
                score_match = re.search(r'score:\s*(\d+)', reason)
                score = int(score_match.group(1)) if score_match else 'VTScanX'
                reason = [{'category': score, 'reason': reason}]
            elif not isinstance(reason, list):
                # If it's neither string nor list, convert to proper format
                reason = [{'category': 'VTScanX', 'reason': str(reason)}]
            # Ensure each item in the list has both 'category' and 'reason' keys
            elif isinstance(reason, list):
                for i, item in enumerate(reason):
                    if not isinstance(item, dict):
                         reason[i] = {'category': 'VTScanX', 'reason': str(item)}
                    else:
                        if 'category' not in item:
                            item['category'] = 'VTScanX'
                        if 'reason' not in item:
                            item['reason'] = str(item)
        
        if key in suspicious_processes[pid]["reasons"]:
            if isinstance(suspicious_processes[pid]["reasons"][key], list):
                if isinstance(reason, list):
                    suspicious_processes[pid]["reasons"][key].extend(reason)
                else:
                    suspicious_processes[pid]["reasons"][key].append(reason)
            else:
                suspicious_processes[pid]["reasons"][key] = [suspicious_processes[pid]["reasons"][key], reason]
        else:
            suspicious_processes[pid]["reasons"][key] = reason if isinstance(reason, list) else [reason]


def analyze_hidden_network_artifacts():
    if "netscan" in results and results["netscan"]:
        connections_df = pd.DataFrame(results["netscan"]["rows"], columns=results["netscan"]["columns"])
        for i in range(len(connections_df)):
            row = connections_df.iloc[i]
            pid = row["PID"]
            if int(pid) in suspicious_processes:
                foreign_addr = row["ForeignAddr"]
                process_name = row["Owner"]

                if foreign_addr and not foreign_addr.startswith("0.0.0.0") and not foreign_addr.startswith("*") and not foreign_addr.startswith(":::"):
                    add_reasons(pid, process_name, {
                        "netscan_reasons": [{'reason': "Possible C2 communication: {}".format(foreign_addr), 'category': 'C2_IP'}]
                    })

    elif all(p in results and results[p] for p in ["connections", "connscan", "sockets", "sockscan"]):
        connections_df = pd.DataFrame(results["connections"]["rows"], columns=results["connections"]["columns"])
        connscan_df = pd.DataFrame(results["connscan"]["rows"], columns=results["connscan"]["columns"])
        sockets_df = pd.DataFrame(results["sockets"]["rows"], columns=results["sockets"]["columns"])
        sockscan_df = pd.DataFrame(results["sockscan"]["rows"], columns=results["sockscan"]["columns"])
        psscan_df = pd.DataFrame(results["psscan"]["rows"],
                                 columns=["Offset(P)", "Process Name", "PID", "PPID", "PDB", "Time Created", "Time Exited"])

        def get_process_name(pid):
            row = psscan_df[psscan_df["PID"] == pid]
            return row.iloc[0]["Process Name"] if not row.empty else "Unknown"

        conn_keys = ["LocalAddress", "RemoteAddress", "PID"]
        conn_reasons = find_hidden_entries(connections_df, connscan_df, conn_keys)

        for pid, reasons in conn_reasons.iteritems():
            if int(pid) in suspicious_processes:
                process_name = get_process_name(pid)
                new_reasons = {
                    "connections": reasons
                }
                add_reasons(pid, process_name, new_reasons)

        sock_keys = ["PID", "Port", "Proto", "Protocol", "Address"]
        sock_reasons = find_hidden_entries(sockets_df, sockscan_df, sock_keys)

        for pid, reasons in sock_reasons.iteritems():
            process_name = get_process_name(pid)
            if int(pid) in suspicious_processes:
                add_reasons(pid, process_name, {
                    "sockets": reasons
                })

    return suspicious_processes

def analyse_ldrmodules_malfind():
    psscan_df = pd.DataFrame(results["psscan"]["rows"], columns=["Offset(P)", "Process Name", "PID", "PPID", "PDB", "Time Created", "Time Exited"])
    ldrmodules = pd.DataFrame(results["ldrmodules"]["rows"],
                              columns=["Pid", "Process", "Base", "InLoad", "InInit", "InMem", "MappedPath"])
    malfind_df = pd.DataFrame(results["malfind"]["rows"], columns=results["malfind"]["columns"])

    for _, row in psscan_df.iterrows():
        process_name = row["Process Name"]
        pid = row["PID"] 
        if int(pid) in suspicious_processes:
            new_reasons = {}

            # Get all modules for this process
            pid_ldrmodules_df = ldrmodules[ldrmodules["Pid"] == pid]

            # *** FIX ***: Filter to only check actual DLLs for injection patterns.
            if not pid_ldrmodules_df.empty:
                # The str accessor must be used for each string method.
                pid_dlls_only_df = pid_ldrmodules_df[
                    pid_ldrmodules_df['MappedPath'].str.lower().str.endswith('.dll', na=False)
                ].copy()

                if not pid_dlls_only_df.empty:
                    is_ldrmodules_suspicious, reasons = check_ldrmodules(pid_dlls_only_df)
                    if is_ldrmodules_suspicious:
                        new_reasons["ldrmodules_reasons"] = reasons

            if not malfind_df[malfind_df["Pid"] == pid].empty:
                new_reasons["malfind_reasons"] = [{'reason':"Invalid memory protection permission: PAGE_EXECUTE_READWRITE",'category':'RWX_Memory_Permissions'}]

            if new_reasons:
                add_reasons(pid, process_name, new_reasons)


def load_vt_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_vt_cache(cache):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        print("Error saving cache: {}".format(str(e)))

def vtscanx_scan_file(file_path):
    """
    Submit file hash to the VTScanX API and return scan results if suspicious.
    Uses local cache to avoid redundant queries.
    """
    SERVER_IP_SCAN_URL = "{}/check_hash".format(VTSCANX_URL)
    headers = {"Authorization": "Bearer {}".format(VTSCANX_API_KEY)}
    sha256_hash = calculate_sha256(file_path)

    vt_cache = load_vt_cache()
    if sha256_hash in vt_cache:
        return vt_cache[sha256_hash] or None  # Return cached result or None

    try:
        response = requests.post(SERVER_IP_SCAN_URL, json={"hash_value": sha256_hash}, headers=headers)
        if response.status_code == 200:
            data = response.json()
            score = data.get("score", 0)
            category = (data.get("threat_category") or "").strip()
            label = (data.get("threat_label") or "").strip()
            threat_name = (data.get("threat_name") or "").strip()
            if score > VT_SCAN_THRESHOLD:
                parts = ["score: {}".format(score)]
                if category:
                    parts.append("Popular Threat Category: {}".format(category))
                if label:
                    parts.append("suggested_threat_label: {}".format(label))
                if threat_name:
                    parts.append("popular_threat_name: {}".format(threat_name))
                if score >= 40:
                    cat = "vt_40"
                elif score >= 20:
                    cat = "vt_20"
                else:
                    cat = "vt_10"
                reason_str = ", ".join(parts)
                reason = [{'reason': reason_str, 'category': cat}]
                vt_cache[sha256_hash] = reason
                save_vt_cache(vt_cache)
                return reason
            else:
                # Not suspicious
                vt_cache[sha256_hash] = None
                save_vt_cache(vt_cache)

    except requests.RequestException as e:
        print("Error during hash submission: {}".format(str(e)))

    return None

def extract_pid_from_filename(filename, source_type):
    """
    Extract PID based on file type (exe or dll)
    """
    if source_type == "exe":
        match = re.search(r'\.(\d+)\.exe$', filename)
        if match:
            return int(match.group(1))
    elif source_type == "dll":
        # Example: module.880.ea13030.10000000.dll → extract second part
        parts = filename.split('.')
        if len(parts) >= 3:
            try:
                return int(parts[1])  # This is the correct PID for the process owning the DLL
            except ValueError:
                pass
    return None


def scan_dump_table(table_name, valid_extensions, source_type, filter_pids=None):
    if not results.get(table_name) or not results[table_name].get("rows"):
        print("[-] No data in '{}' to scan. Skipping.".format(table_name))
        return

    dump_df = pd.DataFrame(results[table_name]["rows"], columns=results[table_name]["columns"])
    dump_dir = os.path.join(".", "dump", os.path.splitext(os.path.basename(memory_file))[0])

    for _, row in dump_df.iterrows():
        process_name = row.get("Name") or row.get("Process") or "Unknown"
        result = row.get("Result", "")

        if result.startswith("OK:"):
            file_name = result.split(":", 1)[1].strip()
            file_path = os.path.join(dump_dir, file_name)

            # This outer check is primarily for file existence and PID filtering
            if file_name.lower().endswith(valid_extensions):
                pid = extract_pid_from_filename(file_name, source_type)
                if pid is None:
                    continue

                if (filter_pids is None or pid in filter_pids) and os.path.exists(file_path):
                    # If scanning DLLs, ensure the source module is a DLL, not the EXE.
                    if source_type == "dll":
                        module_path = row.get("Module Name") or row.get("Module")
                        if not module_path or not module_path.lower().endswith('.dll'):
                            continue  # Skip this item as it's not a true DLL.

                    vt_reasons = vtscanx_scan_file(file_path)
                    if vt_reasons:
                        # Logic for adding reasons is now correctly filtered.
                        if source_type == "dll":
                            module_path = row.get("Module Name") or row.get("Module") # Re-get for safety
                            dll_real_name = os.path.basename(module_path) if module_path else file_name
                            label = "Suspicious DLL: {}".format(dll_real_name)
                            
                            new_vt_reasons = []
                            reasons_to_process = vt_reasons if isinstance(vt_reasons, list) else [vt_reasons]
                            
                            for item in reasons_to_process:
                                if isinstance(item, dict):
                                    reason_text = item.get("reason", "")
                                    category = item.get("category", "VTScanX")
                                    new_vt_reasons.append({
                                        "reason": "{} | {}".format(label, reason_text),
                                        "category": category
                                    })
                                else:
                                    new_vt_reasons.append({
                                        "reason": "{} | {}".format(label, str(item)),
                                        "category": "VTScanX"
                                    })
                            
                            add_reasons(pid, process_name, {"vtscanx_reasons": new_vt_reasons})
                        else: # For source_type == "exe"
                            add_reasons(pid, process_name, {"vtscanx_reasons": vt_reasons})

def vtscanx_scan():
    if scan_procdump:
        print("\n[+] Scanning all process dumps...")
        scan_dump_table("procdump", (".exe", ), "exe")

    if scan_dlldump:
        print("\n[+] Scanning all DLL dumps...")
        # Note: Volatility's dlldump can save files with a .dll extension, so we use that here.
        scan_dump_table("dlldump", (".dll", ), "dll")

    if scan_suspicious_only:
        print("\n[+] Scanning only suspicious process dumps...")
        pids = suspicious_processes.keys()
        scan_dump_table("procdump", (".exe", ), "exe", pids)

    if scan_suspicious_dll_only:
        print("\n[+] Scanning only suspicious DLLs...")
        pids = suspicious_processes.keys()
        scan_dump_table("dlldump", (".dll", ), "dll", pids)

def ssdt_hooks():
    RED = "\033[91m"    # Red color
    RESET = "\033[0m"   # Reset color
    print("\n[+] SSDT Hooking Report")
    print("=" * 50)

    if not results.get("ssdt") or not results["ssdt"].get("rows"):
        print("No SSDT data available.")
        return

    APIHooking_df = pd.DataFrame(results["ssdt"]["rows"], columns=results["ssdt"]["columns"])
    allowed_owners = ['ntoskrnl.exe', 'win32k.sys']

    hooked_functions = []

    for index, row in APIHooking_df.iterrows():
        owner = row['Owner']
        function_name = row['Function']
        if owner not in allowed_owners:
            hooked_functions.append((function_name, owner, row['Entry'], row['Addr']))

    if not hooked_functions:
        print("No SSDT hooks detected.")
        return

    for func_name, owner, entry, addr in hooked_functions:
        print("Function Name: {}{}{}".format(RED, func_name, RESET))
        print("Entry Number: {}".format(entry))
        print("Address: 0x{:X}".format(addr))  # Format address in hex
        print("Hooked By: {}".format(owner))
        print("-" * 50)

def suspicious_modules():
    RED = "\033[91m"     # Red color for module name
    YELLOW = "\033[93m"  # Yellow color for hidden status
    RESET = "\033[0m"    # Reset color

    print "\n[+] Suspicious Modules:"
    print "=" * 60

    if not all(p in results and results[p] for p in ["modules", "modscan"]):
        print "Module data not available. Skipping."
        return

    # Load DataFrames
    modules_df = pd.DataFrame(results["modules"]["rows"], columns=results["modules"]["columns"])
    modscan_df = pd.DataFrame(results["modscan"]["rows"], columns=results["modscan"]["columns"])

    # Convert Base columns to int (assumes already int or convertible)
    def safe_int(val):
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    modules_df['Base'] = modules_df['Base'].apply(safe_int)
    modscan_df['Base'] = modscan_df['Base'].apply(safe_int)

    # Suspicious path detection
    def is_suspicious(path):
        if not isinstance(path, (str, unicode)) or "\\" not in path:
            return False
        normalized_path = path.replace("\\", "\\\\").lower()
        safe_paths = [
            r"\\systemroot\\system32\\",
            r"c:\\windows\\system32\\",
            r"\\windows\\system32\\"
        ]
        for safe in safe_paths:
            if normalized_path.startswith(safe):
                return False
        return True

    # Mark suspicious modules from modules list
    modules_df['is_suspicious'] = modules_df['File'].apply(is_suspicious)
    suspicious_df = modules_df[modules_df['is_suspicious'] == True].copy()
    if not suspicious_df.empty:
        suspicious_df['Status'] = ''
        suspicious_df['Reason'] = 'Suspicious path'

    # Detect hidden modules (bases in modscan but NOT in modules)
    known_bases = set(modules_df['Base'].dropna())
    hidden_df = modscan_df[~modscan_df['Base'].isin(known_bases)].copy()
    if not hidden_df.empty:
        hidden_df['Status'] = 'Hidden'

        # Reset index before applying functions to avoid pandas error
        hidden_df = hidden_df.reset_index(drop=True)

        hidden_df['is_suspicious'] = hidden_df['File'].apply(is_suspicious)

        def reason_label(row):
            if row['Status'] == 'Hidden' and row['is_suspicious']:
                return 'Hidden + Suspicious path'
            elif row['Status'] == 'Hidden':
                return 'Hidden'
            elif row.get('is_suspicious', False):
                return 'Suspicious path'
            else:
                return ''

        hidden_df['Reason'] = hidden_df.apply(reason_label, axis=1)
    
    # Fill missing cols in hidden_df for consistent concat
    for col in ['Name', 'File', 'Size']:
        if col not in hidden_df.columns:
            hidden_df[col] = 'Unknown'
        hidden_df[col] = hidden_df[col].fillna('Unknown')

    # Ensure suspicious_df has all needed columns
    for col in ['Name', 'File', 'Base', 'Size', 'Status', 'Reason']:
        if col not in suspicious_df.columns:
            suspicious_df[col] = 'Unknown'

    # Combine both DataFrames
    combined_df = pd.concat([suspicious_df, hidden_df], ignore_index=True, sort=True)
    if combined_df.empty:
        print "No suspicious or hidden modules detected."
    else:
        for idx, row in combined_df.iterrows():
            name_str = RED + str(row['Name']) + RESET
            if row['Status'] == 'Hidden':
                name_str += " " + YELLOW + "[Hidden]" + RESET

            print "Module Name: " + name_str
            print "File Path  : " + str(row.get('File', 'Unknown')).encode('utf-8')

            try:
                base_val = int(row['Base'])
                print "Base Addr  : 0x%X" % base_val
            except (ValueError, TypeError):
                print "Base Addr  : Unknown"

            print "Size       : " + str(row.get('Size', 'Unknown'))
            print "Reason     : " + str(row.get('Reason', 'Unknown'))
            print "-" * 50

def print_suspicious_process():
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

    def highlight_score(reason_text):
        try:
            reason_text = str(reason_text)
            match = re.search(r"(score:\s*)(\d+)", reason_text)
            if match:
                score_val = int(match.group(2))
                if score_val > 50:
                    color = RED
                elif score_val > 20:
                    color = YELLOW
                else:
                    color = CYAN
                colored_score = "{}{}{}".format(match.group(1), color + match.group(2), RESET)
                return reason_text.replace(match.group(0), colored_score)
        except:
            pass
        return reason_text

    print "\n[+] Suspicious Processes Report"
    print "=" * 80

    if not suspicious_processes:
        print "No suspicious processes detected."
        return

    # --- Calculate Scores for Summary Table ---
    process_scores = []
    for pid, details in suspicious_processes.iteritems():
        process_name = details.get("process_name", "Unknown")
        reasons_dict = details.get("reasons", {})

        total_score = 0
        for reason_key, reason_list in reasons_dict.iteritems():
            if not isinstance(reason_list, list):
                reason_list = [reason_list]

            for reason_item in reason_list:
                if isinstance(reason_item, dict):
                    cat = reason_item.get('category')
                    try:
                        total_score += int(cat)
                    except (TypeError, ValueError):
                        total_score += CATEGORY_PRIORITIES.get(cat, 0)

        process_scores.append((total_score, pid, process_name))

    # --- Sort by score descending ---
    process_scores.sort(reverse=True)

    # --- Print Summary Table ---
    # --- Print Summary Table (Improved) ---
    print "\n" + "=" * 80
    print " " * 28 + "Suspicious Process Summary"
    print "=" * 80
    print "| {:<3} | {:<25} | {:<10} | {:<17} |".format("No.", "Process Name", "PID", "Suspicious Score")
    print "-" * 80

    for idx, (score, pid, name) in enumerate(process_scores, start=1):
        print "| {:<3} | {:<25} | {:<10} | {:<17} |".format(idx, name, pid, score)

    print "=" * 80


    # --- Detailed Per-Process Report ---
    for _, pid, process_name in process_scores:
        details = suspicious_processes[pid]
        reasons_dict = details.get("reasons", {})

        if "hidden_process" in reasons_dict:
            print "Process Name: {}{}{} {}[Hidden]{}".format(RED, process_name, RESET, YELLOW, RESET)
        else:
            print "Process Name: {}{}{}".format(RED, process_name, RESET)

        print "PID: {}".format(pid)
        print "Reasons:"

        other_reasons = []
        ldr_reasons = []

        for reason_key, reason_list in reasons_dict.iteritems():
            if reason_key == "ldrmodules_reasons":
                ldr_reasons.extend(reason_list)
            elif reason_key == "hidden_process":
                continue
            else:
                other_reasons.extend(reason_list)

        def print_reason_list(reason_list):
            for reason_item in reason_list:
                if isinstance(reason_item, dict) and 'reason' in reason_item:
                    reason_text = reason_item['reason']
                else:
                    reason_text = str(reason_item)
                print "     - {}".format(highlight_score(reason_text))

        print_reason_list(other_reasons)
        print_reason_list(ldr_reasons)

        print "-" * 50


def print_hidden_processes(pslist_data, psscan_data):
    """Identify and print hidden processes using tabulate in rst format."""
    global suspicious_processes
    
    if not pslist_data or not psscan_data:
        print("pslist or psscan data not available. Cannot check for hidden processes.")
        return

    pslist_pids = {entry[2] for entry in pslist_data}  # Extract PIDs from pslist_data
    psscan_pids = {entry[2] for entry in psscan_data}  # Extract PIDs from psscan_data
    hidden_pids = psscan_pids - pslist_pids  # Find PIDs present in psscan but not in pslist
    hidden_processes = []

    for row in psscan_data:
        pid = row[2]
        if pid in hidden_pids:
            reasons_dict = {"hidden_process": [{'category': 'HiddenProcess', 'reason' : "Hidden"}]}
            add_reasons(pid, row[1], reasons_dict)
            hidden_processes.append(row)
    if hidden_processes:
        headers = ["Offset(P)", "Name", "PID", "PPID", "PDB", "Time Created", "Time Exited"]
        print(tabulate(hidden_processes, headers=headers, tablefmt="rst"))
    else:
        print("No hidden processes found.")

def is_plugin_exist(plugin_name):
    global plugin_list
    plugin_name = plugin_name.lower()  # Normalize input

    if plugin_list is not None:
        # Compare after converting list items to lowercase
        if plugin_name in [p.lower() for p in plugin_list]:
            return True
        return False

    config = conf.ConfObject()
    registry.PluginImporter()
    registry.register_global_options(config, commands.Command)
    plugin_classes = registry.get_plugin_classes(commands.Command, lower=True)
    plugin_list = plugin_classes.keys()

    # Compare with lowercase keys
    if plugin_name in [p.lower() for p in plugin_list]:
        return True
    return False

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]')
    return ansi_escape.sub('', text)

def generate_txt_report(report_name, report_dir, include_plugins=None, include_all=False):
    output_buffer = StringIO.StringIO()
    output_buffer.write("======= Volatility Automated Report =======\n")
    output_buffer.write("Memory File: {}\n".format(memory_file))
    output_buffer.write("Profile Used: {}\n".format(profile))
    output_buffer.write("===========================================\n\n")

    output_buffer.write("General Info:\n")
    output_buffer.write("- Generated on: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    output_buffer.write("\n\n")

    # Capture and write print_suspicious_process output
    original_stdout = sys.stdout
    temp_output = StringIO.StringIO()
    sys.stdout = temp_output
    try:
        print_suspicious_process()
    finally:
        sys.stdout = original_stdout
        output_buffer.write(strip_ansi(temp_output.getvalue()) + "\n")

    # Capture and write ssdt_hooks output
    temp_output = StringIO.StringIO()
    sys.stdout = temp_output
    try:
        ssdt_hooks()
    finally:
        sys.stdout = original_stdout
        output_buffer.write(strip_ansi(temp_output.getvalue()) + "\n")

    # Capture and write suspicious_modules output
    temp_output = StringIO.StringIO()
    sys.stdout = temp_output
    try:
        suspicious_modules()
    finally:
        sys.stdout = original_stdout
        output_buffer.write(strip_ansi(temp_output.getvalue()) + "\n")

    if include_all is True and include_plugins is not None:
        selected_plugins = plugins[:]
        
        for p in include_plugins:
            if is_plugin_exist(p) and p not in selected_plugins:
                run_plugin(memory_file, profile, p, results)
                selected_plugins.append(p)

    elif include_all is True:
        selected_plugins = plugins[:]

    else:
        selected_plugins = [p for p in (include_plugins or []) if is_plugin_exist(p)]

    for plugin in selected_plugins:
        data = results.get(plugin)
        if not data:
            continue

        output_buffer.write("===== Plugin: {} =====\n".format(plugin))
        if plugin in ['pstree', 'hollowfind']:
            output_buffer.write(data + "\n\n")
        elif isinstance(data, dict):
            headers = data.get("columns", [])
            rows = data.get("rows", [])
            if rows:
                output_buffer.write(tabulate(rows, headers=headers, tablefmt="grid") + "\n\n")
            else:
                output_buffer.write("No data available\n\n")
        else:
            output_buffer.write(str(data) + "\n\n")

    # Save the report
    try:
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        file_path = os.path.join(report_dir, "{}.txt".format(report_name))
        with open(file_path, "w") as f:
            f.write(output_buffer.getvalue())
        print("[+] TXT report saved to: {}".format(file_path))
    except Exception as e:
        print("[-] Failed to save TXT report: {}".format(e))

def inject_wrap_td(row_html, index):
    cells = re.findall(r"<td>(.*?)</td>", row_html, flags=re.DOTALL)
    output = []
    for i, cell in enumerate(cells):
        if i == index:
            output.append('<td class="wrap-col">%s</td>' % cell)
        else:
            output.append('<td>%s</td>' % cell)
    return ''.join(output)

def _highlight_score_html(reason):
    """
    Finds a 'score' in a reason string and wraps it in a colored <span> for HTML.
    """
    try:
        reason = str(reason)
        match = re.search(r"(score:\s*)(\d+)", reason)
        if match:
            score_val = int(match.group(2))
            if score_val > 50:
                color = "#e74c3c"  # Red
            elif score_val > 20:
                color = "#f1c40f"  # Yellow
            else:
                color = "#3498db"  # Blue

            colored_score = '{}<span style="color: {}; font-weight: bold;">{}</span>'.format(
                match.group(1), color, match.group(2))
            return reason.replace(match.group(0), colored_score)
    except:
        pass
    return reason

# This function should already be in your script from the last step.
# No changes are needed here.
def _calculate_process_scores(suspicious_data):
    """
    Calculates a summary score for each suspicious process.
    ... (function content is unchanged) ...
    """
    process_scores = []

    for pid, details in suspicious_data.iteritems():
        process_name = details.get("process_name", "Unknown")
        reasons_dict = details.get("reasons", {})

        # Calculate the total suspicious score (Priority)
        total_score = 0
        for reason_key, reason_list in reasons_dict.iteritems():
            if not isinstance(reason_list, list):
                reason_list = [reason_list]
                
            for reason_item in reason_list:
                if isinstance(reason_item, dict):
                    cat = reason_item.get('category')
                    try:
                        total_score += int(cat)
                    except (ValueError, TypeError):
                        total_score += CATEGORY_PRIORITIES.get(cat, 0)

        # Extract the highest VirusTotal score
        max_vt_score = -1
        if "vtscanx_reasons" in reasons_dict:
            for item in reasons_dict["vtscanx_reasons"]:
                reason_text = item.get('reason', '')
                match = re.search(r'score:\s*(\d+)', reason_text)
                if match:
                    score = int(match.group(1))
                    if score > max_vt_score:
                        max_vt_score = score
        
        vt_score_display = str(max_vt_score) if max_vt_score != -1 else "N/A"

        process_scores.append({
            'pid': pid,
            'name': process_name,
            'score': total_score,
            'vt_score': vt_score_display
        })

    process_scores.sort(key=lambda x: x['score'], reverse=True)
    return process_scores

def _generate_suspicious_process_html(suspicious_data):
    """
    Generates an interactive HTML block for suspicious processes where the
    summary table itself contains the hyperlinks.
    """
    if not suspicious_data:
        return "<h2>Suspicious Process Analysis</h2><p>No suspicious processes detected.</p>"

    scores_data = _calculate_process_scores(suspicious_data)
    html_buffer = StringIO.StringIO()
    
    html_buffer.write("<h2>Suspicious Process Analysis</h2>")
    html_buffer.write("<h3>Process Risk Summary (Click Name for Details)</h3>")
    html_buffer.write('<table class="summary-table">')
    html_buffer.write("<thead><tr>")
    
    # --- THIS IS THE MODIFIED LINE ---
    html_buffer.write("<th>PID</th><th>Process Name</th><th>Suspicious Score (Priority)</th><th>VirusTotal</th>")
    # --- END OF MODIFICATION ---

    html_buffer.write("</tr></thead>")
    
    html_buffer.write("<tbody>")
    for item in scores_data:
        pid = item['pid']
        process_name = escape(str(item['name']))
        process_name_link = "<a href='#suspicious-pid-{}'>{}</a>".format(pid, process_name)
        html_buffer.write("<tr>")
        html_buffer.write("<td>%s</td>" % item['pid'])
        html_buffer.write("<td>%s</td>" % process_name_link)
        html_buffer.write("<td>%s</td>" % item['score'])
        html_buffer.write("<td>%s</td>" % item['vt_score']) # This data comes from the 'vt_score' key
        html_buffer.write("</tr>")
    html_buffer.write("</tbody></table>")
    html_buffer.write("<hr>")
    
    html_buffer.write("<h3>Process Details</h3>")
    # ... (the rest of the function remains the same) ...
    for item in scores_data:
        pid = item['pid']
        details = suspicious_data[pid]
        process_name = item['name']
        is_hidden = "hidden_process" in details.get("reasons", {})
        header_text = "Process: {} (PID: {})".format(escape(process_name), pid)
        if is_hidden:
            header_text += ' <span class="hidden-tag">[Hidden]</span>'
        html_buffer.write(
            "<h4 id='suspicious-pid-{}' class='clickable-header' onclick='toggleReasons(\"reasons-for-{}\")'>{} ▾</h4>".format(
                pid, pid, header_text
            )
        )
        html_buffer.write("<div id='reasons-for-{}' class='reasons-div' style='display:none;'>".format(pid))
        html_buffer.write("<ul>")
        reasons = details.get("reasons", {})
        if not reasons:
            html_buffer.write("<li>No specific reasons found, but flagged by heuristics.</li>")
        else:
            all_reasons = []
            for reason_key, reason_list in reasons.items():
                if reason_key == "hidden_process": continue
                if not isinstance(reason_list, list): reason_list = [reason_list]
                for reason_item in reason_list:
                    if isinstance(reason_item, dict):
                        all_reasons.append(reason_item.get('reason', ''))
                    else:
                        all_reasons.append(str(reason_item))
            for reason in sorted(all_reasons):
                highlighted_reason = _highlight_score_html(reason)
                html_buffer.write("<li>{}</li>".format(highlighted_reason))
        html_buffer.write("</ul></div>")
        
    return html_buffer.getvalue()

def generate_html_report(report_name, report_dir, include_plugins=None, include_all=False):
    output_buffer = StringIO.StringIO()
    file_hash = calculate_sha256(memory_file)

    output_buffer.write("<html><head><title>Volatility Report</title>")
    output_buffer.write('<meta charset="UTF-8">')
    output_buffer.write("""
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #f4f6f8;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 100%;
            margin: auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 15px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        h1 {
            text-align: center;
            color: #2c3e50;
        }
        h2 {
            color: #1f618d;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
            margin-top: 30px;
        }
        h3 { color: #2980b9; margin-top: 25px; }
        h4.clickable-header {
            cursor: pointer;
            color: #c0392b;
            padding: 8px;
            border-radius: 4px;
            background-color: #f9ebea;
            border: 1px solid #f5b7b1;
            margin-top: 15px;
            transition: background-color 0.2s;
        }
        h4.clickable-header:hover { background-color: #f2d7d5; }
        /* The separate summary-list style is no longer needed */
        .reasons-div {
            padding: 15px;
            margin-left: 20px;
            border-left: 3px solid #f1c40f;
            background-color: #fef9e7;
        }
        .reasons-div ul {
             margin-top: 0;
             padding-left: 20px;
        }
        .hidden-tag {
            color: #e67e22;
            font-weight: bold;
            font-style: italic;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: auto;
        }
        th, td {
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
            vertical-align: top;
            word-wrap: break-word;
        }
        th {
            background-color: #f0f0f0;
        }
        pre, .code-block {
            background: #f8f8f8;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            overflow-x: auto;
            white-space: pre-wrap; /* Ensures long lines wrap */
        }
        .meta {
            font-size: 14px;
            margin-bottom: 20px;
        }
        /* Styles for the summary table */
        .summary-table {
            width: 90%; /* Increased width slightly */
            margin: 20px auto;
            border-collapse: collapse;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .summary-table th {
            background-color: #1f618d;
            color: white;
            font-weight: bold;
        }
        .summary-table td {
             background-color: #ffffff; /* Explicitly set white background for all cells */
        }
        .summary-table tr:nth-child(even) td { /* Target TDs in even rows for background color */
            background-color: #f2f2f2;
        }
        .summary-table tr:hover td { /* Target TDs on hover */
            background-color: #ddd;
        }
        .summary-table a {
            text-decoration: none;
            color: #2e86c1;
            font-weight: bold;
        }
        .summary-table a:hover {
            text-decoration: underline;
        }
    </style>
    <script>
        function toggleReasons(elementId) {
            var element = document.getElementById(elementId);
            if (element.style.display === "none") {
                element.style.display = "block";
            } else {
                element.style.display = "none";
            }
        }
    </script>
    </head><body><div class='container'>
    """)

    output_buffer.write("<h1>Volatility Automated Report</h1>")
    output_buffer.write("<div class='meta'>")
    output_buffer.write("<p><strong>Memory File:</strong> %s</p>" % memory_file)
    output_buffer.write("<p><strong>SHA256 Hash:</strong> %s</p>" % file_hash)
    output_buffer.write("<p><strong>Profile Used:</strong> %s</p>" % profile)
    output_buffer.write("<p><strong>Generated on:</strong> %s</p>" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    output_buffer.write("</div>")

    # This function call remains the same, but relies on the updated helper function below
    suspicious_html = _generate_suspicious_process_html(suspicious_processes)
    output_buffer.write(suspicious_html)
    
    def capture_plugin_output(func, title):
        temp_output = StringIO.StringIO()
        original_stdout = sys.stdout
        sys.stdout = temp_output
        try:
            func()
        finally:
            sys.stdout = original_stdout
            cleaned_output = strip_ansi(temp_output.getvalue())
            output_buffer.write("<h2>%s</h2>" % title)
            output_buffer.write("<pre class='code-block'>%s</pre>" % unicode(cleaned_output, 'utf-8', errors='replace'))

    capture_plugin_output(ssdt_hooks, "SSDT Hook Analysis")
    capture_plugin_output(suspicious_modules, "Suspicious Modules")

    # This section for including plugin output remains the same
    if include_all is True and include_plugins is not None:
        selected_plugins = plugins[:]
        for p in include_plugins:
            if is_plugin_exist(p) and p not in selected_plugins:
                run_plugin(memory_file, profile, p, results)
                selected_plugins.append(p)
    elif include_all is True:
        selected_plugins = plugins[:]
    elif include_plugins is not None:
        selected_plugins = []
        for p in include_plugins:
            if p not in results.keys() and is_plugin_exist(p):
                run_plugin(memory_file, profile, p, results)
            selected_plugins.append(p)
    else:
        selected_plugins = []

    for plugin in selected_plugins:
        data = results.get(plugin)
        if not data:
            continue

        output_buffer.write("<h2>Plugin: %s</h2>" % plugin)

        if plugin in ['pstree', 'hollowfind']:
            output_buffer.write("<pre class='code-block'>%s</pre>" % cgi.escape(unicode(strip_ansi(data), 'utf-8', errors='replace')))

        elif isinstance(data, dict):
            headers = data.get("columns", [])
            rows = data.get("rows", [])
            if headers and rows:
                output_buffer.write('<table>')
                output_buffer.write('<tr>')
                for header in headers:
                    output_buffer.write('<th style="background-color:#dbe9f4; font-weight:bold;">%s</th>' % header)
                output_buffer.write('</tr>')
                for row in rows:
                    output_buffer.write('<tr>')
                    for cell in row:
                        # *** THIS IS THE CORRECTED AND MORE ROBUST WAY TO ESCAPE HTML ***
                        clean_cell = cgi.escape(strip_ansi(unicode(str(cell), 'utf-8', errors='replace')))
                        output_buffer.write('<td>%s</td>' % clean_cell)
                    output_buffer.write('</tr>')
                output_buffer.write('</table>')
            else:
                output_buffer.write("<p>No data available.</p>")
        else:
            output_buffer.write("<pre class='code-block'>%s</pre>" % cgi.escape(unicode(strip_ansi(str(data)), 'utf-8', errors='replace')))

    output_buffer.write("</div></body></html>")

    try:
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        file_path = os.path.join(report_dir, "%s.html" % report_name)
        with io.open(file_path, "w", encoding='utf-8') as f:
            f.write(output_buffer.getvalue())
        print("[+] HTML report saved to: %s" % file_path)
    except Exception as e:
        print("[-] Failed to save HTML report: %s" % str(e))


def _generate_suspicious_process_pdf_elements(suspicious_data, styles):
    """
    Generates ReportLab Flowables where the summary table itself contains
    the hyperlinks, removing the separate link list.
    """
    elements = []
    if not suspicious_data:
        elements.append(Paragraph("<b>Suspicious Process Analysis</b>", styles['Heading2']))
        elements.append(Paragraph("No suspicious processes detected.", styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))
        return elements

    scores_data = _calculate_process_scores(suspicious_data)

    elements.append(Paragraph("<b>Suspicious Process Analysis</b>", styles['Heading2']))
    elements.append(Paragraph("<u>Process Risk Summary (Click Name for Details)</u>", styles['Heading3']))
    
    # --- THIS IS THE MODIFIED LINE ---
    table_headers = ['PID', 'Process Name', 'Suspicious Score', 'VirusTotal']
    # --- END OF MODIFICATION ---

    table_rows = [table_headers]
    link_in_cell_style = ParagraphStyle('link_in_cell', parent=styles['Normal'], textColor=colors.blue)

    for item in scores_data:
        pid = item['pid']
        process_name = escape(str(item['name']))
        link_text = u'<link href="#pid_{}">{}</link>'.format(pid, process_name)
        process_name_paragraph = Paragraph(link_text, link_in_cell_style)
        
        row_data = [
            str(item['pid']),
            process_name_paragraph,
            str(item['score']),
            str(item['vt_score']) # This data comes from the 'vt_score' key
        ]
        table_rows.append(row_data)

    col_widths = [0.8 * inch, 2.7 * inch, 1.5 * inch, 1.5 * inch]
    summary_table = Table(table_rows, colWidths=col_widths)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 0.2 * inch))

    # Detailed sections logic follows...
    elements.append(Paragraph("<u>Process Details</u>", styles['Heading3']))
    bullet_style = ParagraphStyle('bullet_style', parent=styles['Normal'], leftIndent=20)
    
    for item in scores_data:
        pid = item['pid']
        details = suspicious_data[pid]
        process_name = item['name']
        is_hidden = "hidden_process" in details.get("reasons", {})
        header_text = u'<a name="pid_{}"/><b>Process: {} (PID: {})</b>'.format(pid, escape(process_name), pid)
        if is_hidden:
            header_text += u' <font color="orange"><i>[Hidden]</i></font>'
        elements.append(Paragraph(header_text, styles['h4']))
        
        reasons = details.get("reasons", {})
        if not reasons:
            elements.append(Paragraph(" - No specific reasons found.", bullet_style))
        else:
            all_reasons_text = []
            for reason_key, reason_list in reasons.items():
                if reason_key == "hidden_process": continue
                if not isinstance(reason_list, list): reason_list = [reason_list]
                for reason_item in reason_list:
                    if isinstance(reason_item, dict):
                        all_reasons_text.append(reason_item.get('reason', ''))
                    else:
                        all_reasons_text.append(str(reason_item))
            for reason in sorted(all_reasons_text):
                # Highlighting logic for PDF
                highlighted_reason_text = u""
                try:
                    reason_text = strip_ansi(unicode(reason))
                    match = re.search(r"(score:\s*)(\d+)", reason_text)
                    if match:
                        score_val = int(match.group(2))
                        color = "blue"
                        if score_val > 50: color = "red"
                        elif score_val > 20: color = "orange"
                        pre_match = escape(reason_text[:match.start()])
                        colored_score_html = u'{}<font color="{}"><b>{}</b></font>'.format(escape(match.group(1)), color, match.group(2))
                        post_match = escape(reason_text[match.end():])
                        highlighted_reason_text = pre_match + colored_score_html + post_match
                    else:
                        highlighted_reason_text = escape(reason_text)
                except Exception:
                    highlighted_reason_text = escape(strip_ansi(unicode(reason)))
                reason_para = Paragraph(u"- {}".format(highlighted_reason_text), bullet_style)
                elements.append(reason_para)
        elements.append(Spacer(1, 0.1 * inch))

    elements.append(Spacer(1, 0.2 * inch))
    return elements

def generate_pdf_report(report_name, report_dir, include_plugins=None, include_all=False):
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    file_path = os.path.join(report_dir, "%s.pdf" % report_name)
    doc = SimpleDocTemplate(file_path,pagesize=A4,rightMargin=20,leftMargin=20,topMargin=20,bottomMargin=20)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='h4', parent=styles['Heading4'], textColor=colors.HexColor('#c0392b')))
    elements = []

    # Report Header
    elements.append(Paragraph("Volatility Automated Report", styles['Title']))
    elements.append(Spacer(1, 0.2 * inch))

    # Meta Info
    file_hash = calculate_sha256(memory_file)
    info = [
        "Memory File: %s" % memory_file,
        "SHA256 Hash: %s" % file_hash,
        "Profile Used: %s" % profile,
        "Generated On: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ]
    for line in info:
        elements.append(Paragraph(escape(line), styles['Normal']))
    elements.append(Spacer(1, 0.2 * inch))

    # *** MODIFICATION STARTS HERE ***

    # Call the new helper to generate interactive PDF elements for suspicious processes
    suspicious_pdf_elements = _generate_suspicious_process_pdf_elements(suspicious_processes, styles)
    elements.extend(suspicious_pdf_elements)

    # Capture output for the other analysis sections
    for title, func in [
        # ("Suspicious Process Analysis", print_suspicious_process), # This is now handled above
        ("SSDT Hook Analysis", ssdt_hooks),
        ("Suspicious Modules", suspicious_modules)
    ]:
        temp_output = StringIO.StringIO()
        original_stdout = sys.stdout
        sys.stdout = temp_output
        try:
            func()
        finally:
            sys.stdout = original_stdout
        cleaned_output = strip_ansi(temp_output.getvalue())
        elements.append(Paragraph("<b>%s</b>" % title, styles['Heading2']))
        # Use a Code style for monospaced font
        code_style = ParagraphStyle('code_style', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
        for line in cleaned_output.splitlines():
            # Escape HTML special characters to prevent rendering issues
            escaped_line = escape(line)
            elements.append(Paragraph(escaped_line, code_style))
        elements.append(Spacer(1, 0.2 * inch))

    # *** MODIFICATION ENDS HERE ***

    if include_all is True and include_plugins is not None:
        selected_plugins = plugins[:]
        for p in include_plugins:
            if is_plugin_exist(p) and p not in selected_plugins:
                run_plugin(memory_file, profile, p, results)
                selected_plugins.append(p)

    elif include_all is True:
        selected_plugins = plugins[:]

    elif include_plugins is not None:
        selected_plugins = []
        for p in include_plugins:
            if p not in results.keys() and is_plugin_exist(p):
                run_plugin(memory_file, profile, p, results)
            selected_plugins.append(p)

    else:
        selected_plugins = []

    for plugin in selected_plugins:
        data = results.get(plugin)
        if not data:
            continue

        elements.append(Paragraph("<b>Plugin: %s</b>" % plugin, styles['Heading2']))

        if plugin in ['pstree', 'hollowfind']:
            code_style = ParagraphStyle('code_style', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
            for line in strip_ansi(data).splitlines():
                escaped_line = escape(line)
                elements.append(Paragraph(escaped_line, code_style))
        elif isinstance(data, dict):
            headers = data.get("columns", [])
            rows = data.get("rows", [])
            if headers and rows:
                # Simplified table creation for PDF to avoid complex width calculations
                table_data = [headers] + [[unicode(str(c), 'utf-8', 'ignore') for c in r] for r in rows]
                table = Table(table_data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0,0), (-1,-1), 1, colors.black)
                ]))
                elements.append(table)
            else:
                elements.append(Paragraph("No data available", styles['Normal']))
        else:
            code_style = ParagraphStyle('code_style', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
            for line in strip_ansi(str(data)).splitlines():
                escaped_line = escape(line)
                elements.append(Paragraph(escaped_line, code_style))

        elements.append(Spacer(1, 0.2 * inch))

    # Final save
    try:
        doc.build(elements)
        print("[+] PDF report saved to: %s" % file_path)
    except Exception as e:
        print("[-] Failed to save PDF report: %s" % str(e))
        

def get_profile(memory_file):
    """Run imageinfo to get suggested profiles."""
    print("\nRunning imageinfo to suggest a profile...\n")
    global suggested_profiles
    suggested_profiles = []

    try:
        process = subprocess.Popen("python2 vol.py -f '{}' imageinfo".format(memory_file), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        for line in iter(process.stdout.readline, ''):
            print line,
            if "Suggested Profile(s)" in line:
                profile_line = line.split(":", 1)[-1].strip()
                
                # Clean profiles: remove anything in parentheses and strip whitespace
                raw_profiles = profile_line.split(',')
                for p in raw_profiles:
                    clean_profile = re.sub(r"\s*\(.*?\)", "", p).strip()
                    if clean_profile:
                        suggested_profiles.append(clean_profile)

        process.stdout.close()
        process.wait()
    except Exception as e:
        print("[-] Error running imageinfo: {}".format(e))


    return suggested_profiles if suggested_profiles else None

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Volatility Automation Script - Analyzes memory dumps for suspicious processes."
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the memory dump file")
    parser.add_argument("-p", "--profile", help="Volatility profile to use (optional)")
    parser.add_argument("--scan-procdump", action="store_true", help="Scan dumped processes with VTScanX")
    parser.add_argument("--scan-dlldump", action="store_true", help="Scan dumped DLLs with VTScanX")
    parser.add_argument("--scan-suspicious-proc", action="store_true", help="Scan only suspicious processes with VTScanX")
    parser.add_argument("--scan-suspicious-dll", action="store_true", help="Scan only suspicious DLLs with VTScanX")
    parser.add_argument("--generate-txt", action="store_true", help="Generate report in TXT format")
    parser.add_argument("--generate-html", action="store_true", help="Generate report in HTML format")
    parser.add_argument("--generate-pdf", action="store_true", help="Generate report in PDF format")
    parser.add_argument("--report-name", type=str, default="memory_report", help="Name of the report file without extension")
    parser.add_argument("--report-dir", type=str, default="reports", help="Directory to save the report")
    parser.add_argument("--include-plugins", nargs="+", help="List of plugin names to include in report.")
    parser.add_argument("--all-include-plugins", action="store_true", help="To include all plugins")

    return parser.parse_args()

def main():
    print("Welcome to the Volatility Automation Script")
    global profile, memory_file, plugins, scan_procdump, scan_dlldump, scan_suspicious_only, scan_suspicious_dll_only

    args = parse_arguments()

    if not args.file:
        print("Usage: python2 {} -f <memory_dump_file> [options]".format(sys.argv[0]))
        sys.exit(1)

    memory_file = args.file

    if not os.path.exists(memory_file):
        print("[-] Error: Memory file not found at '{}'".format(memory_file))
        sys.exit(1)

    if args.profile:
        profile = args.profile.strip()
    else:
        # This is the restored interactive block
        s_profiles = get_profile(memory_file)
        if s_profiles:
            use_suggested = raw_input("\nUse suggested profile '{}'? [Enter=yes, type 'no' for manual]: ".format(s_profiles[0])).strip().lower()
            if use_suggested in ['', 'yes', 'y']:
                profile = s_profiles[0]
            else:
                profile = raw_input("Enter the profile to use: ").strip()
        else:
            print("No suggested profiles found.")
            profile = raw_input("Enter the profile to use: ").strip()

    if not profile:
        print("[-] No profile selected. Exiting.")
        sys.exit(1)

    if profile not in profiles:
        print("\n[!] Warning: The profile '{}' is not in this script's known list.".format(profile))
        print("[*] The script will attempt to use it, but it may not be compatible with all analyses.")
        print("[*] Known profiles are:")
        for p in profiles:
            print("  -", p)
    
    scan_procdump = args.scan_procdump
    scan_dlldump = args.scan_dlldump
    scan_suspicious_only = args.scan_suspicious_proc
    scan_suspicious_dll_only = args.scan_suspicious_dll

    print("\nUsing profile: {}\n".format(profile))

    # Determine which dump plugins to run
    if scan_procdump or scan_suspicious_only:
        if "procdump" not in plugins:
            plugins.append("procdump")
    
    if scan_dlldump or scan_suspicious_dll_only:
        if "dlldump" not in plugins:
            plugins.append("dlldump")

    threads = []
    # Determine if we should run netscan or the older network plugins
    is_win7_or_later = False
    try:
        # This check is fragile if `profiles` list is incomplete, but it's a good heuristic
        if profile in profiles and profiles.index(profile) >= profiles.index("Win7SP0x64"):
             is_win7_or_later = True
    except (ValueError, AttributeError):
        # Fallback for profiles not in the list, like Win10x64_15063
        if any(p in profile.lower() for p in ['win7', 'win8', 'win10', '2008', '2012', '2016', '2019']):
            is_win7_or_later = True

    current_plugins = list(plugins)
    if "networkscan" in current_plugins:
        if not is_win7_or_later:
            # It's older (like XP), replace networkscan with older plugins
            print("[*] Profile appears to be pre-Win7. Using connections, connscan, etc. instead of netscan.")
            current_plugins.remove("networkscan")
            current_plugins.extend(["connections", "connscan", "sockets", "sockscan"])

    for plugin in set(current_plugins): # Use set to avoid duplicates
        thread = threading.Thread(target=run_plugin, args=(memory_file, profile, plugin, results))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()  

    NPIP_check()
    analyze_hidden_network_artifacts()
    if VTSCANX_API_KEY and (scan_procdump or scan_dlldump or scan_suspicious_only or scan_suspicious_dll_only):
        vtscanx_scan()
    analyse_ldrmodules_malfind()

    include_plugins = args.include_plugins if args.include_plugins else []
    include_all = args.all_include_plugins
    report_name = args.report_name
    report_dir = args.report_dir
    
    print("\n[+] Checking for hidden processes...")
    print_hidden_processes(results.get("pslist", {}).get("rows"), results.get("psscan", {}).get("rows"))
    
    if args.generate_txt:
        # Decide which plugins to include in report
        generate_txt_report(report_name, report_dir, include_plugins, include_all)
    elif args.generate_html:
        generate_html_report(report_name, report_dir, include_plugins, include_all)
    elif args.generate_pdf:
        generate_pdf_report(report_name, report_dir, include_plugins, include_all)
    else:
        # Default console output if no report format is specified
        print_suspicious_process()
        ssdt_hooks()
        suspicious_modules()
        
if __name__ == "__main__":
    main()