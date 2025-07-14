#dll, lsrmodules, network, handles
from parent_child_process import SUSPICIOUS_PATHS, SUSPICIOUS_MUTEXES, SUSPICIOUS_EVENTS, SUSPICIOUS_PIPES, normalize_path

def check_handles(df):
    suspicious = []

    # File paths
    if "File" in df["Type"].values:
        file_df = df[df["Type"] == "File"]
        for path in SUSPICIOUS_PATHS:
            matched = file_df[file_df["Details"].str.contains(path, case=False, na=False, regex=False)]
            for _, row in matched.iterrows():
                suspicious.append({'reason':"Accessed suspicious file: {}".format(row["Details"]),
                'category':'SuspiciousFile'
                })

    # Mutexes
    if "Mutant" in df["Type"].values:
        mutex_df = df[df["Type"] == "Mutant"]
        for m in SUSPICIOUS_MUTEXES:
            matched = mutex_df[mutex_df["Details"].str.contains(m, case=False, na=False, regex=False)]
            for _, row in matched.iterrows():
                suspicious.append({'reason':"Created or accessed suspicious mutex: '{}'".format(row["Details"]),
                'category':'SuspiciousMutex'
                })

    # Events
    if "Event" in df["Type"].values:
        event_df = df[df["Type"] == "Event"]
        for e in SUSPICIOUS_EVENTS:
            matched = event_df[event_df["Details"].str.contains(e, case=False, na=False, regex=False)]
            for _, row in matched.iterrows():
                suspicious.append({'reason':"Accessed suspicious event: '{}'".format(row["Details"]),
                'category' : 'SuspiciousEvent'
                })

    # Named pipes
    if "NamedPipe" in df["Type"].values:
        pipe_df = df[df["Type"] == "NamedPipe"]
        for p in SUSPICIOUS_PIPES:
            matched = pipe_df[pipe_df["Details"].str.contains(p, case=False, na=False, regex=False)]
            for _, row in matched.iterrows():
                suspicious.append({'reason':"Communicated over suspicious named pipe: '{}'".fromat(row["Details"]),
                'category':'Suspicious_Pipe'
                })

    # Return True if any suspicious handles found, else False
    return (True, suspicious) if suspicious else (False, [])



def check_ldrmodules(ldrmodules_data):
    """
    Analyzes LDRModules plugin output and checks for suspicious entries.
    Returns (True, reasons) if suspicious modules are found, otherwise (False, []).
    """
    suspicious_entries = []

    # Iterate through each row in the DataFrame
    for _, module in ldrmodules_data.iterrows():
        pid = module.get("Pid", "Unknown PID")
        process = module.get("Process", "Unknown Process")
        mapped_path = module.get("MappedPath", "Unknown Path")
        if mapped_path.endswith(".exe"):
            continue
        in_load = str(module.get("InLoad", "False")).lower() == "false"
        in_init = str(module.get("InInit", "False")).lower() == "false"
        in_mem = str(module.get("InMem", "False")).lower() == "false"

        # Check if any of the flags are False (suspicious)
        if in_load or in_init or in_mem:
            suspicious_entries.append({
                "Pid": pid,
                "Process": process,
                "MappedPath": mapped_path,
                "InLoad": module.get("InLoad", "False"),
                "InInit": module.get("InInit", "False"),
                "InMem": module.get("InMem", "False")
            })

    # Return formatted reasons or empty
    if suspicious_entries:
        reasons = []
        for entry in suspicious_entries:
            missing_lists = []
            if entry["InLoad"] == "False":
                missing_lists.append("InLoad")
            if entry["InInit"] == "False":
                missing_lists.append("InInit")
            if entry["InMem"] == "False":
                missing_lists.append("InMem")

            missing_str = ", ".join(missing_lists)

            reasons.append({'reason':"Suspicious DLL detected: missing from [{}]. Path: {}".format(missing_str, entry["MappedPath"]),
            'category' : 'DLLMissingFromList'
            })

        return (True, reasons)
    else:
        return (False, [])

def check_dll(process_name, dll_paths):
    if len(dll_paths) < 3:
        is_suspicious=0
        reasons=[]
        return is_suspicious, reasons
    dll_paths_lower = [normalize_path(dll.lower()) for dll in dll_paths]
    process_name = normalize_path(process_name)

    reasons = []
    expected_order = [
        process_name.replace(r"\\", r"\\\\").lower(),
        (u"c:\\windows\\system32\\ntdll.dll", u"c:\\windows\\syswow64\\ntdll.dll"),
        (u"c:\\windows\\system32\\kernel32.dll", u"c:\\windows\\syswow64\\kernel32.dll", u"c:\\windows\\system32\\csrsrv.dll")
    ]

    found_order = False
    injected_dlls = []

    # Loop through the DLL paths and find the expected order
    for i in range(len(dll_paths_lower) - len(expected_order) + 1):
        segment = dll_paths_lower[i:i + len(expected_order)]  # Extract the current segment

        # Check if the extracted segment matches the expected order
        match_found = True  
        for j in range(len(expected_order)):
            current_dll = segment[j]
            expected_dll = expected_order[j]

            # Match against expected DLLs (including tuples for alternative paths)
            if isinstance(expected_dll, tuple):
                if current_dll not in expected_dll:
                    match_found = False
                    break
            else:
                if current_dll != expected_dll:
                    match_found = False
                    break

        # If a match is found, determine if DLLs were injected
        if match_found:
            found_order = True
            if i > 0:  # DLLs before the expected order are considered injected
                injected_dlls = dll_paths[:i]
            break  # Stop checking further once we find a match

    # Generate the reasons based on findings
    if found_order:
        if injected_dlls:
            reasons.append({'reason':"Injected DLLs detected before the expected order:\n        " + "\n        ".join(injected_dlls),
            'category' : 'DLLInjected'
            })
    else:
        # If no match was found, show the first three DLLs loaded
        current_order = "\n        ".join(dll_paths_lower[:3])
        reasons.append({'reason':"The expected DLL load order is not maintained. First three DLLs loaded:\n        {}".format(current_order),
        'category' : 'DLLNotinorder'
        })

    # Check paths of all DLLs for legitimacy
    legitimate_paths = [
        "c:\\windows\\system32",
        "c:\\windows",
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\windows\\winsxs",
        "c:\\windows\\syswow64"
    ]

    dll_paths_lower = [dll for dll in dll_paths_lower if dll.strip()]

    # Now perform the filtering check
    for dll in dll_paths_lower:
        if dll == process_name:
            continue
        if not any(dll.startswith(path) for path in legitimate_paths):
            reasons.append({'reason':"DLL loaded from an illegitimate path: {}".format(dll),
            'category': 'DLLIllegitimatePath'
            })

    is_suspicious = len(reasons) > 0
    return is_suspicious, reasons

def find_hidden_entries(df_primary, df_scan, key_columns):
    # Merge the primary DataFrame with the scan DataFrame using a left join
    merged = df_scan.merge(df_primary, on=key_columns, how='left', indicator=True)
    
    # Find hidden entries (those that appear only in df_scan but not in df_primary)
    hidden_entries = merged[merged['_merge'] == 'left_only']

    # Create detailed human-readable messages
    hidden_messages = {}
    for _, row in hidden_entries.iterrows():
        pid = row.get("PID", "Unknown")
        details = []

        # For connection-related entries
        if "LocalAddress" in key_columns:
            local = row.get("LocalAddress", "N/A")
            remote = row.get("RemoteAddress", "N/A")
            ip_only = remote.split(':')[0] if ':' in remote else remote
            if API_KEY:
                score = send_ip_to_vtscanx(ip_only)
                if score > 0:
                    details.append("VirusTotal score for remote IP {}: {}".format(remote, score))
            proto = row.get("Protocol", row.get("Proto", "N/A"))
            details.append({'reason':"Hidden connection Local: {}, Remote: {}, Protocol: {}".format(local, remote, proto),
            'category' :'HiddenNetwork'
            })

        # For socket-related entries
        elif "Port" in key_columns:
            port = row.get("Port", "N/A")
            address = row.get("Address", "N/A")
            proto = row.get("Protocol", row.get("Proto", "N/A"))
            details.append({'reason':"Hidden socket Address: {}, Port: {}, Protocol: {}".format(address, port, proto),
            'category' :'HiddenSocket'
            })

        # Add to the messages dictionary under the correct PID
        hidden_messages.setdefault(pid, []).extend(details)

    return hidden_messages