import wmi
import yara
import os
import json
import hashlib
import vt
import ctypes
import threading
import psutil

"""compiles yara rules"""
def yara_compile():
    rule_location = "C:\\yara_rules\\"  #Defines the location the yara rules are stored.
    rules = os.listdir(rule_location) # Gets a list of the rules in the rule_location directory
    full_compiled = []
    for rule in rules:
            yara_rule = os.path.join(rule_location + rule)
            if yara_rule.endswith('.yar') or yara_rule.endswith('.yara'):
                compiled_rules = yara.compile(filepath=yara_rule)
                full_compiled.append(compiled_rules)
    return full_compiled

"""Scans given processes memory against the compiled rules"""    
def yara_scanning(processId , full_compiled):
    all_matches = []
    for item in full_compiled:
        matches = item.match(pid=processId)
        if len(matches) > 0:
            all_matches.append(matches)
    return all_matches
  
def main():
    full_compiled = yara_compile()
    def inside_main():
        """Sets up a WMI process watcher to watch for process creation hooks."""
        c = wmi.WMI()
        process_watcher = c.Win32_Process.watch_for("creation")
        while True:
            new_process = process_watcher()
            processId = new_process.processId
            ctypes.windll.kernel32.DebugActiveProcess(processId) #Puts process into Debug mode so it cannot do harm to machine
            parentprocessID = new_process.parentprocessId
            name = new_process.Name
            exepath = new_process.ExecutablePath
            commandline = new_process.CommandLine
            try:
                psutilprocesser = psutil.Process(processId)
                parentprocessname = psutilprocesser.parent().name()
                username = psutilprocesser.username()
                children = psutilprocesser.children(recursive=True)
                child_list = []
                for child in children:
                    ctypes.windll.kernel32.DebugActiveProcess(child.pid)
                    child_list.append(child.pid)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                pass
            try:
                all_matches = yara_scanning(processId, full_compiled)#Trys to match the rule to the strings in the process memory
                if len(all_matches) > 0:
                    """If there is a match it gathers more information and puts it into a dictionary, then kills the process"""
                    try:
                        sha256 = hashlib.sha256(open(exepath, 'rb').read()).hexdigest()
                        analysis_stats = virustotalscan(sha256)
                        jsondata = {"Process_Name:": name, "Process_ID:": processId, "Executable_Path:": exepath, "Executable_Hash:": sha256, "VirusTotal_Scan:": str(analysis_stats), "CName_Username:": username, "Parent_Process_Name_ID:": (parentprocessname , str(parentprocessID)), "CommandLine:": commandline, "Matches:": str(all_matches)}
                        dump = json.dumps(jsondata, indent=4)
                        with open('MaliciousProcess.json', 'w') as outfile:
                            outfile.write(dump)
                    except Exception:
                        continue
                    PROCESS_TERMINATE = 0x0001
                    PROCESS_QUERY_INFORMATION = 0x0400
                    hprocess = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, False, processId)
                    ctypes.windll.kernel32.TerminateProcess(hprocess, 1)
                    continueprocess(processId) # After TerminateProcess is called a continue process needs to occur in order to close all open process handles.
                    if parentprocessname == "explorer.exe":
                        pass
                    else:
                        hprocess = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, False, parentprocessID)
                        ctypes.windll.kernel32.TerminateProcess(hprocess, 1)
                        continueprocess(parentprocessID)
                        for item in child_list:
                            hprocess = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, False, item)
                            ctypes.windll.kernel32.TerminateProcess(hprocess, 1)
                            continueprocess(item)
                    t1 = threading.Thread(target=gui)
                    t2 = threading.Thread(target=inside_main)
                    t1.start()
                    t2.run()
                    t1.join()
                    continue
                else:
                    continueprocess(processId)#Continues process if there are no matches
                    for child in child_list:
                        continueprocess(child)
            except yara.Error:
                continue
    inside_main()
    
"""Function to continue the process"""
def continueprocess(processId):
    ctypes.windll.kernel32.DebugActiveProcessStop(processId)

"""Scans a file based on hash using VT API"""
def virustotalscan(filehash):
    client = vt.Client("API KEY")
    file = client.get_object("/files/" + filehash)
    analysis_stats= file.last_analysis_stats
    return analysis_stats

"""Spawns a GUI (This doesn't pop up when ran as a service"""
def gui():
    return ctypes.windll.user32.MessageBoxW(0, "Malicious Process Detected", "ALERT", 1)

main()