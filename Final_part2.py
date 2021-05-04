import wmi
import yara
import os
import json
import hashlib
import vt
import ctypes
import threading
import psutil


WMI_Set = wmi.WMI() #Sets Up wmi 
process_watcher = WMI_Set.Win32_Process.watch_for("creation") #Watches for process creation hooks


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
    print("Yara Compiled")
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
    while True:
        """Sets up a WMI process watcher to watch for process creation hooks."""
        processId, parentprocessID, name, exepath, commandline = watch_process()
        try:
            parentprocessname, username, child_list = psutilprocess(processId)
        except TypeError:
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
                    pass
                TerminateProcess(processId)
                if parentprocessname == "explorer.exe":
                    pass
                else:
                    TerminateProcess(parentprocessID)
                    for item in child_list:
                        TerminateProcess(item)
                t1 = threading.Thread(target=gui)
                t1.start()
                pass
            else:
                RemoveDebugger(processId)
                for child in child_list:
                    RemoveDebugger(child)
        except yara.Error:
            pass

"""Any new processes will run through this function"""
def watch_process():
    while True:
        new_process = process_watcher()
        processId = new_process.processId
        ctypes.windll.kernel32.DebugActiveProcess(processId) #Puts process into Debug mode so it cannot do harm to machine
        parentprocessID = new_process.parentprocessId
        name = new_process.Name
        exepath = new_process.ExecutablePath
        commandline = new_process.CommandLine
        break
    return processId, parentprocessID, name, exepath, commandline

"""Encrich json using psutil data"""    
def psutilprocess(processId):
    try:
        psutilprocesser = psutil.Process(processId)
        parentprocessname = psutilprocesser.parent().name()
        username = psutilprocesser.username()
        children = psutilprocesser.children(recursive=True)
        child_list = []
        for child in children:
            ctypes.windll.kernel32.DebugActiveProcess(child.pid)
            child_list.append(child.pid)  
        return parentprocessname, username, child_list
    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
        pass

"""Function to terminate the process"""
def TerminateProcess(processId):
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_INFORMATION = 0x0400
    hprocess = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, False, processId)
    ctypes.windll.kernel32.TerminateProcess(hprocess, 1) #Terminates the process
    ctypes.windll.kernel32.DebugActiveProcessStop(processId) #Takes the process out of debug state so it can be terminated properly.

"""Function to take debugger off of process"""
def RemoveDebugger(processId):
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