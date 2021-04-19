import wmi
import yara
import os
import json
import hashlib
import vt
import ctypes
import threading
import psutil


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
            ctypes.windll.kernel32.DebugActiveProcess(processId)
            parentprocessID = new_process.parentprocessId
            name = new_process.Name
            exepath = new_process.ExecutablePath
            commandline = new_process.CommandLine
            try:
                psutilprocesser = psutil.Process(processId)
                parentprocessname = psutilprocesser.parent().name()
                username = psutilprocesser.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            try:
                all_matches = yara_scanning(processId, full_compiled)#Trys to match the rule to the strings in the process memory
                if len(all_matches) > 0:
                    print(all_matches)
                    sha256 = hashlib.sha256(open(exepath, 'rb').read()).hexdigest()
                    analysis_stats = virustotalscan(sha256)
                    jsondata = {"Process Name: ": name, "Process ID: ": processId, "Executable Path:" : exepath, "Executable Hash:": sha256, "VirusTotal Scan:" : str(analysis_stats), "CName\\Username:" : username, "Parent Process Name/ID:" : (parentprocessname , str(parentprocessID)), "Command Line: ": commandline, "Matches: ": str(all_matches)}
                    dump = json.dumps(jsondata, indent=4)
                    with open('MaliciousProcess.json', 'w') as outfile:
                        outfile.write(dump)
                    PROCESS_TERMINATE = 0x0001
                    PROCESS_QUERY_INFORMATION = 0x0400
                    hprocess = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, False, processId)
                    ctypes.windll.kernel32.TerminateProcess(hprocess, 1)
                    continueprocess(processId)
                    t1 = threading.Thread(target=gui)
                    t2 = threading.Thread(target=inside_main)
                    t1.start()
                    t2.run()
                    t1.join()
                    continue
                else:
                    continueprocess(processId)
            except yara.Error:
                continue
    inside_main()

def continueprocess(processId):
    ctypes.windll.kernel32.DebugActiveProcessStop(processId)
    
def virustotalscan(filehash):
    client = vt.Client("Input VT API Key")
    file = client.get_object("/files/" + filehash)
    analysis_stats= file.last_analysis_stats
    return analysis_stats

def gui():
    return ctypes.windll.user32.MessageBoxW(0, "Malicious Process Detected", "ALERT", 1)

main()