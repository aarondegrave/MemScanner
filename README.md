# MemScanner
This is a tool I build for my SEC350 (Network and Security Controls) Final

# Information
This tool requires a VirusTotal API key to work properly. This api key should be placed in the client variable under the virustotalscan function.
The tool uses Yara rules located at C:\yara_rules folder to scan process memory for known malicious signatures. There is a json output to send to a SIEM software.

# Speed
In order to speed up the program use pyinstaller to compile the python to executable ex. pyinstaller --onefile Final_part2.py --clean
