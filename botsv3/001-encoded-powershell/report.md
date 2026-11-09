Investigation 001: Encoded PowerShell Execution
Executive Summary

A suspicious PowerShell execution event was identified in PowerShell Operational logs. Analysis revealed the use of an encoded PowerShell command containing multiple defense-evasion techniques, including AMSI bypass, Script Block Logging suppression, remote payload retrieval, and in-memory execution.

The investigation identified communication with an external IP address and evidence consistent with a staged malware execution chain.
Artifacts
Dataset=BOTSV3
Event ID=4103
Host=hostx
user=userx
process=powershell.exe
Initial Hypothesis
The PowerShell event contains indicators suggesting malicious execution through an encoded command designed to evade security controls and execute remote content.

Supporting Observations
Encoded PowerShell command detected. 
Hidden execution parameters observed.
Non-interactive execution observed.
PowerShell logging controls manipulated.
AMSI bypass code identified.
Remote network communication present.
Investigation actions
Reviewed PowerShell Operational Logs and identified Event ID 4103 containing an encoded PowerShell command.

Evidence:

PowerShell execution detected.
Base64 encoded payload identified.
Process execution logged.
Investigation steps
Step 1
queried the BOTSV3 for available powershell.exe events 
Step 2-payload decoding
used cybershef to decode the base64 encoded script which revealed the functionality of the script
Step 4-script analysis
Performed manual script analysis of the scripts where i identified 
Defense evasion: 
EnableScriptBlockLogging = 0
EnableScriptBlockInvocationLogging = 0
AMSI Bypass:
amsiInitFailed = true 
Hidden powershell execution
-NoP
-NonI
-W Hidden 
Step 4 Network Analysis
I identified an external ip 45.x.x.x out reach 
Downloaddata() method 
URI admin/get.php
Findings

The decoded script demonstrated multiple malicious characteristics commonly associated with PowerShell-based malware campaigns.

Key findings include:

PowerShell command obfuscation through Base64 encoding.
Script Block Logging suppression.
AMSI bypass implementation.
Remote payload retrieval.
In-memory execution using Invoke-Expression (IEX).
Risk level 
High
Analysis

The observed behavior strongly indicates an attempt to evade detection mechanisms, retrieve additional payloads remotely, and execute code within memory.

The combination of AMSI bypass, PowerShell logging suppression, encoded commands, and external communication significantly increases confidence that the activity is malicious.
Recommendations
Detection Improvements
Alert on PowerShell execution using -enc.
Alert on PowerShell execution using -W Hidden.
Alert on AMSI bypass attempts.
Alert on Script Block Logging modifications.
Conclusion

The investigation identified a suspicious encoded PowerShell execution event leveraging multiple defense-evasion techniques. The script attempted to disable PowerShell logging, bypass AMSI protections, establish communication with an external host, retrieve additional content, and execute the downloaded payload in memory. Based on the collected evidence, the activity is assessed as malicious and consistent with a staged PowerShell malware execution chain.
