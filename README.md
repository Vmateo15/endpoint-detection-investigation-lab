# endpoint-detection-investigation-lab
SOC endpoint investigation lab using Sysmon, Windows Event Logs, Microsoft Sentinel, and KQL to detect suspicious PowerShell execution, trace process relationships, identify scheduled task persistence, and perform containment/remediation.


## Project Overview

This project simulates an endpoint security investigation in a controlled lab environment. I generated suspicious PowerShell and scheduled task activity on a Windows endpoint, collected process telemetry with Sysmon, and investigated the activity using Microsoft Sentinel and KQL.

The investigation focused on identifying suspicious process execution, analyzing parent-child process relationships, reviewing command-line activity, and validating persistence through a scheduled task.

After confirming the simulated activity, I performed containment and remediation by removing the scheduled task and associated PowerShell script.

## Lab Environment

- Microsoft Azure
- Microsoft Sentinel
- Log Analytics Workspace
- Windows Virtual Machine
- Sysmon
- Windows Event Viewer
- PowerShell
- Kusto Query Language (KQL)
