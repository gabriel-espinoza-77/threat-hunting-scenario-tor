<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/gabriel-espinoza-77/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that employees may be using the TOR browser to circumvent network security controls due to recent network logs showing abnormal encrypted traffic and connections to known TOR entry nodes. Additionally, anonymous reports indicate employees discussing methods to access restricted sites during work hours. The objective is to identify any TOR activity, investigate related security incidents, and mitigate potential risks. If TOR usage is detected, management must be informed.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)`, `firefox(.exe)`, `browser(.exe)`, `tor-browser(.exe)` or `tor-browser64(.exe)` file events.
- **Check `DeviceProcessEvents`** for any indications of installation or activity..
- **Check `DeviceNetworkEvents`** for any indications of outbound connections on known TOR ports..

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Performed a search for files containing the string "tor" and found evidence that the user "employee" downloaded a TOR installer. Further activity resulted in multiple TOR-related files being copied to the desktop, along with the creation of a file named `tor-shopping-list.txt`. These events started at `2025-02-28T19:18:52.1552148Z`.

**Query used to identify events:**

```kql
DeviceFileEvents
| where DeviceName == "ge-threat-hunt-"
| where InitiatingProcessAccountName  == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-02-28T19:18:52.1552148Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/cfa2dfd7-e655-4939-a4f4-67b645aa51c3">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` entries containing the string "tor-browser-windows" According to the logs, at `2025-02-28T19:20:32.3678972Z`, an employee on the "ge-threat-hunt-" device executed `tor-browser-windows-x86_64-portable-14.0.6.exe` from their Downloads folder using a command that initiated a silent installation.

**Query used to identify event:**

```kql

DeviceProcessEvents
| where DeviceName == "ge-threat-hunt-"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/485b1b83-8a8d-4c8a-8ff3-3ab8a45d3a71">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Checked for any signs that the user "employee" had launched the TOR browser. Evidence confirmed that it was opened at `2025-02-28T19:21:02.4004259Z`. Multiple instances of `firefox.exe` (TOR) an `tor.exe` were also spawned afterwards.

**Query used to identify events:**

```kql
DeviceProcessEvents
| where DeviceName == "ge-threat-hunt-"
| where FileName has_any ("tor.exe", "firefox.exe", "browser.exe", "tor-browser.exe", "tor-browser64.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/5ccceaca-c104-4aa0-9c0f-c5df3245b5ac">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Checked for any indications that the TOR browser was used to establish a connection through known TOR ports. At `2025-02-28T19:21:15.6533026Z`, an employee on the "ge-threat-hunt-" device successfully connected to the remote IP address `195.201.34.213 ` via port `9001`. The connection was initiated by the process `tor.exe`, located at `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. Additionally, there was another connection to a site over port `9150`.

**Query used to identify events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ge-threat-hunt-"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/05871d08-6208-4da9-8cc3-a2762eafc9b7">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-02-28T19:18:52.1552148Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-02-28T19:20:32.3678972Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.6.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-02-28T19:21:06.9185899Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-02-28T19:21:15.6533026Z`
- **Event:** A network connection to IP `195.201.34.213` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-02-28T19:21:24.2913044Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** An additional network connection was established, indicating ongoing activity by user "employee".
- **Action:** Another successful connection was detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-02-28T19:29:00.1069029Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "ge-threat-hunt-" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `ge-threat-hunt-` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
