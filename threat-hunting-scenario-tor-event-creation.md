# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Activity**

## Steps taken by the "Bad Actor" to Create Logs and IoCs:
1. Download the TOR browser installer from [TorProject](https://www.torproject.org/download/)
2. Perform a silent installation: ```tor-browser-windows-x86_64-portable-14.0.6.exe /S```
3. Launch the TOR browser from the desktop folder.
4. Connect to the TOR network and browse various websites:
   - **WARNING: Onion site URLs frequently change. However, visiting standard websites through TOR should still generate relevant logs:**
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```

6. Create a file named ```tor-shopping-list.txt``` on the desktop and list several fake illicit items.
7. Delete the file to simulate data removal.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detects TOR download and installation, along with the creation and deletion of the shopping list file.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detects the silent installation of TOR, along with the execution of the TOR browser and service.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Designed to detect TOR network activity by monitoring tor.exe and firefox.exe for connections on TOR-related ports (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// TOR Browser being silently installed
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

## Created By:
- **Author Name**: Gabriel Espinoza
- **Author Contact**: www.linkedin.com/in/gabriel-espinoza10305070
- **Date**: March 5, 2025

---
