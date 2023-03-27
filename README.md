# SoYouWannaBeAnAMSIProvider
Simple AMSI Provider that can use yara rules to match and block content.

*AMSI Provider Code is based on [Microsoft Sample AMSI provider](https://github.com/microsoft/windows-classic-samples/tree/main/Samples/AmsiProvider)*

# Credits
This Repo Utilizes
 - [Yara](https://github.com/VirusTotal/yara)
 - [nlohmann-JSON](https://github.com/nlohmann/json)
 - [cpp-base64-2.rc.08](https://github.com/ReneNyffenegger/cpp-base64/)
 - [Microsoft Sample AMSI provider](https://github.com/microsoft/windows-classic-samples/tree/main/Samples/AmsiProvider)


# Introduction

This AMSI provider is called `CaseyAMSIProvider` and is registered under `00000A62-77F9-4F7B-A90C-2744820139B2`

All usage of this AMSI provider will be in `C:\ProgramData\CaseyAMSI`

# Usage

## Register AMSI Provider Detection Only

**Requires elevated command prompt**

`regsvr32.exe <PATHTODLL>`

**Will Persist with Reboot**


![DetectedAndAllowed](https://user-images.githubusercontent.com/27497619/227823303-36cd973d-bc11-467c-ad58-a71e5babca75.jpeg)

## Register  AMSI Provider Blocking Mode

**Requires elevated command prompt**

`regsvr32.exe <PATHTODLL> /i:blocking`

**Will Persist with Reboot**

![DetectedAndBlocked](https://user-images.githubusercontent.com/27497619/227823366-c6e79fa7-4dba-4187-81d4-71f29169828d.jpeg)


## UnRegister AMSI Provider

`regsvr32.exe /u <PATHTODLL>`


## Yara Rules

Yara rules are will be located in `C:\ProgramData\CaseyAMSI`

Each `.yar` file within the folder will be compiled together, if any errors occur they will be placed in a file called `yara.log`

### Example
```yara
rule cats :cats{
  strings:
    $b1 = "catdogs" ascii wide nocase
  condition:
    $b1
}
```

# AMSI Logs  
 - JSON Format in `amsi.log` 
Structure:
```json
{
    "0_Timestamp": "string",
    "1_Provider": "string",
    "2_Source": "string",
    "3_Matches": "[]string",
    "4_Action": "string",
    "5_Data": "string"
}
```

### Example
```json
{
    "0_Timestamp": "2023-03-26 16:52:43",
    "1_Provider": "PowerShell_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe_10.0.19041.1",
    "2_Source": "Interactive",
    "3_Matches": [
        "cats"
    ],
    "4_Action": "Blocked",
    "5_Data": "write-host catdogs"
}
```
![AMSI_Provider_Test](https://user-images.githubusercontent.com/27497619/227823420-02a83b4d-2d0a-466a-8892-52713c550b2f.jpeg)

![AMSI_Block](https://user-images.githubusercontent.com/27497619/227823438-96d55ae0-1d5a-4710-9199-0bf83ddf2330.jpeg)

![2023-03-19_21-59](https://user-images.githubusercontent.com/27497619/227823490-52b5dd19-f5ce-4061-bbaa-ccc543427a2f.jpeg)

# Trace Logs

This AMSI provider also provides the following Trace Log Provider `0eb41778-68b3-4a08-8974-0788cbf094b4`

In order to capture these events After AMSI provider is registered.

**Requires elevated command prompt**
1. `xperf.exe -start CaseyAMSIProvider -f CaseyAMSIProvider.etl -on 0eb41778-68b3-4a08-8974-0788cbf094b4` 
    - begin the capture of eventsevents from the provider.
2. Execute Samples (Another Prompt if via Powershell )
3. `xperf.exe -stop CaseyAMSIProvider` 
    - stop capturing events.
4. `tracerpt CaseyAMSIProvider.etl`
    - View Logs
