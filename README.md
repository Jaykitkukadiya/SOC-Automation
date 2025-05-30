# Setting up SOC home lab

## Goal of this project 
  Building a SOC home lab with various tools which I will further use in detonating malware and analysing the traffic for greater visibility through next projects. 
  Gaining hands-on experience through setting up all these tools, and integrating them together. 
  
## Tech stack
```
  Host OS: Mac
  UTM : Universal Turing Machine (virtual machine for macOS)  
  PFSense - firewall, DNS server & forwarder, DHCP provider etc.    
  Suricata - intrusion detection/prevention system  
  Splunk Server - Security Information and Event Management tool  
  Wazuh Server - Endpoint detection and response solution  
  Shuffle - Security Orchestration, Automation, and Response tool  
  jira - Case Management tool  
  MISP - Malware Information Sharing Platform  
  Slack - Notifications
```

## network map
![Network diagram example](https://github.com/user-attachments/assets/37a44f28-e2f3-4678-b619-c49e4d735dcd)

## Machines in the home lab
  ### FreeBSD
  ```
    Mode of running: emulated(AMD)
    Role: deployed PFSense and Suricata
    Number of NICS: 3 (1 external, 2 internal)
    IP: <dynamic IP>(WAN network) / 192.168.99.1(Security network) / 192.168.101.1(Endpoint network)
  ```
   ### Windows 11 
   ```
    Mode of running: virtualized(ARM)
    Role: Endpoint for end users
    Number of NICS: 1 (internal)
    IP: any from 192.168.101.10/24 to 192.168.101.245/24
    Static: no
    Network: Endpoint
  ```
  ### Windows 11 
  ```
    Mode of running: virtualized(ARM)
    Role: Splunk server and centeral monitoring machine.
    Number of NICS: 1 (internal)
    IP: 192.168.99.2
    static: Yes
    Network: Security
  ```
  ### Ubuntu 24.10 
  ```
    Mode of running: emulated(AMD)
    Role: WAZUH server
    Number of NICS: 1 (internal)
    IP: 192.168.99.3
    static: Yes
    network: Security
  ```

## Overall Network architecture (implemented on pfsense firewall)
  ### Wide area network (external network)
  ```
    NIC type: Bridge mode (IP through DHCP on external router)
    NAT: configured
  ```
  ### Local area Networks
  #### Endpoint Network (internal isolated network)
  ```
    NIC type: internal-isolated
    DHCP: Configured
    DNS Resolver: Configured
    IP address range: 192.168.101.10/24 - 192.168.101.245/24
    Rule set: configured
      block all traffic from endpoint network to security network except for some required ports (9997, 1514, 1515, 8089 etc.) for log forwarding.
    Static IP machines: None
  ```
  #### Security Network (internal isolated network)
  ```
    NIC type: internal-isolated
    DHCP: Configured
    DNS Resolver: Configured
    IP address range: 192.168.99.10/24 - 192.168.99.245/24
    Rule set: configured
      block all traffic from endpoint network to security network except for some required ports for log forwarding. Allow all traffic from security network to endpoint network.
    Static IP machines: WAZUH server, Splunk server
  ```
## Static machine ip details in home lab
```
  Splunk Server: splunk.local OR 192.168.99.2
  WAZUH Server: wazuh.local OR 192.168.99.3
```
## Installation and Integration process

1. Installation of pfsense
```
Download .ISO file from https://www.pfsense.org/download/.
added as disk image as installation disk.
configured network interface as WAN & LAN network during installation process.
configured DHCP with interface specific IP range, static IPs.
configured DNS service.
harden basic security through interface specific rule setup.
```
2. Installation of Suricata
```
installed suricata package from System > Package Manager > Available Packages
configured endpoint and security interface with inline mode.
updated rule sets.
configured passlist.
```
3. Installation of Splunk server
```
download splunk enterprice community version from https://www.splunk.com/en_us/download.html
installed splunk by activating installer on splunk server.
confirmed installation by nevigating through splunk dashboard.
configured local domain in pfsense as splunk.local pointing to machine's static ip.
```
4. Installation of WAZUH server
```
followed step by step installation from https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/step-by-step.html for all three components including indexer, manager, and dashboard.
confirmed installation by accessing dashboard on analyst's machine(splunk server).
configured local domain name in pfsense as wazuh.local pointing to machin's static ip.
```
5. Installation and integration of Splunk universal forwarder on endpoint and pfsense machine for suricata logs  
5.1 Installation and integration of Splunk universal forwarder on endpoint
```
downloaded splunk universal forwarder on endpoint and setted up with destination splunk server's ip on 8089 port.
allowed port 8089 on firewall and splunk machine's firewall to receive logs.
```
5.2 Installation and integration of Splunk universal forwarder on pfsense machine
```
downloaded splunk universal forwarder and splunk ta for suricata as .txz file on pfsense's machine. unzip both file in root, move ta-suricata in "opt/splunkforwarder/etc/apps"
added outputs.conf in /opt/splunkforwarder/etc/system/local with following contents

"[tcpout]
defaultGroup=my_indexers
[tcpout:my_indexers]
server=192.168.99.2:9997" (allowed this port on splunk machine's firewall)

updated inputs.conf with following content

"[monitor:///var/log/suricata/suricata_vtnet12947/eve.json]
sourcetype = suricata
index = suricata
host = pfSense.homenet.fgh"

finally started splunk forwarder with splunk enable boot-start command from bin folder.
allowed port 9997 on firewall and splunk machine's firewall to receive logs.
```
5.3 configuring splunk server for receiving and parsing logs for each forwarder, and pfsense firewall
```
defined new index for endpoint's log, suricata's log, and pfsense logs with names endpoint_0x01, firewall_pfsense, and suricata respectively.
setted up index storage size limitation, integrity checks per index data, etc.
configured listening port 9997 on splunk server to receive logs from endpoint, and suricata and data input through standard add data forward method for endpoint
installed TA-suracata app from splunk base for better parsing suricata logs.
configured port 5147 for receiving pfsense's syslogs.
```
6. installation and integration of wazuh agent on endpoint and  splunk server's machine
```
downloaded wazuh installer from "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi" and installed it by providing wazuh server's ip 192.168.99.3.
allowed port 1514, 1515 on firewall and server to receive logs.
```
7. settingup project in jira
```
created new project named "socsecurityalerts".
added 3 column in sprint named new alert, alert in progress, alert closed.
```

## automating ip reputation check through AbuseIPDB, blocking malicious ip, and notifying on slack upon every unique ip connect while also looking for calls to previously known malicious ip by the network in realtime.

### workflow
![Blank diagram](https://github.com/user-attachments/assets/a665fbb2-0852-4d58-bc7c-61a8643f2b97)

### alerts for ip blocking in splunk
Previously unknown malicious ip detector alert
```
index="firewall_pfsense" sourcetype=pfsense:filterlog
[ search index="firewall_pfsense" sourcetype=pfsense:filterlog
| stats values(dest_ip) as dest_ip
| mvexpand dest_ip
| regex dest_ip="^\d{1,3}(\.\d{1,3}){3}$"
| dedup dest_ip
| lookup abuseipdbs dest_ip OUTPUTNEW abuseConfidenceScore, last_checked
| where isnull(abuseConfidenceScore)
| eval last_checked=strftime(now(), "%F %T")
| abuseipdbcheck ip=dest_ip
| table dest_ip, abuseConfidenceScore, last_checked
| outputlookup append=true abuseipdbs
| where abuseConfidenceScore>50
| fields dest_ip
| format
] | lookup abuseipdbs dest_ip OUTPUTNEW abuseConfidenceScore, last_checked
| sort -_time
| dedup dest_ip  
| table _time src_ip dest_ip dest_port action abuseConfidenceScore *
```
> scheduled to run every 1 minute.  
> calls webhook for slack message, runs ip_block.py to block ip in firewall.
previously known malicious ip detector alert
```
index=firewall_pfsense sourcetype=pfsense:filterlog
[
  search index=firewall_pfsense sourcetype=pfsense:filterlog
  | stats values(dest_ip) as dest_ip
  | mvexpand dest_ip
  | regex dest_ip="^\d{1,3}(\.\d{1,3}){3}$"
  | dedup dest_ip
  | lookup abuseipdbs dest_ip OUTPUTNEW abuseConfidenceScore, last_checked
  | where isnotnull(abuseConfidenceScore)
  | where abuseConfidenceScore > 50
  | fields dest_ip
  | format
] 
| lookup abuseipdbs dest_ip OUTPUTNEW abuseConfidenceScore, last_checked
| table _time src_ip dest_ip dest_port action abuseConfidenceScore *
```
> scheduled in realtime mode.    
> calls webhook for slack message.  
### script for blocking ip efficiently vie direct ssh from splunk to pfsense.

```
import sys
import json
import subprocess
from datetime import datetime

LOG_FILE = "C:/Program Files/Splunk/var/log/splunk/block_ip_splunk.log"

def log(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | {message}\n")

try:
    payload = sys.stdin.read() # takes input from splunk
    log(f"Input: {repr(payload)}")
    
    # format and retrive destination ip
    results = json.loads(payload)
    result = results.get("result", {})
    ip = result.get("dest_ip")

    # validation
    if not ip:
        log("No dest_ip found in payload.")
        sys.exit(1)

    # add ip in table
    cmd = 'ssh -i \"C:\\ssh\\pfsense_key\" admin@192.168.99.1 pfctl -t \'splunk_blocklist\' -T add ' + ip
    
    # add ip in txt file in firewall for persistence.
    cmd1 = 'ssh -i \"C:\\ssh\\pfsense_key\" admin@192.168.99.1 \"echo \'' + ip + '\' >> \/root\/splunk_blocklist.txt\"'

    # kill all active connection's stat on firewall.
    cmd2 = 'ssh -i \"C:\\ssh\\pfsense_key\" admin@192.168.99.1 pfctl -k 0.0.0.0/0 -k ' + ip 

    log(f"Running: {cmd}")
    log(f"running: {cmd1}")
    log(f"running: {cmd2}")
    try:
        # execution of commands
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result1 = subprocess.run(
            cmd1,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result2 = subprocess.run(
            cmd2,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        log(f"Command return code: {result.returncode}")
        log(f"Command return code: {result1.returncode}")
        log(f"Command return code: {result2.returncode}")

        # result validation
        if result.returncode == 0:
            log(f"Successfully blocked: {ip}")
        else:
            log(f"there is an error while blocking {ip}: return code {result.returncode}")

    except subprocess.TimeoutExpired:
        log(f"Oops: SSH command timed out for {ip}")

except Exception as e:
    log(f"Exception: {str(e)}")
```
### firewall configuration for blocking dynamic list of ip
Create alias on firewall with "splunk_blocklist" name with type hosts.
add firewall rules on all 3 interface to block these list of ips comming toward firewall from any direction and not allow to pass on any port, and protocol

> WAN interface : ipv4 protocol:* source:splunk_blocklist port:* destination: WAN address port *    
> Endpoint interface : ipv4 protocol:* source:endpoint_sunbent port:* destination:splunk_blocklist port *    
> Security interface : ipv4 protocol:* source:security_sunbent port:* destination:splunk_blocklist port *    

### shuffle workflow for automated message in slack with additional reputation check on virustotal.
<img width="1061" alt="image" src="https://github.com/user-attachments/assets/f8e7c0b9-a9eb-4a5b-b1ac-fd4ca5f4c3ea" />
slack messages:
<img width="1800" alt="image" src="https://github.com/user-attachments/assets/fa3135b4-f6ff-4dae-a761-48815bc94505" />

## wazuh automation for malicious file detection with virustotal integration, automated active response to remove malicious file, and notify on slack and email.

### workflow diagram for automated wazuh detection, maliciousness check, active response, and notifications
![wazuh automation](https://github.com/user-attachments/assets/f4e4f4a2-0400-4920-9987-ea45aa2b7e44)

### configure active monitoring destination folder.
wazuh's file integrity module is comes in picture when we wants to actively monitor the directory's changes either in realtime or periodically.
To add my custom monitoring directory I did following.
> added ``` <directories check_all="yes" realtime="yes">C:\Users\jaykit\Downloads</directories> ``` under ``` <syscheck> ``` tag in ``` ossec.conf ``` file in server and endpoint to look for any changes in this directory

and then restart both wazuh agent and manager to reload the configuration  

### integration of virustotal on wazuh.
added following code in the ossec.conf on server to configure it to integrate virustotal service on wazuh, makes hash check api call on virustotal with following api key to fetch the report.
```
  <integration>
    <name>virustotal</name>
    <api_key>055a**************************************************818e9</api_key>
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>
```
The virustotal rules on wazuh actively looks for the api response and triggers an alert upon found malicious or not. 
<img width="1512" alt="Screenshot 2025-05-29 at 7 53 59 PM" src="https://github.com/user-attachments/assets/3af80f95-0be7-42b2-8237-17dec8cf7be2" />

### configuring active response upon virustotal malicious file report.
upon confirmation of alert is triggering upon malicious file present in the directory. the following thig will be remove it from that directory automatically. 
for that, i am using custom statless active response script that will be run on the endpoint to delete malicious file.
first add following this in ``` ossec.conf ``` file on server

```
<command>
  <name>rm-th-ar</name>
  <executable>rmth.bat</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>rm-th-ar</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>

```
this configuration ensures that the response command will only be initiated when the rule with id 87105 (virus total malicious file detected) is triggered. location confirms it running on endpoint's local machine.

once the alert triggered, it will execute the ``` rmth.bat ``` a custom batch script on endpoint machine with input provided over stdin chennal.
```
@echo off
setlocal enabledelayedexpansion

set "INPUT_FILE=C:/stdin_input1SS.json"
set "EXTRACTED_PATH=C:/file_path.txt"
set "LOG_FILE=C:/rmth.log"

more > "%INPUT_FILE%"

echo Active response started > "%LOG_FILE%"

powershell -NoProfile -Command "try { ($p = Get-Content -Raw '%INPUT_FILE%' | ConvertFrom-Json).parameters.alert.data.virustotal.source.file } catch { '' }" > "%EXTRACTED_PATH%"

set "FILE_PATH="
for /f "usebackq delims=" %%A in ("%EXTRACTED_PATH%") do (
    set "FILE_PATH=%%A"
)

echo Extracted path: !FILE_PATH! >> "%LOG_FILE%"

if exist "!FILE_PATH!" (
    del /f /q "!FILE_PATH!" >nul 2>&1
    echo Deleted file: !FILE_PATH! >> "%LOG_FILE%"
) else (
    echo File not found or empty path >> "%LOG_FILE%"
)

endlocal
exit /b 0

```
and the sample output that is provided to this script will be 
```
{"version":1,"origin":{"name":"node01","module":"wazuh-execd"},"command":"add","parameters":{"extra_args":[],"alert":{"timestamp":"2025-05-29T21:37:32.128+0000",
"rule":{"level":12,"description":"VirusTotal: Alert - c:\\users\\jaykit\\downloads\\asdf.txt - 64 engines detected this file","id":"87105","mitre":{"id":["T1203"],"tactic":["Execution"],"technique":["Exploitation for Client Execution"]},"firedtimes":1,"mail":true,"groups":["virustotal"],"pci_dss":["10.6.1","11.4"],"gdpr":["IV_35.7.d"]},"agent":{"id":"003","name":"ENDPOINT-Jaykit","ip":"192.168.101.10"},"manager":{"name":"wazuh"},"id":"1748554652.31442705","decoder":{"name":"json"},
 "data":{"virustotal":{"found":"1","malicious":"1","source":{"alert_id":"1748554644.31441457","file":"c:\\users\\jaykit\\downloads\\asdf.txt",
"md5":"44d88612fea8a8f36de82e1278abb02f","sha1":"3395856ce81f2b7382dee72602f798b642f14140"},"sha1":"3395856ce81f2b7382dee72602f798b642f14140","scan_date":"2025-05-29 21:26:57","positives":"64","total":"68","permalink":"https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/detection/f-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1748554017"},"integration":"virustotal"},"location":"virustotal"},"program":"active-response/bin/rmth.bat"}}
```
 * i used batch file for this execution, but we can use python, java, exe, msi, sh, or any other file

### configuring shuffle workflow and webhook integration on wazuh.

to integrate shuffle shuffle to send slack message upon detection, wazuh needs to call a webhook, for that i added following in the ``` ossec.conf ```.
```
  <integration>
    <name>shuffle</name>
    <hook_url>https://shuffler.io/api/v1/hooks/webhook_a9ab55d8-7784-4dd8-944e-405df7c9331c</hook_url>
    <rule_id>87105</rule_id>
    <alert_format>json</alert_format>
  </integration>
```
this ensures that the webhook only calls when alert with rule id 87105 called.

#### shuffle workflow diagram
<img width="1081" alt="image" src="https://github.com/user-attachments/assets/2a02ecea-ed56-424e-acae-a47499cd5658" />


#### gmail configuration
To send email, It required to authenticate. for this, i used client id and secret generated from ```https://console.cloud.google.com/``` with limited scope and requester domain, and authenticate sender's email.

##### email message body
```
FROM: jaykitkukadiya0@gmail.com
TO: mr.jaykit@gmail.com
subject: $exec.pretext: $exec.title

 Pretext: $exec.pretext
Severity: $exec.severity
Title: $exec.title
Rule ID: $exec.rule_id
Timestamp: $exec.timestamp
Event ID: $exec.id

——— Rule Details ———

Level: $exec.all_fields.rule.level
Description: $exec.all_fields.rule.description
Rule ID: $exec.all_fields.rule.id
Fired Times: $exec.all_fields.rule.firedtimes

--- Agent Details ---
Agent ID: $exec.all_fields.agent.id
Agent Name: $exec.all_fields.agent.name
Agent IP: $exec.all_fields.agent.ip
Manager: $exec.all_fields.manager.name
Decoder: $exec.all_fields.decoder.name

--- VirusTotal Data ---
Found: $exec.all_fields.data.virustotal.found
Malicious: $exec.all_fields.data.virustotal.malicious
Source Alert ID: $exec.all_fields.data.virustotal.source.alert_id
Source File: $exec.all_fields.data.virustotal.source.file
MD5: $exec.all_fields.data.virustotal.source.md5
SHA1: $exec.all_fields.data.virustotal.source.sha1
Scan Date: $exec.all_fields.data.virustotal.scan_date
Positives: $exec.all_fields.data.virustotal.positives
Total Engines: $exec.all_fields.data.virustotal.total
Permalink: $exec.all_fields.data.virustotal.permalink

Integration: $exec.all_fields.data.integration
Location: $exec.all_fields.location
```
above body message will than converted to base64 and than it will be added as value of key "raw" in gmail app's body.

##### Final email
<img width="1209" alt="image" src="https://github.com/user-attachments/assets/0ea79c93-0a64-49b0-9486-4a2aa5d63c69" />

#### slack configuration
To send the message in slack, I have created ```malicious-file-detection-response``` channel, add an soclab app in the channel, and retrive channel ID.

added following text in body to generate the message
```
{
  "channel": "C08U8CMHNMV",
  "username": "Wazuh",
  "icon_emoji": ":rotating_light:",
  "text": "🚨 WAZUH Alert – VirusTotal Detection",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "🚨 WAZUH Alert"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Pretext:*\n$exec.pretext"
        },
        {
          "type": "mrkdwn",
          "text": "*Severity:*\n$exec.severity"
        },
        {
          "type": "mrkdwn",
          "text": "*Title:*\nVirusTotal: Alert - $path_replacer.message - $exec.all_fields.data.virustotal.positives engines detected this file."
        },
        {
          "type": "mrkdwn",
          "text": "*Rule ID:*\n$exec.rule_id"
        },
        {
          "type": "mrkdwn",
          "text": "*Timestamp:*\n$exec.timestamp"
        },
        {
          "type": "mrkdwn",
          "text": "*Event ID:*\n$exec.id"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Level:*\n$exec.all_fields.rule.level"
        },
        {
          "type": "mrkdwn",
          "text": "*Description:*\nVirusTotal: Alert - $path_replacer.message - $exec.all_fields.data.virustotal.positives engines detected this file."
        },
        {
          "type": "mrkdwn",
          "text": "*Rule ID:*\n$exec.all_fields.rule.id"
        },
        {
          "type": "mrkdwn",
          "text": "*Fired Times:*\n$exec.all_fields.rule.firedtimes"
        },
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Agent:*\n$exec.all_fields.agent.name (`$exec.all_fields.agent.id`)"
        },
        {
          "type": "mrkdwn",
          "text": "*IP:*\n$exec.all_fields.agent.ip"
        },
        {
          "type": "mrkdwn",
          "text": "*Manager:*\n$exec.all_fields.manager.name"
        },
        {
          "type": "mrkdwn",
          "text": "*Decoder:*\n$exec.all_fields.decoder.name"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Found:*\n$exec.all_fields.data.virustotal.found"
        },
        {
          "type": "mrkdwn",
          "text": "*Malicious:*\n$exec.all_fields.data.virustotal.malicious"
        },
        {
          "type": "mrkdwn",
          "text": "*Positives:*\n$exec.all_fields.data.virustotal.positives"
        },
        {
          "type": "mrkdwn",
          "text": "*Total Engines:*\n$exec.all_fields.data.virustotal.total"
        },
        {
          "type": "mrkdwn",
          "text": "*File:*\n$path_replacer.message"
        },
        {
          "type": "mrkdwn",
          "text": "*Scan Date:*\n$exec.all_fields.data.virustotal.scan_date"
        },
        {
          "type": "mrkdwn",
          "text": "*MD5:*\n$exec.all_fields.data.virustotal.source.md5"
        },
        {
          "type": "mrkdwn",
          "text": "*SHA1:*\n$exec.all_fields.data.virustotal.source.sha1"
        }
      ]
    },
    {
      "type": "context",
      "elements": [
        {
          "type": "mrkdwn",
          "text": ":link: <$exec.all_fields.data.virustotal.permalink|View on VirusTotal>"
        }
      ]
    }
  ]
}

```
 * i used python script in the middle to replace \ with \\ to avoid misconfiguration.
   
##### Final slack message
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/8b79e794-dc3e-40fa-88bc-d531806a7748" />



