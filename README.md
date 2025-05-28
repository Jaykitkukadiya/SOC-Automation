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

