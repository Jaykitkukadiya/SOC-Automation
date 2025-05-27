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
8. settingup project in jira
```
created new project named "socsecurityalerts".
added 3 column in sprint named new alert, alert in progress, alert closed.
```

## automating ip reputation check through AbuseIPDB, blocking malicious ip, and notifying on slack upon every unique ip connect while also looking for calls to previously known malicious ip by the network in realtime.

### workflow
![Blank diagram](https://github.com/user-attachments/assets/a665fbb2-0852-4d58-bc7c-61a8643f2b97)

### alerts for ip blocking in splunk

### script for blocking ip efficiently vie direct ssh from splunk to pfsense.

### firewall configuration for blocking dynamic list of ip

### shuffle workflow for automated message in slack with additional reputation check on virustotal.

### timeline of alerts and messages.


