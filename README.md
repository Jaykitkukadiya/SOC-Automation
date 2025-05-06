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
  Thehive - Case Management tool  
  MISP - Malware Information Sharing Platform  
  Slack - Notifications
```

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
## Installation process

1. Installation of pfsense
2. Installation of Suricata
3. Installation of Splunk server
4. Installation of WAZUH server
5. Installation of Splunk universal forwarder and WAZUH agent on endpoints

## Integration process

1. Sending Suricata logs to Splunk server
2. Sending pfsense logs to Splunk server
3. Sending endpoint logs to Splunk server
4. Sending endpoint and Splunk machine logs in WAZUH server

** Please check back later for further progress. Currently working on documentation, while continuing integrating other tools.


    
