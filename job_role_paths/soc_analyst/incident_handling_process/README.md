# Incident Handling Process

## Module Description 

Security Incident handling has become a vital part of every organization's  defensive strategy, as attacks constantly evolve and successful  compromises are becoming a daily occurrence. In this module, we will  review the process of handling an incident from the very early stage of  detecting a suspicious event to confirming a compromise and responding  to it.

## Module Summary 

Incident handling is a clearly defined set of procedures to manage and respond  to security incidents in a computer or network environment. This module  introduces the overall process of handling security incidents and walks  through each stage of the incident handling process. Important key  points and implementation details will also be provided regarding all  stages of the incident handling process. This module is also aligned  with NIST's Computer "Security Incident Handling Guide", as it is one of the most widely used and referenced resources on the matter.

The fundamentals of monitoring and monitoring using SIEM (Security  Information and Event Management) solutions, as well as the majority of  SOC-related and investigation-related topics, will be covered in  separate modules and in a highly hands-on manner. This module focuses  solely on the procedural aspect of incident handling, hence the lack of  hands-on exercises.

This module is broken into sections and there are no accompanying hands-on  exercises as the focus is understanding the different stages of the  incident handling process from a handler's perspective.

You can start and stop the module at any time and pick up where you left  off. There is no time limit or "grading," but you must complete all of  the question assessments to receive the maximum number of cubes and have this module marked as complete in any paths you have chosen.

The module is classified as "`Fundamental`" but assumes an understanding of information security fundamentals and common attack principles.

A firm grasp of the following module can be considered a prerequisite for successful completion of this module:

- Penetration Testing Process

# Sections 

- Introduction
- The Incident Handling Process
- Incident Analysis and Response
- Skills Assessment

# Introduction

## Incident Handling

### Incident Handling Definition & Scope

Incident handling (IH) has become an important part of an organization's  defensive capability against cybercrime. While protective measures are  constantly being implemented to prevent or reduce the number of security incidents, an incident handling capability is undeniably a necessity  for any organization that cannot afford a compromise of its data  confidentiality, integrity, or availability. Some organizations choose  to implement this capability in-house, while others rely on third-party  providers to support them, continuously or when needed. Before we dive  into the world of security incidents, let's define some terms and  establish a common understanding of them.

An `event` is an action occurring in a system or network. Examples of events include:

- A user sending an email.
- A mouse click.
- A firewall allowing a connection request.

An `incident` is an event with a negative consequence. One example of an incident is a system crash. Another example is unauthorized access to sensitive data. Incidents can also occur due to natural disasters, power failures, so  on.

There is no single  definition of what an IT security incident is, and therefore it varies  between organizations. We define an IT security incident as an event  with a clear intent to cause harm that is performed against a computer  system. Examples of incidents include:

- Data theft.
- Funds theft.
- Unauthorized access to data.
- Installation and use of malware and remote access tools.

```
Incident handling is a clearly defined set of procedures for managing and  responding to security incidents in a computer or network environment.
```

![Incident Response Life Cycle flowchart: Preparation → Detection and Analysis → Containment, Eradication, and Recovery → Post‑Incident Activity, with arrows showing feedback loops from each stage back to earlier stages and to Preparation for continuous improvement. Title beneath: “Incident Response Life Cycle Model.”](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir-lifecycle.png)

It is important to note that incident handling is not limited to intrusion incidents alone.

Other types of incidents, such as those caused by malicious insiders,  availability issues, and loss of intellectual property, also fall within the scope of incident handling. A comprehensive incident handling plan  should address various types of incidents and provide appropriate  measures to identify, contain, eradicate, and recover from them to  restore normal business operations as quickly and efficiently as  possible.

Bear in mind that it may not be immediately clear that an event is an incident until an  initial investigation is performed. That being said, there are some  suspicious events that should be treated as incidents unless proven  otherwise.

------

### Incident Handling's Value & Generic Notes

IT security incidents frequently involve the compromise of personal and  business data, and it is therefore crucial to respond quickly and  effectively. In some incidents, the impact may be limited to a few  devices, while in others, a large part of the environment can be  compromised. A great benefit of having an incident handling team (often  referred to as an "`incident response team`") handle events is that a trained workforce will respond systematically,  and therefore appropriate actions will be taken. In fact, the objective  of such teams is to minimize the theft of information or the disruption  of services that the incident is causing. This is achieved by performing `investigations` and `remediation` steps, which we will discuss more in depth shortly. Overall, the  decisions that are made before, during, and after an incident will  affect its impact.

Because different incidents will have different impacts on the organization, we need to understand the importance of `prioritization`. Incidents with greater severity will require immediate attention and  resources to be allocated to them, while others rated lower may also  require an initial investigation to determine whether they are, in fact, IT security incidents that we are dealing with.

The incident handling team is led by an incident manager. This role is  often assigned to a SOC manager, CISO/CIO, or third-party (trusted)  vendor, and this person usually has the ability to direct other business units as well. The incident manager must be able to obtain information  or have the mandate to require any employee in the organization to  perform an activity in a timely manner, if necessary. The incident  manager is the single point of communication who tracks the activities  taken during the investigation and their status of completion.

One of the most widely used resources on incident handling is [NIST's Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf). The document aims to assist organizations in mitigating the risks from  computer security incidents by providing practical guidelines for  responding to incidents effectively and efficiently.

------

### Different Types of Real-World Incidents

### Leaked Credentials

- `Colonial Pipeline Ransomware Attack`: The Colonial Pipeline, a major American oil pipeline system, fell victim to a ransomware attack. This [attack](https://en.wikipedia.org/wiki/Colonial_Pipeline_ransomware_attack) originated from a breached employee's personal password, likely found  on the dark web, rather than a direct attack on the company's network.  The attackers gained access to the company's systems using a compromised password for an inactive VPN (Virtual Private Network) account, which  did not have Multi-Factor Authentication (MFA) enabled.

### Default / Weak Credentials

- `Mirai Botnet (2016)`: The Mirai botnet scanned for IoT devices using factory or default  credentials (e.g., admin/admin) and conscripted them into a massive DDoS botnet. This led to large-scale DDoS disruptions affecting companies  like Dyn and OVH, with hundreds of thousands of devices infected. The  root cause was the devices being shipped with unchanged default  credentials and poor remote access security.
- `LogicMonitor Incident (2023)`: Some LogicMonitor customers were compromised because the vendor issued  weak default passwords to customer accounts. Affected customers  experienced follow-on ransomware incidents or unauthorized access. The  root cause involved vendor-assigned weak/default credentials and delayed enforcement of password hardening.

### Outdated Software / Unpatched Systems

- `Equifax (2017) Breach`: Attackers exploited a known Apache Struts vulnerability (CVE-2017-5638) in Equifax’s web application. This breach exposed the personal data of  approximately 143–147 million people, leading to major regulatory and  legal fallout. The incident occurred due to a failure to apply a  publicly released patch in a timely manner.
- `WannaCry (2017)`: The WannaCry ransomware spread as a worm using the SMB EternalBlue  exploit, affecting more than 200,000 systems across over 150 countries.  High-profile impacts included hospitals and enterprises. This incident  was due to unpatched Windows systems, despite the MS17-010 patch being  available before the outbreak.

### Rogue Employee / Insider Threat

- `Cash App / Block Inc. (2021 Disclosure; Public 2022 Notice)`: A former employee accessed the personal information of millions of Cash App users, as reported in company disclosures. Approximately 8.2  million current and former customers were potentially impacted, leading  to regulatory scrutiny and settlements. The root cause was the abuse of  legitimate employee access and insufficient internal controls and  monitoring.

### Phishing / Social Engineering

- `Industry Trend & Representative Data`: Phishing is a pervasive vector used to obtain credentials, deliver  malware, or trick users into enabling remote access. It frequently leads to account compromise, fraud, and network footholds. A significant  portion of breaches over multiple years are linked to phishing.
- `U.S. Interior Department Phishing Attack`: Attackers used an "evil twin" technique to trick individuals into  connecting to a fake Wi-Fi network, allowing hackers to steal  credentials and access the network. This incident revealed a lack of  secure wireless network infrastructure and insufficient security  measures, including weak user authentication and inadequate network  testing.
- `2020 Twitter Account Hijacking`: In 2020, many high-profile Twitter accounts were compromised by outside parties to promote a bitcoin scam. Attackers gained access to Twitter's administrative tools, allowing them to alter accounts and post tweets  directly. They appeared to have used social engineering to gain access  to the tools via Twitter employees.

### Supply-Chain Attack

- `SolarWinds Orion (2020)`: Nation-state actors compromised the SolarWinds build/release  environment and injected a malicious backdoor into Orion updates, which  were distributed to thousands of customers. This caused wide-reaching  espionage and unauthorized access across government and private sectors, leading to protracted detection and remediation efforts.

### Example of Incident Reports

We should be able to document a real-world security incident in a  sequential, stage-by-stage format aligned with frameworks such as the `Cyber Kill Chain` (explained in the next section) and the `MITRE ATT&CK` framework (i.e., moving from initial access to impact), just as seen in professional reports from [Mandiant](https://www.mandiant.com/), [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/), [Proofpoint](https://www.proofpoint.com/), etc.

An example of an incident report from DFIR Labs is as follows:

- [Confluence Exploit Leads to LockBit Ransomware](https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/)

This report documents the incident findings in a sequential manner. Each  section represents a distinct phase of the adversary’s operation, i.e.,  from Initial Access and Execution to Exfiltration and Impact. This  illustrates how the attack progressed across the environment.

The DFIR Labs platform contains many more incident reports. You can check them out [here](https://thedfirreport.com/).

https://thedfirreport.com/

![The DFIR Report homepage showing three featured articles in a grid beneath a red header with navigation.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/dfirreport.png)

Here's another example of an incident report from Cybereason.

- [CHAES:Novel Malware Targeting Latin American E-Commerce](https://www.cybereason.com/hubfs/dam/collateral/reports/11-2020-Chaes-e-commerce-malware-research.pdf)

These are `incident-specific reports` that focus on one particular event or outbreak. For example, the  "Confluence Exploit Leads to LockBit Ransomware" style report walks  step-by-step through what happened in that one attack: how the adversary gained access, what they did, how they were detected, what the impact  was, etc. The aim is to provide a detailed forensic narrative and  actionable findings specific to that incident.

There are `global incident-response reports` as well (such as the 2025 Unit 42 report), which aggregate data from  hundreds of incidents across a variety of industries, geographies, and  threat actors. Their aim is to identify trends, patterns, emerging  threats, and to provide statistical insights, and high-level  recommendations for defenders.

For example, the 2025 Unit 42 report states:

- "`In 2024, 86% of incidents that Unit 42 responded to involved business  disruption — spanning operational downtime, reputational damage, or both`".
- Additionally, "`Software supply chain and cloud attacks are growing in both frequency and  sophistication. In one campaign, attackers scanned more than 230 million unique targets for sensitive information.`"

A report from PaloAlto Unit42 that covers global incidents is as follows:

- [Global Incident Response Report](https://www.paloaltonetworks.com/engage/unit42-2025-global-incident-response-report)

------

### Incident Scenario

Throughout this module, we'll refer to an incident scenario to understand some  challenges that incident handlers face. This incident shows an example  of the patterns repeatedly observed in real-world incidents. The victim  in this scenario is `Insight Nexus`, a global market research firm that handles sensitive competitive data  for high-profile clients in the IT sector. The firm becomes a target of  two distinct threat groups operating simultaneously within its  environment.

The diagram below shows an overview of the victim and the threat actors.

![Network flow diagram: Internet threat actors probe two web consoles—ManageEngine AD Manager and a PHP Client Reports Portal—through a firewall into an internal network containing a Domain Controller, multiple Windows machines, a Database Server, and File Servers. Event logs from these systems go to the SIEM, which integrates with TheHive. TheHive notifies a SOC Analyst, who performs analysis and generates alerts and cases.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights1.png)

Based on the information we have collected, the first threat actor gained  entry when system administrators forgot to change the default  admin/admin password on an internet-facing application, i.e.,  ManageEngine ADManager Plus, after a product update. By leveraging this, the attackers logged in successfully, performed reconnaissance, mapped  users and machines, and eventually created new privileged Active  Directory accounts. Using one of the newly created accounts, the  adversaries pivoted further into the environment, identifying an  external RDP service exposed by misconfiguration. Exploiting that entry  point, they escalated their control and eventually used Group Policy  Objects (GPOs) to deploy spyware using an MSI package across multiple  endpoints.

In the next  section, we'll learn about the Cyber Kill Chain and MITRE ATT&CK  frameworks. The phases in these frameworks reflect the attacker's  lifecycle and the observable actions at each stage.

## Cyber Kill Chain

### What Is The Cyber Kill Chain?

Before we start talking about  handling incidents, we need to understand the attack lifecycle (a.k.a.  the cyber kill chain). This lifecycle describes how attacks manifest  themselves. Understanding this lifecycle will provide us with valuable  insights into how far in the network an attacker is and what they may  have access to during the investigation phase of an incident.

The cyber kill chain consists of seven different stages, as depicted in the image below: ![Flowchart of cyber kill chain steps: Recon, Weaponize, Deliver, Exploit, Install, C&C, Action.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/Cyber_kill_chain.png)

### Stages of the Cyber Kill Chain

The `Recon` (Reconnaissance) stage is the initial stage, and it involves the part  where an attacker chooses their target. Additionally, the attacker  performs information gathering to become more familiar with the target  and gathers as much useful data as possible, which can be used not only  in this stage but also in other stages of this chain. Some attackers  prefer to perform passive information gathering from web sources such as LinkedIn and Instagram, but also from documentation on the target  organization's web pages. Job ads and company partners often reveal  information about the technology utilized in the target organization.  They can provide extremely specific information about antivirus tools,  operating systems, and networking technologies. Other attackers go a  step further; they start 'poking' and actively scan external web  applications and IP addresses that belong to the target organization.

![Reconnaissance Stage diagram split into Active and Passive Recon. Active Recon: Identify target and scope; Locate open ports; Identify services on open ports; Map entire network. Passive Recon: Information gathering from web sources (job ads, company partners); Social media (LinkedIn, Instagram, Facebook); Avoid detection at all times. Icons accompany each item on a dark background.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir_recon.png)

In the `Weaponize` stage, the malware to be used for initial access is developed and  embedded into some type of exploit or deliverable payload. This malware  is crafted to be extremely lightweight and undetectable by antivirus and detection tools. It is likely that the attacker has gathered  information to identify the present antivirus or EDR technology present  in the target organization. On a large scale, the sole purpose of this  initial stage is to provide remote access to a compromised machine in  the target environment, which also has the capability to persist through machine reboots and the ability to deploy additional tools and  functionality on demand.

In the `Delivery` stage, the exploit or payload is delivered to the victim(s).  Traditional approaches include phishing emails that either contain a  malicious attachment or a link to a web page. The web page can serve two purposes: either containing an exploit or hosting the malicious payload to avoid sending it through email scanning tools. In some cases, the  web page can also mimic a legitimate website used by the target  organization in an attempt to trick the victim into entering their  credentials and collecting them. Some attackers call the victim on the  phone with a social engineering pretext in an attempt to convince the  victim to run the payload. The payload in these trust-gaining cases is  hosted on an attacker-controlled website that mimics a well-known  website to the victim (e.g., a copy of the target organization's  website). It is extremely rare to deliver a payload that requires the  victim to do more than double-click an executable file or a script (in  Windows environments, this can be .bat, .cmd, .vbs, .js, .hta, and other formats). Finally, there are cases where physical interaction is  utilized to deliver the payload via USB tokens and similar storage tools that are purposely left around.

The `Exploitation` stage is the moment when an exploit or a delivered payload is  triggered. During the exploitation stage of the Cyber Kill Chain, the  attacker typically attempts to execute code on the target system in  order to gain access or control.

In the `Installation` stage, the initial stager is executed and is running on the compromised machine. As already discussed, the installation stage can be carried  out in various ways, depending on the attacker's goals and the nature of the compromise. Some common techniques used in the installation stage  include:

- **Droppers**: Attackers may use droppers to deliver malware onto the target system. A dropper is a small piece of code designed to install malware on the  system and execute it. The dropper may be delivered through various  means, such as email attachments, malicious websites, or social  engineering tactics.
- **Backdoors**: A backdoor is a type of malware designed to provide the attacker with  ongoing access to the compromised system. The backdoor may be installed  by the attacker during the exploitation stage or delivered through a  dropper. Once installed, the backdoor can be used to execute further  attacks or steal data from the compromised system.
- **Rootkits**: A rootkit is a type of malware designed to hide its presence on a  compromised system. Rootkits are often used in the installation stage to evade detection by antivirus software and other security tools. The  rootkit may be installed by the attacker during the exploitation stage  or delivered through a dropper.

In the `Command and Control` stage, the attacker establishes a remote access capability to the  compromised machine. As discussed, it is not uncommon to use a modular  initial stager that loads additional scripts 'on-the-fly'. However,  advanced groups will utilize separate tools to ensure that multiple  variants of their malware live in a compromised network, and if one of  them gets discovered and contained, they still have the means to return  to the environment.

The final stage of the chain is the `Action` or objective of the attack. The objective of each attack can vary. Some adversaries may aim to exfiltrate confidential data, while others may  want to obtain the highest level of access possible within a network to  deploy ransomware. Ransomware is a type of malware that renders all data stored on endpoint devices and servers unusable or inaccessible unless a ransom is paid within a limited timeframe (not recommended).

It is important to understand that adversaries don't operate linearly (as  the Cyber Kill Chain suggests). Some previous Cyber Kill Chain stages  will be repeated multiple times. For example, after the `Installation` stage of a successful compromise, the logical next step for an adversary is to initiate the `Recon` (Reconnaissance) stage again to identify additional targets and find  vulnerabilities to exploit, allowing them to move deeper into the  network and eventually achieve the attack's objective(s).

Our objective is to `stop an attacker from progressing further up the kill chain`, ideally in one of the earliest stages.

------

### MITRE ATT&CK Framework

Another framework for understanding adversary behavior is the [MITRE ATT&CK](https://attack.mitre.org/) framework. It is a more granular, matrix-based knowledge base of  adversary tactics and techniques used to achieve specific goals.  Cybersecurity professionals use both frameworks to understand and defend against cyberattacks.

The  MITRE ATT&CK Enterprise Matrix is a knowledge base that documents  adversary behavior observed in the wild against enterprise IT  environments (Windows, Linux, macOS, cloud, network, mobile, etc.). It  is presented as a `matrix` where columns represent adversary goals (`tactics`), and cells are `techniques` attackers use to achieve those goals. The framework helps defenders  understand, model, detect, and respond to attacker behavior in a  structured way.

The screenshot below shows an example of the MITRE ATT&CK Enterprise Matrix:

https://attack.mitre.org/matrices/enterprise/

![The tactics and techniques representing the MITRE ATT&CK® Matrix for Enterprise.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/mitreintro.png)

#### Tactic

A tactic is a high-level adversary objective during an intrusion (the goal they want to accomplish at that stage). For Example:

- `Initial Access`.
- `Persistence`.
- `Privilege Escalation`.

#### Technique

A technique is a specific method adversaries use to achieve a tactic.  Techniques describe concrete attacker behavior (tools, commands, APIs,  protocols, etc.).

Techniques have IDs like [T1105 (Ingress Tool Transfer)](https://attack.mitre.org/techniques/T1105/) or [T1021 (Remote Services)](https://attack.mitre.org/techniques/T1021/). For example:

- `T1105 Ingress Tool Transfer`: Refers to the tools used by attackers to download a tool, such as `wget`, `curl`, etc., commonly OS built-in commands/tools.
- `T1021 Remote Services`: Refers to adversaries using protocols such as SSH, RDP, and SMB for lateral movement.

#### Sub-technique

Sub-techniques are children of techniques that capture a particular implementation or  target. Sub-technique IDs extend the parent technique: [T1003.001 (Credential Dumping -> LSASS Memory)](https://attack.mitre.org/techniques/T1003/001/), [T1021.002 (Remote Services -> SMB/Windows Admin Shares)](https://attack.mitre.org/techniques/T1021/002/). For example:

- `T1003.001 - OS Credentials: LSASS Memory`: Refers to adversaries dumping credentials directly from the LSASS process memory when achieving the necessary privileges.
- `T1021.002 - Remote Services: SMB/Windows Admin Shares`: Refers to adversaries interacting with shares using valid credentials.

This enables precise detection, attribution, and reporting (we can say "We detected `T1003.001` — LSASS memory dumping" instead of just `T1003`).

### Pyramid of Pain

In the diagram below, the Pyramid of Pain illustrates how much `effort it takes for an adversary to change their tactics` when defenders detect and block different types of indicators. At the  base of the pyramid are simple indicators like hash values, IP  addresses, and domain names — these are easily changed by attackers (low pain).

![Pyramid of pain graphic mapping indicator types to defender difficulty. From bottom to top: Hash Values (Trivial), IP Addresses (Easy), Domain Names (Simple), Network/Host Artifacts (Annoying), Tools (Challenging), TTPs—ATT&CK (Tough). Header shows MITRE ATT&CK tactics across the top (Reconnaissance through Impact).](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir_mitre.png)

For example, `blocking a malicious IP` in a MITRE ATT&CK "Command and Control" ([T1071](https://attack.mitre.org/techniques/T1071/)) scenario will only `slightly slow down` the adversary since they can quickly switch to a new C2 server. Moving  upward, network and host artifacts (like registry keys, mutex names, or  filenames) correspond to specific techniques in ATT&CK (e.g., [T1547.001](https://attack.mitre.org/techniques/T1547/001/) – Registry Run Keys/Startup Folder). These take `more effort` to change and are more resilient indicators for defenders.

At the top of the pyramid are Tools, Tactics, Techniques, and Procedures  (TTPs) — these align directly with the core of MITRE ATT&CK.  Detecting and disrupting these (e.g., identifying PowerShell abuse under [T1059](https://attack.mitre.org/techniques/T1059/) or process injection under [T1055](https://attack.mitre.org/techniques/T1055/)) forces the adversary to fundamentally change how they operate — causing maximum pain.

In summary:

- Hash/IP detections = `easy` to evade.
- Behavioral TTP detections (MITRE-based) = `hard to evade`, higher attacker cost, and stronger defense maturity.

Analysts map observed events and indicators to ATT&CK techniques and tactics to quickly understand adversary intent and likely next steps. Usually,  it is also used to prioritize alerts based on techniques that target  high-value assets. Additionally, it can be used to refer to the  mitigation and containment/eradication actions that disrupt the  attacker's kill chain.

### MITRE ATT&CK integration in TheHive

`TheHive` is a case management platform designed for cybersecurity teams to  efficiently handle incidents by processing alerts. Users can create  cases and link multiple relevant alerts within them. This platform  serves as a centralized hub to collect and manage all security alerts  from various devices on a single, comprehensive page. Additionally,  TheHive offers the capability to import all MITRE ATT&CK Framework  Tactics, Techniques, and Procedures (TTPs) into its alert management  system. This integration enriches incident analysis by associating  discovered attack patterns with the alerts.

To access TheHive platform, navigate to `http://TARGET_IP:9000` and use the following credentials:

- `Username`: htb-analyst
- `Password`: P3n#31337@LOG

![TheHive web app login page in Firefox at http://10.129.234.131:9000/login (marked Not Secure). Right pane shows greeting “Hello,” with fields prefilled: username “htb-analyst” and a masked password, plus a “Let me in” button and “I forgot my password” link. Left pane displays TheHive logo and wordmark on a dark background.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir_hive.png)

Upon logging in, the dashboard will be displayed. We can view the alerts  page as shown in the screenshot below, allowing us to view and manage  alerts effectively.

![TheHive “Alerts” page in Firefox at http://10.129.234.131:9000/alerts showing 43 alerts. Two visible alerts read “Possible suspicious access to Windows admin shares,” status New, type wazuh_alert from source wazuh. Details show rule=92105, agent_name=SCDC01, agent_id=005, agent_ip=172.16.200.50, references a130aa and fa3660, Observables count 1, TTPs 0, created/updated 09/10/2025 04:41 (one updated 10:04). Left sidebar highlights the Alerts icon; top bar includes search and “Create Case+.”](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir_hive1.png)

### Example of MITRE ATT&CK Mapping

The table below shows some of the techniques (MITRE ATT&CK) that were observed during the incident.

| Tactic              | Technique                                     | ID        | Description                          |
| ------------------- | --------------------------------------------- | --------- | ------------------------------------ |
| `Initial Access`    | Exploit Public-Facing Application             | T1190     | Confluence CVE exploited             |
| `Execution`         | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell used for payload download |
| `Persistence`       | Windows Service                               | T1543.003 | Windows Service for persistence      |
| `Credential Access` | LSASS Memory Dumping                          | T1003.001 | Extracted credentials                |
| `Lateral Movement`  | Remote Desktop Protocol                       | T1021.001 | RDP lateral movement                 |
| `Impact`            | Data Encrypted for Impact                     | T1486     | LockBit ransomware                   |

### Questions

1 - In which stage of the Cyber Kill Chain is malware developed?

> **Answer:** Weaponize

2 - Check the alert with reference 67c202 (LSASS Access) in TheHive, and provide the MITRE rule ID as the answer.

Authenticate to  with user "htb-analyst" and password "P3n#31337@LOG" 

> **Answer:** T1003.001

# The Incident Handling Process

## Incident Handling Process Overview

Now that we are familiar with the Cyber Kill Chain and its stages, we can better predict and anticipate  the next steps in an attack and also suggest appropriate measures  against them.

Just like the Cyber Kill Chain, there are different stages when responding to an incident, defined as the `Incident Handling Process`. The `Incident Handling Process` defines a capability for organizations to prepare, detect, and respond  to malicious events. Note that this process is suited for responding to  IT security events, but its stages do not correspond to the stages of  the Cyber Kill Chain in a one-to-one manner.

As defined by NIST, the incident handling process consists of the following four distinct stages: ![Incident response process flowchart: Preparation, Detection & Analysis, Containment Eradication & Recovery, Post-Incident Activity.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir-lifecycle.png)

Incident handlers spend most of their time in the first two stages, `preparation` and `detection and analysis`. This is where we, as incident handlers, spend much time improving  ourselves and looking for the next malicious event. When a malicious  event is detected, we move on to the next stage and respond to the event (but there should always be resources operating in the first two  stages, so there is no disruption of preparation and detection  capabilities). As we can see in the image, the process is not linear but cyclic. The main point to understand at this stage is that as new  evidence is discovered, the next steps may also change. It is vital to  ensure that we don't skip steps in the process and that we complete a  step before moving on to the next one. For example, if we discover ten  infected machines, we should certainly not proceed with containing just  five of them and starting eradication while the remaining five stay in  an infected state. Such an approach can be ineffective because, at the  bare minimum, we are notifying an attacker that we have discovered them  and that we are hunting them down, which, as we can imagine, can have  unpredictable consequences.

So, incident handling has two main activities, which are `investigating` and `recovering`. The investigation aims to:

- `Discover` the initial '`patient zero`' victim and create an ongoing (if still active) incident timeline.
- Determine which `tools` and malware the adversary used.
- `Document` the compromised systems and what the adversary has done.

Following the investigation, the recovery activity involves `creating and implementing a recovery plan`. Once the plan is implemented, the business should resume normal operations, if the incident caused any disruptions.

When an incident is fully handled, a report is issued that details the cause and cost of the incident. Additionally, "lessons learned" activities  are performed, among others things, to understand what the organization  should do to prevent incidents of a similar type from occurring again.

We will now walk through all stages of the `Incident Handling Process` in the next sections.

### Questions

1 - True or False: Incident handling contains two main activities: investigating and reporting.

> **Answer:** False

## Preparation Stage (Part 1)

In the `Preparation` stage, we have two separate objectives. The first is the establishment  of incident handling capability within the organization. The second is  the ability to protect against and prevent IT security incidents by  implementing appropriate protective measures. Such measures include  endpoint and server hardening, Active Directory tiering, Multi-Factor  Authentication, privileged access management, and so on. While  protecting against incidents is not the responsibility of the incident  handling team, this activity is fundamental to the overall success of  that team.

------

### Preparation Prerequisites

During the preparation stage, we need to ensure that we have:

- Skilled incident handling team members (incident handling team members can be  outsourced, but a basic capability and understanding of incident  handling are necessary in-house regardless).
- A trained workforce (as much as possible, through security awareness activities or other means of training).
- Clear policies and documentation.
- Tools (software and hardware).

![Slide titled “Incident Handling Preparation Prerequisites” listing five items: Incident handling capability within the organization, Protect against & prevent IT security incidents, Clear policies, Documentation, and Tools (software & hardware).](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir_preparation.png)

------

### Clear Policies & Documentation

Some of the written policies and documentation should contain an up-to-date version of the following information:

- Contact information and roles of the incident handling team members.
- Contact information for the legal and compliance department, management team,  IT support, communications and media relations department, law  enforcement, internet service providers, facility management, and  external incident response team.
- Incident response policy, plan, and procedures.
- Incident information sharing policy and procedures.
- Baselines of systems and networks, out of a golden image and a clean state environment.
- Network diagrams.
- Organization-wide asset management database.
- User accounts with excessive privileges that can be used on-demand by the  team when necessary (also for business-critical systems, which are  handled with the skills needed to administer that specific system).  These user accounts are normally enabled when an incident is confirmed  during the initial investigation and then disabled once it is over. A  mandatory password reset is also performed when disabling the users.
- Ability to acquire hardware, software, or an external resource without a  complete procurement process (urgent purchase of up to a certain  amount). The last thing you need during an incident is to wait for weeks for the approval of a $500 tool.
- Forensic/Investigative cheat sheets.

Some of the non-severe cases may be handled relatively quickly and without  too much friction within the organization or outside of it. Other cases  may require law enforcement notification and external communication to  customers and third-party vendors, especially in cases of legal concerns arising from the incident. For example, a data breach involving  customer data must to be reported to law enforcement within a certain  time threshold in accordance with GDPR. There may be many compliance  requirements depending on the location and/or branches where the  incident has occurred, so the best way to understand these is to discuss them with your legal and compliance teams on a per-incident basis (or  proactively).

While having  documentation in place is vital, it is also important to document the  incident as we investigate. Therefore, during this stage, we will also  have to establish an effective reporting capability. Incidents can be  extremely stressful, and it becomes easy to forget this part as the  incident unfolds, especially when we are focused and moving extremely  fast in order to solve it as soon as possible. We should try to remain  calm, take notes, and ensure that these notes contain timestamps, the  activity performed, the result of it, and who did it. Overall, we should seek answers to who, what, when, where, why and how.

------

### Tools (Software & Hardware)

Moving forward, we also need to ensure that we have the right tools to perform the job. These include, but are not limited to:

- An additional laptop or a forensic workstation for each incident handling  team member to preserve disk images and log files, perform data  analysis, and investigate without any restrictions (we know malware will be tested here, so tools such as antivirus should be disabled). These  devices should be handled appropriately and not in a way that introduces risks to the organization.
- Digital forensic image acquisition and analysis tools.
- Memory capture and analysis tools.
- Live response capture and analysis tools.
- Log analysis tools.
- Network capture and analysis tools.
- Network cables and switches.
- Write blockers.
- Hard drives for forensic imaging.
- Power cables.
- Screwdrivers, tweezers, and other relevant tools to repair or disassemble hardware devices if needed.
- Indicator of Compromise (IOC) creator and the ability to search for IOCs across the organization.
- Chain of custody forms.
- Encryption software.
- Ticket tracking system.
- Secure facility for storage and investigation.
- Incident handling system independent of your organization's infrastructure.

Many of the tools mentioned above will be part of what is known as a `jump bag` - always ready with the necessary tools to be picked up and taken  immediately. Without this prepared bag, gathering all necessary tools on the fly may take days or weeks before we are ready to respond.

Finally, we want to stress the importance of having our documentation system  completely independent from our organization's infrastructure and  properly secured. Assume from the beginning that our entire domain is  compromised and that all systems can become unavailable. In a similar  fashion, communications about an incident should be conducted through  channels that are not part of the organization's systems; assume that  adversaries have control over everything and can read communication  channels such as email.

### Questions

1 - What should we have prepared and always ready to 'grab and go'?

> **Answer:** jump bag

2 - True or False: Using baselines, we can discover deviations from the golden image, which aids us in discovering  suspicious or unwanted changes to the configuration.

> **Answer:** True

## Preparation Stage (Part 2)

Another part of the `Preparation` stage is to protect against incidents. While protection is not  necessarily the responsibility of the incident handling team, any  protection-related activities should be known to them to better  understand the type and sophistication of an incident and know where to  look for artifacts or evidence, that could aid the investigation.

Let us now take a look at some of the highly recommended protective  measures, which have a high mitigation impact against the majority of  threats.

------

### DMARC

[DMARC](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-dmarc) is an email protection mechanism against phishing built on top of the already existing [SPF](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-spf) and [DKIM](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-dkim). The idea behind DMARC is to reject emails that 'pretend' to originate  from our organization. Therefore, if an adversary is spoofing an email  pretending to be an employee asking for an invoice to be paid, the  system will reject the email before it reaches the intended recipient.  DMARC is easy and inexpensive to implement; however, we cannot stress  enough that thorough testing is mandatory; otherwise (and this is  oftentimes the case), we risk blocking legitimate emails with no ability to recover them.

With email  filtering rules, we may be able to take DMARC to the 'next' level and  apply additional protection against emails failing DMARC from domains we do not own. This is possible because some email systems will perform a  DMARC check and include a header stating whether DMARC passed or failed  in the message headers. While this can be incredibly powerful for  detecting phishing emails from any domain, it requires extensive testing before it can be introduced in a production environment. High false  positives here are emails that are sent 'on behalf of' via some email  sending service, as they tend to fail DMARC due to domain mismatch.

------

### Endpoint Hardening (& EDR)

Endpoint devices (workstations, laptops, etc.) are the entry points for most of  the attacks that we face on a daily basis. Considering that most threats will originate from the internet and target users who are browsing  websites, opening attachments, or running malicious executables, a  significant percentage of this activity will occur on their corporate  endpoints.

There are a few  widely recognized endpoint hardening standards now, with CIS and  Microsoft baselines being the most popular, and these should really be  the building blocks for our organization's hardening baselines. Some  highly important actions (that actually work) to note and do something  about are:

- Disable LLMNR/NetBIOS.
- Implement LAPS and remove administrative privileges from regular users.
- Disable or configure PowerShell in "ConstrainedLanguage" mode.
- Enable Attack Surface Reduction (ASR) rules if using Microsoft Defender.
- Implement whitelisting. We know this is nearly impossible to implement. Consider  at least blocking execution from user-writable folders (Downloads,  Desktop, AppData, etc.). These are the locations where exploits and  malicious payloads will initially find themselves. Remember to also  block script types such as .hta, .vbs, .cmd, .bat, .js, and similar. We  need to pay attention to [LOLBin](https://lolbas-project.github.io) files while implementing whitelisting. Do not overlook them; they are  really used in the wild as initial access to bypass whitelisting.
- Utilize host-based firewalls. As a bare minimum, block  workstation-to-workstation communication and block outbound traffic to  LOLBins.
- Deploy an EDR product. At this point in time, [AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps) provides great visibility into obfuscated scripts for antimalware  products to inspect the content before it gets executed. It is highly  recommended that we only choose products that integrate with AMSI.

------

### Network Protection

Network segmentation is a powerful technique for preventing a breach from  spreading across the entire organization. Business-critical systems must be isolated, and connections should be allowed only as required by the  business. Internal resources should not face the Internet directly  (unless placed in a DMZ).

Additionally, when speaking of network protection, we should consider IDS/IPS  (Intrusion Detection System/Intrusion Prevention System) systems. Their  power really shines when SSL/TLS interception is performed so that they  can identify malicious traffic based on content on the wire and not  based on the reputation of IP addresses, which is a traditional and very inefficient way of detecting malicious traffic.

Additionally, ensure that only organization-approved devices can access the network.  Solutions such as 802.1x can be utilized to reduce the risk of bring  your own device (BYOD) or malicious devices connecting to the corporate  network. If we are a cloud-only company using, for example, Azure/Azure  AD (now called Microsoft Entra ID), then we can achieve similar  protection with Conditional Access policies that will allow access to  organization resources only if we are connecting from a company-managed  device.

------

### Privilege Identity Management / MFA / Passwords

At this point in time, stealing privileged user credentials is the most  common escalation path in Active Directory environments. Additionally, a common mistake is that admin users either have a weak (but often  complex) password or a shared password with their regular user account  (which can be obtained via multiple attack vectors such as keylogging).  For reference, a weak but complex password is "Password1!". It includes  uppercase, lowercase, numerical, and special characters, but despite  this, it's easily predictable and can be found in many password lists  that adversaries employ in their attacks. It is recommended to teach  employees to use passphrases because they are harder to guess and  difficult to brute force. An example of a passphrase that is easy to  remember yet long and complex is "i LIK3 my coffeE warm". If one knows a second language, they can mix up words from multiple languages for  additional protection.

Multi-factor authentication (MFA) is another identity-protecting solution that  should be implemented at least for any type of administrative access to `all` applications and devices.

------

### Vulnerability Scanning

Perform continuous vulnerability scans of our environment and remediate at  least the "High" and "Critical" vulnerabilities that are discovered.  While the scanning can be automated, the fixes usually require manual  involvement. If we can't apply patches for some reason, we definitely  need to segment the systems that are vulnerable.

------

### User Awareness Training

Training users to recognize suspicious behavior and report it when discovered is a big win for us. While it is unlikely to reach 100% success in this  task, these training sessions are known to significantly reduce the  number of successful compromises. Periodic "surprise" testing should  also be part of this training, including, for example, monthly phishing  emails, dropped USB sticks in the office building, etc.

------

### Active Directory Security Assessment

The best way to detect security misconfigurations or exposed critical  vulnerabilities is by looking for them from an attacker's perspective.  Conducting our own reviews (or hiring a third party if the skill set is  missing from the organization) will ensure that when an endpoint device  is compromised, the attacker will not have a one-step escalation  possibility to high privileges on the network. The more additional tools and activities an attacker generates, the higher the likelihood of us  detecting them, so we try to eliminate easy wins and low-hanging fruit  as much as possible.

Active  Directory has a few known and unique escalation paths/bugs. New ones are quite often discovered as well. Active Directory security assessments  are crucial for the security posture of the environment as a whole. We  don't assume that our system administrators are aware of all discovered  or published bugs, because in reality, they probably aren't.

------

### Purple Team Exercises

We need to train incident handlers and keep them engaged. There is no  question about that, and the best place to do it is inside an  organization's own environment. Purple team exercises are essentially  security assessments by a red team that either continuously or  eventually informs the blue team about their actions, findings, any  visibility or security shortcomings, etc. Such exercises will help in  identifying vulnerabilities in an organization while testing the blue  team's defensive capability in terms of logging, monitoring, detection,  and responsiveness. If a threat goes unnoticed, there is an opportunity  to improve. For those that are detected, the blue team can test any  playbooks and incident handling procedures to ensure they are robust and the expected result has been achieved.

To practice purple team-related exercises, you can refer to modules such as [Intro to Academy's Purple Modules](https://academy.hackthebox.com/module/details/257) and [Detection & OpSec Cyber Range](https://academy.hackthebox.com/module/details/285), which provide an environment to perform purple team exercises.

### Questions

1 - What mechanism can we use to block phishing emails pretending to originate from our mail server?

> **Answer:** DMARC

2 - True or False: The "Summer2021!" password meets the complex password criteria but can be easily guessed or brute-forced.

> **Answer:** True

## Detection & Analysis Stage (Part 1)

At this point, we have created processes and procedures, and we have guidelines on how to act upon security incidents.

The `Detection & Analysis` stage involves all aspects of detecting an incident, such as utilizing  sensors, logs, and trained personnel. It also includes information and  knowledge sharing, as well as utilizing context-based threat  intelligence. Segmentation of the architecture and having a clear  understanding of and visibility within the network are also important  factors.

Threats are  introduced to the organization via an infinite number of attack vectors, and their detection can come from sources such as:

- An employee who notices abnormal behavior.
- An alert from one of our tools (EDR, IDS, Firewall, SIEM, etc.).
- Threat hunting activities.
- A third-party notification informing us that they discovered signs of our organization being compromised.

It is highly recommended to create levels of detection by logically categorizing our network as follows:

- Detection at the network perimeter (using firewalls, internet-facing network  intrusion detection/prevention systems, demilitarized zone, etc.).
- Detection at the internal network level (using local firewalls, host intrusion detection/prevention systems, etc.).
- Detection at the endpoint level (using antivirus systems, endpoint detection & response systems, etc.).
- Detection at the application level (using application logs, service logs, etc.).

------

### Initial Investigation

When a security incident is detected, we should conduct some initial  investigation and establish context before assembling the team and  calling an organization-wide incident response. Think about how  information is presented in the event of an administrative account  connecting to an IP address at HH:MM:SS. Without knowing what system is  on that IP address and which time zone the time refers to, we may easily jump to the wrong conclusion about what this event is about. To sum up, we should aim to collect as much information as possible at this stage  about the following:

- Date/Time when the incident was reported. Additionally, who detected the incident and/or who reported it?
- How was the incident detected?
- What was the incident? Phishing? System unavailability? etc.
- Assemble a list of impacted systems (if relevant).
- Document who has accessed the impacted systems and what actions have been taken. Make a note of whether this is an ongoing incident or if the suspicious activity has been stopped.
- Physical location, operating systems, IP addresses and hostnames, system owner, system's purpose, current state of the system.
- List of IP addresses, if malware is involved, time and date of detection,  type of malware, systems impacted, export of malicious files with  forensic information on them (such as hashes, copies of the files,  etc.).

With that  information at hand, we can make decisions based on the knowledge we  have gathered. What does this mean? We would likely take different  actions if we knew that the CEO's laptop was compromised as opposed to  an intern's.

With the  initially gathered information, we can start building an incident  timeline. This timeline will keep us organized throughout the event and  provide an overall picture of what happened. The events in the timeline  are sorted based on when they occurred. Note that during the  investigative process later on, we will not necessarily uncover evidence in this chronological order. However, when we sort the evidence based  on when it occurred, we will get context from the separate events that  took place. The timeline can also shed light on whether newly discovered evidence is part of the current incident. For example, imagine that  what we thought was the initial payload of an attack was later  discovered to be present on another device two weeks ago. We will  encounter situations where the data we are looking at is extremely  relevant and situations where the data is unrelated and we are looking  in the wrong place. Overall, the timeline should contain the information described in the following columns:

| `Date` | `Time of the event` | `hostname` | `event description` | `data source` |
| ------ | ------------------- | ---------- | ------------------- | ------------- |
|        |                     |            |                     |               |

Let's take one event and populate the example table from above. It will look as follows:

| `Date`     | `Time of the event` | `hostname`  | `event description`                 | `data source`      |
| ---------- | ------------------- | ----------- | ----------------------------------- | ------------------ |
| 09/09/2021 | 13:31 CET           | SQLServer01 | Hacker tool 'Mimikatz' was detected | Antivirus Software |

As you can infer, the timeline focuses primarily on attacker behavior, so  the recorded activities depict when the attack occurred, when a network  connection was established to access a system, when files were  downloaded, etc. It is important to ensure that we capture where the  activity was detected or discovered and the systems associated with it.

We can also view an alert related to this event log in the TheHive Case Management Platform.

![TheHive Alerts page showing 43 alerts. Three visible items: “Possible suspicious access to Windows admin shares” — status New, source wazuh_alert/wazuh, agent SCDC01 (id 005, IP 172.16.200.50), Observables 1, TTPs 0., “InsightNexus Hacker tool Mimikatz was detected” — status New, severity C, tags InsightNexus, Mimikatz, T1003.001, Credential Dumping, T1003; Observables 3, TTPs 0, ID INX-WAZUH-2025-00080., InsightNexus Admin Login via ManageEngine Web Console” — status New, severity H, tags InsightNexus, T1078.001, Valid Accounts, Initial Access; Observables 2, TTPs 0, ID INX-ALERT-2025-00077. Top bar includes search and Create Case.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/hivealert1.png)

Let's navigate to the bottom of this section and click on "`Click here to spawn the target system!`".  			   Then, let's open TheHive webpage on "Target IP:9000" on port 9000 using the provided credentials to view the alerts. 

We can assign the alert to ourselves, create a case, work on it, add more details about  the incident in the case, and then, once the investigation is completed, we can documents all findings and lessons in the case and close it.

------

### Incident Severity & Extent Questions

When handling a security incident, we should also try to answer the  following questions to get an idea of the incident's severity and  extent:

- What is the exploitation impact?
- What are the exploitation requirements?
- Can any business-critical systems be affected by the incident?
- Are there any suggested remediation steps?
- How many systems have been impacted?
- Is the exploit being used in the wild?
- Does the exploit have any worm-like capabilities?

The last two can possibly indicate the level of sophistication of an adversary.

As you can imagine, high-impact incidents will be handled promptly, and  incidents with a high number of impacted systems will have to be  escalated.

------

### Incident Confidentiality & Communication

Incidents are very confidential topics, and as such, all of the information  gathered should be kept on a need-to-know basis unless applicable laws  or a management decision instruct us otherwise. There are multiple  reasons for this. The adversary may be, for example, an employee of the  company, or if a breach has occurred, the communication to internal and  external parties should be handled by the appointed person in accordance with the legal department.

When an investigation is launched, we will set some expectations and goals.  These often include the type of incident that occurred, the sources of  evidence that we have available, and a rough estimate of how much time  the team needs for the investigation. Also, based on the incident, we  will set expectations on whether we will be able to uncover the  adversary or not. Of course, a lot of the above may change as the  investigation evolves and new leads are discovered. It is important to  keep everyone involved and the management informed about any  advancements and expectations.

### Moving On

In the next section, we will dive deeper into the details of the  investigation, what can be an indicator of compromise, and how to start  the investigation based on it.

### Questions

1 - True or False: Can a third-party vendor be a source of detecting a compromise?

> **Answer:** True

2 - Assign the Mimikatz alert (shown in the  section) to yourself in TheHive, and go through the description and  summary. Provide the username of the person who executed the Mimikatz  tool. The answer format is "domain\user_name."

Authenticate to  with user "htb-analyst" and password "P3n#31337@LOG" 

> **Answer:** insight\svc_deployer

## Detection & Analysis Stage (Part 2)

When an investigation is started, we aim to understand `what happened` and `how it happened`. To analyze the incident-related data properly and efficiently, the  incident handling team members need deep technical knowledge and  experience in the field. One may ask, "Why do we care about how an  incident happened? Why don't we simply rebuild the impacted systems and  basically forget it ever happened?"

If we don't know how an incident happened or what was impacted, then any  remedial steps we take will not ensure that the attacker cannot repeat  their actions to regain access. If we, on the other hand, know exactly  how the adversary got in, what tools they used, and which systems were  impacted, then we can plan our remediation to ensure that this attack  path cannot be replicated.

------

### The Investigation

The investigation starts based on the initially gathered (and limited)  information that contains what we know about the incident so far. With  this initial data, we will begin a 3-step cyclic process that will  iterate over and over again as the investigation evolves. This process  includes:

- Creation and usage of indicators of compromise (IOCs).
- Identification of new leads and impacted systems.
- Data collection and analysis from the new leads and impacted systems.

![Flowchart showing investigation process: Initial Investigation Data leads to IOCs, Compromised Systems, and Collection & Analysis.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir-ioc.png)

Let us now elaborate more on the process depicted above.

------

### Initial Investigation Data

In order to reach a conclusion, an investigation should be based on valid  leads that have been discovered not only during this initial phase but  throughout the entire investigation process. The incident handling team  should constantly bring up new leads and not focus solely on a specific  finding, such as a known malicious tool. Narrowing an investigation down to a specific activity often results in limited findings, premature  conclusions, and an incomplete understanding of the overall impact.

------

### Creation & Usage Of IOCs

An indicator of compromise (IOC) is a `sign that an incident has occurred`. IOCs are documented in a structured manner, which represents the `artifacts` of the compromise. Examples of IOCs can be IP addresses, hash values of files, and file names. In fact, because IOCs are so important to an  investigation, special languages such as `OpenIOC` have been developed to document them and share them in a standard manner. Another widely used standard for IOCs is `YARA`. There are a number of free tools that can be utilized, such as Mandiant's `IOC Editor`, to create or edit IOCs. Using these languages, we can describe and use  the artifacts that we uncover during an incident investigation. We may  even obtain IOCs from third parties if the adversary or the attack is  known. For example, CISA publishes the IOCs in a format called `STIX` (`Structured Threat Information eXpression`). STIX is an open-source, machine-readable language and serialization  format, primarily in JSON, used to exchange cyber threat intelligence  (CTI) in a standardized and consistent way.

As an example, in [this report](https://www.cisa.gov/news-events/alerts/2025/08/06/cisa-releases-malware-analysis-report-associated-microsoft-sharepoint-vulnerabilities), we can check the "Downloadable copy of IOCs associated with this  malware" section for the STIX file, which contains the IOCs in JSON  format.

```json
        json
...SNIP...
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--474454e8-d393-5a4f-9069-19631ea9d397",
            "hashes": {
                "MD5": "40e609840ef3f7fea94d53998ec9f97f",
                "SHA-1": "141af6bcefdcf6b627425b5b2e02342c081e8d36",
                "SHA-256": "3461da3a2ddcced4a00f87dcd7650af48f97998a3ac9ca649d7ef3b7332bd997",
                "SHA-512": "deaed6b7657cc17261ae72ebc0459f8a558baf7b724df04d8821c7a5355e037a05c991433e48d36a5967ae002459358678873240e252cdea4dcbcd89218ce5c2",
                "SSDEEP": "384:cMQLQ5VU1DcZugg2YBAxeFMxeFAReF9ReFj4U0QiKy8Mg3AxeFaxeFAReFLxTYma:ElHh1gtX10u5A"
            },
            "size": 13373,
            "name": "osvmhdfl.dll",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--d896763f-3f6f-4917-86e8-1a4b043d9771"
            ],
            "extensions": {
                "windows-pebinary-ext": {
                    "pe_type": "dll",
                    "number_of_sections": 4,
                    "time_date_stamp": "2025-07-22T08:33:22Z",
                    "size_of_optional_header": 512,
                    "sections": [
                        {
                            "name": "header",
                            "size": 512,
                            "entropy": 2.545281,
                            "hashes": {
                                "MD5": "2a11da5809d47c180a7aa559605259b5"
                            }
                        },
                        {
                            "name": ".text",
                            "size": 4608,
                            "entropy": 4.532967,
                            "hashes": {
                                "MD5": "531ff1038e010be3c55de9cf1f212b56"
                            }
                        },
                        {
                            "name": ".rsrc",
                            "size": 1024,
                            "entropy": 2.170401,
                            "hashes": {
                                "MD5": "ef6793ef1a2f938cddc65b439e44ea07"
                            }
                        },
                        {
                            "name": ".reloc",
                            "size": 512,
                            "entropy": 0.057257,
                            "hashes": {
                                "MD5": "403090c0870bb56c921d82a159dca5a3"
                            }
                        }
                    ]
                }
            }
        },
...SNIP...
```

In TheHive, we can add IOCs in the observables section of an alert.

![TheHive “Observables” tab for alert “InsightNexus Admin Login via ManageEngine Web Console.” Two observables listed: hostname “manage.insightnexus…” and IP “103.112.60.117,” both tagged TLP:AMBER and PAP:AMBER with no reports. On the right, “Adding an Observable” panel shows a Type dropdown (options: autonomous-system, domain, file, filename, fqdn, hash, hostname, ip), and an “Is IOC” toggle (off), plus fields for Tags and Description.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/hivealert2.png)

To leverage IOCs, we will have to deploy an `IOC-obtaining/IOC-searching tool` (native or third-party and possibly at scale). A common approach is to utilize `WMI` or `PowerShell` for IOC-related operations in Windows environments.

A word of caution! During an investigation, we have to be extra careful  to prevent the credentials of our highly privileged user(s) from being  cached when connecting to (potentially) compromised systems (or any  systems, really). More specifically, we need to ensure that only  connection protocols and tools that don't cache credentials upon a  successful login are utilized (such as `WinRM`). Windows logons with `logon type 3 (Network Logon)` typically don't cache credentials on the remote systems. The best  example of "know your tools" that comes to mind is "PsExec". When  "PsExec" is used with explicit credentials, those credentials are cached on the remote machine. When "PsExec" is used without credentials  through the session of the currently logged-on user, the credentials are not cached on the remote machine. This is a great example of  demonstrating how the same tool leaves different tracks, so we must be  aware.

------

### Identification Of New Leads & Impacted Systems

After searching for IOCs, we expect to have some hits that reveal other  systems with the same signs of compromise. These hits may not be  directly associated with the incident we are investigating. Our IOC  could be, for example, too generic. We need to identify and `eliminate false positives`. We may also end up in a position where we come across a large number of hits. In this case, we should prioritize the ones we will focus on,  ideally those that can provide us with new leads after a potential  forensic analysis.

------

### Data Collection and Analysis from the New Leads and Impacted Systems

Once we have identified systems that include our IOCs, we will want to `collect and preserve the state` of those systems for further analysis in order to uncover new leads  and/or answer investigative questions about the incident. Depending on  the system, there are multiple approaches to how and what data to  collect. Sometimes we want to perform a '`live response`' on a system as it is running, while in other cases, we may want to shut down a system and then perform any analysis on it. Live response is the most common approach, where we collect a predefined set of data that is usually rich in artifacts that may explain what happened to a system.  Shutting down a system is not an easy decision when it comes to  preserving valuable information because, in many cases, much of the  artifacts will only live within the RAM memory of the machine, which  will be lost if the machine is turned off. Regardless of the collection  approach we choose, it is vital to ensure that minimal interaction with  the system occurs to avoid altering any evidence or artifacts.

Once the data has been collected, it is time to analyze it. This is often  the most time-consuming process during an incident. Malware analysis and disk forensics are the most common examination types. Any newly  discovered and validated leads are added to the timeline, which is  constantly updated. Also, note that memory forensics is a capability  that is becoming more and more popular and is extremely relevant when  dealing with advanced attacks.

Keep in mind that during the data collection process, we should keep track of the `chain of custody` to ensure that the examined data is court-admissible if legal action is to be taken against an adversary.

------

### Use of AI in Threat Detection

Artificial Intelligence (AI) is transforming how organizations detect, triage, and respond to security incidents. In traditional IR workflows, analysts  manually review logs, alerts, and reports. This process usually takes  hours or days. AI `automates much of this analysis`, reducing response time and improving accuracy by learning from historical incidents and `identifying behavioral anomalies` faster than humans.

For example: Elastic Security’s "`Attack Discovery`" feature uses generative AI to analyze events from thousands of  detections, summarizing and clustering related alerts into an attack  story.

AI Attack Discovery leverages `LLMs` (large language models) to analyze alerts in an environment and  identify threats. The summary represents an attack and shows  relationships among multiple alerts to help us identifying which users  and hosts are involved. This also show MITRE ATT&CK mappings. Here's an example of how the attack discovery looks like:

![Elastic detection page titled “BPFDoor Linux backdoor deployment” (status Open, 4 alerts). Summary: On host SRVNIX05, the BPFDoor backdoor was extracted, copied, and executed by user root. Details show root unzips file “74ef6cc38f5a1a80148752b63c117e6846984debd2af806c65887195a8eecc56” into /home/ubuntu/... then a bash shell copies it to /dev/shm/kdmtmpflush, sets chmod 755, and runs it with elevated permissions; cleanup removes the original. File is identified as Linux.Trojan.BPFDoor. Justification notes all alerts tie to host SRVNIX05 and user root with a clear sequence from extraction to execution and detection. Attack Chain timeline highlights Initial Access, Execution, Persistence, and Defense Evasion. Buttons: View in AI Assistant, Investigate in Timeline.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ai-attack.png)

In this discovery, AI helped by going through multiple alerts and  generated a comprehensive overview of the attack, identifying key  activities that occurred during the incident. AI can help in incident  response as well. Some of the use cases include:

- Automated Triage & Alert Prioritization
- Incident Correlation & Timeline Reconstruction
- Automated Response Playbooks
- AI Assistance in Post-Incident Analysis & Learning

### Summary

In the last two sections, we have gone through the initial steps of the  Detection and Analysis stage, managing vital processes and documenting  each of the steps needed during an incident. Staying focused and  organized is one of the key things we need to maintain to properly  conduct this stage.

Let's navigate to the bottom of this section and click on "`Click here to spawn the target system!`". Then, let's open TheHive webpage on "Target IP:9000" on port 9000 using the provided credentials to view the alerts. 

### Questions

1 - During an investigation, we discovered a  malicious file with an MD5 hash value of  'b40f6b2c167239519fcfb2028ab2524a'. What do we usually call such a hash  value in investigations? Answer format: Abbreviation

> **Answer:** IoC

2 - In TheHive, check the alert with rule=92153  related to the VaultCli.dll module. What is the MD5 hash value mentioned in the alert?

Authenticate to  with user "htb-analyst" and password "P3n#31337@LOG" 

> **Answer:** FCDE97D37B7C0CADB3BC71267BEB5405

3 - True/False: As an analyst, you detected lateral movement attempts to systems owned by another department (e.g.,  finance). As it belongs to another department, you will not perform  escalation internally.

> **Answer:** False

## Containment, Eradication, and Recovery Stage

When the investigation is  complete and we have understood the type of incident and the impact on  the business (based on all the leads gathered and the information  assembled in the timeline), it is time to enter the containment stage to prevent the incident from causing more damage.

![Incident response flow titled “Containment, Eradication, and Recovery Stage.” Steps listed: Investigation is complete → Containment Strategy → Evidence gathering (note: Preserve Evidence) → Identify the attacking host → Eradication and Recovery → Bring systems back to normal operation. Side notes under containment: Forensic images, changing passwords, applying firewall rules, applying a system patch.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir_stages.png)

------

### Containment

In this stage, we take action to prevent the spread of the incident. We divide the actions into `short-term containment` and `long-term containment`. It is important that containment actions are coordinated and executed  across all systems simultaneously. Otherwise, we risk notifying  attackers that we are after them, in which case they might change their  techniques and tools in order to persist in the environment.

In short-term containment, the actions taken leave a minimal footprint on  the systems on which they occur. Some of these actions can include  placing a system in a separate/isolated VLAN, pulling the network cable  out of the system(s), or modifying the attacker's C2 DNS name to a  system under our control or to a non-existing one. The actions here  contain the damage and provide time to develop a more concrete  remediation strategy. Additionally, since we keep the systems unaltered  (as much as possible), we have the opportunity to take forensic images  and preserve evidence if this wasn't already done during the  investigation (this is also known as the `backup` substage of the containment stage). If a short-term containment action  requires shutting down a system, we have to ensure that this is  communicated to the business and appropriate permissions are granted.

In long-term containment actions, we focus on persistent actions and  changes. These can include changing user passwords, applying firewall  rules, inserting a host intrusion detection system, applying a system  patch, and shutting down systems. While performing these activities, we  should keep the business and the relevant stakeholders updated. Bear in  mind that just because a system is now patched does not mean that the  incident is over. Eradication, recovery, and post-incident activities  are still pending.

------

### Eradication

Once the incident is contained, eradication is necessary to eliminate both  the root cause of the incident and what is left of it to ensure that the adversary is out of the systems and network. Some of the activities in  this stage include removing the detected malware from systems,  rebuilding some systems, and restoring others from backup. During the  eradication stage, we may extend the previously performed containment  activities by applying additional patches, that were not immediately  required. Additional system-hardening activities are often performed  during the eradication stage (not only on the impacted system but across the network in some cases).

------

### Recovery

In the recovery stage, we bring systems back to normal operation. Of  course, the business needs to verify that a system is in fact working as expected and that it contains all the necessary data. When everything  is verified, these systems are brought into the production environment.  All restored systems will be subject to heavy logging and monitoring  after an incident, as compromised systems tend to be targets again if  the adversary regains access to the environment in a short period of  time. Typical suspicious events to monitor for are:

- Unusual logons (e.g., user or service accounts that have never logged-in there before).
- Unusual processes.
- Changes to the registry in locations that are usually modified by malware.

The recovery stage in some large incidents may take months, as it is often  approached in phases. During the early phases, the focus is on  increasing overall security to prevent future incidents through quick  wins and the elimination of low-hanging fruit. The later phases focus on permanent, long-term changes to keep the organization as secure as  possible.

### Questions

1 - True or False: Patching a system is considered a short-term containment.

> **Answer:** False

2 - During recovery, IOCs are still observed  intermittently. Should recovery proceed, or should the case be escalated back to the investigation phase? Answer format: Recovery/Investigation

> **Answer:** Investigation

## Post-Incident Activity Stage

In this stage, our objective is  to document the incident and improve our capabilities based on lessons  learned from it. This stage gives us an opportunity to reflect on the  threat by understanding what occurred, what we did, and how our actions  and activities worked out. This information is best gathered and  analyzed in a meeting with all stakeholders who were involved during the incident. It generally takes place within a few days after the  incident, when the incident report has been finalized.

![Vertical post-incident process flow. Steps top to bottom: Incident Resolved → Post‑Incident Review → Lessons Learned Meeting → Root Cause Analysis → Update Policies & Playbooks → Enhance Detection & Monitoring Rules → Knowledge Sharing & Awareness → Report to Management & Close Case.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/post-incident.png)

------

### Reporting

The final report is a crucial part of the entire process. A complete report will contain answers to questions such as:

- What happened and when?
- How did the team perform in dealing with the incident in regard to plans, playbooks, policies, and procedures?
- Did the business provide the necessary information and respond promptly to  aid in handling the incident efficiently? What can be improved?
- What actions have been implemented to contain and eradicate the incident?
- What preventive measures should be put in place to prevent similar incidents in the future?
- What tools and resources are needed to detect and analyze similar incidents in the future?

Such reports can eventually provide us with measurable results. For example, they can provide us with knowledge about how many incidents have been  handled, how much time the team spends per incident, and the different  actions that were performed during the handling process. Additionally,  incident reports provide a reference for handling future events of a  similar nature. In situations where legal action is to be taken, an  incident report will also be used in court and as a source for  identifying the costs and impact of incidents.

This stage is also a great place to train new team members by showing them  how the incident was handled by more experienced colleagues. The team  should also evaluate whether updating plans, playbooks, policies, and  procedures is necessary. During the post-incident activity stage, it is  important that we reevaluate the tools, training, and readiness of the  team, as well as the overall team structure, and not focus only on the  documentation and process front.

------

Note: We will explore the reporting part of the Incident Handling Process in more detail in the `Security Incident Reporting` module of the `SOC Analyst` job role path.

# Incident Analysis and Response

## Incident Scenario

The victim in this incident is `Insight Nexus`, a mid-sized market research and data analytics firm headquartered in  Singapore. They provide competitive intelligence and consumer insights  for global clients, including Fortune 500 companies in IT and finance.  Their infrastructure includes many applications, servers, and hosts, but we'll focus on the important ones, such as an internet-facing  application stack for clients, a ManageEngine server for IT  administration, and a PHP-based customer reporting portal. Because of  the nature of their work, they became an attractive target for  adversaries interested in client data theft.

Let's take a look at the incident to understand some challenges that incident handlers face. This incident shows an example of the patterns  repeatedly observed in real-world incidents. The victim in this scenario is `Insight Nexus`, a global market research firm that handles sensitive competitive data  for high-profile clients in the IT sector. The firm becomes a target of  two distinct threat groups operating simultaneously within its  environment. The first threat actor gained entry when system  administrators forgot to change the default admin/admin password on an  internet-facing application, i.e., `ManageEngine ADManager Plus`, after a product update. By leveraging this, the attackers logged in  successfully, performed reconnaissance, mapped users and machines, and  eventually created new privileged Active Directory accounts. Using one  of the newly created accounts, the adversaries pivoted further into the  environment, identifying an external RDP service exposed by  misconfiguration. Exploiting that entry point, they escalated their  control and eventually used Group Policy Objects (GPOs) to deploy  spyware using an MSI package across multiple endpoints.

![Network monitoring flow diagram. Left: Internet connects to two web consoles—ManageEngine AD Manager and a Client Reports Portal (PHP)—in front of a Firewall. Center: Internal network block containing a Domain Controller, multiple Windows machines, a Database server, and File servers. Event logs from AD Manager and the internal hosts go to a SIEM. Right: SIEM integrates with TheHive, which sends notifications to a SOC Analyst; analyst performs analysis resulting in Alerts and Cases.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights.png)

For days, these activities went unnoticed. The incident was first  discovered one day when an analyst from the SOC team investigated an  alert on `TheHive` (Security Incident Response Platform) related to the creation of a suspicious file named `checkme.txt` in the root of a web server. Upon investigation, they discovered that  it was deliberately placed there as a signature — "SilentJackal was  here". This unusual artifact triggered a deeper investigation. What made the situation more complex was that the SOC team then realized two  different threat actor groups were active in the same environment. While the first group was still exploring and deploying persistence  mechanisms, a second actor had already compromised a vulnerable PHP  application earlier, exfiltrated sensitive market research data, and  significantly reduced their activity after achieving their objective,  leaving only occasional connections to an external IP.

## Threat Actors

- `Crimson Fox` (Primary threat actor): A group with known links to the IT industry  supply chain targeting, suspected to be state-backed. They specialize in credential theft and long-term persistence for data exfiltration. It is a capable and persistent group known for several previous successful  attacks related to supply-chain and corporate intelligence.
- `Silent Jackal` (Secondary actor): A loosely organized criminal group focused on  opportunistic website defacements and proof-of-concept intrusions, not  necessarily financially motivated but disruptive. The members of this  group are low-skill web intruders.

------

## Environment & Important Assets

### Public Internet

- External Web Application (`manage.insightnexus.com`): The web application `ManageEngine ADManager Plus` provides the capability for Active Directory management to the  organization's system administrators. HTTPS (port 443) was accessible  from the Internet (management portal).
- Client Reports Portal (`portal.insightnexus.com`): A PHP-based client reporting portal (file upload enabled for reports).

### Internal environment structure

- `Domain Controller`: DC01.insight.local
- `File Server`: FS01.insight.local (file share: \fs01\projects)
- `Database Server`: DB01.insight.local contains sensitive databases.
- `Workstations`: This includes the developer fleet (ranging from DEV-001 to DEV-120),  including some workstations with permissions to allow incoming RDP  connections. A Windows machine with external RDP exposure was discovered during reconnaissance: DEV-021 (misconfigured).

### Security

- Perimeter `firewall` with default logging (**no integration with Threat Intelligence**).
- Basic `IDS` with a high false-positive rate.
- `Wazuh` agents on most Windows hosts (partial coverage).
- Centralized `SIEM` (Wazuh) ingesting Windows Sysmon, Windows Security, web server logs, and firewall logs (limited retention).
- `TheHive` is used for case management, with Cortex available for enrichment.

------

## Incident Analysis

A system administrator noticed unusual outbound connections from the  ManageEngine server to an IP address in Eastern Europe while working on  the server for scheduled maintenance. He called the SOC team and  collaborated with them to investigate the alerts to find anything  suspicious. One of the SOC analysts started investigating the alerts and found an alert mentioning a suspicious `checkme.txt` file on the same server.

------

`Detection Gap: `There were too many alerts about new files being created on the servers, and  this alert was not escalated due to alert fatigue. They need to reduce  some false positives and add more filters.

------

The SOC team started investigating this incident and found many reconnaissance attempts on the external web applications.

![Network monitoring diagram. From Internet, traffic reaches two web consoles: ManageEngine AD Manager and a PHP Client Reports Portal (noted: threat actors performing reconnaissance), both behind a Firewall. Internal network includes a Domain Controller, multiple Windows machines, a Database server, and File servers. Event logs from AD Manager and internal hosts flow to a SIEM. The SIEM integrates with TheHive, which sends notifications to a SOC Analyst; analyst performs analysis resulting in Alerts and Cases.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights1.png)

Upon further investigation, the responders found that on `2025-10-01 03:12:02`, the threat actor `Crimson Fox` obtained initial access via ManageEngine. Initially, they performed targeted login attempts against `manage.insightnexus.com`. They found that the default credentials (i.e., `admin/admin`) worked, which means either the system administrators forgot to change  the default credentials after an update or they left the web application accessible to everyone on the public internet. The result was  unfortunate for the organization, and the threat actors performed an  interactive web login via HTTPS. The logon audit report shows this  successful login activity.

------

`Organizational oversight: `Despite vendor advisories, the default credentials were never changed.  Multi-factor authentication was not enforced, and there was no  [WAF](https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/) inspection on the endpoint. The logon events of the web application were not sent to a centralized SIEM.

![Network-SOC flow. From the Internet, an attacker logs in to ManageEngine AD Manager with default credentials; Internet also reaches a PHP Client Reports Portal behind a Firewall. Internal network includes a Domain Controller, multiple Windows machines, a Database server, and File servers. Event logs from AD Manager and internal hosts go to a SIEM. The SIEM integrates with TheHive, which sends notifications to a SOC analyst; the analyst performs analysis, producing alerts and cases.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights2.png)

There was a Java web vulnerability related to the ManageEngine ADManager Plus product where unauthenticated remote code execution was possible. The  actor utilized this and established an outbound C2 over HTTPS to `103.112.60.117` (an attacker-controlled cloud host), impersonating update traffic. The  following Sysmon Event ID 3 (Network Connection detected) was logged:

```cmd-session
        cmd-session
Event 3, Sysmon 

Network Connection detected:
UtcTime: 2025-10-01 03:18:32.557
Image: C:\ManageEngine\jre\bin\java.exe
DestinationIp: 103.112.60.117
DestinationPort: 443
```

On `2025-10-02 04:02:11`, attackers enumerated domain users and computers via queries from the  ManageEngine console. Using the ManageEngine foothold, they also created a new Domain Administrator account. During Active Directory  enumeration, they found that a Windows 10 machine (`DEV-021`) had a publicly exposed RDP port. This desktop machine is used  occasionally by developers to perform development and release tasks by  taking RDP directly on its public IP while working from home. The  attacker took RDP directly into this machine using the newly created  Domain Administrator account.

![Network security flow diagram. From the Internet, an attacker establishes C2 and uses RDP to an internal host via a Firewall (no threat intel integration). Exposed web consoles: ManageEngine AD Manager and a PHP Client Reports Portal. Inside the network: a Domain Controller, multiple Windows machines (one labeled DEV-021), a Database server, and File servers. Event logs from AD Manager and internal hosts go to a SIEM. The SIEM integrates with TheHive, which sends notifications to a SOC Analyst; analyst performs analysis producing alerts and cases.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights3.png)

For this activity, the following event log was created in the Windows Event Logs with Event ID `4624`.

```cmd-session
        cmd-session
An account was successfully logged on.

 Subject:
    Security ID: SYSTEM
    Account Name: DEV-021$
    Account Domain: INSIGHT
    Time: 2025-10-04T02:03:12Z

 Logon Information:
    Logon Type: 10

 Network Information:
    Workstation Name: DEV-021
    Source Network Address: 103.112.60.117

 New Logon:
    SubjectUserName: insight\svc_deployer
    SourceNetworkAddress: 103.112.60.117
```

After a successful logon,  the attackers conducted some domain reconnaissance. They found some  interesting file shares on the file server, which they attempted to  access multiple times. On the file server, they located client project  folders that contained draft reports, survey data, and market forecasts.

![Network attack and monitoring flow. From the Internet, an attacker establishes C2 and uses VPN/RDP through a Firewall (no threat‑intel integration) to internal host DEV‑021. Exposed web consoles: ManageEngine AD Manager and a PHP Client Reports Portal. Internal network includes a Domain Controller, multiple Windows machines, a Database Server, and File Servers; sensitive data accessed on network shares. Event logs from AD Manager and internal hosts go to a SIEM, which integrates with TheHive to send notifications to a SOC Analyst, who performs analysis producing alerts and cases.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights0.png)

On the file server, multiple event logs were created, such as `5140(S, F): A network share object was accessed`. However, there were no rules created for generating alerts specifically for these public IP RDP events.

These kinds of event logs can be detected using the following [Sigma rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_successful_external_remote_rdp_login.yml), for example:

```sigma
        sigma
title: External Remote RDP Logon from Public IP
id: 259a9cdf-c4dd-4fa2-b243-2269e5ab18a2
related:
    - id: 78d5cab4-557e-454f-9fb9-a222bd0d5edc
      type: derived
status: test
description: Detects successful logon from public IP address via RDP. This can indicate a publicly-exposed RDP port.
references:
    - https://www.inversecos.com/2020/04/successful-4624-anonymous-logons-to.html
    - https://twitter.com/Purp1eW0lf/status/1616144561965002752
author: Micah Babinski (@micahbabinski), Zach Mathis (@yamatosecurity)
date: 2023-01-19
modified: 2024-03-11
tags:
    - attack.initial-access
    - attack.credential-access
    - attack.t1133
    - attack.t1078
    - attack.t1110
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    filter_main_local_ranges:
        IpAddress|cidr:
            - '::1/128'  # IPv6 loopback
            - '10.0.0.0/8'
            - '127.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
            - '169.254.0.0/16'
            - 'fc00::/7'  # IPv6 private addresses
            - 'fe80::/10'  # IPv6 link-local addresses
    filter_main_empty:
        IpAddress: '-'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate or intentional inbound connections from public IP addresses on the RDP port.
level: medium
```

After exploring and  observing for a week, they started compressing and exfiltrating selected data. The attackers packaged stolen client materials into a file named `diagnostics_data.zip`, a filename chosen to resemble routine telemetry. The archive was then  uploaded to the attacker-controlled host over HTTPS. Because the  filename resembled legitimate diagnostics data and the upload used  standard HTTPS, it did not immediately raise alarms. This tactic  increases the attackers chance of exfiltrating data before defenders  escalate.

![Network attack and monitoring flow. From the Internet, an attacker establishes C2 and uses VPN/RDP through a Firewall to internal host DEV‑021. Exposed web consoles: ManageEngine AD Manager and a PHP Client Reports Portal. Internal network contains a Domain Controller, multiple Windows machines, a Database server, and File servers where data is exfiltrated. Event logs from AD Manager and internal hosts go to a SIEM, which integrates with TheHive to notify a SOC analyst, who performs analysis producing alerts and cases.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights6.png)

Then, on `2025-10-04 02:10:45`, from `DEV-021`, they executed some PowerShell scripts that used domain administrator  credentials to create a Group Policy Object (GPO) that pushes an MSI  package (`java-update.msi`) across the domain. This MSI package created a scheduled task to run a  process that performs spying and data exfiltration on the machines.

These events were also captured in the event logs, such as the creation of a new `.msi` file as Sysmon Event ID 11.

```cmd-session
        cmd-session
Sysmon Event 11: TargetFilename: C:\Windows\Temp\java-update.msi
```

Also, Sysmon Event ID 1 captures the command line for the execution of the `.msi` file in the background.

```cmd-session
        cmd-session
Sysmon Event 1: Image: C:\Windows\System32\msiexec.exe CommandLine: "msiexec /i C:\Windows\Temp\java-update.msi /quiet"
```

This malware, with spying and data exfiltration capabilities, is deployed on all domain machines using GPO.

![Network attack and monitoring flow. From the Internet, an attacker establishes C2 and installs spyware via the exposed ManageEngine AD Manager web console; spyware is later pushed by GPO across the domain. A PHP Client Reports Portal is also exposed. Through the Firewall, VPN/RDP reaches internal host DEV‑021 and the wider network: a Domain Controller, multiple Windows machines, a Database server, and File servers (data access/exfil path shown). Event logs from AD Manager and internal hosts go to a SIEM, which integrates with TheHive to send notifications to a SOC Analyst, who performs analysis generating alerts and cases.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights4.png)

Around the same time, another threat actor, `Silent Jackal`, also performed some activities on a separate PHP-based reporting  portal. This server had an unpatched file upload vulnerability, which  was exploited by the threat actor to gain access to this server. Silent  Jackal uploaded a file into the root directory of the web server. Their  activities appeared limited to leaving the `checkme.txt` marker file. This created noise in the environment and provided defenders with the first clue of compromise.

![Diagram of an attack and monitoring flow. An attacker from the Internet abuses an exploited file‑upload vulnerability in a PHP Client Reports Portal (web console) and can reach the internal network through a Firewall. The internal network includes a Domain Controller, multiple Windows machines, a Database Server, and File Servers. ManageEngine AD Manager (web console) and internal hosts send event logs to a SIEM. The SIEM integrates with TheHive, which sends notifications to a SOC analyst, who performs analysis and generates alerts and cases.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/insights5.png)

However, the threat actor did not proceed beyond their initial access. This was  likely a low-skill intrusion meant to signal presence rather than cause  immediate damage.

`Organizational oversight: `No web application firewall monitoring and no regular vulnerability assessments of internet-facing portals.

Crimson Fox  reduced high-activity operations, with only occasional low-rate beacons  to 103.112.60.117 to check for new instructions. Silent Jackal similarly reduced activity.

------

### Immediate Incident Response Actions

The first tangible discovery was `checkme.txt` by a SOC analyst. That file alone would normally be low priority, but  the SOC analyst performing correlation saw that the same time window had ManageEngine events with unusual outbound traffic and multiple login  events from an unfamiliar foreign IP.

The correlation of the following was done as follows:

- ManageEngine successful admin logins from foreign IPs.
- Sysmon process creation of `msiexec` installing an MSI across many hosts.
- LDAP enumeration logs and GPO changes.
- File server file compression and upload logs.
- Outbound HTTPS to an unusual IP address.

After the correlation, the SOC analyst immediately escalated the incident to the incident response team and opened a case in `TheHive`. The following actions and findings completed the investigation and response:

1. `Case creation and triage`
   - The SOC created a TheHive case titled “Insight Nexus — ManageEngine  Compromise,” linked all related alerts (ManageEngine admin logins,  Sysmon msiexec events, LDAP enumeration, file server uploads, and the  portal `checkme.txt` event), and assigned roles: Triage Analyst, Forensics Lead, Containment Lead, and Communications Lead.
   - Priority was set to Critical due to confirmed data exfiltration.
2. `Containment — network controls`
   - Blocked outbound traffic to `103.112.60.117` at the perimeter firewall and on host-based firewalls. Added temporary egress block rules for the attacker IPs.
   - Added an IDS signature to alert on connections to `103.112.60.117` and similar endpoints.
3. `Containment — credential & account actions`
   - Disabled the ManageEngine admin account and rotated all high-privilege  credentials exposed in logs (service accounts, deployer accounts, and  any account showing suspicious activity).
   - Restricted the ManageEngine web console to be accessed only internally.
   - Implemented forced password changes and immediate revocation of active sessions where possible.
4. `Host isolation`
   - Isolated `manage.insightnexus.com`, `DEV-021`, and any machines that showed evidence of MSI installation from the  production network for forensic collection (network access blocked, but  preserved in a manner to allow analysis).
   - Suspended scheduled tasks and disabled GPO-initiated deployments until confirmation of remediation.
5. `Collect forensic artifacts`
   - On isolated hosts, collected volatile memory, process lists, registry  hives, and disk images. Exported ManageEngine audit logs and the web  server access logs with full timestamps.
   - Preserved copies of the MSI file (`java-update.msi`), the compressed exfiltrated package (`diagnostics_data.zip`), and any web shell files found in management app directories.

### Mapping to MITRE ATT&CK

- `Reconnaissance`: Scanning public assets; MITRE `T1595` (Active Scanning).
- `Weaponization / Initial Access`: ManageEngine default credentials (`T1078.004` - Valid Accounts), PHP upload exploitation (`T1190` - Exploit Public-Facing Application).
- `Delivery / Exploitation`: Web shell uploads, console command execution; (`T1505` - Server Software Component).
- `Installation / Persistence`: Scheduled tasks, services, GPO-deployed MSI (`T1547`, `T1543`, `T1069`).
- `Command & Control`: HTTPS to attacker-controlled IP (`T1071.001` - Web Protocols).
- `Action on Objective / Exfiltration`: Compress and upload project data (`T1560`/`T1041`).

### Lessons Learned

The following lessons were learned:

- `Default credentials` on Internet-facing applications remain one of the simplest but most damaging oversights.
- `Multiple concurrent threat actors` can be present in a single environment, with different motivations —  one opportunistic, one highly targeted. This complicates response  because defenders may underestimate the severity if they only see the  “loud” intruder.
- `Failure to correlate alerts` across teams delays containment, giving advanced actors more time to achieve objectives.
- `Post-incident monitoring` must include scanning for persistence mechanisms, since deleting an attacker’s marker file does not neutralize the root cause.

### Questions

1 - Download the Wazuh exported logs file (i.e.,  wazuh_export.zip), and identify all events that indicate potential  credential compromise. Check the event ID 4688 and verify the full path  of the parent process name that executed a credential dumping tool.  Answer format is C:\\Pr........

> **Answer:** C:\\Program Files\\Mozilla Firefox\\firefox.exe

2 - Identify events that show persistence  mechanisms. Type the value of imagePath for a persistence mechanism that took place on the host DB01.

> **Answer:** C:\\Windows\\PSEXESVC.exe

3 - Identify exfiltration activity — file(s)  uploaded or outbound traffic. What is the external IP address to which  the file diagnostics_data.zip was uploaded?

> **Answer:** 93.184.216.34

4 - Which user tried to connect to the file share \\fs01\projects?

> **Answer:** svc_admin

# Skills Assessment

## Skills Assessment

In the skills assessment, you are in the role of a junior incident responder and need to perform some tasks.

Let's navigate to the bottom of this section and click on "`Click here to spawn the target system!`".  			   Then, let's open TheHive webpage on "Target IP:9000" on port 9000 using the provided credentials to view the alerts. 

## Triage the alerts

TheHive is loaded with alerts related to the Insights Nexus breach. You are requested to triage them, starting with:

- Task 1: Create a new case in TheHive. Find all the alerts that are specific  to the Insights Nexus breach scenario, and link the alerts in the case.  This exercise introduces you to work in TheHive alerts and cases.
- Task 2: Perform triage, enrichment, and correlation in TheHive. In the notes of an alert, you can add useful information for enrichment.
- Task 3: One of the alerts related to Insights Nexus in TheHive contains some information in the notes. The netstat command output shows some  connectivity to external IP addresses. You can validate this finding.

![TheHive case interface showing a “Comments” panel with a pasted netstat -ano snippet from host 10.10.5.23. Entries include TCP 127.0.0.1:5357 LISTENING, TCP 10.10.5.23:139 LISTENING, outbound TCP 10.10.5.23:52344 → 198.5.x.x:443 ESTABLISHED, 10.10.5.23:52345 → 203.0.x.x:4444 ESTABLISHED, UDP 10.10.5.23:123 listening, and SMB connections to 10.10.5.17:445 and 10.10.5.18:445 (ESTABLISHED/TIME_WAIT). Top bar shows controls (Create Case, language EN-UK, user HTB-ANALYST).](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/148/ir-netstat.png)

This output was captured after the host machine rejoined the domain  following recovery. However, it is still connecting to an IP address.  The analyst added this in the comments of the alert.

There are some further questions asked at bottom of this section.

## Mapping to the Cyber Kill Chain

A user opens an attachment, which executes a downloader that writes an .exe file to `%AppData%`, creates a `Run` registry key, and later loads `VaultCli.dll` via a suspicious tool, exfiltrating credentials to an external IP. Your task is to map each step of the attack to the kill chain phase.

- Task 1: Map the file download, registry, and exfiltration activity to MITRE ATT&CK.
- Task 2: Check the alert related to Mimikatz in TheHive and identify the MITRE Technique ID.

## Investigate the collected logs

- Task 1: Additionally, you are provided with some event log files (i.e., `logs-wazuh.zip`). One of the tasks is to decode some PowerShell commands and extract IOCs from them.
- Task 2: Identify the user who executed the suspicious PowerShell command.

### Questions

1 - Open the alert "[InsightNexus] Admin Login via  ManageEngine Web Console." Find the foreign IP address starting with  "203" in the comments. Check VirusTotal for the information related to  this IP address, and add the details as a comment in this alert. In  VirusTotal, what is the name of the file starting with "Mango" in the  Files Referring section?

Authenticate to 10.129.3.102 (ACADEMY-INCIDENT-HIVE), with user "htb-analyst" and password "P3n#31337@LOG" 

> **Answer:** MangoJava.exe

2 - In VirusTotal, go to the details of the IP address starting with "198." What is the name of the city shown in the Whois Lookup?

Authenticate to 10.129.3.102 (ACADEMY-INCIDENT-HIVE), with user "htb-analyst" and password "P3n#31337@LOG" 

> **Answer:** **Los Angeles**

3 - If malware downloads files from a C2 (Command  and Control) server into the victim network, under what MITRE technique  ID does this tool transfer technique fall? Type it as your answer. The  format is T1***.

> **Answer:** T1105                  

4 - Open TheHive and check the rule ID 92153  related to the VaultCli.dll module. What is the MITRE technique ID for  this activity? The format is T1***.

Authenticate to 10.129.3.102 (ACADEMY-INCIDENT-HIVE), with user "htb-analyst" and password "P3n#31337@LOG" 

> **Answer:** T1555

5 - Download the "logs-wazuh.zip" file from  resources, and identify the suspicious PowerShell command in the logs.  Type the suspicious IP address after decoding the command.

> **Answer:** 198.51.100.24

6 - In the same file (i.e., logs-wazuh.zip),  identify the user who executed the suspicious PowerShell command. The  format is domain\user.

> **Answer:** CORP\svc-update













































































































































