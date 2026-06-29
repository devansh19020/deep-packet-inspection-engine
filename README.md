# Deep Packet Inspection & Network Traffic Analysis Engine

A Java-based Deep Packet Inspection (DPI) and Network Traffic Analysis Engine that reads PCAP files, parses network protocols, inspects application-layer traffic, tracks TCP flows, extracts TLS metadata, and generates rule-based security alerts.

---

## Features

- Reads packets directly from PCAP files
- Parses PCAP global and packet headers
- Parses Ethernet frames
- Parses IPv4 packets with variable header lengths
- Parses TCP headers and extracts TCP payloads
- Tracks bidirectional TCP flows
- Generates traffic statistics
- Detects and parses HTTP traffic
- Extracts HTTP request metadata:
  - Method
  - Path
  - HTTP Version
  - Host
- Detects TLS records
- Parses TLS ClientHello messages
- Extracts TLS Server Name Indication (SNI)
- Supports extensible rule-based inspection
- Generates security alerts for:
  - Suspicious domains
  - Suspicious destination ports
  - Suspicious HTTP paths

---

# Architecture

```text
                    PCAP FILE
                        |
                        v
                   PcapReader
                        |
                        v
                    RawPacket
                        |
                        v
                  PacketParser
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
   EthernetParser    IPv4Parser    TCPParser
          |             |             |
          +-------------+-------------+
                        |
                        v
                  ParsedPacket
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
 TrafficStatistics   FlowTracker  PacketInspector
                                      |
                              +-------+-------+
                              |               |
                              v               v
                         HTTPParser       TLSParser
                              |               |
                              v               v
                           HttpInfo        TlsInfo
                                              |
                                             SNI
                              +-------+-------+
                                      |
                                      v
                              InspectionResult
                                      |
                                      v
                                 RuleEngine
                                      |
                    +-----------------+-----------------+
                    |                 |                 |
                    v                 v                 v
           SuspiciousDomainRule SuspiciousPortRule SuspiciousHttpPathRule
                    |                 |                 |
                    +-----------------+-----------------+
                                      |
                                      v
                                SecurityAlert
```

---

# Project Structure

```text
src/main/java/com/devansh/dpi
│
├── Main.java
│
├── application
│   ├── HTTPParser.java
│   └── TLSParser.java
│
├── enums
│   ├── TransportProtocol.java
│   └── TlsContentType.java
│
├── inspection
│   ├── InspectionResult.java
│   └── PacketInspector.java
│
├── model
│   ├── RawPacket.java
│   ├── PcapGlobalHeader.java
│   ├── PcapPacketHeader.java
│   ├── EthernetFrame.java
│   ├── IPv4Packet.java
│   ├── TCPPacket.java
│   ├── HttpInfo.java
│   └── TlsInfo.java
│
├── parser
│   ├── PacketParser.java
│   ├── EthernetParser.java
│   ├── IPv4Parser.java
│   ├── TCPParser.java
│   └── ParsedPacket.java
│
├── reader
│   └── PcapReader.java
│
├── rule
│   ├── Rule.java
│   ├── RuleEngine.java
│   ├── SecurityAlert.java
│   ├── SuspiciousDomainRule.java
│   ├── SuspiciousPortRule.java
│   └── SuspiciousHttpPathRule.java
│
├── statistics
│   └── TrafficStatistics.java
│
├── tracker
│   ├── Flow.java
│   └── FlowTracker.java
│
└── util
    ├── ByteUtils.java
    ├── PacketPrinter.java
    └── ReportPrinter.java
```

---

# How It Works

The engine processes a PCAP file packet by packet.

```text
PCAP File
    |
    v
Read raw packet bytes
    |
    v
Parse Ethernet Header
    |
    v
Parse IPv4 Header
    |
    v
Parse TCP Header
    |
    v
Extract TCP Payload
    |
    +-----------------------+
    |                       |
    v                       v
Inspect HTTP             Inspect TLS
    |                       |
    v                       v
HTTP Metadata           TLS Metadata + SNI
    |                       |
    +-----------+-----------+
                |
                v
         InspectionResult
                |
                v
           Apply Rules
                |
                v
         Generate Alerts
```

---

# Component Overview

## PcapReader

`PcapReader` is responsible for low-level PCAP file handling.

It:

- Opens the PCAP file
- Reads the PCAP global header
- Validates the PCAP magic number
- Reads packet headers
- Reads raw packet bytes
- Creates `RawPacket` objects

It does not understand Ethernet, IP, TCP, HTTP, or TLS. Its responsibility is limited to reading the binary PCAP format.

```text
PCAP File
    |
    v
PcapReader
    |
    v
RawPacket
```

---

## RawPacket

`RawPacket` represents a packet exactly as it is read from the PCAP file.

Conceptually:

```text
RawPacket
├── PcapPacketHeader
└── byte[] data
```

The raw bytes are later passed to protocol parsers for decoding.

---

## PacketParser

`PacketParser` coordinates the network protocol parsing process.

```text
RawPacket
    |
    v
PacketParser
    |
    +--> EthernetParser
    |
    +--> IPv4Parser
    |
    +--> TCPParser
    |
    v
ParsedPacket
```

Each protocol has its own dedicated parser.

This keeps the design modular and avoids putting all parsing logic inside one large class.

---

# Protocol Parsing

## EthernetParser

The Ethernet parser extracts:

- Destination MAC Address
- Source MAC Address
- EtherType

The EtherType identifies the protocol encapsulated inside the Ethernet frame.

---

## IPv4Parser

The IPv4 parser extracts:

- Source IP Address
- Destination IP Address
- Transport Protocol
- TTL
- Header Length

The parser supports variable IPv4 header lengths using the Internet Header Length (IHL) field.

---

## TCPParser

The TCP parser extracts:

- Source Port
- Destination Port
- Sequence Number
- Acknowledgement Number
- TCP Header Length
- TCP Flags
- Payload Offset

The payload offset identifies where application-layer data begins.

```text
Ethernet Header
       |
       v
IPv4 Header
       |
       v
TCP Header
       |
       v
TCP Payload
```

---

# ParsedPacket

`ParsedPacket` acts as a unified representation of the parsed network packet.

```text
ParsedPacket
├── RawPacket
├── EthernetFrame
├── IPv4Packet
└── TCPPacket
```

It also provides convenience methods such as:

```java
packet.getSourceIp();
packet.getDestinationIp();
packet.getSourcePort();
packet.getDestinationPort();
packet.getPayload();
```

This allows other components to access parsed packet information without directly navigating through multiple protocol objects.

---

# PacketInspector

`PacketInspector` performs application-layer inspection.

After TCP parsing, the application extracts the TCP payload and attempts to identify supported application protocols.

```text
ParsedPacket
      |
      v
Has TCP?
      |
      v
Get TCP Payload
      |
      +-------------------+
      |                   |
      v                   v
  HTTPParser          TLSParser
      |                   |
      v                   v
  HttpInfo             TlsInfo
      |                   |
      +---------+---------+
                |
                v
        InspectionResult
```

---

# HTTP Inspection

The HTTP parser identifies HTTP requests and responses from TCP payloads.

For an HTTP request such as:

```text
GET /login HTTP/1.1
Host: example.com
```

the engine extracts:

```text
Method  : GET
Path    : /login
Version : HTTP/1.1
Host    : example.com
```

The parsed information is stored in `HttpInfo`.

Conceptually:

```text
HttpInfo
├── Request / Response
├── Method
├── Path
├── HTTP Version
├── Host
└── Status Code
```

This allows the engine to inspect unencrypted HTTP application traffic.

---

# TLS Inspection and SNI Extraction

The engine performs metadata-based TLS inspection.

It parses the TLS ClientHello structure to extract information from the handshake.

```text
TLS Record
    |
    +-- Record Header
    |
    +-- Handshake Message
            |
            +-- ClientHello
                    |
                    +-- Extensions
                            |
                            +-- Server Name Extension
                                    |
                                    +-- SNI
```

For example:

```text
SNI: example.com
```

The extracted TLS information can include:

- TLS Content Type
- TLS Version
- Record Length
- Server Name Indication (SNI)

The engine does not decrypt HTTPS traffic.

Instead, it inspects TLS handshake metadata when available.

---

# InspectionResult

`InspectionResult` combines the results of network and application-layer inspection.

```text
InspectionResult
├── ParsedPacket
├── HttpInfo
└── TlsInfo
```

It acts as a bridge between packet inspection and the security rule engine.

Rules receive an already prepared `InspectionResult` instead of performing protocol parsing themselves.

---

# Flow Tracking

The engine groups packets into bidirectional TCP flows.

Example:

```text
192.168.1.10:50000
        |
        | TCP Flow
        |
142.250.183.46:443
```

Packets travelling in both directions:

```text
A -> B
B -> A
```

are associated with the same logical communication flow.

This allows the application to analyze communication sessions instead of treating every packet as completely independent.

---

# Traffic Statistics

`TrafficStatistics` maintains aggregate traffic information.

Examples include:

- Total packets processed
- Total TCP packets
- Total bytes processed
- Protocol-level statistics

This provides a high-level view of the analyzed network capture.

---

# Rule Engine

The security detection system is based on an extensible rule engine.

```text
InspectionResult
       |
       v
   RuleEngine
       |
       +--> SuspiciousDomainRule
       |
       +--> SuspiciousPortRule
       |
       +--> SuspiciousHttpPathRule
       |
       v
SecurityAlert
```

Every detection rule implements the `Rule` interface.

```java
public interface Rule {

    SecurityAlert evaluate(
            InspectionResult result
    );
}
```

New rules can be added by implementing this interface and registering the rule with the `RuleEngine`.

```text
Create New Rule
       |
       v
Implement Rule Interface
       |
       v
Register Rule with RuleEngine
```

This follows an interface-based extensible design.

---

## SuspiciousDomainRule

Checks domains obtained from:

- HTTP `Host`
- TLS `SNI`

Example:

```text
Suspicious domain detected: example.com
```

If the domain matches a configured suspicious domain, a security alert is generated.

---

## SuspiciousPortRule

Checks the TCP destination port against a configured set of ports.

Example:

```text
Destination Port: 4444
```

Possible alert:

```text
Connection detected to suspicious port: 4444
```

This is intended as an MVP detection rule. A port alone does not prove malicious activity, but it can be useful as one signal for further analysis.

---

## SuspiciousHttpPathRule

Checks HTTP request paths against configured paths.

For example:

```text
GET /admin HTTP/1.1
```

Possible alert:

```text
Suspicious HTTP path detected: /admin
```

The rule only applies to HTTP requests.

---

# SecurityAlert

When a rule detects a match, it generates a `SecurityAlert`.

An alert contains information such as:

- Rule Name
- Severity
- Detection Message

Example:

```text
!!! SECURITY ALERT !!!
Rule     : Suspicious Domain Rule
Severity : HIGH
Message  : Suspicious domain detected: example.com
--------------------------------------
```

---

# Complete Processing Pipeline

For every packet, the application performs the following steps:

```text
1. PcapReader reads packet bytes
              |
              v
2. RawPacket is created
              |
              v
3. PacketParser parses Ethernet
              |
              v
4. PacketParser parses IPv4
              |
              v
5. PacketParser parses TCP
              |
              v
6. ParsedPacket is created
              |
              v
7. TrafficStatistics is updated
              |
              v
8. FlowTracker identifies the TCP flow
              |
              v
9. PacketInspector extracts TCP payload
              |
              v
10. HTTP/TLS parser performs application inspection
              |
              v
11. InspectionResult is created
              |
              v
12. RuleEngine evaluates all registered rules
              |
              v
13. Security alerts are generated for matching rules
              |
              v
14. Final traffic report is printed
```

---

# Complete System Architecture

```text
                    +------------------+
                    |    PCAP FILE     |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    |    PcapReader    |
                    |  Binary Reading  |
                    +--------+---------+
                             |
                             v
                        RawPacket
                             |
                             v
                    +------------------+
                    |   PacketParser   |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
              v              v              v
       EthernetParser     IPv4Parser     TCPParser
              |              |              |
              +--------------+--------------+
                             |
                             v
                        ParsedPacket
                             |
               +-------------+-------------+
               |             |             |
               v             v             v
        TrafficStats     FlowTracker   PacketInspector
                                           |
                                  +--------+--------+
                                  |                 |
                                  v                 v
                             HTTPParser         TLSParser
                                  |                 |
                                  v                 v
                               HttpInfo          TlsInfo
                                                    |
                                                   SNI
                                  +--------+--------+
                                           |
                                           v
                                   InspectionResult
                                           |
                                           v
                                      RuleEngine
                                           |
                    +----------------------+----------------------+
                    |                      |                      |
                    v                      v                      v
             Domain Rule               Port Rule             HTTP Path Rule
                    |                      |                      |
                    +----------------------+----------------------+
                                           |
                                           v
                                     SecurityAlert
                                           |
                                           v
                                      Final Report
```

---

# Example Output

```text
--------------------------------------
Source MAC      : 66:77:88:99:AA:BB
Destination MAC : 00:11:22:33:44:55
Source IP       : 192.168.1.10
Destination IP  : 142.250.183.46
Protocol        : TCP
Source Port     : 50000
Destination Port: 443
Sequence Number : 1000
--------------------------------------

TLS INSPECTION
Content Type : HANDSHAKE
TLS Version  : TLS 1.2
Record Length: 67
SNI          : example.com
--------------------------------------

!!! SECURITY ALERT !!!
Rule     : Suspicious Domain Rule
Severity : HIGH
Message  : Suspicious domain detected: example.com
--------------------------------------

==============================
      FLOW ANALYSIS SUMMARY
==============================
Total TCP Flows: 2
```

---

# Technologies Used

- Java 21
- Maven
- Java NIO
- `FileChannel`
- `ByteBuffer`
- Object-Oriented Programming
- Interface-based design

---

# Running the Project

## 1. Clone the Repository

```bash
git clone <repository-url>
cd deep-packet-inspection-engine
```

## 2. Build the Project

```bash
mvn clean compile
```

## 3. Add a PCAP File

Create a `captures` directory in the project root:

```text
deep-packet-inspection-engine
├── captures
│   └── sample.pcap
├── src
├── pom.xml
└── README.md
```

Place your PCAP file inside:

```text
captures/sample.pcap
```

## 4. Run the Application

Run the `Main` class from your IDE.

Alternatively, compile the project:

```bash
mvn clean compile
```

and run the application according to your Java/Maven configuration.

---

# Testing

The project includes manual test classes for individual application-layer parsers.

Test:

```text
HttpParserTest
```

to verify HTTP parsing.

Test:

```text
TLSParserSniTest
```

to verify TLS parsing and SNI extraction.

Run the main application after testing:

```text
Main
```

to verify the complete end-to-end pipeline.

---

# Limitations

This project is an MVP and currently has the following limitations:

- Supports the implemented protocol path: Ethernet -> IPv4 -> TCP
- Does not currently perform UDP application-layer inspection
- Does not perform TCP stream reassembly
- HTTP or TLS messages fragmented across multiple TCP packets may not be fully parsed
- TLS inspection extracts metadata such as SNI when available
- Does not decrypt encrypted HTTPS application data
- Rule configurations are currently defined in code
- Processing is focused on offline PCAP analysis

---

# Future Improvements

Potential future improvements include:

- TCP stream reassembly
- UDP parsing and inspection
- DNS parsing
- PCAPNG support
- Configurable rules using JSON or YAML
- CIDR and IP-based detection rules
- Packet filtering
- Severity scoring
- Alert aggregation
- Configurable suspicious domain feeds
- Spring Boot REST API
- Web dashboard for traffic visualization
- Real-time packet capture integration
- Database storage for alerts and traffic analysis

---

# Key Design Principles

## Separation of Concerns

Each component has a specific responsibility.

For example:

```text
PcapReader        -> Reads PCAP files
PacketParser      -> Coordinates protocol parsing
TCPParser         -> Parses TCP headers
PacketInspector   -> Performs application-layer inspection
FlowTracker       -> Tracks network flows
RuleEngine        -> Evaluates security rules
```

---

## Single Responsibility Principle

Protocol parsing is separated into dedicated classes instead of creating one large parser.

```text
EthernetParser
IPv4Parser
TCPParser
```

Each class focuses on one protocol layer.

---

## Open/Closed Principle

New detection rules can be added without modifying the existing `RuleEngine`.

```text
Existing RuleEngine
        +
New Rule Implementation
        =
New Detection Capability
```

For example, a future `SuspiciousIpRule` could implement the same `Rule` interface.

---

## Layered Protocol Parsing

The project follows the natural hierarchy of network protocols:

```text
Ethernet
    |
    v
IPv4
    |
    v
TCP
    |
    v
Application Payload
    |
    +--> HTTP
    |
    +--> TLS
```

---

## Defensive Binary Parsing

The PCAP reader and protocol parsers work directly with binary data.

The implementation uses techniques such as:

- Length validation
- Header size calculation
- Unsigned byte conversion
- Packet boundary checks
- PCAP magic number validation

This helps prevent invalid data from being incorrectly processed.

---

# Interview Summary

This project is a layered Deep Packet Inspection pipeline built in Java.

`PcapReader` reads raw packets from a PCAP file using Java NIO. Dedicated protocol parsers then decode Ethernet, IPv4, and TCP headers into structured objects. The `PacketInspector` examines TCP payloads and identifies supported application protocols such as HTTP and TLS. For HTTP traffic, it extracts request metadata including the method, path, and host. For TLS traffic, it performs metadata-based inspection of ClientHello messages and extracts the Server Name Indication when available.

The project also maintains aggregate traffic statistics and groups packets into bidirectional TCP flows. Finally, an extensible `RuleEngine` evaluates inspection results using independent detection rules for suspicious domains, destination ports, and HTTP paths, generating security alerts when configured conditions are matched.

The architecture separates binary file reading, protocol parsing, application-layer inspection, traffic analysis, and security detection, making the system modular and easier to extend.

---

# Key Learning Points

This project demonstrates:

- Binary data parsing in Java
- PCAP file processing
- Network protocol structure
- Ethernet frame parsing
- IPv4 header parsing
- TCP header parsing
- TCP payload extraction
- HTTP request inspection
- TLS ClientHello parsing
- TLS SNI extraction
- Network flow tracking
- Traffic statistics
- Interface-based architecture
- Rule engine design
- Object-Oriented Design Principles
- Separation of concerns
- Open/Closed Principle
- Defensive programming
- Java NIO with `FileChannel` and `ByteBuffer`

---
# Screenshots

## Sample Deep Packet Inspection Output

The following output demonstrates HTTP inspection, TLS SNI extraction, rule-based security alerts, and flow analysis.

![Deep Packet Inspection Engine Output](screenshots/one.png)
![Deep Packet Inspection Engine Output](screenshots/three.png)
![Deep Packet Inspection Engine Output](screenshots/four.png)
---

# License

This project is currently intended for educational and learning purposes.