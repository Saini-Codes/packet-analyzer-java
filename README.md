# Packet Analyzer — Java Edition

A Java 21 implementation of the original C++ Deep Packet Inspection (DPI) packet analyzer. It keeps the original project's core ideas—PCAP processing, Ethernet/IPv4/TCP/UDP parsing, five-tuple flow tracking, TLS SNI / HTTP Host / DNS inspection, application classification, rule-based filtering, statistics, and filtered PCAP output—while using Java concurrency and a clean Maven structure.

## Features
- Java 21 + Maven
- Standard-library PCAP reader/writer (Ethernet/DLT_EN10MB)
- Ethernet + VLAN + IPv4 + TCP/UDP parsing
- Five-tuple connection tracking with `ConcurrentHashMap`
- TLS ClientHello SNI extraction
- HTTP Host extraction
- DNS query extraction
- QUIC/HTTP3 basic classification
- Application classification for common services
- Thread-safe IP, port, domain, and application rules
- Wildcard domains (`*.example.com`)
- Multithreaded packet analysis using `ExecutorService`
- Forward/drop filtered PCAP output
- Atomic/concurrent statistics
- CLI suitable for demonstrations and MCA project work

## Build
Requires JDK 21 and Maven 3.9+.

```bash
mvn clean package
```

This creates `target/packet-analyzer-1.0.0.jar`.

## Run
```bash
java -jar target/packet-analyzer-1.0.0.jar show test.pcap -n 10
java -jar target/packet-analyzer-1.0.0.jar analyze test.pcap -o filtered.pcap -r rules.conf -t 8
```

## Rules
```text
BLOCK_IP=192.168.1.10
BLOCK_PORT=443
BLOCK_DOMAIN=*.facebook.com
BLOCK_APP=NETFLIX
```

## Architecture
```text
PCAP -> Reader -> Packet Parser -> Flow Tracker -> DPI Inspector
                                      |               |
                                      |          SNI/HTTP/DNS
                                      |               |
                                      +----------> Classifier
                                                      |
                                                  Firewall
                                                   /     \
                                               DROP    FORWARD
                                                         |
                                                     PCAP Writer
                                                         |
                                                     Statistics
```

## Important limitation
This implementation focuses on offline PCAP analysis. It does not inject/drop packets on a live interface. For live capture, a platform-specific capture layer (e.g. Pcap4J/libpcap/Npcap) can be added without changing the DPI, flow, or firewall modules.
