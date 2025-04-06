
# DNS Utility - Java (PCAP4J + MX + Root Queries)

This Java-based DNS utility allows you to perform live DNS packet sniffing, resolve MX (Mail Exchange) records using `dig`, and compare root server vs ISP DNS responses for selected domains. It uses the [Pcap4J](https://github.com/kaitoy/pcap4j) library for packet capturing and standard Java utilities for command execution.

## Features

- **Sniff DNS Packets:** Capture DNS traffic on your active network interface.
- **Resolve MX Records:** Retrieve mail exchange records for any domain using the `dig` command.
- **Query Root vs ISP DNS:** Compare results from root name servers and your system’s resolver.
- **Function Mapping:** Automatically generates a `function_map.txt` to document internal logic.

---

## Project Structure

```
.
├── function_map.txt              # Auto-generated function map
├── pom.xml                       # Maven project file
├── sniff                         # (Optional) Script to test sniffing
├── src/
│   └── main/java/org/example/dns/DNSApp.java
└── target/                       # Compiled classes and Maven artifacts
```

---

## Commands & Usage

Run the application via Maven:

```bash
mvn compile exec:java
```

You'll see the interactive prompt:

```
DNS Utility - Available Commands:
1. sniff            -> Capture DNS packets
2. resolve <domain> -> Get MX records via dig
3. rootquery        -> Query root server & ISP DNS for cnn.com/hse.ru/draw.io
4. exit             -> Quit the application
```

### Example Session

```text
> resolve gmail.com
gmail.com -> 5 gmail-smtp-in.l.google.com.
gmail.com -> 10 alt1.gmail-smtp-in.l.google.com.
...

> resolve somerandomfake.tld
No MX records found for somerandomfake.tld

> rootquery
Querying root server for: cnn.com
;; AUTHORITY SECTION:
com. IN NS a.gtld-servers.net.
...

ISP DNS response:
cnn.com. IN A 151.101.3.5
...

> sniff
[Captures DNS packets on interface en0, parses and displays raw headers]

> exit
Exiting...
```

---

## Test Commands

These were the commands used to test and validate the application:

```bash
# Compile the project
mvn compile

# Run interactively with main class
mvn compile exec:java

# Alternative: Run via Java manually
java -cp target/classes:target/dependency/* org.example.dns.DNSApp

# Resolve MX
resolve gmail.com
resolve yahoo.com
resolve hse.ru
resolve somerandomfake.tld

# Run Root Queries
rootquery

# DNS Packet Sniffing
sniff

# Exit
exit
```

---

## Output Summary

All features were tested and the following outputs were successfully observed:

### MX Record Resolution

- `gmail.com` returned 5 valid MX entries
- `yahoo.com` returned 3 MX entries
- `hse.ru` returned 2 MX entries
- Fake TLDs returned: `No MX records found`

### Root Query Comparison

- Queried domains: `cnn.com`, `hse.ru`, `draw.io`
- Root server returned authoritative NS records
- ISP DNS returned corresponding A (IP) records

### Sniffing

- Successfully captured DNS packets from interface (`en0`)
- Parsed and displayed raw hexadecimal DNS headers

---

## Function Map

```
main()               -> Console input loop & menu dispatch
printMenu()          -> Prints available commands
sniffDNSPackets()    -> Captures DNS packets
parseDNSPacket()     -> Decodes DNS header & question section
toUnsignedShort()    -> Byte conversion helper
resolveMX()          -> MX record resolution via dig
rootServerQuery()    -> Root & ISP DNS comparison
createFunctionMap()  -> Generates function_map.txt
```

---

## Requirements

- Java 21
- Maven 3.8+
- macOS ARM (or Linux with `dig` and libpcap)
- Internet connection for DNS testing

---

## Dependencies

| Dependency                           | Version  |
|--------------------------------------|----------|
| `jna` (Java Native Access)           | 5.13.0   |
| `pcap4j-core`                        | 1.8.2    |
| `pcap4j-packetfactory-static`        | 1.8.2    |
| `slf4j-simple`                       | 1.7.36   |
| `exec-maven-plugin` (build tool)     | 3.1.0    |

All dependencies are managed via `pom.xml`.

