package org.example.dns;

import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.util.MacAddress;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.Scanner;

/**
 * DNSApp.java
 *
 * A small utility that:
 * 1) Captures DNS packets and prints them (promiscuous mode).
 * 2) Resolves MX records for a given domain (via dig).
 * 3) Queries a root server and ISP DNS for certain domains.
 *
 * Usage:
 *   > sniff
 *   > resolve <domain>
 *   > rootquery
 *   > exit
 */
public class DNSApp {

    public static void main(String[] args) {

        printMenu();

        createFunctionMap();

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("> ");
            String input = scanner.nextLine().trim();
            if (input.isEmpty()) {
                continue;
            }

            String[] tokens = input.split("\\s+");

            switch (tokens[0]) {
                case "sniff":
                    sniffDNSPackets();
                    break;
                case "resolve":
                    if (tokens.length < 2) {
                        System.out.println("Usage: resolve <domain>");
                    } else {
                        resolveMX(tokens[1]);
                    }
                    break;
                case "rootquery":
                    rootServerQuery();
                    break;
                case "exit":
                    System.out.println("Exiting...");
                    return;
                default:
                    System.out.println("Unknown command.");
            }
        }
    }

    /**
     * Prints the available commands to the console. (Assignment requirement)
     */
    private static void printMenu() {
        System.out.println("DNS Utility - Available Commands:");
        System.out.println("1. sniff            -> Capture DNS packets");
        System.out.println("2. resolve <domain> -> Get MX records via dig");
        System.out.println("3. rootquery        -> Query root server & ISP DNS for cnn.com/hse.ru/draw.io");
        System.out.println("4. exit             -> Quit the application");
    }

    /**
     * Task 1: DNS Packet Capture in promiscuous mode.
     * Interprets the DNS header (Transaction ID, Flags, QD/AN/NS/AR)
     * and attempts to parse the first Question name, type, class.
     */
    private static void sniffDNSPackets() {
        try {

            PcapNetworkInterface nif = null;
            for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
                if (dev.getName() == null) continue;

                if (dev.getName().startsWith("en") || dev.getName().startsWith("eth")) {
                    for (PcapAddress addr : dev.getAddresses()) {
                        if (addr.getAddress() instanceof java.net.Inet4Address) {
                            nif = dev;
                            break;
                        }
                    }
                }
                if (nif != null) break;
            }

            if (nif == null) {
                System.err.println("No suitable Ethernet interface found with an IPv4 address.");
                return;
            }

            InetAddress localIp = null;
            for (PcapAddress addr : nif.getAddresses()) {
                if (addr.getAddress() instanceof java.net.Inet4Address) {
                    localIp = addr.getAddress();
                    break;
                }
            }
            if (localIp == null) {
                System.err.println("Interface found, but no IPv4 address assigned.");
                return;
            }

            System.out.println("Using interface: " + nif.getName());
            System.out.println("Local IP Address: " + localIp.getHostAddress());

            MacAddress localMac = MacAddress.getByAddress(nif.getLinkLayerAddresses().get(0).getAddress());
            System.out.println("Local MAC Address: " + localMac);

            PcapHandle handle = nif.openLive(
                    65536,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    10_000
            );

            String filter = "udp port 53";
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

            System.out.println("Sniffing DNS packets... Press Ctrl+C or kill process to stop.");

            PacketListener listener = packet -> {

                System.out.println("\nPacket received (" + packet.length() + " bytes)");

                EthernetPacket eth = packet.get(EthernetPacket.class);
                if (eth != null) {
                    System.out.println("Ethernet SRC: " + eth.getHeader().getSrcAddr() +
                            " | DST: " + eth.getHeader().getDstAddr());
                }

                UdpPacket udp = packet.get(UdpPacket.class);
                if (udp != null && udp.getPayload() != null) {
                    byte[] rawData = udp.getPayload().getRawData();
                    if (rawData.length > 0) {

                        System.out.println("Raw DNS Payload (hex):");
                        for (byte b : rawData) {
                            System.out.printf("%02X ", b);
                        }
                        System.out.println("\nPayload Length: " + rawData.length);

                        parseDNSPacket(rawData);
                    }
                }
            };

            handle.loop(-1, listener);

        } catch (InterruptedException ie) {
            System.err.println("Sniffing interrupted: " + ie.getMessage());
        } catch (Exception e) {
            System.err.println("Setup failed: " + e.getClass().getSimpleName() +
                    " -> " + (e.getMessage() != null ? e.getMessage() : ""));
        }
    }

    /**
     * Helper method to parse a raw DNS packet:
     *  - Transaction ID, Flags, QD/AN/NS/AR
     *  - parse of the first Question (name, type, class).
     *  - Omits pointer-compression details, prints partial question name.
     */
    private static void parseDNSPacket(byte[] rawData) {
        if (rawData.length < 12) {
            System.out.println("Not a valid DNS packet (too short).");
            return;
        }

        int transactionId = toUnsignedShort(rawData[0], rawData[1]);
        int flags = toUnsignedShort(rawData[2], rawData[3]);
        int qdCount = toUnsignedShort(rawData[4], rawData[5]);
        int anCount = toUnsignedShort(rawData[6], rawData[7]);
        int nsCount = toUnsignedShort(rawData[8], rawData[9]);
        int arCount = toUnsignedShort(rawData[10], rawData[11]);

        System.out.printf("Transaction ID: 0x%04X\n", transactionId);
        System.out.printf("Flags: 0x%04X\n", flags);
        System.out.println("Questions: " + qdCount +
                ", Answers: " + anCount +
                ", Authority: " + nsCount +
                ", Additional: " + arCount);

        if (qdCount > 0) {
            int offset = 12;
            StringBuilder qName = new StringBuilder();

            while (offset < rawData.length) {
                int length = rawData[offset] & 0xFF;
                if (length == 0) {
                    offset++;
                    break;
                }

                if ((length & 0xC0) == 0xC0) {
                    qName.append("<compressed>");
                    offset += 2;
                    break;
                }
                offset++;
                if (offset + length > rawData.length) {
                    System.out.println("Invalid QNAME (out of bounds).");
                    return;
                }

                String label = new String(rawData, offset, length);
                qName.append(label).append(".");
                offset += length;
            }

            if (offset + 4 <= rawData.length) {
                int qType = toUnsignedShort(rawData[offset], rawData[offset + 1]);
                int qClass = toUnsignedShort(rawData[offset + 2], rawData[offset + 3]);
                offset += 4;

                System.out.println("Question Name: " + qName.toString());
                System.out.printf("Question Type: %d, Question Class: %d\n", qType, qClass);
            }
        }
    }

    /**
     * Helper: Convert two bytes to an unsigned 16-bit value.
     */
    private static int toUnsignedShort(byte hi, byte lo) {
        return ((hi & 0xFF) << 8) | (lo & 0xFF);
    }

    /**
     * Task 2: MX Record Resolution using 'dig'.
     * The user enters "resolve <domain>", we print each MX in the format:
     *   domain -> <mxRecord>
     */
    private static void resolveMX(String domain) {
        try {
            System.out.println("Resolving MX for: " + domain);
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", domain, "MX");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            boolean found = false;
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    found = true;

                    System.out.println(domain + " -> " + line);
                }
            }
            if (!found) {
                System.out.println("No MX records found for " + domain);
            }

            process.waitFor();
        } catch (Exception e) {
            System.err.println("Error resolving MX: " + e.getMessage());
        }
    }

    /**
     * Task 3: Root Server Query
     */
    private static void rootServerQuery() {

        String rootServerIP = "198.41.0.4";
        String[] domains = {"cnn.com", "hse.ru", "draw.io"};

        for (String domain : domains) {
            try {
                System.out.println("\nQuerying root server for: " + domain);
                ProcessBuilder pbRoot = new ProcessBuilder("dig", "@" + rootServerIP, domain);
                pbRoot.redirectErrorStream(true);
                Process processRoot = pbRoot.start();

                BufferedReader readerRoot = new BufferedReader(new InputStreamReader(processRoot.getInputStream()));
                String line;
                System.out.println("Root server response (authority NS lines):");
                while ((line = readerRoot.readLine()) != null) {
                    if (line.contains("AUTHORITY SECTION") || line.matches(".*\\sIN\\sNS\\s.*")) {
                        System.out.println(line);
                    }
                }
                processRoot.waitFor();

                System.out.println("\nQuerying ISP DNS (default resolver) for: " + domain);
                ProcessBuilder pbISP = new ProcessBuilder("dig", domain);
                pbISP.redirectErrorStream(true);
                Process processISP = pbISP.start();

                BufferedReader readerISP = new BufferedReader(new InputStreamReader(processISP.getInputStream()));
                System.out.println("ISP DNS response (answer A lines):");
                while ((line = readerISP.readLine()) != null) {

                    if (line.contains("ANSWER SECTION") || line.matches(".*\\sIN\\sA\\s.*")) {
                        System.out.println(line);
                    }
                }
                processISP.waitFor();

            } catch (Exception e) {
                System.err.println("Error querying DNS: " + e.getMessage());
            }
        }
    }

    /**
     * Makes a text file function_map.txt listing the methods and their purposes.
     * Also prints "Generated function_map.txt" upon success.
     */
    private static void createFunctionMap() {
        try (FileWriter writer = new FileWriter("function_map.txt")) {
            writer.write("Function Map for DNSApp.java\n");
            writer.write("------------------------------------\n");
            writer.write("main()               -> Console input loop & menu dispatch\n");
            writer.write("printMenu()          -> Prints available commands\n");
            writer.write("sniffDNSPackets()    -> Task 1: Captures DNS packets in promiscuous mode, prints them\n");
            writer.write("parseDNSPacket()     -> Helper to decode DNS header + first question\n");
            writer.write("toUnsignedShort()    -> Byte conversion helper\n");
            writer.write("resolveMX()          -> Task 2: Uses dig to get MX records for a domain\n");
            writer.write("rootServerQuery()    -> Task 3: Queries root & ISP DNS for specified domains\n");
            writer.write("createFunctionMap()  -> Generates this file\n");
            System.out.println("Generated function_map.txt");
        } catch (Exception e) {
            System.err.println("Failed to write function_map.txt: " + e.getMessage());
        }
    }
}