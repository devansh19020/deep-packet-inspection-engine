package com.devansh.dpi;

import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.parser.PacketParser;
import com.devansh.dpi.parser.ParsedPacket;
import com.devansh.dpi.reader.PcapReader;
import com.devansh.dpi.tracker.FlowTracker;
import com.devansh.dpi.util.PacketPrinter;

public class Main {

    public static void main(String[] args) {

        PacketParser parser = new PacketParser();

        PacketPrinter printer = new PacketPrinter();

        FlowTracker flowTracker = new FlowTracker();

        try (PcapReader reader = new PcapReader()) {

            reader.open("captures/sample.pcap");

            RawPacket rawPacket;

            while ((rawPacket = reader.readNextPacket()) != null) {

                ParsedPacket packet =
                        parser.parse(rawPacket);

                // Track the TCP flow this packet belongs to
                flowTracker.process(packet);

                // Print packet details
                printer.print(packet);
            }

            System.out.println();
            System.out.println("==============================");
            System.out.println("      FLOW ANALYSIS SUMMARY");
            System.out.println("==============================");
            System.out.println(
                    "Total TCP Flows: " +
                            flowTracker.getFlowCount()
            );

        } catch (Exception e) {

            e.printStackTrace();

        }

    }
}