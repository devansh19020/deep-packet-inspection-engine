package com.devansh.dpi;

import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.parser.PacketParser;
import com.devansh.dpi.parser.ParsedPacket;
import com.devansh.dpi.reader.PcapReader;
import com.devansh.dpi.statistics.TrafficStatistics;
import com.devansh.dpi.tracker.FlowTracker;
import com.devansh.dpi.util.PacketPrinter;
import com.devansh.dpi.util.ReportPrinter;

public class Main {

    public static void main(String[] args) {

        PacketParser parser = new PacketParser();

        PacketPrinter packetPrinter =
                new PacketPrinter();

        FlowTracker flowTracker =
                new FlowTracker();

        TrafficStatistics statistics =
                new TrafficStatistics();

        ReportPrinter reportPrinter =
                new ReportPrinter();

        try (PcapReader reader = new PcapReader()) {

            reader.open("captures/sample.pcap");

            RawPacket rawPacket;

            while ((rawPacket = reader.readNextPacket()) != null) {

                ParsedPacket packet =
                        parser.parse(rawPacket);

                statistics.process(packet);

                flowTracker.process(packet);

                packetPrinter.print(packet);
            }

            reportPrinter.printReport(
                    statistics,
                    flowTracker
            );

        } catch (Exception e) {

            e.printStackTrace();
        }
    }
}