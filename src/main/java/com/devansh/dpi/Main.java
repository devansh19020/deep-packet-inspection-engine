package com.devansh.dpi;

import com.devansh.dpi.inspection.InspectionResult;
import com.devansh.dpi.inspection.PacketInspector;
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

        PacketInspector inspector =
                new PacketInspector();

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

                InspectionResult result =
                        inspector.inspect(packet);

                statistics.process(packet);

                flowTracker.process(packet);

                packetPrinter.print(packet);

                if (result.hasHttp()) {

                    System.out.println(
                            "HTTP INSPECTION"
                    );

                    System.out.println(
                            "Type    : " +
                                    (result.getHttpInfo().isRequest()
                                            ? "REQUEST"
                                            : "RESPONSE")
                    );

                    System.out.println(
                            "Method  : " +
                                    result.getHttpInfo().getMethod()
                    );

                    System.out.println(
                            "Path    : " +
                                    result.getHttpInfo().getPath()
                    );

                    System.out.println(
                            "Host    : " +
                                    result.getHttpInfo().getHost()
                    );

                    System.out.println(
                            "Status  : " +
                                    result.getHttpInfo().getStatusCode()
                    );

                    System.out.println(
                            "--------------------------------------"
                    );
                }
                if (result.hasTls()) {

                        System.out.println("TLS INSPECTION");

                        System.out.println(
                                "Content Type : " +
                                        result.getTlsInfo().getContentType()
                        );

                        System.out.println(
                                "TLS Version  : " +
                                        result.getTlsInfo().getVersion()
                        );

                        System.out.println(
                                "Record Length: " +
                                        result.getTlsInfo().getRecordLength()
                        );

                        if (result.getTlsInfo().hasServerName()) {

                                System.out.println(
                                        "SNI          : " +
                                                result.getTlsInfo().getServerName()
                                );
                        }

                        System.out.println(
                                "--------------------------------------"
                        );
                }
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