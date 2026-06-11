package com.devansh.dpi.util;

import java.util.Comparator;
import java.util.List;

import com.devansh.dpi.classifier.ProtocolClassifier;
import com.devansh.dpi.enums.ApplicationProtocol;
import com.devansh.dpi.statistics.TrafficStatistics;
import com.devansh.dpi.tracker.Flow;
import com.devansh.dpi.tracker.FlowTracker;

public class ReportPrinter {

    private final ProtocolClassifier protocolClassifier =
            new ProtocolClassifier();

    public void printReport(
            TrafficStatistics statistics,
            FlowTracker flowTracker) {

        printTrafficSummary(
                statistics,
                flowTracker
        );

        printTopFlows(flowTracker);
    }

    private void printTrafficSummary(
            TrafficStatistics statistics,
            FlowTracker flowTracker) {

        System.out.println();
        System.out.println("========================================");
        System.out.println("       DPI TRAFFIC ANALYSIS REPORT");
        System.out.println("========================================");

        System.out.println(
                "Total Packets Processed : " +
                        statistics.getTotalPackets()
        );

        System.out.println(
                "IPv4 Packets            : " +
                        statistics.getIpv4Packets()
        );

        System.out.println(
                "TCP Packets             : " +
                        statistics.getTcpPackets()
        );

        System.out.println(
                "Unsupported Packets     : " +
                        statistics.getUnsupportedPackets()
        );

        System.out.println(
                "Total Captured Bytes    : " +
                        statistics.getTotalCapturedBytes()
        );

        System.out.println(
                "Total TCP Flows         : " +
                        flowTracker.getFlowCount()
        );

        System.out.println("========================================");
    }

    private void printTopFlows(FlowTracker flowTracker) {

        System.out.println();
        System.out.println("TOP TCP FLOWS");
        System.out.println("========================================");

        List<Flow> sortedFlows =
                flowTracker.getFlows()
                        .stream()
                        .sorted(
                                Comparator.comparingLong(
                                        Flow::getTotalBytes
                                ).reversed()
                        )
                        .toList();

        if (sortedFlows.isEmpty()) {
            System.out.println("No TCP flows found.");
            return;
        }

        int rank = 1;

        for (Flow flow : sortedFlows) {

            ApplicationProtocol applicationProtocol =
                    protocolClassifier.classify(flow);

            System.out.println(rank + ". " + flow.getKey());

            System.out.println(
                    "   Application : " +
                            applicationProtocol
            );

            System.out.println(
                    "   Packets     : " +
                            flow.getPacketCount()
            );

            System.out.println(
                    "   Bytes       : " +
                            flow.getTotalBytes()
            );

            System.out.println(
                    "   Duration    : " +
                            flow.getDuration() +
                            " seconds"
            );

            System.out.println();

            rank++;
        }
    }
}