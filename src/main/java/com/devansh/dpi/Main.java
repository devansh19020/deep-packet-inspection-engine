package com.devansh.dpi;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;

import com.devansh.dpi.config.DpiConfig;
import com.devansh.dpi.config.RuleConfigLoader;
import com.devansh.dpi.inspection.InspectionResult;
import com.devansh.dpi.inspection.PacketInspector;
import com.devansh.dpi.model.HttpInfo;
import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.model.TCPStreamData;
import com.devansh.dpi.parser.PacketParser;
import com.devansh.dpi.parser.ParsedPacket;
import com.devansh.dpi.reader.PcapReader;
import com.devansh.dpi.rule.RuleEngine;
import com.devansh.dpi.rule.SecurityAlert;
import com.devansh.dpi.rule.SuspiciousDomainRule;
import com.devansh.dpi.rule.SuspiciousHttpPathRule;
import com.devansh.dpi.rule.SuspiciousPortRule;
import com.devansh.dpi.statistics.TrafficStatistics;
import com.devansh.dpi.tracker.FlowKey;
import com.devansh.dpi.tracker.FlowTracker;
import com.devansh.dpi.tracker.TCPApplicationBuffer;
import com.devansh.dpi.tracker.TCPStreamReassembler;
import com.devansh.dpi.util.ApplicationLayerPrinter;
import com.devansh.dpi.util.ConsoleFileTee;
import com.devansh.dpi.util.PacketPrinter;
import com.devansh.dpi.util.ReportPrinter;

public class Main {

        public static void main(String[] args) {
                try (ConsoleFileTee output = new ConsoleFileTee(
                        Path.of("reports", "dpi-report.log"))) {

                System.out.println("DPI ENGINE RUN REPORT");
                System.out.println("=====================");
                System.out.println();

                runDpi(args);

                } catch (IOException e) {
                System.err.println(
                        "Could not create or write the DPI report: "
                                + e.getMessage()
                );
                }
        }

    public static void runDpi(String[] args) {

        PacketParser parser =
                new PacketParser();

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

        RuleConfigLoader configLoader =
                new RuleConfigLoader();

        TCPStreamReassembler streamReassembler =
                new TCPStreamReassembler();

        TCPApplicationBuffer applicationBuffer =
                new TCPApplicationBuffer();

        ApplicationLayerPrinter applicationLayerPrinter =
                new ApplicationLayerPrinter();

        DpiConfig config;

        RuleEngine ruleEngine =
                new RuleEngine();

        try {
        config = configLoader.load("rules.json");

        } catch (IOException e) {
                System.err.println(
                        "Failed to load rules: " + e.getMessage()
                );
                return;
        }

        ruleEngine.addRule(
                new SuspiciousDomainRule(
                        new HashSet<>(config.getSuspiciousDomains())
                )
        );

        ruleEngine.addRule(
                new SuspiciousPortRule(
                        new HashSet<>(config.getSuspiciousPorts())
                )
        );

        ruleEngine.addRule(
                new SuspiciousHttpPathRule(
                        new HashSet<>(config.getSuspiciousHttpPaths())
                )
        );

        System.out.println("Security rules loaded successfully.");
        System.out.println("Suspicious domains: " +
                config.getSuspiciousDomains().size());
        System.out.println("Suspicious ports: " +
                config.getSuspiciousPorts().size());
        System.out.println("Suspicious HTTP paths: " +
                config.getSuspiciousHttpPaths().size());

        try (PcapReader reader = new PcapReader()) {

            reader.open("captures/sample.pcap");

            RawPacket rawPacket;

            while ((rawPacket =
                    reader.readNextPacket()) != null) {

                ParsedPacket packet =
                        parser.parse(rawPacket);

                InspectionResult result =
                        inspector.inspect(packet);


                List<TCPStreamData> streamChunks =
                        streamReassembler.process(packet);

                for (TCPStreamData chunk : streamChunks) {

                        List<HttpInfo> streamRequests =
                                applicationBuffer.process(chunk);

                        for (HttpInfo streamHttp : streamRequests) {

                                InspectionResult streamResult =
                                        new InspectionResult(
                                                packet,
                                                streamHttp,
                                                null,
                                                null
                                        );

                                List<SecurityAlert> streamAlerts =
                                        ruleEngine.evaluate(streamResult);

                                applicationLayerPrinter.printReassembledHttp(
                                        streamResult,
                                        streamAlerts
                                );
                        }
                }

                for (FlowKey closedFlow : streamReassembler.drainClosedFlows()) {
                        applicationBuffer.removeFlow(closedFlow);
                }


                statistics.process(packet);

                flowTracker.process(packet);

 
                packetPrinter.print(packet);

                List<SecurityAlert> alerts =
                        ruleEngine.evaluate(result);

                applicationLayerPrinter.printInspection(result, alerts);
                
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