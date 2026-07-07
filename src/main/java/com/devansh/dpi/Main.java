package com.devansh.dpi;

import java.util.List;
import java.util.HashSet;

import java.io.IOException;

import com.devansh.dpi.inspection.InspectionResult;
import com.devansh.dpi.inspection.PacketInspector;
import com.devansh.dpi.model.DNSInfo;
import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.parser.PacketParser;
import com.devansh.dpi.parser.ParsedPacket;
import com.devansh.dpi.reader.PcapReader;
import com.devansh.dpi.rule.RuleEngine;
import com.devansh.dpi.rule.SecurityAlert;
import com.devansh.dpi.statistics.TrafficStatistics;
import com.devansh.dpi.tracker.FlowTracker;
import com.devansh.dpi.util.PacketPrinter;
import com.devansh.dpi.util.ReportPrinter;
import com.devansh.dpi.config.DpiConfig;
import com.devansh.dpi.config.RuleConfigLoader;
import com.devansh.dpi.rule.SuspiciousDomainRule;
import com.devansh.dpi.rule.SuspiciousPortRule;
import com.devansh.dpi.rule.SuspiciousHttpPathRule;

public class Main {

    public static void main(String[] args) {

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

        DpiConfig config;

        /*
         * Create Rule Engine
         */
        RuleEngine ruleEngine =
                new RuleEngine();

        /*
         * Register security rules
         */
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

                /*
                 * Layer 1:
                 * Parse network protocols
                 */
                ParsedPacket packet =
                        parser.parse(rawPacket);

                /*
                 * Layer 2:
                 * Inspect application protocols
                 */
                InspectionResult result =
                        inspector.inspect(packet);

                /*
                 * Layer 3:
                 * Update traffic analysis
                 */
                statistics.process(packet);

                flowTracker.process(packet);

                /*
                 * Print packet details
                 */
                packetPrinter.print(packet);

                /*
                 * Print HTTP inspection
                 */
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

                /*
                 * Print TLS inspection
                 */
                if (result.hasTls()) {

                    System.out.println(
                            "TLS INSPECTION"
                    );

                    System.out.println(
                            "Content Type : " +
                                    result.getTlsInfo()
                                            .getContentType()
                    );

                    System.out.println(
                            "TLS Version  : " +
                                    result.getTlsInfo()
                                            .getVersion()
                    );

                    System.out.println(
                            "Record Length: " +
                                    result.getTlsInfo()
                                            .getRecordLength()
                    );

                    if (result.getTlsInfo()
                            .hasServerName()) {

                        System.out.println(
                                "SNI          : " +
                                        result.getTlsInfo()
                                                .getServerName()
                        );
                    }

                    System.out.println(
                            "--------------------------------------"
                    );
                }

                if (result.hasDns()) {

                DNSInfo dns = result.getDnsInfo();

                System.out.println("DNS Inspection");
                System.out.println("  Transaction ID : " +
                        dns.getTransactionId());

                System.out.println("  Message Type   : " +
                        (dns.isResponse() ? "Response" : "Query"));

                System.out.println("  Query Name     : " +
                        dns.getQueryName());

                System.out.println("  Record Type    : " +
                        dns.getRecordType());

                System.out.println("  Questions      : " +
                        dns.getQuestionCount());

                System.out.println("  Answers        : " +
                        dns.getAnswerCount());

                System.out.println("  Response Code  : " +
                        dns.getResponseCode());
                }

                /*
                 * Layer 4:
                 * Apply security rules
                 */
                List<SecurityAlert> alerts =
                        ruleEngine.evaluate(result);

                /*
                 * Print generated alerts
                 */
                for (SecurityAlert alert : alerts) {

                    System.out.println(
                            "!!! SECURITY ALERT !!!"
                    );

                    System.out.println(
                            "Rule     : " +
                                    alert.getRuleName()
                    );

                    System.out.println(
                            "Severity : " +
                                    alert.getSeverity()
                    );

                    System.out.println(
                            "Message  : " +
                                    alert.getMessage()
                    );

                    System.out.println(
                            "--------------------------------------"
                    );
                }
            }

            /*
             * Final traffic report
             */
            reportPrinter.printReport(
                    statistics,
                    flowTracker
            );

        } catch (Exception e) {

            e.printStackTrace();
        }
    }
}