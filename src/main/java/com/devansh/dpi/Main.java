package com.devansh.dpi;

import java.util.List;
import java.util.Set;

import com.devansh.dpi.inspection.InspectionResult;
import com.devansh.dpi.inspection.PacketInspector;
import com.devansh.dpi.model.DNSInfo;
import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.parser.PacketParser;
import com.devansh.dpi.parser.ParsedPacket;
import com.devansh.dpi.reader.PcapReader;
import com.devansh.dpi.rule.RuleEngine;
import com.devansh.dpi.rule.SecurityAlert;
import com.devansh.dpi.rule.SuspiciousDomainRule;
import com.devansh.dpi.rule.SuspiciousHttpPathRule;
import com.devansh.dpi.rule.SuspiciousPortRule;
import com.devansh.dpi.statistics.TrafficStatistics;
import com.devansh.dpi.tracker.FlowTracker;
import com.devansh.dpi.util.PacketPrinter;
import com.devansh.dpi.util.ReportPrinter;

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

        /*
         * Create Rule Engine
         */
        RuleEngine ruleEngine =
                new RuleEngine();

        /*
         * Register security rules
         */
        ruleEngine.addRule(
                new SuspiciousDomainRule(
                        Set.of(
                                "example.com",
                                "malware-site.com",
                                "suspicious-site.com"
                        )
                )
        );

        ruleEngine.addRule(
                new SuspiciousPortRule(
                        Set.of(
                                4444,
                                31337
                        )
                )
        );

        ruleEngine.addRule(
                new SuspiciousHttpPathRule(
                        Set.of(
                                "/admin",
                                "/login.php",
                                "/wp-admin"
                        )
                )
        );

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