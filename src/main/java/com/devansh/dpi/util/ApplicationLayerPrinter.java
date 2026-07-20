
package com.devansh.dpi.util;

import com.devansh.dpi.inspection.InspectionResult;
import com.devansh.dpi.model.DNSInfo;
import com.devansh.dpi.model.HttpInfo;
import com.devansh.dpi.rule.SecurityAlert;

import java.util.List;

public class ApplicationLayerPrinter {

    private static final String SEPARATOR =
            "--------------------------------------";

    /**
     * Prints application-layer inspection results for a packet,
     * followed by any security alerts.
     */
    public void printInspection(
            InspectionResult result,
            List<SecurityAlert> alerts) {

        if (result.hasHttp()) {
            printHttp(result.getHttpInfo(), "HTTP INSPECTION");
        }

        if (result.hasTls()) {
            System.out.println("TLS INSPECTION");

            System.out.println("Content Type : "
                    + result.getTlsInfo().getContentType());

            System.out.println("TLS Version  : "
                    + result.getTlsInfo().getVersion());

            System.out.println("Record Length: "
                    + result.getTlsInfo().getRecordLength());

            if (result.getTlsInfo().hasServerName()) {
                System.out.println("SNI          : "
                        + result.getTlsInfo().getServerName());
            }

            System.out.println(SEPARATOR);
        }

        if (result.hasDns()) {
            DNSInfo dns = result.getDnsInfo();

            System.out.println("DNS INSPECTION");

            System.out.println("Transaction ID : "
                    + dns.getTransactionId());

            System.out.println("Message Type   : "
                    + (dns.isResponse() ? "Response" : "Query"));

            System.out.println("Query Name     : "
                    + dns.getQueryName());

            System.out.println("Record Type    : "
                    + dns.getRecordType());

            System.out.println("Questions      : "
                    + dns.getQuestionCount());

            System.out.println("Answers        : "
                    + dns.getAnswerCount());

            System.out.println("Response Code  : "
                    + dns.getResponseCode());

            System.out.println(SEPARATOR);
        }

        printAlerts(alerts, false);
    }

    /**
     * Prints HTTP messages reconstructed from multiple TCP segments.
     */
    public void printReassembledHttp(
            InspectionResult result,
            List<SecurityAlert> alerts) {

        System.out.println();
        System.out.println("=== REASSEMBLED HTTP INSPECTION ===");

        printHttp(result.getHttpInfo(), null);

        printAlerts(alerts, true);

        System.out.println(SEPARATOR);
    }

    private void printHttp(HttpInfo http, String heading) {
        if (heading != null) {
            System.out.println(heading);
        }

        if (http.isRequest()) {
            System.out.println("Type    : REQUEST");
        } else {
            System.out.println("Type    : RESPONSE");
        }

        System.out.println("Method  : " + http.getMethod());
        System.out.println("Path    : " + http.getPath());
        System.out.println("Host    : " + http.getHost());

        if (heading == null) {
            System.out.println("Version : " + http.getVersion());
            System.out.println("Content Length: "
                    + http.getContentLength());

            if (http.getBody() != null
                    && !http.getBody().isEmpty()) {
                System.out.println("Body    : " + http.getBody());
            }
        } else {
            System.out.println("Status  : " + http.getStatusCode());
        }

        System.out.println(SEPARATOR);
    }

    private void printAlerts(
            List<SecurityAlert> alerts,
            boolean reassembled) {

        if (alerts == null) {
            return;
        }

        for (SecurityAlert alert : alerts) {
            System.out.println(
                    reassembled
                            ? "!!! REASSEMBLY SECURITY ALERT !!!"
                            : "!!! SECURITY ALERT !!!"
            );

            System.out.println("Rule     : " + alert.getRuleName());
            System.out.println("Severity : " + alert.getSeverity());
            System.out.println("Message  : " + alert.getMessage());
            System.out.println(SEPARATOR);
        }
    }
}
