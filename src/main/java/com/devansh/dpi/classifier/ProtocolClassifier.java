package com.devansh.dpi.classifier;

import com.devansh.dpi.enums.ApplicationProtocol;
import com.devansh.dpi.tracker.Flow;

public class ProtocolClassifier {

    public ApplicationProtocol classify(Flow flow) {

        int sourcePort = flow.getKey().getSourcePort();
        int destinationPort = flow.getKey().getDestinationPort();

        return classifyPorts(sourcePort, destinationPort);
    }

    private ApplicationProtocol classifyPorts(
            int sourcePort,
            int destinationPort) {

        if (sourcePort == 80 || destinationPort == 80) {
            return ApplicationProtocol.HTTP;
        }

        if (sourcePort == 443 || destinationPort == 443) {
            return ApplicationProtocol.HTTPS;
        }

        if (sourcePort == 53 || destinationPort == 53) {
            return ApplicationProtocol.DNS;
        }

        if (sourcePort == 22 || destinationPort == 22) {
            return ApplicationProtocol.SSH;
        }

        if (sourcePort == 21 || destinationPort == 21) {
            return ApplicationProtocol.FTP;
        }

        if (sourcePort == 25 || destinationPort == 25) {
            return ApplicationProtocol.SMTP;
        }

        return ApplicationProtocol.UNKNOWN;
    }
}