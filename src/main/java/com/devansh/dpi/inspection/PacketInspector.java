package com.devansh.dpi.inspection;

import com.devansh.dpi.application.HTTPParser;
import com.devansh.dpi.application.TLSParser;
import com.devansh.dpi.model.HttpInfo;
import com.devansh.dpi.model.TlsInfo;
import com.devansh.dpi.parser.ParsedPacket;
import com.devansh.dpi.application.DNSParser;
import com.devansh.dpi.model.DNSInfo;

public class PacketInspector {

    private final HTTPParser httpParser;

    private final TLSParser tlsParser;

    private final DNSParser dnsParser;

    public PacketInspector() {

        this.httpParser = new HTTPParser();

        this.tlsParser = new TLSParser();

        this.dnsParser = new DNSParser();
    }

    public InspectionResult inspect(
            ParsedPacket packet) {

        HttpInfo httpInfo = null;

        TlsInfo tlsInfo = null;

        DNSInfo dnsInfo = null; 

        if (packet.hasTCP()) {

            byte[] payload =
                    packet.getTcpPayload();

            httpInfo =
                    httpParser.parse(payload);

            if (httpInfo == null) {

                tlsInfo =
                        tlsParser.parse(payload);
            }
        }

        if (packet.hasUDP()) {

            int sourcePort = packet.getUdpSourcePort();
            int destinationPort = packet.getUdpDestinationPort();

            boolean isDnsPort =
                    sourcePort == 53 || destinationPort == 53
                    || sourcePort == 5353 || destinationPort == 5353;

            if (isDnsPort) {
                dnsInfo = dnsParser.parse(packet.getUdpPayload());
            }
        }

        return new InspectionResult(
                packet,
                httpInfo,
                tlsInfo,
                dnsInfo
        );
    }
}