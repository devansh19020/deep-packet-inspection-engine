package com.devansh.dpi.inspection;

import com.devansh.dpi.application.HTTPParser;
import com.devansh.dpi.application.TLSParser;
import com.devansh.dpi.model.HttpInfo;
import com.devansh.dpi.model.TlsInfo;
import com.devansh.dpi.parser.ParsedPacket;

public class PacketInspector {

    private final HTTPParser httpParser;

    private final TLSParser tlsParser;

    public PacketInspector() {

        this.httpParser = new HTTPParser();

        this.tlsParser = new TLSParser();
    }

    public InspectionResult inspect(
            ParsedPacket packet) {

        HttpInfo httpInfo = null;

        TlsInfo tlsInfo = null;

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

        return new InspectionResult(
                packet,
                httpInfo,
                tlsInfo
        );
    }
}