package com.devansh.dpi.inspection;

import com.devansh.dpi.model.HttpInfo;
import com.devansh.dpi.model.TlsInfo;
import com.devansh.dpi.parser.ParsedPacket;

public class InspectionResult {

    private final ParsedPacket packet;

    private final HttpInfo httpInfo;

    private final TlsInfo tlsInfo;

    public InspectionResult(
            ParsedPacket packet,
            HttpInfo httpInfo,
            TlsInfo tlsInfo) {

        this.packet = packet;
        this.httpInfo = httpInfo;
        this.tlsInfo = tlsInfo;
    }

    public ParsedPacket getPacket() {
        return packet;
    }

    public HttpInfo getHttpInfo() {
        return httpInfo;
    }

    public TlsInfo getTlsInfo() {
        return tlsInfo;
    }

    public boolean hasHttp() {
        return httpInfo != null;
    }

    public boolean hasTls() {
        return tlsInfo != null;
    }
}