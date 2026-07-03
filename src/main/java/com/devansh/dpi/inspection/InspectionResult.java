package com.devansh.dpi.inspection;

import com.devansh.dpi.model.HttpInfo;
import com.devansh.dpi.model.TlsInfo;
import com.devansh.dpi.parser.ParsedPacket;
import com.devansh.dpi.model.DNSInfo;

public class InspectionResult {

    private final ParsedPacket packet;

    private final HttpInfo httpInfo;

    private final TlsInfo tlsInfo;

    private final DNSInfo dnsInfo;

    public InspectionResult(
            ParsedPacket packet,
            HttpInfo httpInfo,
            TlsInfo tlsInfo,
            DNSInfo dnsInfo) {

        this.packet = packet;
        this.httpInfo = httpInfo;
        this.tlsInfo = tlsInfo;
        this.dnsInfo = dnsInfo;
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

    public DNSInfo getDnsInfo() {
        return dnsInfo;
    }

    public boolean hasDns() {
        return dnsInfo != null;
    }
}