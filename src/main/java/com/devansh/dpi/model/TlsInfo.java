package com.devansh.dpi.model;

import com.devansh.dpi.enums.TlsContentType;

public class TlsInfo {

    private final TlsContentType contentType;

    private final int majorVersion;

    private final int minorVersion;

    private final int recordLength;

    private final String serverName;


    public TlsInfo(
            TlsContentType contentType,
            int majorVersion,
            int minorVersion,
            int recordLength,
            String serverName) {

        this.contentType = contentType;
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
        this.recordLength = recordLength;
        this.serverName = serverName;
    }


    public TlsContentType getContentType() {
        return contentType;
    }

    public int getMajorVersion() {
        return majorVersion;
    }

    public int getMinorVersion() {
        return minorVersion;
    }

    public int getRecordLength() {
        return recordLength;
    }

    public String getServerName() {
        return serverName;
    }

    public boolean hasServerName() {
        return serverName != null &&
                !serverName.isBlank();
    }


    public String getVersion() {

        if (majorVersion != 3) {
            return "UNKNOWN";
        }

        return switch (minorVersion) {

            case 0 -> "SSL 3.0";
            case 1 -> "TLS 1.0";
            case 2 -> "TLS 1.1";
            case 3 -> "TLS 1.2";
            case 4 -> "TLS 1.3";
            default -> "UNKNOWN";
        };
    }
}