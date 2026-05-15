package com.devansh.dpi.model;


import com.devansh.dpi.enums.TransportProtocol;

public class IPv4Packet {

    private final int version;

    private final int headerLength;

    private final int ttl;

    private final TransportProtocol protocol;

    private final String sourceIp;

    private final String destinationIp;

    public IPv4Packet(
            int version,
            int headerLength,
            int ttl,
            TransportProtocol protocol,
            String sourceIp,
            String destinationIp) {

        this.version = version;
        this.headerLength = headerLength;
        this.ttl = ttl;
        this.protocol = protocol;
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
    }

    public int getVersion() {
        return version;
    }

    public int getHeaderLength() {
        return headerLength;
    }

    public int getTtl() {
        return ttl;
    }

    public TransportProtocol getProtocol() {
        return protocol;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

}
