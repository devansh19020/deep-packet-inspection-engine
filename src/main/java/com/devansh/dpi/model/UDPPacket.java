package com.devansh.dpi.model;

public class UDPPacket {

    private final int sourcePort;
    private final int destinationPort;
    private final int length;
    private final int checksum;
    private final int payloadOffset;

    public UDPPacket(
            int sourcePort,
            int destinationPort,
            int length,
            int checksum,
            int payloadOffset) {

        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.length = length;
        this.checksum = checksum;
        this.payloadOffset = payloadOffset;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public int getLength() {
        return length;
    }

    public int getChecksum() {
        return checksum;
    }

    public int getPayloadOffset() {
        return payloadOffset;
    }

    public int getPayloadLength() {
        return length - 8;
    }
}