package com.devansh.dpi.model;


public class TCPPacket {

    private final int sourcePort;

    private final int destinationPort;

    private final long sequenceNumber;

    private final long acknowledgementNumber;

    private final int headerLength;

    private final int flags;

    private final int payloadOffset;

    public TCPPacket(
            int sourcePort,
            int destinationPort,
            long sequenceNumber,
            long acknowledgementNumber,
            int headerLength,
            int flags,
            int payloadOffset) {

        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.sequenceNumber = sequenceNumber;
        this.acknowledgementNumber = acknowledgementNumber;
        this.headerLength = headerLength;
        this.flags = flags;
        this.payloadOffset = payloadOffset;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public long getAcknowledgementNumber() {
        return acknowledgementNumber;
    }

    public int getHeaderLength() {
        return headerLength;
    }

    public int getFlags() {
        return flags;
    }

    public int getPayloadOffset() {
        return payloadOffset;
    }
}