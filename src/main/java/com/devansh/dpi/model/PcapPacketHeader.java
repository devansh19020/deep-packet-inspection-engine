package com.devansh.dpi.model;


public class PcapPacketHeader {

    private final long timestampSeconds;
    private final long timestampMicros;
    private final int capturedLength;
    private final int originalLength;

    public PcapPacketHeader(
            long timestampSeconds,
            long timestampMicros,
            int capturedLength,
            int originalLength) {

        this.timestampSeconds = timestampSeconds;
        this.timestampMicros = timestampMicros;
        this.capturedLength = capturedLength;
        this.originalLength = originalLength;
    }

    public long getTimestampSeconds() {
        return timestampSeconds;
    }

    public long getTimestampMicros() {
        return timestampMicros;
    }

    public int getCapturedLength() {
        return capturedLength;
    }

    public int getOriginalLength() {
        return originalLength;
    }
}
