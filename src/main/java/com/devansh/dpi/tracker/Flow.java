package com.devansh.dpi.tracker;

public class Flow {

    private final FlowKey key;

    private long packetCount;

    private long totalBytes;

    private final long startTime;

    private long lastSeen;

    public Flow(
            FlowKey key,
            long timestamp,
            int packetLength) {

        this.key = key;

        this.packetCount = 1;

        this.totalBytes = packetLength;

        this.startTime = timestamp;

        this.lastSeen = timestamp;
    }

    public void update(
            long timestamp,
            int packetLength) {

        packetCount++;

        totalBytes += packetLength;

        lastSeen = timestamp;
    }

    public FlowKey getKey() {
        return key;
    }

    public long getPacketCount() {
        return packetCount;
    }

    public long getTotalBytes() {
        return totalBytes;
    }

    public long getStartTime() {
        return startTime;
    }

    public long getLastSeen() {
        return lastSeen;
    }

}