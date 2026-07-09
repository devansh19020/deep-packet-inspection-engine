package com.devansh.dpi.model;

import com.devansh.dpi.tracker.FlowKey;

public class TCPStreamData {

    private final FlowKey flowKey;
    private final boolean forwardDirection;
    private final long startingSequenceNumber;
    private final byte[] data;

    public TCPStreamData(
            FlowKey flowKey,
            boolean forwardDirection,
            long startingSequenceNumber,
            byte[] data) {

        this.flowKey = flowKey;
        this.forwardDirection = forwardDirection;
        this.startingSequenceNumber = startingSequenceNumber;
        this.data = data.clone();
    }

    public FlowKey getFlowKey() {
        return flowKey;
    }

    public boolean isForwardDirection() {
        return forwardDirection;
    }

    public long getStartingSequenceNumber() {
        return startingSequenceNumber;
    }

    public byte[] getData() {
        return data.clone();
    }

    public int getLength() {
        return data.length;
    }
}