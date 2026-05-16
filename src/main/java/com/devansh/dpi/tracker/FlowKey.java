package com.devansh.dpi.tracker;

import com.devansh.dpi.enums.TransportProtocol;

import java.util.Objects;

public final class FlowKey {

    private final String sourceIp;

    private final String destinationIp;

    private final int sourcePort;

    private final int destinationPort;

    private final TransportProtocol protocol;

    public FlowKey(
            String sourceIp,
            String destinationIp,
            int sourcePort,
            int destinationPort,
            TransportProtocol protocol) {

        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public TransportProtocol getProtocol() {
        return protocol;
    }

    @Override
    public boolean equals(Object o) {

        if (this == o)
            return true;

        if (!(o instanceof FlowKey))
            return false;

        FlowKey flowKey = (FlowKey) o;

        return sourcePort == flowKey.sourcePort &&
                destinationPort == flowKey.destinationPort &&
                Objects.equals(sourceIp, flowKey.sourceIp) &&
                Objects.equals(destinationIp, flowKey.destinationIp) &&
                protocol == flowKey.protocol;
    }

    @Override
    public int hashCode() {

        return Objects.hash(

                sourceIp,

                destinationIp,

                sourcePort,

                destinationPort,

                protocol

        );
    }

}