package com.devansh.dpi.tracker;

import java.util.Objects;

import com.devansh.dpi.enums.TransportProtocol;

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

    public static FlowKey fromPacket(
            String sourceIp,
            String destinationIp,
            int sourcePort,
            int destinationPort,
            TransportProtocol protocol) {

        int comparison = compareEndpoints(
                sourceIp,
                sourcePort,
                destinationIp,
                destinationPort
        );

        if (comparison <= 0) {

            return new FlowKey(
                    sourceIp,
                    destinationIp,
                    sourcePort,
                    destinationPort,
                    protocol
            );
        }

        return new FlowKey(
                destinationIp,
                sourceIp,
                destinationPort,
                sourcePort,
                protocol
        );
    }

    private static int compareEndpoints(
            String ip1,
            int port1,
            String ip2,
            int port2) {

        int ipComparison = ip1.compareTo(ip2);

        if (ipComparison != 0) {
            return ipComparison;
        }

        return Integer.compare(port1, port2);
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

        if (this == o) {
            return true;
        }

        if (!(o instanceof FlowKey flowKey)) {
            return false;
        }

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

    @Override
    public String toString() {

        return sourceIp + ":" + sourcePort +
                " <-> " +
                destinationIp + ":" + destinationPort +
                " (" + protocol + ")";
    }
}