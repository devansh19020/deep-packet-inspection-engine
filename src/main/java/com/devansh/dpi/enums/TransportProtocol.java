package com.devansh.dpi.enums;

public enum TransportProtocol {

    ICMP(1),
    TCP(6),
    UDP(17),
    UNKNOWN(-1);

    private final int value;

    TransportProtocol(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static TransportProtocol fromValue(int value) {

        for (TransportProtocol protocol : values()) {
            if (protocol.value == value) {
                return protocol;
            }
        }

        return UNKNOWN;
    }
}