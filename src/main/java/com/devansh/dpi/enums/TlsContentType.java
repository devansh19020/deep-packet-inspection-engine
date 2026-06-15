package com.devansh.dpi.enums;

public enum TlsContentType {

    CHANGE_CIPHER_SPEC(20),
    ALERT(21),
    HANDSHAKE(22),
    APPLICATION_DATA(23),
    UNKNOWN(-1);

    private final int value;

    TlsContentType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static TlsContentType fromValue(int value) {

        for (TlsContentType type : values()) {

            if (type.value == value) {
                return type;
            }
        }

        return UNKNOWN;
    }
}