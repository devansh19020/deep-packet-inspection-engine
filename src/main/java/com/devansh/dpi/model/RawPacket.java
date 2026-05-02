package com.devansh.dpi.model;

public class RawPacket {

    private final PcapPacketHeader header;

    private final byte[] data;

    public RawPacket(PcapPacketHeader header, byte[] data) {
        this.header = header;
        this.data = data;
    }

    public PcapPacketHeader getHeader() {
        return header;
    }

    public byte[] getData() {
        return data;
    }
}
