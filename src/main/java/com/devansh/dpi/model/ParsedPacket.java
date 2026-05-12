package com.devansh.dpi.model;

import java.util.Arrays;

public class ParsedPacket {

    private final RawPacket rawPacket;

    private final EthernetFrame ethernetFrame;

    private final IPv4Packet ipv4Packet;

    private final TCPPacket tcpPacket;

    public ParsedPacket(
            RawPacket rawPacket,
            EthernetFrame ethernetFrame,
            IPv4Packet ipv4Packet,
            TCPPacket tcpPacket) {

        this.rawPacket = rawPacket;
        this.ethernetFrame = ethernetFrame;
        this.ipv4Packet = ipv4Packet;
        this.tcpPacket = tcpPacket;
    }

    /*
        Original Parsed Objects
     */

    public RawPacket getRawPacket() {
        return rawPacket;
    }

    public EthernetFrame getEthernetFrame() {
        return ethernetFrame;
    }

    public IPv4Packet getIpv4Packet() {
        return ipv4Packet;
    }

    public TCPPacket getTcpPacket() {
        return tcpPacket;
    }

    /*
        Ethernet Convenience Methods
     */

    public String getSourceMac() {
        return ethernetFrame.getSourceMac();
    }

    public String getDestinationMac() {
        return ethernetFrame.getDestinationMac();
    }

    public int getEtherType() {
        return ethernetFrame.getEtherType();
    }

    /*
        IPv4 Convenience Methods
     */

    public String getSourceIp() {
        return ipv4Packet.getSourceIp();
    }

    public String getDestinationIp() {
        return ipv4Packet.getDestinationIp();
    }

    public int getProtocol() {
        return ipv4Packet.getProtocol();
    }

    public int getTTL() {
        return ipv4Packet.getTtl();
    }

    /*
        TCP Convenience Methods
     */

    public int getSourcePort() {
        return tcpPacket.getSourcePort();
    }

    public int getDestinationPort() {
        return tcpPacket.getDestinationPort();
    }

    public long getSequenceNumber() {
        return tcpPacket.getSequenceNumber();
    }

    public long getAcknowledgementNumber() {
        return tcpPacket.getAcknowledgementNumber();
    }

    public int getTcpHeaderLength() {
        return tcpPacket.getHeaderLength();
    }

    public int getPayloadOffset() {
        return tcpPacket.getPayloadOffset();
    }

    /*
        Protocol Helpers
     */

    public boolean isTCP() {
        return getProtocol() == 6;
    }

    public boolean isUDP() {
        return getProtocol() == 17;
    }

    public boolean isIPv4() {
        return getEtherType() == 0x0800;
    }

    /*
        Payload
     */

    public byte[] getPayload() {

        byte[] data = rawPacket.getData();

        return Arrays.copyOfRange(
                data,
                getPayloadOffset(),
                data.length
        );
    }

}