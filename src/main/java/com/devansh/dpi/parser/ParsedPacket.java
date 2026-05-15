package com.devansh.dpi.parser;

import com.devansh.dpi.enums.TransportProtocol;
import com.devansh.dpi.model.EthernetFrame;
import com.devansh.dpi.model.IPv4Packet;
import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.model.TCPPacket;

import java.util.Arrays;

public class ParsedPacket {

    private final RawPacket rawPacket;

    private EthernetFrame ethernetFrame;

    private IPv4Packet ipv4Packet;

    private TCPPacket tcpPacket;


    public ParsedPacket(RawPacket rawPacket) {
        this.rawPacket = rawPacket;
    }


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


    public void setEthernetFrame(EthernetFrame ethernetFrame) {
        this.ethernetFrame = ethernetFrame;
    }

    public void setIpv4Packet(IPv4Packet ipv4Packet) {
        this.ipv4Packet = ipv4Packet;
    }

    void setTcpPacket(TCPPacket tcpPacket) {
        this.tcpPacket = tcpPacket;
    }


    public boolean hasEthernet() {
        return ethernetFrame != null;
    }

    public String getSourceMac() {
        return ethernetFrame.getSourceMac();
    }

    public String getDestinationMac() {
        return ethernetFrame.getDestinationMac();
    }


    public boolean hasIPv4() {
        return ipv4Packet != null;
    }

    public String getSourceIp() {
        return ipv4Packet.getSourceIp();
    }

    public String getDestinationIp() {
        return ipv4Packet.getDestinationIp();
    }

    public TransportProtocol getProtocol() {
        return ipv4Packet.getProtocol();
    }

    public int getTTL() {
        return ipv4Packet.getTtl();
    }


    public boolean hasTCP() {
        return tcpPacket != null;
    }

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

    public int getPayloadOffset() {
        return tcpPacket.getPayloadOffset();
    }


    public boolean isTCP() {
        return hasIPv4() &&
                getProtocol() == TransportProtocol.TCP;
    }

    public boolean isUDP() {
        return hasIPv4() &&
                getProtocol() == TransportProtocol.UDP;
    }

    public byte[] getPayload() {

        if (!hasTCP()) {
            return new byte[0];
        }

        byte[] data = rawPacket.getData();

        return Arrays.copyOfRange(
                data,
                tcpPacket.getPayloadOffset(),
                data.length
        );
    }

}