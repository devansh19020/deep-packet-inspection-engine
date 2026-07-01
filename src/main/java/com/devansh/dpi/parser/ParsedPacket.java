package com.devansh.dpi.parser;

import java.util.Arrays;

import com.devansh.dpi.enums.TransportProtocol;
import com.devansh.dpi.model.EthernetFrame;
import com.devansh.dpi.model.IPv4Packet;
import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.model.TCPPacket;
import com.devansh.dpi.model.UDPPacket;

public class ParsedPacket {

    private final RawPacket rawPacket;

    private EthernetFrame ethernetFrame;

    private IPv4Packet ipv4Packet;

    private TCPPacket tcpPacket;

    private UDPPacket udpPacket;

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

    public UDPPacket getUdpPacket() {
        return udpPacket;
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

    void setUdpPacket(UDPPacket udpPacket) {
        this.udpPacket = udpPacket;
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

    public byte[] getTcpPayload() {

        if (!hasTCP()) {
            return new byte[0];
        }

        byte[] data = rawPacket.getData();

        int payloadOffset =
                tcpPacket.getPayloadOffset();

        if (payloadOffset < 0 ||
                payloadOffset > data.length) {

            return new byte[0];
        }

        return Arrays.copyOfRange(
                data,
                payloadOffset,
                data.length
        );
    }

    public boolean hasUDP() {
        return udpPacket != null;
    }

    public int getUdpSourcePort() {
        return udpPacket.getSourcePort();
    }

    public int getUdpDestinationPort() {
        return udpPacket.getDestinationPort();
    }

    public byte[] getUdpPayload() {

        if (!hasUDP()) {
            return new byte[0];
        }

        byte[] data = rawPacket.getData();

        int offset = udpPacket.getPayloadOffset();

        if (offset < 0 || offset > data.length) {
            return new byte[0];
        }

        int declaredLength = udpPacket.getPayloadLength();

        int availableLength = data.length - offset;

        int payloadLength = Math.min(
                declaredLength,
                availableLength
        );

        return Arrays.copyOfRange(
                data,
                offset,
                offset + payloadLength
        );
    }    
}