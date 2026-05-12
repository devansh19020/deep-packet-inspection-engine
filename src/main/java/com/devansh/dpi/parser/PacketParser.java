package com.devansh.dpi.parser;

import com.devansh.dpi.model.*;

public class PacketParser {

    private final EthernetParser ethernetParser =
            new EthernetParser();

    private final IPv4Parser ipv4Parser =
            new IPv4Parser();

    private final TCPParser tcpParser =
            new TCPParser();

    public ParsedPacket parse(
            RawPacket rawPacket){

        EthernetFrame ethernet =
                ethernetParser.parse(rawPacket);

        if(ethernet.getEtherType()!=0x0800){

            return null;

        }

        IPv4Packet ip =
                ipv4Parser.parse(rawPacket);

        if(ip.getProtocol()!=6){

            return null;

        }

        TCPPacket tcp =
                tcpParser.parse(rawPacket,ip);

        return new ParsedPacket(

                rawPacket,

                ethernet,

                ip,

                tcp

        );

    }

}