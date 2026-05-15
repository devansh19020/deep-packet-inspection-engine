package com.devansh.dpi.parser;

import com.devansh.dpi.enums.EtherType;
import com.devansh.dpi.model.*;
import com.devansh.dpi.util.ByteUtils;

public class EthernetParser {

    public EthernetFrame parse(
            RawPacket packet){

        byte[] data =
                packet.getData();

        String destinationMac =
                ByteUtils.readMac(data,0);

        String sourceMac =
                ByteUtils.readMac(data,6);

        EtherType etherType =
                EtherType.fromValue(
                        ByteUtils.readUnsignedShort(data, 12));

        return new EthernetFrame(
                destinationMac,
                sourceMac,
                etherType
        );
    }

}
