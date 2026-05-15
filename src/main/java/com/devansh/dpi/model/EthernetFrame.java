package com.devansh.dpi.model;


import com.devansh.dpi.enums.EtherType;

public class EthernetFrame {

    private final String destinationMac;

    private final String sourceMac;

    private final EtherType etherType;

    public EthernetFrame(
            String destinationMac,
            String sourceMac,
            EtherType etherType) {

        this.destinationMac = destinationMac;
        this.sourceMac = sourceMac;
        this.etherType = etherType;
    }

    public String getDestinationMac() {
        return destinationMac;
    }

    public String getSourceMac() {
        return sourceMac;
    }

    public EtherType getEtherType() {
        return etherType;
    }

}
