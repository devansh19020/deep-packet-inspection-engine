package com.devansh.dpi.model;

public class PcapGlobalHeader {

    private final int magicNumber;
    private final short versionMajor;
    private final short versionMinor;
    private final int thisZone;
    private final int sigFigs;
    private final int snapLen;
    private final int network;

    public PcapGlobalHeader(
            int magicNumber,
            short versionMajor,
            short versionMinor,
            int thisZone,
            int sigFigs,
            int snapLen,
            int network) {

        this.magicNumber = magicNumber;
        this.versionMajor = versionMajor;
        this.versionMinor = versionMinor;
        this.thisZone = thisZone;
        this.sigFigs = sigFigs;
        this.snapLen = snapLen;
        this.network = network;
    }

    public int getMagicNumber() {
        return magicNumber;
    }

    public short getVersionMajor() {
        return versionMajor;
    }

    public short getVersionMinor() {
        return versionMinor;
    }

    public int getSnapLen() {
        return snapLen;
    }

    public int getNetwork() {
        return network;
    }
}