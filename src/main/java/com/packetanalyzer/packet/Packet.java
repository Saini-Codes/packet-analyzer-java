package com.packetanalyzer.packet;

public final class Packet {
    public final long tsSec; public final long tsUsec; public final byte[] data;
    public Packet(long tsSec,long tsUsec,byte[] data){this.tsSec=tsSec;this.tsUsec=tsUsec;this.data=data;}
}
