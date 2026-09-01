package com.packetanalyzer.realtime;

import com.packetanalyzer.packet.ParsedPacket;
import com.packetanalyzer.packet.Packet;

public record PacketEvent(
        long timestampMillis,
        String protocol,
        String sourceIp,
        int sourcePort,
        String destinationIp,
        int destinationPort,
        int length,
        String application,
        String domain,
        boolean blocked) {
    public static PacketEvent from(Packet p, ParsedPacket x, String app, String domain, boolean blocked) {
        return new PacketEvent(
                p.tsSec * 1000L + p.tsUsec / 1000L,
                x.protocolName(), x.srcIp, x.srcPort, x.dstIp, x.dstPort,
                p.data.length, app == null ? "UNKNOWN" : app,
                domain == null ? "" : domain, blocked);
    }
}
