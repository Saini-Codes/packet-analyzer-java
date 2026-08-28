package com.packetanalyzer.packet;
public final class ParsedPacket { public String srcMac,dstMac,srcIp,dstIp; public int etherType,ipVersion,protocol,ttl,srcPort,dstPort,tcpFlags; public boolean hasIp,hasTcp,hasUdp; public int payloadOffset,payloadLength; public byte[] raw; public String protocolName(){return switch(protocol){case 6->"TCP";case 17->"UDP";case 1->"ICMP";default->"OTHER";};} }
