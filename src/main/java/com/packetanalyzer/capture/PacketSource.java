package com.packetanalyzer.capture;

import com.packetanalyzer.packet.Packet;

import java.io.Closeable;
import java.io.IOException;

/** Common source abstraction for offline PCAP and live capture. */
public interface PacketSource extends Closeable {
    Packet next() throws IOException;
}
