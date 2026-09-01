package com.packetanalyzer.capture;

import com.packetanalyzer.packet.Packet;
import java.io.Closeable;
import java.io.IOException;

public interface PacketSource extends Closeable {
    Packet next() throws IOException;
}
