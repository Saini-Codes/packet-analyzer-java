package com.packetanalyzer.capture;

import com.packetanalyzer.packet.Packet;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Live capture adapter. Uses Pcap4J when the live-capture dependency is enabled. */
public final class LivePacketSource implements PacketSource {
    private final String interfaceName;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public LivePacketSource(String interfaceName) {
        this.interfaceName = interfaceName;
    }

    public String interfaceName() { return interfaceName; }
    public boolean isRunning() { return running.get(); }

    /**
     * Capture implementation is intentionally isolated here so the rest of the
     * analyzer stays independent from the native capture layer.
     *
     * Enable Pcap4J/Npcap and replace this method with the Pcap4J callback loop.
     */
    @Override
    public Packet next() throws IOException {
        if (!running.get()) return null;
        throw new IOException("Live capture provider is not configured. Enable Pcap4J/Npcap.");
    }

    public void start() { running.set(true); }
    public void stop() { running.set(false); }
    @Override public void close() { stop(); }
}
