package com.packetanalyzer.capture;

import com.packetanalyzer.packet.Packet;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeoutException;

public final class LivePacketSource implements PacketSource {
    private final String interfaceName;
    private PcapHandle handle;

    public LivePacketSource(String interfaceName) throws IOException {
        this.interfaceName = interfaceName;
        try {
            PcapNetworkInterface nif = find(interfaceName);
            if (nif == null) throw new IOException("Network interface not found: " + interfaceName);
            handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 100);
        } catch (PcapNativeException e) {
            throw new IOException("Unable to open capture interface. Install Npcap/libpcap and run with capture permissions: " + e.getMessage(), e);
        }
    }

    private static PcapNetworkInterface find(String requested) throws PcapNativeException {
        List<PcapNetworkInterface> all = Pcaps.findAllDevs();
        if (requested == null || requested.isBlank()) {
            return all.stream().filter(n -> !n.isLoopBack()).findFirst().orElse(all.isEmpty() ? null : all.get(0));
        }
        for (PcapNetworkInterface n : all) {
            if (requested.equals(n.getName()) || requested.equals(n.getDescription())) return n;
        }
        return null;
    }

    @Override
    public Packet next() throws IOException {
        if (handle == null || !handle.isOpen()) return null;
        try {
            org.pcap4j.packet.Packet p = handle.getNextPacketEx();
            if (p == null) return null;
            long now = System.currentTimeMillis();
            return new Packet(now / 1000L, (now % 1000L) * 1000L, p.getRawData());
        } catch (TimeoutException e) {
            return null;
        } catch (Exception e) {
            throw new IOException("Live capture failed: " + e.getMessage(), e);
        }
    }

    public String interfaceName() { return interfaceName; }
    @Override public void close() { if (handle != null) handle.close(); }
}
