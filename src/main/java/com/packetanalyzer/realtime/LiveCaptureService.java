package com.packetanalyzer.realtime;

import com.packetanalyzer.capture.LivePacketSource;
import com.packetanalyzer.dpi.DpiInspector;
import com.packetanalyzer.firewall.RuleManager;
import com.packetanalyzer.flow.Connection;
import com.packetanalyzer.flow.ConnectionTracker;
import com.packetanalyzer.flow.FlowKey;
import com.packetanalyzer.packet.Packet;
import com.packetanalyzer.packet.PacketParser;
import com.packetanalyzer.packet.ParsedPacket;
import com.packetanalyzer.stats.Statistics;

import java.io.IOException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public final class LiveCaptureService implements AutoCloseable {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final CopyOnWriteArrayList<Consumer<String>> listeners = new CopyOnWriteArrayList<>();
    private final ConnectionTracker tracker = new ConnectionTracker();
    private final Statistics statistics = new Statistics();
    private volatile RuleManager rules = new RuleManager();
    private volatile LivePacketSource source;
    private volatile boolean running;
    private volatile long sequence;

    public synchronized void start(String interfaceName) throws IOException {
        if (running) return;
        source = new LivePacketSource(interfaceName);
        running = true;
        executor.submit(this::captureLoop);
        publish("{\"type\":\"status\",\"status\":\"CAPTURING\",\"interface\":\"" + esc(source.interfaceName()) + "\"}");
    }

    private void captureLoop() {
        try {
            while (running) {
                Packet packet = source.next();
                if (packet != null) process(packet);
            }
        } catch (Exception e) {
            publish("{\"type\":\"error\",\"message\":\"" + esc(e.getMessage()) + "\"}");
        } finally {
            running = false;
            closeSource();
            publish("{\"type\":\"status\",\"status\":\"STOPPED\"}");
        }
    }

    private void process(Packet packet) {
        statistics.total.increment();
        statistics.bytes.add(packet.data.length);
        ParsedPacket p = PacketParser.parse(packet.data);
        if (p == null) {
            statistics.forwarded.increment();
            publish(packetJson(packet, "MALFORMED", "", "", 0, 0, "UNKNOWN", "", false));
            return;
        }
        if (!p.hasIp) {
            statistics.forwarded.increment();
            publish(packetJson(packet, p.protocolName(), "", "", 0, 0, "UNKNOWN", "", false));
            return;
        }
        FlowKey key = new FlowKey(p.srcIp, p.dstIp, p.srcPort, p.dstPort, p.protocol);
        Connection c = tracker.get(key);
        c.update(packet.data.length);
        DpiInspector.Result dpi = DpiInspector.inspect(p);
        if (!dpi.domain().isEmpty()) c.domain = dpi.domain();
        c.app = dpi.app().name();
        boolean blocked = rules.blocked(p.srcIp, p.dstIp, p.srcPort, p.dstPort, dpi.app(), dpi.domain());
        c.blocked |= blocked;
        statistics.app(dpi.app().name());
        if (blocked) statistics.dropped.increment(); else statistics.forwarded.increment();
        publish(packetJson(packet, p.protocolName(), p.srcIp, p.dstIp, p.srcPort, p.dstPort, dpi.app().name(), dpi.domain(), blocked));
    }

    private String packetJson(Packet packet, String protocol, String src, String dst, int sport, int dport, String app, String domain, boolean blocked) {
        long id = ++sequence;
        return "{\"type\":\"packet\",\"id\":" + id + ",\"timestamp\":" + (packet.tsSec * 1000L + packet.tsUsec / 1000L)
                + ",\"protocol\":\"" + esc(protocol) + "\",\"source\":\"" + esc(src) + (sport > 0 ? ":" + sport : "")
                + "\",\"destination\":\"" + esc(dst) + (dport > 0 ? ":" + dport : "")
                + "\",\"bytes\":" + packet.data.length + ",\"application\":\"" + esc(app)
                + "\",\"domain\":\"" + esc(domain) + "\",\"blocked\":" + blocked + "}";
    }

    public synchronized void stop() {
        running = false;
        closeSource();
    }

    private void closeSource() { try { if (source != null) source.close(); } catch (Exception ignored) {} source = null; }
    public boolean isRunning() { return running; }
    public String interfaceName() { return source == null ? null : source.interfaceName(); }
    public Statistics statistics() { return statistics; }
    public ConnectionTracker tracker() { return tracker; }
    public void setRules(RuleManager rules) { this.rules = rules == null ? new RuleManager() : rules; }
    public void addListener(Consumer<String> listener) { listeners.add(listener); }
    public void removeListener(Consumer<String> listener) { listeners.remove(listener); }
    private void publish(String json) { for (Consumer<String> l : listeners) try { l.accept(json); } catch (Exception ignored) {} }
    private static String esc(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " "); }
    @Override public void close() { stop(); executor.shutdownNow(); }
}
