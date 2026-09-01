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

    private final ExecutorService executor =
            Executors.newSingleThreadExecutor();

    private final CopyOnWriteArrayList<Consumer<String>> listeners =
            new CopyOnWriteArrayList<>();

    private final ConnectionTracker tracker =
            new ConnectionTracker();

    private final Statistics statistics =
            new Statistics();

    private volatile RuleManager rules =
            new RuleManager();

    private volatile LivePacketSource source;

    private volatile boolean running;

    private volatile long sequence;

    // ============================================================
    // START
    // ============================================================

    public synchronized void start(
            String interfaceName
    ) throws IOException {

        if (running) {
            return;
        }

        if (interfaceName == null ||
                interfaceName.isBlank()) {

            throw new IOException(
                    "Network interface is required"
            );
        }

        System.out.println(
                "Creating live packet source for: [" +
                        interfaceName +
                        "]"
        );

        LivePacketSource newSource =
                new LivePacketSource(interfaceName);

        try {

            /*
             * Open/start the actual Pcap4J capture.
             */
            newSource.start();

            source = newSource;
            running = true;

            System.out.println(
                    "Live capture started on: [" +
                            source.interfaceName() +
                            "]"
            );

            publish(
                    "{\"type\":\"status\"," +
                            "\"status\":\"CAPTURING\"," +
                            "\"interface\":\"" +
                            esc(source.interfaceName()) +
                            "\"}"
            );

            executor.submit(
                    this::captureLoop
            );

        } catch (Exception e) {

            try {
                newSource.close();
            } catch (Exception ignored) {
            }

            throw e;
        }
    }

    // ============================================================
    // CAPTURE LOOP
    // ============================================================

    private void captureLoop() {

        System.out.println(
                "Packet capture loop started."
        );

        try {

            while (running) {

                LivePacketSource current =
                        source;

                if (current == null) {
                    break;
                }

                Packet packet =
                        current.next();

                if (packet != null) {

                    process(packet);

                } else {

                    /*
                     * Avoid busy-spinning while there
                     * are temporarily no packets.
                     */
                    Thread.sleep(5);
                }
            }

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

        } catch (Exception e) {

            e.printStackTrace();

            publish(
                    "{\"type\":\"error\"," +
                            "\"message\":\"" +
                            esc(
                                    e.getMessage() == null
                                            ? "Live capture failed"
                                            : e.getMessage()
                            ) +
                            "\"}"
            );

        } finally {

            running = false;

            closeSource();

            publish(
                    "{\"type\":\"status\"," +
                            "\"status\":\"STOPPED\"}"
            );

            System.out.println(
                    "Packet capture loop stopped."
            );
        }
    }

    // ============================================================
    // PROCESS PACKET
    // ============================================================

    private void process(
            Packet packet
    ) {

        if (packet == null ||
                packet.data == null) {

            return;
        }

        try {

            statistics.total.increment();

            statistics.bytes.add(
                    packet.data.length
            );

            ParsedPacket p =
                    PacketParser.parse(
                            packet.data
                    );

            /*
             * Parser could not decode the packet.
             */
            if (p == null) {

                statistics.forwarded.increment();

                publish(
                        packetJson(
                                packet,
                                "MALFORMED",
                                "",
                                "",
                                0,
                                0,
                                "UNKNOWN",
                                "",
                                false
                        )
                );

                return;
            }

            /*
             * Non-IP packet.
             */
            if (!p.hasIp) {

                statistics.forwarded.increment();

                publish(
                        packetJson(
                                packet,
                                p.protocolName(),
                                "",
                                "",
                                0,
                                0,
                                "UNKNOWN",
                                "",
                                false
                        )
                );

                return;
            }

            /*
             * Create/find connection.
             */
            FlowKey key =
                    new FlowKey(
                            p.srcIp,
                            p.dstIp,
                            p.srcPort,
                            p.dstPort,
                            p.protocol
                    );

            Connection connection =
                    tracker.get(key);

            connection.update(
                    packet.data.length
            );

            /*
             * DPI.
             */
            DpiInspector.Result dpi =
                    DpiInspector.inspect(p);

            if (dpi.domain() != null &&
                    !dpi.domain().isEmpty()) {

                connection.domain =
                        dpi.domain();
            }

            connection.app =
                    dpi.app().name();

            /*
             * Firewall decision.
             */
            boolean blocked =
                    rules.blocked(
                            p.srcIp,
                            p.dstIp,
                            p.srcPort,
                            p.dstPort,
                            dpi.app(),
                            dpi.domain()
                    );

            connection.blocked |=
                    blocked;

            /*
             * Statistics.
             */
            statistics.app(
                    dpi.app().name()
            );

            if (blocked) {

                statistics.dropped.increment();

            } else {

                statistics.forwarded.increment();
            }

            /*
             * Publish packet to SSE listeners.
             */
            publish(
                    packetJson(
                            packet,
                            p.protocolName(),
                            p.srcIp,
                            p.dstIp,
                            p.srcPort,
                            p.dstPort,
                            dpi.app().name(),
                            dpi.domain(),
                            blocked
                    )
            );

        } catch (Exception e) {

            /*
             * One malformed/problematic packet should
             * never terminate the entire capture.
             */
            System.err.println(
                    "Packet processing error: " +
                            e.getMessage()
            );
        }
    }

    // ============================================================
    // PACKET JSON
    // ============================================================

    private String packetJson(
            Packet packet,
            String protocol,
            String src,
            String dst,
            int sport,
            int dport,
            String app,
            String domain,
            boolean blocked
    ) {

        long id =
                ++sequence;

        long timestamp =
                packet.tsSec * 1000L
                        + packet.tsUsec / 1000L;

        String source =
                src == null
                        ? ""
                        : src;

        if (sport > 0) {
            source += ":" + sport;
        }

        String destination =
                dst == null
                        ? ""
                        : dst;

        if (dport > 0) {
            destination += ":" + dport;
        }

        return "{"
                + "\"type\":\"packet\","
                + "\"id\":" + id + ","
                + "\"timestamp\":" + timestamp + ","
                + "\"protocol\":\"" + esc(protocol) + "\","
                + "\"source\":\"" + esc(source) + "\","
                + "\"destination\":\"" + esc(destination) + "\","
                + "\"bytes\":" + packet.data.length + ","
                + "\"application\":\"" + esc(app) + "\","
                + "\"domain\":\"" + esc(domain) + "\","
                + "\"blocked\":" + blocked
                + "}";
    }

    // ============================================================
    // STOP
    // ============================================================

    public synchronized void stop() {

        if (!running &&
                source == null) {
            return;
        }

        System.out.println(
                "Stopping live capture..."
        );

        running = false;

        closeSource();

        publish(
                "{\"type\":\"status\"," +
                        "\"status\":\"STOPPED\"}"
        );
    }

    // ============================================================
    // CLOSE SOURCE
    // ============================================================

    private synchronized void closeSource() {

        LivePacketSource current =
                source;

        source = null;

        if (current != null) {

            try {
                current.close();
            } catch (Exception e) {

                System.err.println(
                        "Error closing capture source: " +
                                e.getMessage()
                );
            }
        }
    }

    // ============================================================
    // STATUS
    // ============================================================

    public boolean isRunning() {
        return running;
    }

    public String interfaceName() {

        LivePacketSource current =
                source;

        return current == null
                ? null
                : current.interfaceName();
    }

    // ============================================================
    // ACCESSORS
    // ============================================================

    public Statistics statistics() {
        return statistics;
    }

    public ConnectionTracker tracker() {
        return tracker;
    }

    public void setRules(
            RuleManager rules
    ) {

        this.rules =
                rules == null
                        ? new RuleManager()
                        : rules;
    }

    // ============================================================
    // SSE LISTENERS
    // ============================================================

    public void addListener(
            Consumer<String> listener
    ) {

        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(
            Consumer<String> listener
    ) {

        if (listener != null) {
            listeners.remove(listener);
        }
    }

    private void publish(
            String json
    ) {

        for (
                Consumer<String> listener :
                listeners
        ) {

            try {

                listener.accept(json);

            } catch (Exception e) {

                /*
                 * A disconnected browser must not
                 * stop packet capture.
                 */
            }
        }
    }

    // ============================================================
    // JSON ESCAPE
    // ============================================================

    private static String esc(
            String value
    ) {

        if (value == null) {
            return "";
        }

        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", " ")
                .replace("\r", " ");
    }

    // ============================================================
    // CLOSE
    // ============================================================

    @Override
    public void close() {

        stop();

        executor.shutdownNow();

        listeners.clear();
    }
}