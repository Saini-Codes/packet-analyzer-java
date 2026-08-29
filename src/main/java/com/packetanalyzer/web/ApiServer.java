package com.packetanalyzer.web;

import com.packetanalyzer.capture.PcapReader;
import com.packetanalyzer.dpi.DpiInspector;
import com.packetanalyzer.firewall.RuleManager;
import com.packetanalyzer.flow.Connection;
import com.packetanalyzer.flow.ConnectionTracker;
import com.packetanalyzer.flow.FlowKey;
import com.packetanalyzer.packet.Packet;
import com.packetanalyzer.packet.ParsedPacket;
import com.packetanalyzer.packet.PacketParser;
import com.packetanalyzer.stats.Statistics;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public final class ApiServer {
    private static final int PORT = 8080;
    private ApiServer() {}

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : PORT;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/health", ApiServer::health);
        server.createContext("/api/sample", ApiServer::sample);
        server.createContext("/api/analyze", ApiServer::analyze);
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("Packet Analyzer API running at http://localhost:" + port);
    }

    private static void headers(HttpExchange ex) {
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    }

    private static void health(HttpExchange ex) throws IOException {
        if (options(ex)) return;
        send(ex, 200, "{\"status\":\"online\",\"service\":\"packet-analyzer-java\"}");
    }

    private static void sample(HttpExchange ex) throws IOException {
        if (options(ex)) return;
        Path p = Paths.get("test.pcap");
        if (!Files.exists(p)) { send(ex, 404, "{\"error\":\"test.pcap not found\"}"); return; }
        send(ex, 200, analyzeFile(p, new RuleManager()));
    }

    private static void analyze(HttpExchange ex) throws IOException {
        if (options(ex)) return;
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { send(ex, 405, "{\"error\":\"POST required\"}"); return; }
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Matcher m = Pattern.compile("\\\"data\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"").matcher(body);
        if (!m.find()) { send(ex, 400, "{\"error\":\"Request must contain base64 PCAP data\"}"); return; }
        byte[] data;
        try { data = Base64.getDecoder().decode(m.group(1)); }
        catch (IllegalArgumentException e) { send(ex, 400, "{\"error\":\"Invalid base64 data\"}"); return; }
        RuleManager rules = rulesFrom(body);
        Path tmp = Files.createTempFile("packet-analyzer-", ".pcap");
        try { Files.write(tmp, data); send(ex, 200, analyzeFile(tmp, rules)); }
        catch (Exception e) { send(ex, 400, jsonError(e.getMessage())); }
        finally { Files.deleteIfExists(tmp); }
    }

    private static RuleManager rulesFrom(String body) {
        RuleManager r = new RuleManager();
        addStrings(body, "blockIps", r::blockIp);
        addStrings(body, "blockDomains", r::blockDomain);
        addStrings(body, "blockPorts", x -> { try { r.blockPort(Integer.parseInt(x)); } catch (Exception ignored) {} });
        return r;
    }

    private static void addStrings(String body, String key, java.util.function.Consumer<String> consumer) {
        Matcher a = Pattern.compile("\\\"" + key + "\\\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(body);
        if (!a.find()) return;
        Matcher v = Pattern.compile("\\\"([^\\\"]*)\\\"").matcher(a.group(1));
        while (v.find()) consumer.accept(v.group(1));
    }

    private static String analyzeFile(Path file, RuleManager rules) throws Exception {
        Statistics st = new Statistics();
        ConnectionTracker tracker = new ConnectionTracker();
        List<String> packets = new ArrayList<>();
        try (PcapReader reader = new PcapReader(file.toString())) {
            Packet packet;
            int id = 0;
            while ((packet = reader.next()) != null) {
                id++;
                st.total.increment(); st.bytes.add(packet.data.length);
                ParsedPacket p = PacketParser.parse(packet.data);
                if (p == null) { st.forwarded.increment(); packets.add(packetJson(id, "MALFORMED", "", "", 0, 0, packet.data.length, "UNKNOWN", "", false)); continue; }
                if (!p.hasIp) { st.forwarded.increment(); packets.add(packetJson(id, p.protocolName(), "", "", 0, 0, packet.data.length, "UNKNOWN", "", false)); continue; }
                FlowKey key = new FlowKey(p.srcIp, p.dstIp, p.srcPort, p.dstPort, p.protocol);
                Connection c = tracker.get(key); c.update(packet.data.length);
                DpiInspector.Result dpi = DpiInspector.inspect(p);
                if (!dpi.domain().isEmpty()) c.domain = dpi.domain();
                c.app = dpi.app().name();
                boolean blocked = rules.blocked(p.srcIp, p.dstIp, p.srcPort, p.dstPort, dpi.app(), dpi.domain());
                c.blocked |= blocked; st.app(dpi.app().name());
                if (blocked) st.dropped.increment(); else st.forwarded.increment();
                packets.add(packetJson(id, p.protocolName(), p.srcIp, p.dstIp, p.srcPort, p.dstPort, packet.data.length, dpi.app().name(), dpi.domain(), blocked));
            }
        }
        StringBuilder flows = new StringBuilder("[");
        boolean first = true;
        for (Connection c : tracker.all()) {
            if (!first) flows.append(','); first = false;
            flows.append("{\"source\":\"").append(esc(c.key.src())).append(':').append(c.key.sport())
                 .append("\",\"destination\":\"").append(esc(c.key.dst())).append(':').append(c.key.dport())
                 .append("\",\"protocol\":\"").append(protocol(c.key.protocol())).append("\",\"packets\":").append(c.packets)
                 .append(",\"bytes\":").append(c.bytes).append(",\"application\":\"").append(esc(c.app))
                 .append("\",\"domain\":\"").append(esc(c.domain)).append("\",\"blocked\":").append(c.blocked).append('}');
        }
        flows.append(']');
        StringBuilder apps = new StringBuilder("{"); first = true;
        for (var e : st.apps.entrySet()) { if (!first) apps.append(','); first = false; apps.append("\"").append(esc(e.getKey())).append("\":").append(e.getValue().sum()); }
        apps.append('}');
        return "{\"summary\":{\"packets\":" + st.total.sum() + ",\"bytes\":" + st.bytes.sum() + ",\"forwarded\":" + st.forwarded.sum() + ",\"dropped\":" + st.dropped.sum() + ",\"flows\":" + tracker.size() + "},\"applications\":" + apps + ",\"packets\":[" + String.join(",", packets) + "],\"flows\":" + flows + "}";
    }

    private static String packetJson(int id, String protocol, String src, String dst, int sport, int dport, int bytes, String app, String domain, boolean blocked) {
        return "{\"id\":" + id + ",\"protocol\":\"" + esc(protocol) + "\",\"source\":\"" + esc(src) + (sport > 0 ? ":" + sport : "") + "\",\"destination\":\"" + esc(dst) + (dport > 0 ? ":" + dport : "") + "\",\"bytes\":" + bytes + ",\"application\":\"" + esc(app) + "\",\"domain\":\"" + esc(domain) + "\",\"blocked\":" + blocked + "}";
    }

    private static String protocol(int n) { return switch (n) { case 6 -> "TCP"; case 17 -> "UDP"; case 1 -> "ICMP"; default -> "OTHER"; }; }
    private static String esc(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\""); }
    private static String jsonError(String s) { return "{\"error\":\"" + esc(s == null ? "Analysis failed" : s) + "\"}"; }
    private static boolean options(HttpExchange ex) throws IOException { if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) { headers(ex); ex.sendResponseHeaders(204, -1); ex.close(); return true; } return false; }
    private static void send(HttpExchange ex, int status, String body) throws IOException { headers(ex); byte[] b = body.getBytes(StandardCharsets.UTF_8); ex.sendResponseHeaders(status, b.length); try (OutputStream out = ex.getResponseBody()) { out.write(b); } }
}
