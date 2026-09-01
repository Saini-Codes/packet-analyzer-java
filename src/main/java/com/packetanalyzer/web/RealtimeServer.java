package com.packetanalyzer.web;

import com.packetanalyzer.realtime.LiveCaptureService;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class RealtimeServer {
    private static final LiveCaptureService capture = new LiveCaptureService();
    private RealtimeServer() {}

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/health", RealtimeServer::health);
        server.createContext("/api/interfaces", RealtimeServer::interfaces);
        server.createContext("/api/capture/start", RealtimeServer::start);
        server.createContext("/api/capture/stop", RealtimeServer::stop);
        server.createContext("/api/capture/status", RealtimeServer::status);
        server.createContext("/api/stream", RealtimeServer::stream);
        server.setExecutor(Executors.newCachedThreadPool());
        Runtime.getRuntime().addShutdownHook(new Thread(capture::close));
        server.start();
        System.out.println("Real-time Packet Analyzer API: http://localhost:" + port);
    }

    private static void health(HttpExchange e) throws IOException { if (options(e)) return; send(e, 200, "{\"status\":\"online\",\"mode\":\"realtime\"}"); }

    private static void interfaces(HttpExchange e) throws IOException {
        if (options(e)) return;
        try {
            List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
            StringBuilder out = new StringBuilder("[");
            boolean first = true;
            for (PcapNetworkInterface d : devs) {
                if (!first) out.append(','); first = false;
                out.append("{\"name\":\"").append(esc(d.getName())).append("\",\"description\":\"").append(esc(d.getDescription())).append("\"}");
            }
            out.append(']'); send(e, 200, out.toString());
        } catch (PcapNativeException ex) { send(e, 500, error(ex.getMessage())); }
    }

    private static void start(HttpExchange e) throws IOException {
        if (options(e)) return;
        if (!"POST".equalsIgnoreCase(e.getRequestMethod())) { send(e, 405, error("POST required")); return; }
        String body = new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Matcher m = Pattern.compile("\\\"interface\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"").matcher(body);
        String name = m.find() ? m.group(1) : "";
        try { capture.start(name); send(e, 200, statusJson()); }
        catch (Exception ex) { send(e, 400, error(ex.getMessage())); }
    }

    private static void stop(HttpExchange e) throws IOException { if (options(e)) return; capture.stop(); send(e, 200, statusJson()); }
    private static void status(HttpExchange e) throws IOException { if (options(e)) return; send(e, 200, statusJson()); }

    private static void stream(HttpExchange e) throws IOException {
        if (options(e)) return;
        e.getResponseHeaders().set("Content-Type", "text/event-stream; charset=utf-8");
        e.getResponseHeaders().set("Cache-Control", "no-cache");
        e.getResponseHeaders().set("Connection", "keep-alive");
        e.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        e.sendResponseHeaders(200, 0);
        OutputStream out = e.getResponseBody();
        java.util.function.Consumer<String> listener = json -> {
            try { synchronized (out) { out.write(("data: " + json + "\n\n").getBytes(StandardCharsets.UTF_8)); out.flush(); } }
            catch (IOException ignored) { capture.removeListener(null); }
        };
        capture.addListener(listener);
        try {
            synchronized (out) { out.write("retry: 2000\n\n".getBytes(StandardCharsets.UTF_8)); out.flush(); }
            while (true) { Thread.sleep(30_000); synchronized (out) { out.write(": heartbeat\n\n".getBytes(StandardCharsets.UTF_8)); out.flush(); } }
        } catch (InterruptedException | IOException ignored) {
            Thread.currentThread().interrupt();
        } finally {
            capture.removeListener(listener);
            try { out.close(); } catch (IOException ignored) {}
        }
    }

    private static String statusJson() { return "{\"running\":" + capture.isRunning() + ",\"interface\":\"" + esc(capture.interfaceName()) + "\"}"; }
    private static String error(String s) { return "{\"error\":\"" + esc(s) + "\"}"; }
    private static String esc(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " "); }
    private static boolean options(HttpExchange e) throws IOException { if ("OPTIONS".equalsIgnoreCase(e.getRequestMethod())) { e.getResponseHeaders().set("Access-Control-Allow-Origin", "*"); e.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type"); e.getResponseHeaders().set("Access-Control-Allow-Methods", "GET,POST,OPTIONS"); e.sendResponseHeaders(204, -1); e.close(); return true; } return false; }
    private static void send(HttpExchange e, int code, String body) throws IOException { e.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8"); e.getResponseHeaders().set("Access-Control-Allow-Origin", "*"); byte[] b = body.getBytes(StandardCharsets.UTF_8); e.sendResponseHeaders(code, b.length); try (OutputStream out = e.getResponseBody()) { out.write(b); } }
}
