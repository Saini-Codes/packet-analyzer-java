package com.packetanalyzer.web;

import com.packetanalyzer.realtime.LiveCaptureService;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class RealtimeServer {

    private static final LiveCaptureService capture =
            new LiveCaptureService();

    private RealtimeServer() {
    }

    public static void main(String[] args) throws Exception {

        int port = args.length > 0
                ? Integer.parseInt(args[0])
                : 8080;

        HttpServer server = HttpServer.create(
                new InetSocketAddress(port),
                0
        );

        server.createContext(
                "/api/health",
                RealtimeServer::health
        );

        server.createContext(
                "/api/interfaces",
                RealtimeServer::interfaces
        );

        server.createContext(
                "/api/capture/start",
                RealtimeServer::start
        );

        server.createContext(
                "/api/capture/stop",
                RealtimeServer::stop
        );

        server.createContext(
                "/api/capture/status",
                RealtimeServer::status
        );

        server.createContext(
                "/api/stream",
                RealtimeServer::stream
        );

        server.setExecutor(
                Executors.newCachedThreadPool()
        );

        Runtime.getRuntime().addShutdownHook(
                new Thread(capture::close)
        );

        server.start();

        System.out.println(
                "Real-time Packet Analyzer API: http://localhost:" + port
        );
    }

    // ============================================================
    // HEALTH
    // ============================================================

    private static void health(HttpExchange e) throws IOException {

        if (options(e)) {
            return;
        }

        send(
                e,
                200,
                "{\"status\":\"online\",\"mode\":\"realtime\"}"
        );
    }

    // ============================================================
    // NETWORK INTERFACES
    // ============================================================

    private static void interfaces(HttpExchange e) throws IOException {

        if (options(e)) {
            return;
        }

        if (!"GET".equalsIgnoreCase(e.getRequestMethod())) {
            send(
                    e,
                    405,
                    error("GET required")
            );
            return;
        }

        try {

            List<PcapNetworkInterface> devs =
                    Pcaps.findAllDevs();

            StringBuilder out =
                    new StringBuilder("[");

            boolean first = true;

            for (PcapNetworkInterface device : devs) {

                String name =
                        device.getName();

                String description =
                        device.getDescription();

                if (description == null ||
                        description.isBlank()) {

                    description = name;
                }

                /*
                 * IMPORTANT:
                 *
                 * Only expose interfaces that are useful
                 * for normal packet capture.
                 */
                if (!isUsableInterface(name, description)) {
                    System.out.println(
                            "Ignoring virtual/unsupported interface: "
                                    + description
                    );
                    continue;
                }

                if (!first) {
                    out.append(",");
                }

                first = false;

                String type =
                        getInterfaceType(
                                name,
                                description
                        );

                out.append("{");

                out.append("\"name\":\"")
                        .append(esc(name))
                        .append("\",");

                out.append("\"description\":\"")
                        .append(esc(description))
                        .append("\",");

                out.append("\"type\":\"")
                        .append(esc(type))
                        .append("\"");

                out.append("}");
            }

            out.append("]");

            send(
                    e,
                    200,
                    out.toString()
            );

        } catch (PcapNativeException ex) {

            ex.printStackTrace();

            send(
                    e,
                    500,
                    error(
                            ex.getMessage() == null
                                    ? "Unable to enumerate network interfaces"
                                    : ex.getMessage()
                    )
            );
        }
    }

    // ============================================================
    // INTERFACE FILTER
    // ============================================================

    private static boolean isUsableInterface(
            String name,
            String description
    ) {

        String value =
                ((name == null ? "" : name) + " "
                        + (description == null ? "" : description))
                        .toLowerCase();

        // --------------------------------------------------------
        // REMOVE WINDOWS WAN MINIport ADAPTERS
        // --------------------------------------------------------

        if (value.contains("wan miniport")) {
            return false;
        }

        // --------------------------------------------------------
        // REMOVE WI-FI DIRECT VIRTUAL ADAPTERS
        // --------------------------------------------------------

        if (value.contains("wi-fi direct virtual adapter")) {
            return false;
        }

        if (value.contains("wifi direct virtual adapter")) {
            return false;
        }

        // --------------------------------------------------------
        // REMOVE COMMON WINDOWS VIRTUAL/TUNNEL ADAPTERS
        // --------------------------------------------------------

        if (value.contains("teredo")) {
            return false;
        }

        if (value.contains("isatap")) {
            return false;
        }

        if (value.contains("6to4")) {
            return false;
        }

        // --------------------------------------------------------
        // KEEP Npcap LOOPBACK
        // --------------------------------------------------------

        if (value.contains("loopback")
                || value.contains("npf_loopback")) {

            return true;
        }

        // --------------------------------------------------------
        // KEEP WI-FI / WIRELESS
        // --------------------------------------------------------

        if (value.contains("wi-fi")
                || value.contains("wifi")
                || value.contains("wireless")
                || value.contains("802.11")) {

            return true;
        }

        // --------------------------------------------------------
        // KEEP ETHERNET
        // --------------------------------------------------------

        if (value.contains("ethernet")
                || value.contains("gigabit")
                || value.contains("realtek")
                || value.contains("intel(r) ethernet")
                || value.contains("intel ethernet")) {

            return true;
        }

        // --------------------------------------------------------
        // KEEP BLUETOOTH PAN
        // --------------------------------------------------------

        if (value.contains("bluetooth")
                && value.contains("personal area network")) {

            return true;
        }

        /*
         * Everything else is considered virtual,
         * unsupported, or unsuitable for this dashboard.
         */
        return false;
    }

    // ============================================================
    // INTERFACE TYPE
    // ============================================================

    private static String getInterfaceType(
            String name,
            String description
    ) {

        String value =
                ((name == null ? "" : name) + " "
                        + (description == null ? "" : description))
                        .toLowerCase();

        if (value.contains("loopback")
                || value.contains("npf_loopback")) {

            return "Loopback";
        }

        if (value.contains("bluetooth")) {
            return "Bluetooth";
        }

        if (value.contains("wi-fi")
                || value.contains("wifi")
                || value.contains("wireless")
                || value.contains("802.11")) {

            return "Wi-Fi";
        }

        if (value.contains("ethernet")
                || value.contains("gigabit")
                || value.contains("realtek")
                || value.contains("intel(r) ethernet")
                || value.contains("intel ethernet")) {

            return "Ethernet";
        }

        return "Network";
    }

    // ============================================================
    // START CAPTURE
    // ============================================================

    private static void start(HttpExchange e) throws IOException {

        if (options(e)) {
            return;
        }

        if (!"POST".equalsIgnoreCase(
                e.getRequestMethod())) {

            send(
                    e,
                    405,
                    error("POST required")
            );

            return;
        }

        String body =
                new String(
                        e.getRequestBody().readAllBytes(),
                        StandardCharsets.UTF_8
                );

        System.out.println(
                "Capture request body: " + body
        );

        /*
         * Matches:
         *
         * {"interface":"\\Device\\NPF_{...}"}
         *
         * while preserving escaped characters.
         */
        Matcher matcher =
                Pattern.compile(
                        "\"interface\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\""
                ).matcher(body);

        if (!matcher.find()) {

            send(
                    e,
                    400,
                    error("Interface is required")
            );

            return;
        }

        String name =
                unescapeJsonString(
                        matcher.group(1)
                );

        name =
                normalizeInterfaceName(name);

        if (name.isBlank()) {

            send(
                    e,
                    400,
                    error("Interface is empty")
            );

            return;
        }

        System.out.println(
                "Starting capture on interface: [" +
                        name +
                        "]"
        );

        try {

            /*
             * Find the requested interface.
             */
            PcapNetworkInterface selected =
                    findInterface(name);

            if (selected == null) {

                send(
                        e,
                        400,
                        error(
                                "Network interface not found or unsupported: "
                                        + name
                        )
                );

                return;
            }

            String selectedDescription =
                    selected.getDescription();

            if (selectedDescription == null ||
                    selectedDescription.isBlank()) {

                selectedDescription =
                        selected.getName();
            }

            /*
             * Double-check that the interface is one
             * of the interfaces exposed by the API.
             */
            if (!isUsableInterface(
                    selected.getName(),
                    selectedDescription
            )) {

                send(
                        e,
                        400,
                        error(
                                "This network interface is not supported for live capture"
                        )
                );

                return;
            }

            System.out.println(
                    "Selected interface: " +
                            selectedDescription
            );

            capture.start(
                    selected.getName()
            );

            send(
                    e,
                    200,
                    statusJson()
            );

        } catch (Exception ex) {

            ex.printStackTrace();

            send(
                    e,
                    400,
                    error(
                            ex.getMessage() == null
                                    ? "Unable to start capture"
                                    : ex.getMessage()
                    )
            );
        }
    }

    // ============================================================
    // FIND INTERFACE
    // ============================================================

    private static PcapNetworkInterface findInterface(
            String requestedName
    ) throws PcapNativeException {

        List<PcapNetworkInterface> devices =
                Pcaps.findAllDevs();

        for (PcapNetworkInterface device : devices) {

            String actual =
                    device.getName();

            if (actual == null) {
                continue;
            }

            String description =
                    device.getDescription();

            if (description == null ||
                    description.isBlank()) {

                description = actual;
            }

            /*
             * Do not allow hidden/unsupported adapters.
             */
            if (!isUsableInterface(
                    actual,
                    description
            )) {
                continue;
            }

            if (actual.equals(requestedName)) {
                return device;
            }

            /*
             * Defensive comparison in case a frontend/client
             * accidentally sends duplicate backslashes.
             */
            if (normalizeInterfaceName(actual)
                    .equals(
                            normalizeInterfaceName(requestedName)
                    )) {

                return device;
            }
        }

        return null;
    }

    // ============================================================
    // STOP CAPTURE
    // ============================================================

    private static void stop(HttpExchange e)
            throws IOException {

        if (options(e)) {
            return;
        }

        if (!"POST".equalsIgnoreCase(
                e.getRequestMethod())) {

            send(
                    e,
                    405,
                    error("POST required")
            );

            return;
        }

        try {

            capture.stop();

            send(
                    e,
                    200,
                    statusJson()
            );

        } catch (Exception ex) {

            ex.printStackTrace();

            send(
                    e,
                    500,
                    error(
                            ex.getMessage() == null
                                    ? "Unable to stop capture"
                                    : ex.getMessage()
                    )
            );
        }
    }

    // ============================================================
    // CAPTURE STATUS
    // ============================================================

    private static void status(HttpExchange e)
            throws IOException {

        if (options(e)) {
            return;
        }

        if (!"GET".equalsIgnoreCase(
                e.getRequestMethod())) {

            send(
                    e,
                    405,
                    error("GET required")
            );

            return;
        }

        send(
                e,
                200,
                statusJson()
        );
    }

    // ============================================================
    // SERVER-SENT EVENTS STREAM
    // ============================================================

    private static void stream(HttpExchange e)
            throws IOException {

        if (options(e)) {
            return;
        }

        if (!"GET".equalsIgnoreCase(
                e.getRequestMethod())) {

            send(
                    e,
                    405,
                    error("GET required")
            );

            return;
        }

        e.getResponseHeaders().set(
                "Content-Type",
                "text/event-stream; charset=utf-8"
        );

        e.getResponseHeaders().set(
                "Cache-Control",
                "no-cache, no-store, must-revalidate"
        );

        e.getResponseHeaders().set(
                "Connection",
                "keep-alive"
        );

        e.getResponseHeaders().set(
                "Access-Control-Allow-Origin",
                "*"
        );

        e.getResponseHeaders().set(
                "X-Accel-Buffering",
                "no"
        );

        e.sendResponseHeaders(
                200,
                0
        );

        OutputStream out =
                e.getResponseBody();

        AtomicReference<Consumer<String>>
                listenerReference =
                new AtomicReference<>();

        Consumer<String> listener =
                json -> {

                    try {

                        synchronized (out) {

                            String event =
                                    "data: " +
                                            json +
                                            "\n\n";

                            out.write(
                                    event.getBytes(
                                            StandardCharsets.UTF_8
                                    )
                            );

                            out.flush();
                        }

                    } catch (IOException ignored) {

                        Consumer<String> current =
                                listenerReference.get();

                        if (current != null) {

                            capture.removeListener(
                                    current
                            );
                        }
                    }
                };

        listenerReference.set(listener);

        capture.addListener(listener);

        try {

            synchronized (out) {

                out.write(
                        "retry: 2000\n\n"
                                .getBytes(
                                        StandardCharsets.UTF_8
                                )
                );

                out.flush();
            }

            System.out.println(
                    "SSE client connected."
            );

            while (true) {

                Thread.sleep(
                        30_000
                );

                synchronized (out) {

                    out.write(
                            ": heartbeat\n\n"
                                    .getBytes(
                                            StandardCharsets.UTF_8
                                    )
                    );

                    out.flush();
                }
            }

        } catch (InterruptedException ex) {

            Thread.currentThread().interrupt();

        } catch (IOException ex) {

            System.out.println(
                    "SSE client disconnected."
            );

        } finally {

            capture.removeListener(
                    listener
            );

            try {
                out.close();
            } catch (IOException ignored) {
            }
        }
    }

    // ============================================================
    // JSON STATUS
    // ============================================================

    private static String statusJson() {

        return "{"
                + "\"running\":"
                + capture.isRunning()
                + ","
                + "\"interface\":\""
                + esc(capture.interfaceName())
                + "\""
                + "}";
    }

    // ============================================================
    // JSON ERROR
    // ============================================================

    private static String error(
            String message
    ) {

        return "{"
                + "\"error\":\""
                + esc(
                        message == null
                                ? "Unknown error"
                                : message
                )
                + "\""
                + "}";
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
    // JSON UNESCAPE
    // ============================================================

    private static String unescapeJsonString(
            String value
    ) {

        if (value == null) {
            return "";
        }

        StringBuilder result =
                new StringBuilder();

        boolean escaped = false;

        for (int i = 0;
             i < value.length();
             i++) {

            char c =
                    value.charAt(i);

            if (escaped) {

                switch (c) {

                    case '\\':
                        result.append('\\');
                        break;

                    case '"':
                        result.append('"');
                        break;

                    case '/':
                        result.append('/');
                        break;

                    case 'n':
                        result.append('\n');
                        break;

                    case 'r':
                        result.append('\r');
                        break;

                    case 't':
                        result.append('\t');
                        break;

                    case 'b':
                        result.append('\b');
                        break;

                    case 'f':
                        result.append('\f');
                        break;

                    default:
                        result.append(c);
                        break;
                }

                escaped = false;

            } else if (c == '\\') {

                escaped = true;

            } else {

                result.append(c);
            }
        }

        if (escaped) {
            result.append('\\');
        }

        return result.toString();
    }

    // ============================================================
    // NORMALIZE Npcap INTERFACE NAME
    // ============================================================

    private static String normalizeInterfaceName(
            String name
    ) {

        if (name == null) {
            return "";
        }

        String normalized =
                name.trim();

        /*
         * Convert accidentally duplicated Windows
         * path separators.
         *
         * Example:
         *
         * \\\Device\\NPF_{ABC}
         *
         * becomes:
         *
         * \Device\NPF_{ABC}
         */
        while (
                normalized.startsWith(
                        "\\\\Device\\NPF"
                )
        ) {

            normalized =
                    normalized.substring(1);
        }

        normalized =
                normalized.replace(
                        "\\\\",
                        "\\"
                );

        return normalized;
    }

    // ============================================================
    // CORS OPTIONS
    // ============================================================

    private static boolean options(
            HttpExchange e
    ) throws IOException {

        if (!"OPTIONS".equalsIgnoreCase(
                e.getRequestMethod()
        )) {

            return false;
        }

        e.getResponseHeaders().set(
                "Access-Control-Allow-Origin",
                "*"
        );

        e.getResponseHeaders().set(
                "Access-Control-Allow-Headers",
                "Content-Type"
        );

        e.getResponseHeaders().set(
                "Access-Control-Allow-Methods",
                "GET,POST,OPTIONS"
        );

        e.getResponseHeaders().set(
                "Access-Control-Max-Age",
                "3600"
        );

        e.sendResponseHeaders(
                204,
                -1
        );

        e.close();

        return true;
    }

    // ============================================================
    // SEND RESPONSE
    // ============================================================

    private static void send(
            HttpExchange e,
            int code,
            String body
    ) throws IOException {

        e.getResponseHeaders().set(
                "Content-Type",
                "application/json; charset=utf-8"
        );

        e.getResponseHeaders().set(
                "Access-Control-Allow-Origin",
                "*"
        );

        byte[] data =
                body.getBytes(
                        StandardCharsets.UTF_8
                );

        e.sendResponseHeaders(
                code,
                data.length
        );

        try (
                OutputStream out =
                        e.getResponseBody()
        ) {

            out.write(data);
            out.flush();
        }
    }
}