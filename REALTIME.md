# Real-time packet capture

The `feature/web-dashboard` branch adds live capture to the analyzer.

## Requirements

- Java 21
- Maven 3.9+
- Windows: install Npcap (WinPcap API-compatible mode is recommended) and run the Java server with permission to capture traffic.
- Linux/macOS: libpcap and appropriate capture permissions are required.

Pcap4J wraps native packet capture libraries such as libpcap/Npcap. The project uses Pcap4J `2.0.0-alpha.6`.

## Start the API

```bash
mvn clean package
java -jar target/packet-analyzer-1.0.0.jar server 8080
```

The server exposes:

- `GET /api/health`
- `GET /api/interfaces`
- `POST /api/capture/start` with `{ "interface": "<interface-name>" }`
- `POST /api/capture/stop`
- `GET /api/capture/status`
- `GET /api/stream` — Server-Sent Events stream of analyzed packets

## Start the dashboard

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL, select the network interface and press **Start capture**.

The browser receives packet events immediately through SSE. The Java process performs parsing, DPI, flow tracking and firewall decisions before publishing each event.

## Windows note

The web browser cannot directly sniff the computer's network interface. The Java process must run locally on the machine being monitored, with Npcap installed. A remotely deployed Vercel/static frontend cannot capture a user's packets by itself; it must connect to a locally running analyzer agent/API.
