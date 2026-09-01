# Packet Analyzer Dashboard

React + Vite frontend for `packet-analyzer-java`.

## Run

From the repository root:

```bash
mvn clean package
java -jar target/packet-analyzer-1.0.0.jar server
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal. The dashboard talks to `http://localhost:8080` by default. Set `VITE_API_URL` if the Java API is hosted elsewhere.

## Features

- PCAP upload and analysis
- Sample `test.pcap` analysis
- Packet inspection table with search
- Flow/5-tuple view
- DPI application classification
- Packet/byte/flow/drop statistics
- IP, port and domain blocking rules
- Responsive dark security-console UI
