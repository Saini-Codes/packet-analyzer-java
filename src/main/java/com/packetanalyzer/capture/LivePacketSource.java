package com.packetanalyzer.capture;

import com.packetanalyzer.packet.Packet;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;

import java.io.IOException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Live network packet source using Pcap4J + Npcap.
 *
 * Designed for:
 * Pcap4J 2.0.0-alpha.6
 */
public final class LivePacketSource implements PacketSource {

    private static final int SNAPLEN = 65_535;

    private static final int READ_TIMEOUT = 100;

    private static final int QUEUE_SIZE = 10_000;

    private final String interfaceName;

    private final ArrayBlockingQueue<CapturedPacket> queue =
            new ArrayBlockingQueue<>(QUEUE_SIZE);

    private final AtomicBoolean running =
            new AtomicBoolean(false);

    private volatile PcapHandle handle;

    private volatile Thread captureThread;


    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    public LivePacketSource(
            String interfaceName
    ) throws IOException {

        if (interfaceName == null ||
                interfaceName.isBlank()) {

            throw new IOException(
                    "Network interface is required"
            );
        }

        this.interfaceName =
                normalize(interfaceName);

        System.out.println(
                "Looking for Npcap interface:"
        );

        System.out.println(
                "[" + this.interfaceName + "]"
        );

        PcapNetworkInterface device =
                findDevice(this.interfaceName);

        if (device == null) {

            throw new IOException(
                    "Network interface not found: " +
                            this.interfaceName
            );
        }

        System.out.println(
                "Found interface: " +
                        device.getName()
        );

        System.out.println(
                "Description: " +
                        device.getDescription()
        );

        try {

            handle =
                    device.openLive(
                            SNAPLEN,
                            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                            READ_TIMEOUT
                    );

        } catch (PcapNativeException e) {

            throw new IOException(
                    "Unable to open network interface: " +
                            device.getDescription(),
                    e
            );
        }

        System.out.println(
                "Pcap4J handle opened successfully."
        );
    }


    // ============================================================
    // FIND NETWORK DEVICE
    // ============================================================

    private static PcapNetworkInterface findDevice(
            String requested
    ) throws IOException {

        try {

            java.util.List<PcapNetworkInterface> devices =
                    Pcaps.findAllDevs();

            if (devices == null ||
                    devices.isEmpty()) {

                throw new IOException(
                        "Npcap returned no network interfaces"
                );
            }

            for (
                    PcapNetworkInterface device :
                    devices
            ) {

                if (device == null) {
                    continue;
                }

                String name =
                        device.getName();

                if (name == null) {
                    continue;
                }

                String normalized =
                        normalize(name);

                if (normalized.equals(requested)) {

                    return device;
                }
            }

        } catch (PcapNativeException e) {

            throw new IOException(
                    "Unable to enumerate Npcap interfaces",
                    e
            );
        }

        return null;
    }


    // ============================================================
    // START CAPTURE
    // ============================================================

    public synchronized void start() {

        if (running.get()) {
            return;
        }

        if (handle == null) {

            throw new IllegalStateException(
                    "Pcap handle is not available"
            );
        }

        running.set(true);

        captureThread =
                new Thread(
                        this::captureLoop,
                        "pcap-live-capture"
                );

        captureThread.setDaemon(true);

        captureThread.start();

        System.out.println(
                "Pcap4J capture thread started."
        );
    }


    // ============================================================
    // CAPTURE LOOP
    // ============================================================

    private void captureLoop() {

        System.out.println(
                "Waiting for live packets..."
        );

        while (running.get()) {

            PcapHandle current =
                    handle;

            if (current == null) {
                break;
            }

            try {

                /*
                 * Pcap4J reads one packet directly
                 * from the Npcap interface.
                 */
                org.pcap4j.packet.Packet captured =
                        current.getNextPacketEx();

                if (captured == null) {
                    continue;
                }

                byte[] raw =
                        captured.getRawData();

                if (raw == null ||
                        raw.length == 0) {

                    continue;
                }

                /*
                 * Use the current system timestamp.
                 */
                long timestampMillis =
                        System.currentTimeMillis();

                long seconds =
                        timestampMillis / 1000L;

                long microseconds =
                        (timestampMillis % 1000L)
                                * 1000L;

                CapturedPacket packet =
                        new CapturedPacket(
                                seconds,
                                microseconds,
                                raw
                        );

                /*
                 * Add packet to queue.
                 *
                 * If queue is full:
                 * remove oldest packet,
                 * then add newest packet.
                 */
                if (!queue.offer(packet)) {

                    queue.poll();

                    queue.offer(packet);
                }

                /*
                 * Console output helps us verify that
                 * Npcap is actually receiving traffic.
                 */
                System.out.println(
                        "Packet captured: " +
                                raw.length +
                                " bytes"
                );

            } catch (Exception e) {

                /*
                 * Timeout and temporary capture errors
                 * should not kill the capture service.
                 */
                if (!running.get()) {
                    break;
                }

                String message =
                        e.getMessage();

                if (message == null ||
                        message.isBlank()) {

                    continue;
                }

                String lower =
                        message.toLowerCase();

                /*
                 * Ignore normal timeout messages.
                 */
                if (lower.contains("timeout")) {
                    continue;
                }

                System.err.println(
                        "Packet capture error: " +
                                message
                );
            }
        }

        running.set(false);

        System.out.println(
                "Pcap4J capture thread stopped."
        );
    }


    // ============================================================
    // GET NEXT PACKET
    // ============================================================

    @Override
    public Packet next()
            throws IOException {

        if (!running.get()) {
            return null;
        }

        try {

            CapturedPacket captured =
                    queue.poll(
                            250,
                            TimeUnit.MILLISECONDS
                    );

            if (captured == null) {
                return null;
            }

            return new Packet(
                    captured.tsSec(),
                    captured.tsUsec(),
                    captured.data()
            );

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            throw new IOException(
                    "Live capture interrupted",
                    e
            );
        }
    }


    // ============================================================
    // INTERFACE NAME
    // ============================================================

    /*
     * PacketSource in your project does not appear
     * to declare interfaceName(), therefore there is
     * intentionally NO @Override here.
     */
    public String interfaceName() {

        return interfaceName;
    }


    // ============================================================
    // RUNNING STATUS
    // ============================================================

    public boolean isRunning() {

        return running.get();
    }


    // ============================================================
    // STOP
    // ============================================================

    public synchronized void stop() {

        running.set(false);

        PcapHandle current =
                handle;

        if (current != null) {

            try {

                current.breakLoop();

            } catch (Exception ignored) {
            }
        }

        Thread currentThread =
                captureThread;

        if (currentThread != null &&
                currentThread !=
                        Thread.currentThread()) {

            try {

                currentThread.join(1000);

            } catch (InterruptedException e) {

                Thread.currentThread().interrupt();
            }
        }

        queue.clear();
    }


    // ============================================================
    // CLOSE
    // ============================================================

    @Override
    public synchronized void close() {

        stop();

        PcapHandle current =
                handle;

        handle = null;

        if (current != null) {

            try {

                current.close();

            } catch (Exception ignored) {
            }
        }

        captureThread = null;
    }


    // ============================================================
    // NORMALIZE INTERFACE NAME
    // ============================================================

    private static String normalize(
            String value
    ) {

        if (value == null) {
            return "";
        }

        String result =
                value.trim();

        /*
         * Fix Windows/Npcap paths such as:
         *
         * \\Device\\NPF_{GUID}
         *
         * to:
         *
         * \Device\NPF_{GUID}
         */
        while (
                result.startsWith(
                        "\\\\Device\\NPF"
                )
        ) {

            result =
                    result.substring(1);
        }

        result =
                result.replace(
                        "\\\\",
                        "\\"
                );

        return result;
    }


    // ============================================================
    // CAPTURED PACKET
    // ============================================================

    private record CapturedPacket(
            long tsSec,
            long tsUsec,
            byte[] data
    ) {
    }
}