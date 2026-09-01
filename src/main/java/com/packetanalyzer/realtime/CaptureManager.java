package com.packetanalyzer.realtime;

import com.packetanalyzer.capture.LivePacketSource;
import com.packetanalyzer.packet.Packet;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/** Owns the capture lifecycle and provides bounded back-pressure between capture and processing. */
public final class CaptureManager {
    private final BlockingQueue<Packet> queue = new ArrayBlockingQueue<>(10_000);
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private volatile LivePacketSource source;
    private volatile Consumer<Packet> processor = p -> {};

    public void setProcessor(Consumer<Packet> processor) { this.processor = processor == null ? p -> {} : processor; }

    public synchronized void start(String interfaceName) {
        if (running.get()) return;
        source = new LivePacketSource(interfaceName);
        source.start();
        running.set(true);
        executor.submit(this::captureLoop);
        executor.submit(this::processLoop);
    }

    private void captureLoop() {
        try {
            while (running.get()) {
                Packet packet = source.next();
                if (packet != null) queue.put(packet);
            }
        } catch (Exception ignored) {
            running.set(false);
        }
    }

    private void processLoop() {
        try {
            while (running.get() || !queue.isEmpty()) processor.accept(queue.poll(250, TimeUnit.MILLISECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public synchronized void stop() {
        running.set(false);
        if (source != null) source.stop();
        queue.clear();
    }

    public boolean isRunning() { return running.get(); }
    public int queuedPackets() { return queue.size(); }
    public String interfaceName() { return source == null ? null : source.interfaceName(); }

    public void close() {
        stop();
        executor.shutdownNow();
    }
}
