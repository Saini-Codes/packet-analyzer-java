package com.packetanalyzer.realtime;

import com.packetanalyzer.capture.LivePacketSource;
import com.packetanalyzer.packet.Packet;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Owns the capture lifecycle and provides bounded back-pressure
 * between capture and processing.
 */
public final class CaptureManager {

    private final BlockingQueue<Packet> queue =
            new ArrayBlockingQueue<>(10_000);

    private final AtomicBoolean running =
            new AtomicBoolean(false);

    private final ExecutorService executor =
            Executors.newFixedThreadPool(2);

    private volatile LivePacketSource source;

    private volatile Consumer<Packet> processor =
            p -> {};

    public void setProcessor(
            Consumer<Packet> processor
    ) {
        this.processor =
                processor == null
                        ? p -> {}
                        : processor;
    }

    public synchronized void start(
            String interfaceName
    ) throws java.io.IOException {

        if (running.get()) {
            return;
        }

        source =
                new LivePacketSource(interfaceName);

        source.start();

        running.set(true);

        executor.submit(
                this::captureLoop
        );

        executor.submit(
                this::processLoop
        );
    }

    private void captureLoop() {

        try {

            while (running.get()) {

                Packet packet =
                        source.next();

                if (packet != null) {

                    /*
                     * Prevent the capture thread from
                     * crashing when the queue is full.
                     */
                    if (!queue.offer(
                            packet,
                            250,
                            TimeUnit.MILLISECONDS
                    )) {

                        // Drop packet when processing
                        // cannot keep up.
                    }
                }
            }

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

        } catch (Exception e) {

            running.set(false);

        } finally {

            if (!running.get()) {
                closeSource();
            }
        }
    }

    private void processLoop() {

        try {

            while (
                    running.get()
                            || !queue.isEmpty()
            ) {

                Packet packet =
                        queue.poll(
                                250,
                                TimeUnit.MILLISECONDS
                        );

                if (packet != null) {

                    processor.accept(packet);
                }
            }

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();
        }
    }

    public synchronized void stop() {

        running.set(false);

        closeSource();

        queue.clear();
    }

    private void closeSource() {

        LivePacketSource current =
                source;

        source = null;

        if (current != null) {

            try {
                current.stop();
            } catch (Exception ignored) {
            }
        }
    }

    public boolean isRunning() {
        return running.get();
    }

    public int queuedPackets() {
        return queue.size();
    }

    public String interfaceName() {

        LivePacketSource current =
                source;

        return current == null
                ? null
                : current.interfaceName();
    }

    public void close() {

        stop();

        executor.shutdownNow();
    }
}