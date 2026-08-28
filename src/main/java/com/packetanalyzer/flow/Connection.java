package com.packetanalyzer.flow;
import java.util.*;
public final class Connection {public final FlowKey key; public long packets,bytes; public String app="UNKNOWN",domain=""; public boolean blocked; public final long firstSeen=System.currentTimeMillis(); public long lastSeen=firstSeen; public Connection(FlowKey k){key=k;} public synchronized void update(int n){packets++;bytes+=n;lastSeen=System.currentTimeMillis();}}
