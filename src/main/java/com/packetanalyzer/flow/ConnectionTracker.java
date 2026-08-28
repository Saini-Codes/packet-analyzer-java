package com.packetanalyzer.flow;
import java.util.concurrent.*; import java.util.*;
public final class ConnectionTracker {private final ConcurrentHashMap<FlowKey,Connection> map=new ConcurrentHashMap<>(); public Connection get(FlowKey k){return map.computeIfAbsent(k,Connection::new);} public Collection<Connection> all(){return map.values();} public int size(){return map.size();} public void cleanup(long ms){long now=System.currentTimeMillis();map.entrySet().removeIf(e->now-e.getValue().lastSeen>ms);}}
