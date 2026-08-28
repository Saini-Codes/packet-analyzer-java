package com.packetanalyzer.flow;
public record FlowKey(String src,String dst,int sport,int dport,int protocol){public FlowKey reverse(){return new FlowKey(dst,src,dport,sport,protocol);} public String toString(){return src+":"+sport+" -> "+dst+":"+dport+"/"+protocol;}}
