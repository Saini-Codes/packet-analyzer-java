package com.packetanalyzer.capture;
import com.packetanalyzer.packet.Packet; import java.io.*; import java.nio.*; import java.util.*;
public final class PcapReader implements Closeable {
 private final DataInputStream in; private final boolean little; private final int snaplen;
 public PcapReader(String f)throws IOException{in=new DataInputStream(new BufferedInputStream(new FileInputStream(f))); byte[] h=in.readNBytes(24); if(h.length<24)throw new EOFException(); int magic=ByteBuffer.wrap(h).getInt(); if(magic==0xa1b2c3d4){little=false;}else if(Integer.reverseBytes(magic)==0xa1b2c3d4){little=true;}else throw new IOException("Unsupported PCAP magic"); int link=read32(h,20); snaplen=read32(h,16); if(link!=1) throw new IOException("Only Ethernet PCAP (DLT_EN10MB) is supported"); }
 private int read32(byte[] b,int o){return little?Integer.reverseBytes(ByteBuffer.wrap(b,o,4).getInt()):ByteBuffer.wrap(b,o,4).getInt();}
 public Packet next()throws IOException{byte[] h=in.readNBytes(16); if(h.length==0)return null; if(h.length<16)throw new EOFException(); long sec=Integer.toUnsignedLong(read32(h,0)), usec=Integer.toUnsignedLong(read32(h,4)), len=Integer.toUnsignedLong(read32(h,8)); if(len>snaplen || len>100_000_000)throw new IOException("Invalid packet length: "+len); byte[] d=in.readNBytes((int)len); if(d.length!=len)throw new EOFException(); return new Packet(sec,usec,d);}
 public void close()throws IOException{in.close();}
}
