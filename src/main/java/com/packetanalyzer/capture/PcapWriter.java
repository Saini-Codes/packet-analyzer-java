package com.packetanalyzer.capture;
import com.packetanalyzer.packet.Packet; import java.io.*; import java.nio.*;
public final class PcapWriter implements Closeable { private final DataOutputStream out;
 public PcapWriter(String f)throws IOException{out=new DataOutputStream(new BufferedOutputStream(new FileOutputStream(f))); byte[] h=new byte[24]; ByteBuffer b=ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN); b.putInt(0xa1b2c3d4).putShort((short)2).putShort((short)4).putInt(0).putInt(0).putInt(65535).putInt(1); out.write(h);}
 public synchronized void write(Packet p)throws IOException{byte[] h=new byte[16];ByteBuffer b=ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN);b.putInt((int)p.tsSec).putInt((int)p.tsUsec).putInt(p.data.length).putInt(p.data.length);out.write(h);out.write(p.data);}
 public void close()throws IOException{out.close();}}
