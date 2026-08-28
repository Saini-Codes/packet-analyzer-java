package com.packetanalyzer.packet;
import java.net.*; import java.util.*;
public final class PacketParser {
 static int u8(byte[]b,int i){return b[i]&255;} static int u16(byte[]b,int i){return (u8(b,i)<<8)|u8(b,i+1);} static long u32(byte[]b,int i){return ((long)u16(b,i)<<16)|u16(b,i+2);}
 static String mac(byte[]b,int o){return String.format("%02x:%02x:%02x:%02x:%02x:%02x",u8(b,o),u8(b,o+1),u8(b,o+2),u8(b,o+3),u8(b,o+4),u8(b,o+5));}
 static String ip(byte[]b,int o){return u8(b,o)+"."+u8(b,o+1)+"."+u8(b,o+2)+"."+u8(b,o+3);}
 public static ParsedPacket parse(byte[]d){ParsedPacket p=new ParsedPacket();p.raw=d;if(d.length<14)return null;p.dstMac=mac(d,0);p.srcMac=mac(d,6);p.etherType=u16(d,12);int o=14;if(p.etherType==0x8100 && d.length>=18){p.etherType=u16(d,16);o=18;} if(p.etherType!=0x0800)return p;if(d.length<o+20)return p;p.hasIp=true;p.ipVersion=u8(d,o)>>4;int ihl=(u8(d,o)&15)*4;if(p.ipVersion!=4||d.length<o+ihl)return p;p.ttl=u8(d,o+8);p.protocol=u8(d,o+9);p.srcIp=ip(d,o+12);p.dstIp=ip(d,o+16);o+=ihl;if(p.protocol==6&&d.length>=o+20){p.hasTcp=true;p.srcPort=u16(d,o);p.dstPort=u16(d,o+2);p.tcpFlags=u8(d,o+13);int h=((u8(d,o+12)>>4)&15)*4;p.payloadOffset=o+h;p.payloadLength=Math.max(0,d.length-p.payloadOffset);}else if(p.protocol==17&&d.length>=o+8){p.hasUdp=true;p.srcPort=u16(d,o);p.dstPort=u16(d,o+2);p.payloadOffset=o+8;p.payloadLength=Math.max(0,d.length-p.payloadOffset);}return p;}
 public static String flags(int f){StringBuilder s=new StringBuilder();if((f&2)!=0)s.append("SYN ");if((f&16)!=0)s.append("ACK ");if((f&1)!=0)s.append("FIN ");if((f&4)!=0)s.append("RST ");if((f&8)!=0)s.append("PSH ");return s.toString().trim();}
}
