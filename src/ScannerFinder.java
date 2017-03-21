

import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;


public class ScannerFinder {
	public static void main(String args[])
	{
		 Ip4 ip = new Ip4();
		 Tcp tcp = new Tcp();
		 Dictionary<String, Integer> syn = new Hashtable<String, Integer>();
		 Dictionary<String, Integer> ack = new Hashtable<String, Integer>();
		 List<String> loop=new ArrayList<String>();
		
		 final StringBuilder errbuf = new StringBuilder(); // For any error msgs
		 final String file = args[0];
		 int found = args[0].lastIndexOf("/");
		 
		 System.out.printf("Opening file for reading: %s%n", args[0].substring(found+1));
		 Pcap pcap = Pcap.openOffline(file, errbuf);
		 if (pcap == null) {
			 System.err.printf("Error while opening device for capture: " + errbuf.toString());
			 return;
		 }
		 else
		 {
			 System.out.println("Scanning PCAP input, please wait...");
		 }
		 PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			int tempcount = 1;
			String source;
			String destination;
			byte[]sip = new byte[4];
			byte[] dip=new byte[4];
			
			public void nextPacket(PcapPacket packet, String user) {
				if (packet.hasHeader(Tcp.ID)) {
					packet.getHeader(tcp);
					
					if(!tcp.flags_ACK()&&tcp.flags_SYN())
					{
						sip = packet.getHeader(ip).source();
						source= org.jnetpcap.packet.format.FormatUtils.ip(sip);
						
						if(!loop.contains(source))
							loop.add(source);
						
						if(syn.get(source)==null){
							syn.put(source, tempcount);
							if(ack.get(source)==null)
								ack.put(source, 0);
						}
							
						
						else {
							tempcount=syn.get(source);
					    	tempcount++;
					    	syn.put(source,tempcount);
					    }
						tempcount = 1;
					}
					else if(tcp.flags_ACK()&&tcp.flags_SYN()) {
						dip=packet.getHeader(ip).destination();
						destination= org.jnetpcap.packet.format.FormatUtils.ip(dip);
			    		
						if(!loop.contains(destination))
							loop.add(destination);
						
						if(ack.get(destination)==null)
							ack.put(destination, tempcount);
			       	    else { 
			    			tempcount=ack.get(destination);
			    			tempcount++;
			    			ack.put(destination,tempcount);
			       	    }
						tempcount = 1;
					}
				}	
			}
		};
		
		try {
		    pcap.loop(-1, jpacketHandler, null);
		} 
		
		finally {
			pcap.close();
		}
		
		//System.out.println(syn);
		//System.out.println(ack);
		//System.out.println(loop);
		for(int i=0;i<loop.size();i++) { 
			if(syn.get(loop.get(i))!=null&&ack.get(loop.get(i))!=null)
				if((syn.get(loop.get(i)))>3*ack.get(loop.get(i)))
					System.out.println(loop.get(i));
		}
	}
}
