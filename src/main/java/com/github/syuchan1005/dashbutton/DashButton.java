package com.github.syuchan1005.dashbutton;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.text.SimpleDateFormat;

public class DashButton {
	public static void main(String[] args) throws Exception {
		String filter = "ether proto 0x0806 and ether host " + args[0]; // 0x0806 == ARP
		PcapNetworkInterface nif = new NifSelector().selectNetworkInterface();
		final PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
		PacketListener listener = new PacketListener() {
			public void gotPacket(Packet packet) {
				printPacket(packet, handle);
				System.out.println("Dash Button Pushed!");
			}
		};
		handle.loop(10, listener);
	}

	private static void printPacket(Packet packet, PcapHandle ph) {
		StringBuilder sb = new StringBuilder();
		sb.append("A packet captured at ")
				.append(ph.getTimestamp())
				.append(":");
		System.out.println(sb);
		System.out.println(packet);
	}

	private static SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

}