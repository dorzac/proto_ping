/// @author Zach Dorf
/// Basic multithreaded Ping program.

use std::thread;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicBool, Ordering};
use std::process::exit;
use structopt::StructOpt;
use dns_lookup::lookup_host;
use pnet::util;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::{IcmpTypes};
use pnet::packet::icmp::{echo_request};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::transport::transport_channel;
use pnet::transport::TransportSender;
use pnet::transport::icmp_packet_iter;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};

const BUFFER_SIZE: usize = 4096;
const PKT_SIZE: usize = 64;
const NUM_PACKETS: i32 = 5;

// Uses StructOpt crate to parse arguments
#[derive(StructOpt, Debug)]
struct Arguments {

	#[structopt(required = true)]
	tgt_ip: String,

	#[structopt(short, long, default_value="100")]
	ttl: u64,
}


/// Main method merely interprets cli arguments and passes 
/// them onwards.
fn main() {
	
	let opt = Arguments::from_args();
	let ttl5 = Duration::from_millis(5 * opt.ttl);
	let address = opt.tgt_ip;
	let mut addr : IpAddr;

	// Parse String address into an IpAddr
	let ips: Vec<IpAddr> = match lookup_host(&address) {
		Ok(ips) => ips,
		Err(_e) => {
			println!("Invalid address!");
			exit(0);
		},
	};
	addr = ips[0];
	if ips.len() == 0 {
		addr = match address.to_string().parse() {
			Ok(addr) => addr,
			Err(e) => { 
				println!("***{}", e.to_string());
				return; 
			},
		};
	}

	// Main pinging loop
	let mut sum = 0 as f32;
	let mut iterations = 0 as f32;
	let mut percent: f32;
	loop {
		let (us, packet_count) = ping(addr, ttl5);
		sum += packet_count as f32;
		iterations += 1.0;
		percent = (((5.0 * iterations) - sum) / (5.0 * iterations)) as f32;
		println!("Pinging {:?} -- loss={}% time={} us", address.to_string(), percent * 100.0, us);
	}
}


/// Driver method. Sends a burst of five packets from the parent
/// thread while listening for a reply on the child.
/// @param dest is an `IpAddr` object
/// @param ttl5 is the packet's time to live, scaled by 5
///        to account for the five packet nature of a ping.
///        It is represented by a time `Duration`.
/// @return a tuple containing an `i64` representation of
///		   elapsed time and an `i32` representation of
///		   number of packets sent.

fn ping(dest: IpAddr, ttl5: Duration) -> (i64, i32) {

	let num_packets = Arc::new(AtomicI32::new(-1));
	let num_packets_copy = Arc::clone(&num_packets);
	let done_sending = Arc::new(AtomicBool::new(true));
	let done_sending_copy = Arc::clone(&done_sending);

	//Construct a channel for sending and receiving at stated ttl
	let mut channel_type = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
	if !dest.is_ipv4() {
		channel_type = Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6));
	}
	let (mut sender, mut receiver) = match transport_channel(BUFFER_SIZE, channel_type) {
		Ok((sender, receiver)) => (sender, receiver),
		Err(e) => {
			println!("***{}.",e.to_string());
			exit(0);
		},
	};
	let ttl: u8 = Duration::as_millis(&ttl5) as u8;
	match sender.set_ttl(ttl / 5) {
		Ok(t) => t,
		Err(e) => {
			println!("***{}.",e.to_string());
			exit(0);
		},
	};

	// SENDER
	let start = Instant::now();
	let done = &done_sending;
	let packets_sent = &num_packets;
	for _x in 0..NUM_PACKETS {
		send(&mut sender, dest);
	}
	done.swap(false, Ordering::Relaxed);
	packets_sent.swap(NUM_PACKETS, Ordering::Relaxed);	

	// LISTENER
	let listener_thread = thread::spawn(move || {

		let start = Instant::now();
		let done = &done_sending_copy;
		let received_packets = &num_packets_copy;
		let mut iter = icmp_packet_iter(&mut receiver);
		let mut count = 0;
		while count < 5 && (start.elapsed() < ttl5 || done.load(Ordering::Relaxed)) {
			thread::sleep(Duration::from_millis(54));
			iter.next().unwrap();
			count += 1;
			//If time exceeded, don't include kill packet echo
			if start.elapsed() > ttl5 {
				count -= 2;
			}
		}
		received_packets.swap(count, Ordering::Relaxed);
	});

	let early_time = start.elapsed().as_micros().to_string().parse::<i64>().unwrap();
	// Compensate for poorly written pmap library by sending kill packet to close
	while start.elapsed() < ttl5 {}
	if dest.is_ipv4() {
		send(&mut sender, IpAddr::V4(Ipv4Addr::LOCALHOST));
	} else {
		send(&mut sender, IpAddr::V6(Ipv6Addr::LOCALHOST));
	}

	listener_thread.join().unwrap();

	// Prep return data
	let mut elapsed = start.elapsed().as_micros().to_string().parse::<i64>().unwrap();
	if packets_sent.load(Ordering::Relaxed) == 5 {
		elapsed = early_time;
	}
	if packets_sent.load(Ordering::Relaxed) < 0 {
		packets_sent.swap(0, Ordering::Relaxed);	
	}
	return (elapsed, packets_sent.load(Ordering::Relaxed));
}


/// Method that sends a single packet to an IP address.
/// As with the ping method, control structures handle
/// IP version.
/// @param sink is a `TransportSender` which is used to
/// send the packet.
/// @param address is an `IpAddr` representing the IP
/// address to send to.

fn send(sink: &mut TransportSender, address: IpAddr) {
	let mut vec : Vec<u8> = vec![0; PKT_SIZE];

	if address.is_ipv4() {

		let mut pkt = echo_request::MutableEchoRequestPacket::new(&mut vec[..]).unwrap();

		pkt.set_sequence_number(0);
		pkt.set_identifier(0);
		pkt.set_icmp_type(IcmpTypes::EchoRequest);

		let csum = icmp_checksum(&pkt);
		pkt.set_checksum(csum);

		let _status = match sink.send_to(pkt, address) {
			Ok(_status) => {
				return;
			}
			Err(e) => {
				println!("***{}",e.to_string());
				return;
			},
		};

	} else {
		let mut pkt = MutableIcmpv6Packet::new(&mut vec[..]).unwrap();
		pkt.set_icmpv6_type(Icmpv6Types::EchoRequest);
		let csum = icmpv6_checksum(&pkt);
		pkt.set_checksum(csum);
		let _status = match sink.send_to(pkt, address) {
			Ok(_status) => {
				return;
			}
			Err(e) => {
				println!("***{}",e.to_string());
				println!("v6 error");
				return;
			},
		};
	}
}


/// Checksum method for ipv4.
/// @param packet is a reference to a `MutableEchoRequestPacket`.
/// @return a `u16` representation of a checksum.

fn icmp_checksum(packet: &echo_request::MutableEchoRequestPacket) -> u16 {
	return util::checksum(packet.packet(),1);
}


/// Checksum method for ipv6.
/// @param packet is a reference to a `MutableIcmpv6Packet`.
/// @return a `u16` representation of a checksum.

fn icmpv6_checksum(packet: &MutableIcmpv6Packet) -> u16 {
	return util::checksum(packet.packet(),1);
}
