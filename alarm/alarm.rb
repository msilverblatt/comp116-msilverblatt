require 'packetfu'

$inum = 1

def checkCC(pkt)
	if pkt.is_tcp?
		protocol = "TCP"
	elsif pkt.is_udp?
		protocol = "UDP"
	end

	if ((pkt.ip_header.body.to_s =~ /\W(4|5)\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}\W/) != nil)
		reportIncident("CC leaked in plain-text", pkt.ip_saddr, protocol)
	elsif ((pkt.ip_header.body.to_s =~ /\W6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}\W/) != nil )
		reportIncident("CC leaked in plain-text", pkt.ip_saddr, protocol)	
	elsif ((pkt.ip_header.body.to_s =~ /\W3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}\W/) != nil)
		reportIncident("CC leaked in plain-text", pkt.ip_saddr, protocol)
	end
end


def checkPW(pkt)
	if ((pkt.ip_header.body.to_s =~ /(p|P)(a|A)(s|S){2}(w|W)(o|O)(r|R)(d|D)/) != nil)
		if pkt.is_tcp?
			protocol = "TCP"
		elsif pkt.is_udp?
			protocol = "UDP"
		end
		reportIncident("Password leaked in the clear", pkt.ip_saddr, protocol)
	end
end


def checkNull(pkt)
	#puts pkt.peek_format()
	if pkt.is_tcp? 
		f = pkt.tcp_flags
		unless f.urg == 1
			unless f.ack == 1
				unless f.psh == 1
					unless f.rst == 1 
						unless f.syn == 1
							unless f.fin == 1
								reportIncident("NULL SCAN", pkt.ip_saddr, "TCP")
							end
						end
					end
				end
			end
		end
	end
end


def checkXmas(pkt)
	if pkt.is_tcp? 
		f = pkt.tcp_flags
		unless f.urg == 0
			unless f.ack == 1
				unless f.psh == 0
					unless f.rst == 1 
						unless f.syn == 1
							unless f.fin == 0
								reportIncident("XMAS SCAN", pkt.ip_saddr, "TCP")
							end
						end
					end
				end
			end
		end
	end
end


def checkFin(pkt)
	if pkt.is_tcp? 
		f = pkt.tcp_flags
		unless f.urg == 1
			unless f.ack == 1
				unless f.psh == 1
					unless f.rst == 1 
						unless f.syn == 1
							unless f.fin == 0
								reportIncident("FIN SCAN", pkt.ip_saddr, "TCP")
							end
						end
					end
				end
			end
		end
	end
end

def checkSyn(pkt)
	if pkt.is_tcp? 
		f = pkt.tcp_flags
		unless f.urg == 1
			unless f.ack == 1
				unless f.psh == 1
					unless f.rst == 1 
						unless f.syn == 0
							unless f.fin == 1
								if pkt.ip_len == 44
									reportIncident("SYN SCAN", pkt.ip_saddr, "TCP")
								end
							end
						end
					end
				end
			end
		end
	end
end


def checkNmap(pkt)

end


def checkXSS(pkt)
	if ((pkt.ip_header.body.to_s =~ /%3C(s|S)(c|C)(r|R)(i|I)(p|P)(t|T)%3E/) != nil)
		if pkt.is_tcp?
			protocol = "TCP"
		elsif pkt.is_udp?
			protocol = "UDP"
		end
		reportIncident("Cross-site Scripting", pkt.ip_saddr, protocol)
	end
end


def checkUDP(pkt)
	if pkt.is_udp?
		if pkt.udp_len <= 8
			reportIncident("UDP SCAN", pkt.ip_saddr, "UDP")
		end
	end
end


def reportIncident(attack, srcip, protocol)
	puts "#{$inum}. ALERT: #{attack} is detected from #{srcip} (#{protocol})!"
	$inum += 1
end


stream = PacketFu::Capture.new(:start => true, :iface => 'en1', :promisc => true)
stream.stream.each do |p|
	pkt = PacketFu::Packet.parse p
	if pkt.is_ip?
	#	puts "Found an IP packet"
		checkCC(pkt)
		checkPW(pkt)
		checkNull(pkt)
		checkSyn(pkt)
		checkFin(pkt)
		checkXmas(pkt)
		checkNmap(pkt)
		checkXSS(pkt)
		checkUDP(pkt)
	else 
	#	puts "Found a non-IP packet"
		#checkNull(pkt)
	end
end


#stream.show_live()



