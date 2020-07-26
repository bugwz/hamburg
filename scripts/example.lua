function process(packet)
    print(string.format("%20s %15s:%-5s => %15s:%-5s || %4s || Seq:%-10s || Ack:%-10s || %-12s || PayloadLen:%s",
        packet.type, -- packet type
        packet.sip, -- source ip
        packet.sport, -- source port
        packet.dip, -- destination ip
        packet.dport, -- destination port
        packet.direction, -- packet direction
        packet.seq, -- sequence number
        packet.ack, -- ack number
        packet.flag, -- flags, e.g. syn|ack|psh..
        packet.payloadlen -- payload
    ))
end
