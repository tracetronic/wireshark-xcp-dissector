-- XCP_ETH.lua
-- XCP dissector for Wireshark, transport layer "XCP on Ethernet"
-- Version 0.1
--
-- Copyright (c) 2023-2024 tracetronic GmbH
--
-- SPDX-License-Identifier: GPL-2.0


xcp_eth = Proto("xcp_eth", "XCP on Ethernet")

message_length = ProtoField.uint16("xcp_eth.len", "LEN", base.DEC)
message_counter = ProtoField.uint16("xcp_eth.ctr", "CTR", base.DEC)

xcp_eth.fields = { message_length, message_counter }
tcp_stream = Field.new("tcp.stream")
udp_stream = Field.new("udp.stream")
tcp_sport = Field.new("tcp.srcport")
tcp_dport = Field.new("tcp.dstport")
udp_sport = Field.new("udp.srcport")
udp_dport = Field.new("udp.dstport")

function xcp_eth.dissector(buffer, pinfo, tree)
    local bufferLength = buffer:len()
    if bufferLength == 0 then
        return
    end

    pinfo.cols.protocol = xcp_eth.name

    local offset = 0

    while offset + 4 < bufferLength do


        local len = buffer(offset, 2):le_uint()

        -- assumption: if port not 5555, lower port number is ECU, higher is MC software
        if pinfo.port_type == 2 then
            pinfo.private.xcp_conversation = "TCP" .. tostring(tcp_stream())
            if tcp_sport()() == 5555 then
                pinfo.private.xcp_dir = "RES"  -- RES/ERR/EV/SERV/DAQ
            elseif tcp_dport()() == 5555 then
                pinfo.private.xcp_dir = "CMD"  -- CMD/STIM
            elseif tcp_sport()() > tcp_dport()() then
                pinfo.private.xcp_dir = "CMD"  -- CMD/STIM
            else
                pinfo.private.xcp_dir = "RES"  -- RES/ERR/EV/SERV/DAQ
            end
        elseif pinfo.port_type == 3 then
            pinfo.private.xcp_conversation = "UDP" .. tostring(udp_stream())
            if udp_sport()() == 5555 then
                pinfo.private.xcp_dir = "RES"  -- RES/ERR/EV/SERV/DAQ
            elseif udp_dport()() == 5555 then
                pinfo.private.xcp_dir = "CMD"  -- CMD/STIM
            elseif udp_sport()() > udp_dport()() then
                pinfo.private.xcp_dir = "CMD"  -- CMD/STIM
            else
                pinfo.private.xcp_dir = "RES"  -- RES/ERR/EV/SERV/DAQ
            end
        end
        local subtree = tree:add(xcp_eth, buffer(offset, len + 4), "XCP")
        local ethSubtree = subtree:add(xcp_eth, buffer(offset, 4))
        ethSubtree:add(message_length, buffer(offset, 2), len)
        ethSubtree:add_le(message_counter, buffer(offset + 2, 2))
        Dissector.get("xcp"):call(buffer(offset + 4, len):tvb(), pinfo, subtree)
        offset = offset + len + 4

    end
end

local tcp_port = DissectorTable.get("tcp.port")
local udp_port = DissectorTable.get("udp.port")

tcp_port:add(5555, xcp_eth)
udp_port:add(5555, xcp_eth)
-- udp_port:add(5556, xcp_eth)  GET_SLAVE_ID
-- udp_port:add(5557, xcp_eth)  GET_DAQ_CLOCK_MULTICAST
