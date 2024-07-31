-- XCP_CAN.lua
-- XCP dissector for Wireshark, transport layer "XCP on CAN (FD)"
-- Version 0.1
--
-- Copyright (c) 2023-2024 tracetronic GmbH
--
-- SPDX-License-Identifier: GPL-2.0



xcp_can = Proto("xcp_can", "XCP on CAN")
xcp_can.fields = {}
can_id_field = Field.new("can.id")

xcp_can.prefs.info = Pref.statictext("Only CAN frames whose CAN IDs match the CAN IDs configured in fields below are dissected")
xcp_can.prefs.master_can_ids = Pref.range("Master CAN IDs:", "", "CAN IDs which a master \z
uses to send frames to a slave\n\nMultiple comma separated values (both decimal and hex) \z
are supported e.g.: '21,0x42,0xab'.\n\z Ranges like '21-42' are NOT supported.", 2^29)
xcp_can.prefs.slave_can_ids = Pref.range("Slave CAN IDs:   ", "", "CAN IDs which slaves \z
are using to send frames to the master\n\nMultiple comma separated values (both decimal and hex) \z
are supported e.g.: '21,0x42,0xab'.\nRanges like '21-42' are NOT supported.", 2^29)


local function contains(table, value)
    for _, table_value in ipairs(table) do
        if table_value == value then
            return true
        end
    end
    return false
end


local function parse_ids(str)
    local ids = {}
    for id in string.gmatch(str, '([^,]+)') do
        table.insert(ids, tonumber(id))
    end
    return ids
end


function xcp_can.dissector(buffer, pinfo, tree)
    local bufferLength = buffer:len()
    if bufferLength == 0 then
        return
    end

    local master_ids = parse_ids(xcp_can.prefs.master_can_ids)
    local slave_ids = parse_ids(xcp_can.prefs.slave_can_ids)
    local can_id = can_id_field().value

    if not contains(master_ids, can_id) and not contains(slave_ids, can_id) then
        return
    end
    
    if contains(master_ids, can_id) then
        pinfo.private.xcp_dir = "CMD"  -- CMD/STIM
        pinfo.cols.src = string.format("Master 0x%02x", can_id)
    end

    if contains(slave_ids, can_id) then
        pinfo.private.xcp_dir = "RES"  -- RES/ERR/EV/SERV/DAQ
        pinfo.cols.src = string.format("Slave  0x%02x", can_id)
    end

    pinfo.private.xcp_conversation = "CAN"

    pinfo.cols.protocol = xcp_can.name
    local subtree = tree:add(xcp_can, buffer(), "XCP on CAN")
    Dissector.get("xcp"):call(buffer():tvb(), pinfo, subtree)
end


local sd = DissectorTable.get("can.subdissector")
sd:add_for_decode_as(xcp_can)