-- XCP.lua
-- XCP dissector for Wireshark, protocol layer
-- Version 0.1
--
-- Copyright (c) 2023-2024 tracetronic GmbH
--
-- SPDX-License-Identifier: GPL-2.0


xcpProto = Proto("xcp", "Universal Measurement and Calibration Protocol")

--[[
conversations: request-response tracking
for each conversation ID (e.g. tcp.stream), for each packet, record
* for commands, the PID (so the response can be interpreted accordingly)
* for commands whose parameters influence the repsonse format, these parameters
* for commands and responses whose parameters influence events or behavior of other commands, these parameters
* for commands and responses that describe DAQ properties, the information needed later to decode DAQ packets

find_stored_data can then retrieve the latest (but before the current packet) value for a specific recorded datum (such as PID)

current limitations: the interleaved communication model is not supported
]]
--
conversations = {}

COMMAND_NAMES = {
    -- Standard commands
    [0xFF] = "CONNECT",
    [0xFE] = "DISCONNECT",
    [0xFD] = "GET_STATUS",
    [0xFC] = "SYNCH",
    [0xFB] = "GET_COMM_MODE_INFO",
    [0xFA] = "GET_ID",
    [0xF9] = "SET_REQUEST",
    [0xF8] = "GET_SEED",
    [0xF7] = "UNLOCK",
    [0xF6] = "SET_MTA",
    [0xF5] = "UPLOAD",
    [0xF4] = "SHORT_UPLOAD",
    [0xF3] = "BUILD_CHECKSUM",
    [0xF2] = "TRANSPORT_LAYER_CMD",
    [0xF1] = "USER_CMD",
    -- Calibration commands
    [0xF0] = "DOWNLOAD",
    [0xEF] = "DOWNLOAD_NEXT",
    [0xEE] = "DOWNLOAD_MAX",
    [0xED] = "SHORT_DOWNLOAD",
    [0xEC] = "MODIFY_BITS",
    -- Page switching commands
    [0xEB] = "SET_CAL_PAGE",
    [0xEA] = "GET_CAL_PAGE",
    [0xE9] = "GET_PAG_PROCESSOR_INFO",
    [0xE8] = "GET_SEGMENT_INFO",
    [0xE7] = "GET_PAGE_INFO",
    [0xE6] = "SET_SEGMENT_MODE",
    [0xE5] = "GET_SEGMENT_MODE",
    [0xE4] = "COPY_CAL_PAGE",
    -- Basic data acquisition and stimulation commands
    [0xE2] = "SET_DAQ_PTR",
    [0xE1] = "WRITE_DAQ",
    [0xE0] = "SET_DAQ_LIST_MODE",
    [0xDE] = "START_STOP_DAQ_LIST",
    [0xDD] = "START_STOP_SYNCH",
    [0xC7] = "WRITE_DAQ_MULTIPLE",
    [0xDB] = "READ_DAQ",
    [0xDC] = "GET_DAQ_CLOCK",
    [0xDA] = "GET_DAQ_PROCESSOR_INFO",
    [0xD9] = "GET_DAQ_RESOLUTION_INFO",
    [0xDF] = "GET_DAQ_LIST_MODE",
    [0xD7] = "GET_DAQ_EVENT_INFO",
    [0xC5] = "DTO_CTR_PROPERTIES",
    -- Static data acquisition and stimulation commands
    [0xE3] = "CLEAR_DAQ_LIST",
    [0xD8] = "GET_DAQ_LIST_INFO",
    -- Dynamic data acquisition and stimulation commands
    [0xD6] = "FREE_DAQ",
    [0xD5] = "ALLOC_DAQ",
    [0xD4] = "ALLOC_ODT",
    [0xD3] = "ALLOC_ODT_ENTRY",
    -- Non-volatile memory programming commands
    [0xD2] = "PROGRAM_START",
    [0xD1] = "PROGRAM_CLEAR",
    [0xD0] = "PROGRAM",
    [0xCF] = "PROGRAM_RESET",
    [0xCE] = "GET_PGM_PROCESSOR_INFO",
    [0xCD] = "GET_SECTOR_INFO",
    [0xCC] = "PROGRAM_PREPARE",
    [0xCB] = "PROGRAM_FORMAT",
    [0xCA] = "PROGRAM_NEXT",
    [0xC9] = "PROGRAM_MAX",
    [0xC8] = "PROGRAM_VERIFY",
    -- Time synchronization commands
    [0xC6] = "TIME_CORRELATION_PROPERTIES",
}

ERR_CODES = {
    [0x00] = "ERR_CMD_SYNCH",
    [0x10] = "ERR_CMD_BUSY",
    [0x11] = "ERR_DAQ_ACTIVE",
    [0x12] = "ERR_PGM_ACTIVE",
    [0x20] = "ERR_CMD_UNKNOWN",
    [0x21] = "ERR_CMD_SYNTAX",
    [0x22] = "ERR_OUT_OF_RANGE",
    [0x23] = "ERR_WRITE_PROTECTED",
    [0x24] = "ERR_ACCESS_DENIED",
    [0x25] = "ERR_ACCESS_LOCKED",
    [0x26] = "ERR_PAGE_NOT_VALID",
    [0x27] = "ERR_MODE_NOT_VALID",
    [0x28] = "ERR_SEGMENT_NOT_VALID",
    [0x29] = "ERR_SEQUENCE",
    [0x2A] = "ERR_DAQ_CONFIG",
    [0x30] = "ERR_MEMORY_OVERFLOW",
    [0x31] = "ERR_GENERIC",
    [0x32] = "ERR_VERIFY",
    [0x33] = "ERR_RESOURCE_TEMPORARY_NOT_ACCESSIBLE",
    [0x34] = "ERR_SUBCMD_UNKNOWN",
}

EV_CODES = {
    [0x00] = "EV_RESUME_MODE",
    [0x01] = "EV_CLEAR_DAQ",
    [0x02] = "EV_STORE_DAQ",
    [0x03] = "EV_STORE_CAL",
    [0x05] = "EV_CMD_PENDING",
    [0x06] = "EV_DAQ_OVERLOAD",
    [0x07] = "EV_SESSION_TERMINATED",
    [0x08] = "EV_TIME_SYNC",
    [0x09] = "EV_STIM_TIMEOUT",
    [0x0A] = "EV_SLEEP",
    [0x0B] = "EV_WAKE_UP",
    [0x0C] = "EV_ECU_STATE_CHANGE",
    [0xFE] = "EV_USER",
    [0xFF] = "EV_TRANSPORT",
}

SERV_CODES = {
    [0x00] = "SERV_RESET",
    [0x01] = "SERV_TEXT",
}

AG_TYPES = {
    [0] = "bytes",
    [1] = "words",
    [2] = "dwords",
    [3] = "elements (of unknown size)"
}

xcp_type = ProtoField.string("xcp.type", "TYPE", base.ASCII)
xcp_cmd = ProtoField.uint8("xcp.cmd", "CMD", base.HEX, COMMAND_NAMES)
xcp_err = ProtoField.uint8("xcp.err", "ERR", base.HEX, ERR_CODES)
xcp_ev = ProtoField.uint8("xcp.ev", "EV", base.HEX, EV_CODES)
xcp_serv = ProtoField.uint8("xcp.serv", "SERV", base.HEX, SERV_CODES)
xcp_info = ProtoField.string("xcp.info", "INFO", base.ASCII)
xcp_data = ProtoField.bytes("xcp.data", "DATA", base.SPACE)
xcp_request = ProtoField.framenum("xcp.request", "REQUEST", base.NONE, frametype.REQUEST, 0, "Associated request")
xcp_reserved = ProtoField.bytes("xcp.reserved", "RESERVED", base.SPACE)

xcpProto.fields = { xcp_type, xcp_cmd, xcp_err, xcp_ev, xcp_serv, xcp_info, xcp_data, xcp_request, xcp_reserved }

local band = bit.band
local rshift = bit.rshift
local lshift = bit.lshift
local format = string.format

function hex(number, digits)
    if type(number) == "table" then
        return "0x" .. number:tohex(digits / 2)
    end
    return format("0x%0" .. digits .. "x", number)
end

function parse_number(bufferslice, comm_mode_basic)
    -- convert a buffer slice into a number, using the correct endianness. Use uint64 only if needed
    if bufferslice:len() == 8 then
        if band(comm_mode_basic, 1) == 0 then
            return bufferslice:le_uint64()
        else
            return bufferslice:uint64()
        end
    end
    if band(comm_mode_basic, 1) == 0 then
        return bufferslice:le_uint()
    else
        return bufferslice:uint()
    end
end

function find_stored_data(conversation_id, max_pkt_num, key, default)
    -- find the stored data from the highest-numbered packet of the current conversation that has a lower number than the current one
    local found_pktnum = -1
    local found_data = default
    for pkt_num, pkt_data in pairs(conversations[conversation_id]) do
        if pkt_num <= max_pkt_num and pkt_num >= found_pktnum then
            if pkt_data ~= nil and pkt_data[key] ~= nil then
                found_pktnum = pkt_num
                found_data = pkt_data[key]
            end
        end
    end
    return found_data
end

function decode_cmd_connect(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    pkt_data.TIME_SYNCHRONIZATION_PROPERTIES__extended = false
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    if mode == 0 then
        tree:add(xcp_info, mode_field, "mode: Normal (0)")
    elseif mode == 1 then
        tree:add(xcp_info, mode_field, "mode: user-defined (1)")
    else
        tree:add(xcp_info, mode_field, "mode: " .. mode .. " (unknown)")
    end
end

function decode_cmd_get_id(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local id_type_field = buffer(1, 1)
    local id_type = id_type_field:uint()
    if id_type == 0 then
        tree:add(xcp_info, id_type_field, "type: ASCII text (0)")
    elseif id_type == 1 then
        tree:add(xcp_info, id_type_field, "type: ASAM-MC2 filename without path and extension (1)")
    elseif id_type == 2 then
        tree:add(xcp_info, id_type_field, "type: ASAM-MC2 filename with path and extension (2)")
    elseif id_type == 3 then
        tree:add(xcp_info, id_type_field, "type: URL where the ASAM-MC2 file can be found (3)")
    elseif id_type == 4 then
        tree:add(xcp_info, id_type_field, "type: ASAM-MC2 file to upload (4)")
    elseif 128 <= id_type and id_type <= 255 then
        tree:add(xcp_info, id_type_field, "type: user defined (" .. hex(id_type, 2) .. ")")
    else
        tree:add(xcp_info, id_type_field, "type: unknown (" .. hex(id_type, 2) .. ")")
    end
end

function decode_cmd_set_request(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local sess_field = buffer(2, 2)
    local session_configuration_id = parse_number(sess_field, comm_mode_basic)
    local infotext = "mode: " .. hex(mode, 2) .. " -- "
    if band(mode, 0x1) ~= 0 then
        infotext = infotext .. "STORE_CAL_REQ|"
    end
    if band(mode, 0x2) ~= 0 then
        infotext = infotext .. "STORE_DAQ_REQ_NO_RESUME|"
    end
    if band(mode, 0x4) ~= 0 then
        infotext = infotext .. "STORE_DAQ_REQ_RESUME|"
    end
    if band(mode, 0x8) ~= 0 then
        infotext = infotext .. "CLEAR_DAQ_REQ|"
    end
    if mode == 0 then
        infotext = "mode: 0|"
    end
    tree:add(xcp_info, mode_field, infotext:sub(1, -2))
    tree:add(xcp_info, sess_field, "session configuration id: " .. session_configuration_id)
end

function decode_cmd_get_seed(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local resource_field = buffer(2, 1)
    local resource = resource_field:uint()
    pkt_data.GET_SEED__MODE = mode
    if mode == 0 then
        tree:add(xcp_info, mode_field, "Mode: 0 -- first part of seed")
        tree:add(xcp_info, resource_field, "resource: " .. resource)
    elseif mode == 1 then
        tree:add(xcp_info, mode_field, "Mode: 1 -- remaining part of seed")
        tree:add(xcp_reserved, resource_field, "don't care")
    else
        tree:add(xcp_info, mode_field, "Mode: unknown (" .. hex(mode, 2) .. ")")
        tree:add(xcp_info, resource_field, "resource: " .. resource)
    end
end

function decode_cmd_unlock(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local length_field = buffer(1, 1)
    local length = length_field:uint()
    local key = buffer(2)
    tree:add(xcp_info, length_field, "remaining key length: " .. length)
    tree:add(xcp_data, key, key:bytes():raw())
end

function decode_cmd_set_mta(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local addrExt_field = buffer(3, 1)
    local addrExt = addrExt_field:uint()
    local address_field = buffer(4, 4)
    local address = parse_number(address_field, comm_mode_basic)
    tree:add(xcp_reserved, buffer(1, 2))
    tree:add(xcp_info, addrExt_field, "Address Extension: " .. hex(addrExt, 2))
    tree:add(xcp_info, address_field, "Address: " .. hex(address, 8))
end

function decode_cmd_upload(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local nElem_field = buffer(1, 1)
    local nElem = nElem_field:uint()
    -- save nElem to conversations to retrieve data field length in next pos upload response
    pkt_data["N_ELEM"] = nElem
    tree:add(xcp_info, nElem_field, nElem .. " " .. AG_TYPES[address_granularity])
end

function decode_cmd_short_upload(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local nElem_field = buffer(1, 1)
    local nElem = nElem_field:uint()
    -- save nElem to conversations to retrieve data field length in next pos upload response
    pkt_data["N_ELEM"] = nElem
    local addrExt_field = buffer(3, 1)
    local addrExt = addrExt_field:uint()
    local address_field = buffer(4, 4)
    local address = parse_number(address_field, comm_mode_basic)
    tree:add(xcp_info, nElem_field, nElem .. " " .. AG_TYPES[address_granularity])
    tree:add(xcp_reserved, buffer(2, 1))
    tree:add(xcp_info, addrExt_field, "Address Extension: " .. hex(addrExt, 2))
    tree:add(xcp_info, address_field, "Address: " .. hex(address, 8))
end

function decode_cmd_build_checksum(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local blockSize_field = buffer(4, 4)
    local blockSize = parse_number(blockSize_field, comm_mode_basic)
    tree:add(xcp_reserved, buffer(1, 3))
    tree:add(xcp_info, blockSize_field, blockSize .. " " .. AG_TYPES[address_granularity])
end

function decode_cmd_transport_layer_cmd__user_cmd(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local subCmd_field = buffer(1, 1)
    local subCmd = subCmd_field:uint()
    local params_field = buffer(2)
    local params = params_field:bytes():raw()
    tree:add(xcp_info, subCmd_field, "Subcommand " .. hex(subCmd, 2))
    tree:add(xcp_data, params_field, params)
end

function decode_cmd_download__program(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local nElem_field = buffer(1, 1)
    local nElem = nElem_field:uint()
    local data_field = buffer(2, nElem*2^address_granularity)
    local data = data_field:bytes():raw()
    tree:add(xcp_info, nElem_field, nElem .. " " .. AG_TYPES[address_granularity])
    if address_granularity == 2 then
        tree:add(xcp_reserved, buffer(2, 2), "DWORD alignment")
        data_field = data_field(2)
        data = data_field:bytes():raw()
    end
    tree:add(xcp_data, data_field, data)
end

function decode_cmd_download__program__max(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local offset = 1
    if address_granularity == 0 then
        -- no alignment
    elseif address_granularity == 1 then
        offset = 2
        tree:add(xcp_reserved, buffer(1, 1), "WORD alignment")
    elseif address_granularity == 2 then
        offset = 4
        tree:add(xcp_reserved, buffer(1, 3), "DWORD alignment")
    end
    local data_field = buffer(offset)
    local data = data_field:bytes():raw()
    tree:add(xcp_data, data_field, data)
end

function decode_cmd_short_download(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local nElem_field = buffer(1, 1)
    local nElem = nElem_field:uint()
    local addrExt_field = buffer(3, 1)
    local addrExt = addrExt_field:uint()
    local address_field = buffer(4, 4)
    local address = parse_number(address_field, comm_mode_basic)
    tree:add(xcp_info, nElem_field, nElem .. " " .. AG_TYPES[address_granularity])
    tree:add(xcp_reserved, buffer(2, 1))
    tree:add(xcp_info, addrExt_field, "Address Extension: " .. hex(addrExt, 2))
    tree:add(xcp_info, address_field, "Address: " .. hex(address, 8))
    local data_field = buffer(8, nElem*2^address_granularity)
    local data = data_field:bytes():raw()
    tree:add(xcp_data, data_field, data)
end

function decode_cmd_modify_bits(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local shiftValue_field = buffer(1, 1)
    local shiftValue = shiftValue_field:uint()
    local andMask_field = buffer(2, 2)
    local xorMask_field = buffer(4, 2)
    tree:add(xcp_info, shiftValue_field, "Shift value: " .. hex(shiftValue, 2))
    tree:add(xcp_info, andMask_field, "AND mask: " .. andMask_field:bytes():raw():tohex(false, ":"))
    tree:add(xcp_info, xorMask_field, "XOR mask: " .. xorMask_field:bytes():raw():tohex(false, ":"))
end

function decode_cmd_set_cal_page(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local segNum_field = buffer(2, 1)
    local segNum = segNum_field:uint()
    local pageNum_field = buffer(3, 1)
    local pageNum = pageNum_field:uint()
    if band(mode, 0x3) == 0x3 then
        tree:add(xcp_info, mode_field, "Mode: ECU | XCP (3)")
    elseif band(mode, 0x3) == 0x2 then
        tree:add(xcp_info, mode_field, "Mode: XCP (2)")
    elseif band(mode, 0x3) == 0x1 then
        tree:add(xcp_info, mode_field, "Mode: ECU (1)")
    else
        tree:add(xcp_info, mode_field, "Mode: No access (0)")
    end
    if band(mode, 0x80) ~= 0 then
        tree:add(xcp_info, mode_field, "All segments (0x80)")
        tree:add(xcp_reserved, segNum_field, "Segment number ignored")
    else
        tree:add(xcp_info, segNum_field, "Segment " .. segNum)
    end
    if band(mode, 0x7c) ~= 0 then
        tree:add(xcp_info, mode_field, "Mode: unknown flags (" .. hex(band(mode, 0x7c), 2) .. ")")
    end
    tree:add(xcp_info, pageNum_field, "Page " .. pageNum)
end

function decode_cmd_get_cal_page(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local segNum_field = buffer(2, 1)
    local segNum = segNum_field:uint()

    if mode == 2 then
        tree:add(xcp_info, mode_field, "Mode: XCP (2)")
    elseif mode == 1 then
        tree:add(xcp_info, mode_field, "Mode: ECU (1)")
    else
        tree:add(xcp_info, mode_field, "Mode: invalid (" .. hex(mode, 2) .. ")")
    end
    tree:add(xcp_info, segNum_field, "Segment " .. segNum)
end

function decode_cmd_get_segment_info(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local segNum_field = buffer(2, 1)
    local segNum = segNum_field:uint()
    local segInfo_field = buffer(3, 1)
    local segInfo = segInfo_field:uint()
    local mapIdx_field = buffer(4, 1)
    local mapIdx = mapIdx_field:uint()
    if mode == 0 then
        tree:add(xcp_info, mode_field, "Mode: basic address info (0)")
    elseif mode == 1 then
        tree:add(xcp_info, mode_field, "Mode: standard info (1)")
    elseif mode == 2 then
        tree:add(xcp_info, mode_field, "Mode: address mapping info (2)")
    else
        tree:add(xcp_info, mode_field, "Mode: unknown (" .. hex(mode, 2) .. ")")
    end
    tree:add(xcp_info, segNum_field, "Segment number: " .. segNum)
    if mode == 0 then
        if segInfo == 0 then
            tree:add(xcp_info, segInfo_field, "Segment Info: address (0)")
        elseif segInfo == 1 then
            tree:add(xcp_info, segInfo_field, "Segment Info: length (1)")
        else
            tree:add(xcp_info, segInfo_field, "Segment Info: unknown (" .. hex(segInfo, 2) .. ")")
        end
        tree:add(xcp_reserved, mapIdx_field, "Mapping Index: ignored")
    elseif mode == 1 then
        tree:add(xcp_reserved, segInfo_field, "Segment Info: ignored")
        tree:add(xcp_reserved, mapIdx_field, "Mapping Index: ignored")
    elseif mode == 2 then
        if segInfo == 0 then
            tree:add(xcp_info, segInfo_field, "Segment Info: source address (0)")
        elseif segInfo == 1 then
            tree:add(xcp_info, segInfo_field, "Segment Info: destination address (1)")
        elseif segInfo == 2 then
            tree:add(xcp_info, segInfo_field, "Segment Info: length address (2)")
        else
            tree:add(xcp_info, segInfo_field, "Segment Info: unknown (" .. hex(segInfo, 2) .. ")")
        end
        tree:add(xcp_info, mapIdx_field, "Mapping Index: " .. mapIdx)
    end
    pkt_data.GET_SEGMENT_INFO__MODE = mode
    pkt_data.GET_SEGMENT_INFO__SEGMENT_INFO = segInfo
end

function decode_cmd_get_page_info(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local segNum_field = buffer(2, 1)
    local segNum = segNum_field:uint()
    local pageNum_field = buffer(3, 1)
    local pageNum = pageNum_field:uint()
    tree:add(xcp_reserved, buffer(1, 1), "Reserved")
    tree:add(xcp_info, segNum_field, "Segment number: " .. segNum)
    tree:add(xcp_info, pageNum_field, "Page number: " .. pageNum)
end

function decode_cmd_set_segment_mode(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local segNum_field = buffer(2, 1)
    local segNum = segNum_field:uint()
    if band(mode, 1) == 1 then
        tree:add(xcp_info, mode_field, "Mode: enable FREEZE (bit 0 set)")
    else
        tree:add(xcp_info, mode_field, "Mode: disable FREEZE (bit 0 not set)")
    end
    if band(mode, 0xfe) ~= 0 then
        tree:add(xcp_info, mode_field, "Mode: unknown flags set (" .. hex(mode, 2) .. ")")
    end
    tree:add(xcp_info, segNum_field, "Segment number: " .. segNum)
end

function decode_cmd_get_segment_mode(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local segNum_field = buffer(2, 1)
    local segNum = segNum_field:uint()
    tree:add(xcp_reserved, buffer(1, 1), "Reserved")
    tree:add(xcp_info, segNum_field, "Segment number: " .. segNum)
end

function decode_cmd_copy_cal_page(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local segSrc_field = buffer(1, 1)
    local segSrc = segSrc_field:uint()
    local pageSrc_field = buffer(2, 1)
    local pageSrc = pageSrc_field:uint()
    local segDst_field = buffer(3, 1)
    local segDst = segDst_field:uint()
    local pageDst_field = buffer(4, 1)
    local pageDst = pageDst_field:uint()
    tree:add(xcp_info, segSrc_field, "Source segment: " .. segSrc)
    tree:add(xcp_info, pageSrc_field, "Source page: " .. pageSrc)
    tree:add(xcp_info, segDst_field, "Destination segment: " .. segDst)
    tree:add(xcp_info, pageDst_field, "Destination page: " .. pageDst)
end

function decode_cmd_clear_daq_list__get_daq_list_mode__info(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local daqListNr_field = buffer(2, 2)
    local daqListNr = parse_number(daqListNr_field, comm_mode_basic)
    tree:add(xcp_reserved, buffer(1, 1))
    tree:add(xcp_info, daqListNr_field, "DAQ List number: " .. daqListNr)
end

function decode_cmd_set_daq_ptr(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local daqListNr_field = buffer(2, 2)
    local daqListNr = parse_number(daqListNr_field, comm_mode_basic)
    local odtNr_field = buffer(4, 1)
    local odtNr = odtNr_field:uint()
    local odtEntryNr_field = buffer(5, 1)
    local odtEntryNr = odtEntryNr_field:uint()
    tree:add(xcp_reserved, buffer(1, 1), "Reserved")
    tree:add(xcp_info, daqListNr_field, "DAQ list number: " .. daqListNr)
    tree:add(xcp_info, odtNr_field, "ODT number (relative): " .. odtNr)
    tree:add(xcp_info, odtEntryNr_field, "ODT entry number (relative): " .. odtEntryNr)
end

function decode_cmd_write_daq(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local bitOffset_field = buffer(1, 1)
    local bitOffset = bitOffset_field:uint()
    local size_field = buffer(2, 1)
    local size = size_field:uint()
    local addrExt_field = buffer(3, 1)
    local addrExt = addrExt_field:uint()
    local addr_field = buffer(4, 4)
    local addr = parse_number(addr_field, comm_mode_basic)

    if bitOffset == 0xff then
        tree:add(xcp_info, bitOffset_field, "whole data element (0xff)")
    else
        tree:add(xcp_info, bitOffset_field, "Bit offset: " .. hex(bitOffset, 2))
        if bitOffset <= 0x1f then
            local bitMask = lshift(1, bitOffset)
            tree:add(xcp_info, bitOffset_field, "Bit mask: " .. hex(bitMask, 8))
        end
    end

    tree:add(xcp_info, size_field, "Size: " .. size .. " " .. AG_TYPES[address_granularity])

    tree:add(xcp_info, addrExt_field, "Address extension: " .. hex(addrExt, 2))
    tree:add(xcp_info, addr_field, "Address: " .. hex(addr, 8))
end

function decode_cmd_set_daq_list_mode(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local daqListNr_field = buffer(2, 2)
    local daqListNr = parse_number(daqListNr_field, comm_mode_basic)
    local eventChannelNr_field = buffer(4, 2)
    local eventChannelNr = parse_number(eventChannelNr_field, comm_mode_basic)
    local prescaler_field = buffer(6, 1)
    local prescaler = prescaler_field:uint()
    local prio_field = buffer(7, 1)
    local prio = prio_field:uint()

    local mode_string = hex(mode, 2) .. " -- "
    if band(mode, 0x1) == 0 then
        mode_string = mode_string .. "Alternating: off, "
    else
        mode_string = mode_string .. "Alternating: on, "
    end
    if band(mode, 0x2) == 0 then
        mode_string = mode_string .. "Direction: DAQ, "
    else
        mode_string = mode_string .. "Direction: STIM, "
    end
    if band(mode, 0x8) == 0 then
        mode_string = mode_string .. "DTO_CTR: not used, "
        pkt_data.DTO_CTR = { table.unpack(find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "DTO_CTR", {})) }
        pkt_data.DTO_CTR[daqListNr] = false
    else
        mode_string = mode_string .. "DTO_CTR: in use, "
        pkt_data.DTO_CTR = { table.unpack(find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "DTO_CTR", {})) }
        pkt_data.DTO_CTR[daqListNr] = true
    end
    if band(mode, 0x10) == 0 then
        mode_string = mode_string .. "Timestamp: disabled, "
        pkt_data.TIMESTAMP_ENABLED = false
    else
        mode_string = mode_string .. "Timestamp: enabled, "
        pkt_data.TIMESTAMP_ENABLED = true
    end
    if band(mode, 0x20) == 0 then
        mode_string = mode_string .. "PID_OFF: disabled - DTO with identification field"
    else
        mode_string = mode_string .. "PID_OFF: enabled - DTO without identification field"
    end

    tree:add(xcp_info, mode_field, mode_string)
    tree:add(xcp_info, daqListNr_field, "DAQ List #" .. daqListNr)
    tree:add(xcp_info, eventChannelNr_field, "Event Channel #" .. eventChannelNr)
    tree:add(xcp_info, prescaler_field, "Prescaler: " .. prescaler)
    tree:add(xcp_info, prio_field, "Priority: " .. prio)
end

function decode_cmd_start_stop_daq_list(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local daqListNr_field = buffer(2, 2)
    local daqListNr = parse_number(daqListNr_field, comm_mode_basic)
    pkt_data.DAQ_LIST_NR = daqListNr
    pkt_data.DAQ_RUNNING = { table.unpack(find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "DAQ_RUNNING", {})) }
    pkt_data.DAQ_SELECTED = { table.unpack(find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "DAQ_RUNNING", {})) }
    if mode == 0 then
        tree:add(xcp_info, mode_field, "Mode: stop (0)")
        pkt_data.DAQ_RUNNING[daqListNr] = false
    elseif mode == 1 then
        tree:add(xcp_info, mode_field, "Mode: start (1)")
        pkt_data.DAQ_RUNNING[daqListNr] = true
    elseif mode == 2 then
        tree:add(xcp_info, mode_field, "Mode: select (2)")
        pkt_data.DAQ_SELECTED[daqListNr] = true
    else
        tree:add(xcp_info, mode_field, "Mode: unknown (" .. hex(mode, 2) .. ")")
    end
    tree:add(xcp_info, daqListNr_field, "DAQ List #" .. daqListNr)
end

function decode_cmd_start_stop_synch(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    pkt_data.DAQ_RUNNING = { table.unpack(find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "DAQ_RUNNING", {})) }
    pkt_data.DAQ_SELECTED = { table.unpack(find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "DAQ_RUNNING", {})) }
    if mode == 0 then
        tree:add(xcp_info, mode_field, "Mode: stop all (0)")
        pkt_data.DAQ_RUNNING = {}
        pkt_data.DAQ_SELECTED = {}
    elseif mode == 1 then
        tree:add(xcp_info, mode_field, "Mode: start selected (1)")
        pkt_data.DAQ_RUNNING = pkt_data.DAQ_SELECTED
        pkt_data.DAQ_SELECTED = {}
    elseif mode == 2 then
        tree:add(xcp_info, mode_field, "Mode: stop selected (2)")
        for daq, flag in pairs(pkt_data.DAQ_SELECTED) do
            pkt_data.DAQ_RUNNING[daq] = false
        end
        pkt_data.DAQ_SELECTED = {}
    else
        tree:add(xcp_info, mode_field, "Mode: unknown (" .. hex(mode, 2) .. ")")
    end
end

function decode_cmd_get_daq_event_info(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local eventChannelNr_field = buffer(2, 2)
    local eventChannelNr = parse_number(eventChannelNr_field, comm_mode_basic)
    tree:add(xcp_reserved, buffer(1, 1))
    tree:add(xcp_info, eventChannelNr_field, "Event channel number: " .. eventChannelNr)
end

function decode_cmd_alloc_daq(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local daqCount_field = buffer(2, 2)
    local daqCount = parse_number(daqCount_field, comm_mode_basic)
    tree:add(xcp_reserved, buffer(1, 1))
    tree:add(xcp_info, daqCount_field, "DAQ_COUNT: " .. daqCount)
end

function decode_cmd_alloc_odt(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local daqListNr_field = buffer(2, 2)
    local daqListNr = parse_number(daqListNr_field, comm_mode_basic)
    local odtCount_field = buffer(4, 1)
    local odtCount = odtCount_field:uint()
    tree:add(xcp_reserved, buffer(1, 1))
    tree:add(xcp_info, daqListNr_field, "DAQ list number: " .. daqListNr)
    tree:add(xcp_info, odtCount_field, "ODT_COUNT: " .. odtCount)
end

function decode_cmd_alloc_odt_entry(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local daqListNr_field = buffer(2, 2)
    local daqListNr = parse_number(daqListNr_field, comm_mode_basic)
    local odtNumber_field = buffer(4, 1)
    local odtNumber = odtNumber_field:uint()
    local odtEntriesCount_field = buffer(5, 1)
    local odtEntriesCount = odtEntriesCount_field:uint()
    tree:add(xcp_reserved, buffer(1, 1))
    tree:add(xcp_info, daqListNr_field, "DAQ list number: " .. daqListNr)
    tree:add(xcp_info, odtNumber_field, "ODT number: " .. odtNumber)
    tree:add(xcp_info, odtEntriesCount_field, "ODT_ENTRIES_COUNT: " .. odtEntriesCount)
end

function decode_cmd_program_clear(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local clearRange_field = buffer(4, 4)
    local clearRange = parse_number(clearRange_field, comm_mode_basic)
    if mode == 0 then
        tree:add(xcp_info, mode_field, "Mode: absolute (0)")
        tree:add(xcp_reserved, buffer(2, 2))
        tree:add(xcp_info, clearRange_field, "Range: " .. clearRange .. " Bytes starting at MTA")
    elseif mode == 1 then
        tree:add(xcp_info, mode_field, "Mode: functional (1)")
        tree:add(xcp_reserved, buffer(2, 2))
        local clearString = ""
        if band(clearRange, 1) ~= 0 then
            clearString = clearString + "CALIB (1), "
        end
        if band(clearRange, 2) ~= 0 then
            clearString = clearString + "CODE excluding BOOT (2), "
        end
        if band(clearRange, 4) ~= 0 then
            clearString = clearString + "NVRAM (4), "
        end
        if band(clearRange, 0xf8) ~= 0 then
            clearString = clearString + "RESERVED (" .. hex(band(clearRange, 0xf8), 2) .. "), "
        end
        if clearRange > 0x100 then
            clearString = clearString + "user defined (" .. hex(band(clearRange, 0xffffff00), 8) .. "), "
        end
        if clearRange == 0 then
            clearString = "NONE (0)"
        else
            clearString = clearString:sub(1, -3)
        end
        tree:add(xcp_info, clearRange_field, "Range: " .. clearString)
    else
        tree:add(xcp_info, mode_field, "Mode: unknown (" .. hex(mode, 2) .. ")")
        tree:add(xcp_reserved, buffer(2, 2))
        tree:add(xcp_info, clearRange_field, "Range: " .. hex(clearRange, 8))
    end
end

function decode_cmd_get_sector_info(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local secNum_field = buffer(2, 1)
    local secNum = secNum_field:uint()
    local infoType = "unknown information about this sector"
    if mode == 0 then
        infoType = "start address of this sector"
    elseif mode == 1 then
        infoType = "length of this sector in bytes"
    elseif mode == 2 then
        infoType = "name length of this sector"
    end
    tree:add(xcp_info, mode_field, "Mode: Get " .. infoType)
    tree:add(xcp_info, secNum_field, "Sector number: " .. secNum)
    pkt_data.GET_SECTOR_INFO__MODE = mode
end

function decode_cmd_program_prepare(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local codesize_field = buffer(2, 2)
    local codesize = parse_number(codesize_field, comm_mode_basic)
    tree:add(xcp_reserved, buffer(1, 1), "Not used")
    tree:add(xcp_info, codesize_field, "Code size: " .. codesize .. " " .. AG_TYPES[address_granularity])
end

function decode_cmd_program_format(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local compressionMethod_field = buffer(1, 1)
    local compressionMethod = compressionMethod_field:uint()
    local encryptionMethod_field = buffer(2, 1)
    local encryptionMethod = encryptionMethod_field:uint()
    local programmingMethod_field = buffer(3, 1)
    local programmingMethod = programmingMethod_field:uint()
    local accessMethod_field = buffer(4, 1)
    local accessMethod = accessMethod_field:uint()
    if compressionMethod == 0 then
        tree:add(xcp_info, compressionMethod_field, "Uncompressed (0)")
    elseif compressionMethod >= 0x80 then
        tree:add(xcp_info, compressionMethod_field,
            "User defined compression (" .. hex(compressionMethod, 2) + ")")
    else
        tree:add(xcp_info, compressionMethod_field,
            "Invalid compression (" .. hex(compressionMethod, 2) + ")")
    end
    if encryptionMethod == 0 then
        tree:add(xcp_info, encryptionMethod_field, "Not encrypted (0)")
    elseif encryptionMethod >= 0x80 then
        tree:add(xcp_info, encryptionMethod_field,
            "User defined encryption (" .. hex(encryptionMethod, 2) + ")")
    else
        tree:add(xcp_info, encryptionMethod_field,
            "Invalid encryption (" .. hex(encryptionMethod, 2) + ")")
    end
    if programmingMethod == 0 then
        tree:add(xcp_info, programmingMethod_field, "Sequential programming (0)")
    elseif programmingMethod >= 0x80 then
        tree:add(xcp_info, programmingMethod_field,
            "User defined programming mode (" .. hex(programmingMethod, 2) + ")")
    else
        tree:add(xcp_info, programmingMethod_field,
            "Invalid programming mode (" .. hex(programmingMethod, 2) + ")")
    end
    if accessMethod == 0 then
        tree:add(xcp_info, accessMethod_field, "Absolute access (0)")
    elseif accessMethod == 1 then
        tree:add(xcp_info, accessMethod_field, "Functional access (1)")
    elseif accessMethod >= 0x80 then
        tree:add(xcp_info, accessMethod_field, "User defined access mode (" .. hex(accessMethod, 2) + ")")
    else
        tree:add(xcp_info, accessMethod_field, "Invalid access mode (" .. hex(accessMethod, 2) + ")")
    end
end

function decode_cmd_program_verify(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local type_field = buffer(2, 2)
    local type = parse_number(type_field, comm_mode_basic)
    local value_field = buffer(4, 4)
    local value = parse_number(value_field, comm_mode_basic)
    if mode == 0 then
        tree:add(xcp_info, mode_field, "Verification mode: 0 (internal)")
        tree:add(xcp_info, type_field, "Verification type: " .. hex(type, 4) .. " (ignored)")
        tree:add(xcp_info, type_field, "Verification value: " .. hex(value, 8) .. " (ignored)")
    elseif mode == 1 then
        local typeString = hex(type, 4) .. " -- "
        if band(type, 1) ~= 0 then
            typeString = typeString .. "CALIB, "
        end
        if band(type, 2) ~= 0 then
            typeString = typeString .. "CODE, "
        end
        if band(type, 4) ~= 0 then
            typeString = typeString .. "FLASH, "
        end
        if band(type, 0xf8) ~= 0 then
            typeString = typeString .. "reserved (" .. hex(band(type, 0xf8), 2) .. "), "
        end
        if band(type, 0xff00) ~= 0 then
            typeString = typeString .. "user defined (" .. hex(band(type, 0xff00), 4) .. "), "
        end
        tree:add(xcp_info, mode_field, "Verification mode: 1 (value-based)")
        tree:add(xcp_info, type_field, "Verification type: " .. string.sub(typeString, 1, -3))
        tree:add(xcp_info, type_field, "Verification value: " .. hex(value, 8))
    end
end

function decode_cmd_write_daq_multiple(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local noDAQ_field = buffer(1, 1)
    local noDAQ = noDAQ_field:uint()
    tree:add(xcp_info, noDAQ_field, "Number of DAQ elements: " .. noDAQ)
    for i = 1, noDAQ + 1, 1 do
        local bitOffset_field = buffer((i - 1) * 8 + 2, 1)
        local bitOffset = bitOffset_field:uint()
        local size_field = buffer((i - 1) * 8 + 3, 1)
        local size = size_field:uint()
        local address_field = buffer((i - 1) * 8 + 4, 4)
        local address = parse_number(address_field, comm_mode_basic)
        local addrExt_field = buffer((i - 1) * 8 + 8, 1)
        local addrExt = addrExt_field:uint()
        local dummy_field = buffer((i - 1) * 8 + 9, 1)
        local elem_tree = tree:add(xcp_info, buffer((i - 1) * 8 + 2, 8), "Element #" .. i)
        elem_tree:add(xcp_info, bitOffset_field, "Bit offset: " .. bitOffset)
        elem_tree:add(xcp_info, size_field, "Size: " .. size)
        elem_tree:add(xcp_info, address_field, "Address: " .. hex(address, 8))
        elem_tree:add(xcp_info, addrExt_field, "Address Extension: " .. hex(addrExt, 2))
        elem_tree:add(xcp_reserved, dummy_field, "Dummy for alignment")
    end
end

function decode_cmd_time_correlation_properties(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local set_properties_field = buffer(1, 1)
    local set_properties = set_properties_field:uint()
    local get_properties_request_field = buffer(2, 1)
    local get_properties_request = get_properties_request_field:uint()
    local cluster_id_field = buffer(4, 2)
    local cluster_id = parse_number(cluster_id_field, comm_mode_basic)

    local response_fmt = band(set_properties, 0x03)
    local time_sync_bridge = rshift(band(set_properties, 0x0c), 2)
    local set_cluster_id = band(set_properties, 0x10) ~= 0
    local unknown_set_properties_flags = band(set_properties, 0xe0)

    local get_clk_info = band(get_properties_request, 1) == 1
    local unknown_get_properties_flags = band(get_properties_request, 0xfe)

    if response_fmt ~= 0 then
        pkt_data["TIME_SYNCHRONIZATION_PROPERTIES__extended"] = true
    end

    if response_fmt == 0 then
        tree:add(xcp_info, set_properties_field, "Response format: 0 (unchanged)")
    elseif response_fmt == 1 then
        tree:add(xcp_info, set_properties_field, "Response format: 1 (EV_TIME_SYNC on trigger initiator 0, 2, and 3 only)")
    elseif response_fmt == 2 then
        tree:add(xcp_info, set_properties_field, "Response format: 2 (EV_TIME_SYNC on all triggers)")
    else
        tree:add(xcp_info, set_properties_field, "Response format: 3 (reserved)")
    end

    if time_sync_bridge == 0 then
        tree:add(xcp_info, set_properties_field, "Time sync bridge: 0 (unchanged)")
    elseif time_sync_bridge == 1 then
        tree:add(xcp_info, set_properties_field, "Time sync bridge: 1 (enable)")
    elseif time_sync_bridge == 2 then
        tree:add(xcp_info, set_properties_field, "Time sync bridge: 2 (disable)")
    else
        tree:add(xcp_info, set_properties_field, "Time sync bridge: 3 (reserved)")
    end

    if set_cluster_id then
        tree:add(xcp_info, set_properties_field, "Assign to cluster")
    else
        tree:add(xcp_info, set_properties_field, "Do not change cluster assignment")
    end

    if unknown_set_properties_flags ~= 0 then
        tree:add(xcp_info, set_properties_field,
            "Unknown extra set_properties flags: " .. hex(unknown_set_properties_flags, 2))
    end

    if get_clk_info then
        tree:add(xcp_info, get_properties_request_field, "Clock info requested")
    else
        tree:add(xcp_info, get_properties_request_field, "Clock info not requested")
    end

    if unknown_get_properties_flags ~= 0 then
        tree:add(xcp_info, get_properties_request_field,
            "Unknown extra get_properties flags: " .. hex(unknown_get_properties_flags, 2))
    end

    tree:add(xcp_reserved, buffer(3, 1), "Reserved")

    if set_cluster_id then
        tree:add(xcp_info, cluster_id_field, "Cluster ID: " .. cluster_id)
    else
        tree:add(xcp_info, cluster_id_field, "Cluster ID: " .. cluster_id .. " (ignored)")
    end
end

function decode_cmd_dto_ctr_properties(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    local modifier_field = buffer(1, 1)
    local modifier = modifier_field:uint()
    local eventChannelNr_field = buffer(2, 2)
    local eventChannelNr = parse_number(eventChannelNr_field, comm_mode_basic)
    local relatedEventChannelNr_field = buffer(4, 2)
    local relatedEventChannelNr = parse_number(relatedEventChannelNr_field, comm_mode_basic)
    local mode_field = buffer(6, 1)
    local mode = mode_field:uint()
    local modify_relatedEvent = band(modifier, 1) ~= 0
    local modify_daqMode = band(modifier, 2) ~= 0
    local modify_stimMode = band(modifier, 4) ~= 0
    local unknown_modify_flags = band(modifier, 0xf8)
    local daqMode = band(mode, 1) ~= 0
    local stimMode = band(mode, 2) ~= 0
    local unknown_mode_flags = band(mode, 0xfc)
    local modifier_string = ""
    if modify_relatedEvent then
        modifier_string = modifier_string .. "modify related event (1), "
    end
    if modify_daqMode then
        modifier_string = modifier_string .. "modify DAQ mode (2), "
    end
    if modify_stimMode then
        modifier_string = modifier_string .. "modify STIM mode (4), "
    end
    if unknown_modify_flags ~= 0 then
        modifier_string = modifier_string .. "unknown modifier (" .. hex(unknown_modify_flags, 2) .. "), "
    end
    modifier_string = string.sub(modifier_string, 1, -3)
    local mode_string = ""
    if daqMode then
        mode_string = mode_string .. "Insert STIM counter copy (bit 0 set)"
    else
        mode_string = mode_string .. "Insert counter (bit 0 not set)"
    end
    if not modify_daqMode then
        mode_string = mode_string .. " (ignored), "
    else
        mode_string = mode_string .. ", "
    end
    if stimMode then
        mode_string = mode_string .. "check counter (bit 1 set)"
    else
        mode_string = mode_string .. "don't check counter (bit 1 not set)"
    end
    if not modify_stimMode then
        mode_string = mode_string .. " (ignored), "
    else
        mode_string = mode_string .. ", "
    end
    if unknown_mode_flags ~= 0 then
        mode_string = mode_string .. "unknown mode (" .. hex(unknown_mode_flags, 2) .. "), "
    end
    mode_string = string.sub(mode_string, 1, -3)
    tree:add(xcp_info, modifier_field, modifier_string)
    tree:add(xcp_info, eventChannelNr_field, "Event channel: " + eventChannelNr)
    if modify_relatedEvent then
        tree:add(xcp_info, relatedEventChannelNr_field, "Related event channel: " .. relatedEventChannelNr)
    else
        tree:add(xcp_info, relatedEventChannelNr_field, "Related event channel: " .. relatedEventChannelNr .. " (ignored)")
    end
    tree:add(xcp_info, mode_field, mode_string)
end

CMD_DECODERS = {
    [0xFF] = decode_cmd_connect,
    [0xFA] = decode_cmd_get_id,
    [0xF9] = decode_cmd_set_request,
    [0xF8] = decode_cmd_get_seed,
    [0xF7] = decode_cmd_unlock,
    [0xF6] = decode_cmd_set_mta,
    [0xF5] = decode_cmd_upload,
    [0xF4] = decode_cmd_short_upload,
    [0xF3] = decode_cmd_build_checksum,
    [0xF2] = decode_cmd_transport_layer_cmd__user_cmd,
    [0xF1] = decode_cmd_transport_layer_cmd__user_cmd,
    [0xF0] = decode_cmd_download__program,
    [0xEF] = decode_cmd_download__program,
    [0xEE] = decode_cmd_download__program__max,
    [0xED] = decode_cmd_short_download,
    [0xEC] = decode_cmd_modify_bits,
    [0xEB] = decode_cmd_set_cal_page,
    [0xEA] = decode_cmd_get_cal_page,
    [0xE8] = decode_cmd_get_segment_info,
    [0xE7] = decode_cmd_get_page_info,
    [0xE6] = decode_cmd_set_segment_mode,
    [0xE5] = decode_cmd_get_segment_mode,
    [0xE4] = decode_cmd_copy_cal_page,
    [0xE3] = decode_cmd_clear_daq_list__get_daq_list_mode__info,
    [0xE2] = decode_cmd_set_daq_ptr,
    [0xE1] = decode_cmd_write_daq,
    [0xE0] = decode_cmd_set_daq_list_mode,
    [0xDF] = decode_cmd_clear_daq_list__get_daq_list_mode__info,
    [0xDE] = decode_cmd_start_stop_daq_list,
    [0xDD] = decode_cmd_start_stop_synch,
    [0xD8] = decode_cmd_clear_daq_list__get_daq_list_mode__info,
    [0xD7] = decode_cmd_get_daq_event_info,
    [0xD5] = decode_cmd_alloc_daq,
    [0xD4] = decode_cmd_alloc_odt,
    [0xD3] = decode_cmd_alloc_odt_entry,
    [0xD1] = decode_cmd_program_clear,
    [0xD0] = decode_cmd_download__program,
    [0xCD] = decode_cmd_get_sector_info,
    [0xCC] = decode_cmd_program_prepare,
    [0xCB] = decode_cmd_program_format,
    [0xCA] = decode_cmd_download__program,
    [0xC9] = decode_cmd_download__program__max,
    [0xC8] = decode_cmd_program_verify,
    [0xC7] = decode_cmd_write_daq_multiple,
    [0xC6] = decode_cmd_time_correlation_properties,
    [0xC5] = decode_cmd_dto_ctr_properties,
}

function decode_cmd(buffer, pinfo, tree)
    local comm_mode_basic = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "COMM_MODE_BASIC", 0)
    local pkt_data = {}
    conversations[pinfo.private.xcp_conversation][pinfo.number] = pkt_data
    local pid_field = buffer(0, 1)
    local pid = pid_field:uint()
    local cmd_name = COMMAND_NAMES[pid]
    if cmd_name then
        pinfo.cols.info:set("XCP command: " .. cmd_name)
    else
        pinfo.cols.info:set("Unknown XCP command: " .. hex(pid, 2))
    end


    -- store the PID so decode_res and decode_err can find it
    pkt_data["CMD"] = pid
    pkt_data["pinfo.number"] = pinfo.number
    tree:add(xcp_type, pid_field, "Command")
    tree:add(xcp_cmd, pid_field, pid)

    local decoder = CMD_DECODERS[pid]
    if decoder then
        decoder(buffer, pinfo, tree, pkt_data, comm_mode_basic)
    end
end

function decode_res_connect(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local resource_field = buffer(1, 1)
    local resource = resource_field:uint()
    local comm_mode_basic_field = buffer(2, 1)
    comm_mode_basic = comm_mode_basic_field:uint()
    local max_cto_field = buffer(3, 1)
    local max_cto = max_cto_field:uint()
    local max_dto_field = buffer(4, 2)
    local max_dto = parse_number(max_dto_field, comm_mode_basic)
    local proto_version_field = buffer(6, 1)
    local proto_version = proto_version_field:uint()
    local transport_version_field = buffer(7, 1)
    local transport_version = proto_version_field:uint()
    cmd_pkt["RESOURCE"] = resource
    cmd_pkt["COMM_MODE_BASIC"] = comm_mode_basic
    cmd_pkt["MAX_CTO"] = max_cto
    cmd_pkt["MAX_DTO"] = max_dto
    local info_string = "resource: "
    if band(resource, 0x1) == 0 then
        info_string = info_string .. "CAL/PAG unavailable (bit 0 not set), "
    else
        info_string = info_string .. "CAL/PAG available (bit 0 set), "
    end
    if band(resource, 0x4) == 0 then
        info_string = info_string .. "DAQ unavailable (bit 2 not set), "
    else
        info_string = info_string .. "DAQ available (bit 2 set), "
    end
    if band(resource, 0x8) == 0 then
        info_string = info_string .. "STIM unavailable (bit 3 not set), "
    else
        info_string = info_string .. "STIM available (bit 3 set), "
    end
    if band(resource, 0x10) == 0 then
        info_string = info_string .. "PGM unavailable (bit 4 not set)"
    else
        info_string = info_string .. "PGM available (bit 4 set)"
    end
    if band(resource, 0xe2) ~= 0 then
        info_string = info_string .. ", unknown RESOURCE flags: (" .. hex(resource, 2) .. ")"
    end
    tree:add(xcp_info, resource_field, info_string)
    info_string = "comm_mode_basic: "
    if band(comm_mode_basic, 0x01) == 0 then
        info_string = info_string .. "little endian, "
    else
        info_string = info_string .. "big endian, "
    end
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    if address_granularity == 0 then
        info_string = info_string .. "address granularity BYTE (0)"
    elseif address_granularity == 1 then
        info_string = info_string .. "address granularity WORD (1)"
    elseif address_granularity == 2 then
        info_string = info_string .. "address granularity DWORD (2)"
    else
        info_string = info_string .. "address granularity 3 (reserved)"
    end
    if band(comm_mode_basic, 0x40) == 0x40 then
        info_string = info_string .. ", blockMode available"
    end
    if band(comm_mode_basic, 0x80) == 0x80 then
        info_string = info_string .. ", GET_COMM_MODE_INFO available"
    end
    if band(comm_mode_basic, 0x38) ~= 0 then
        info_string = info_string .. ", unknown COMM_MODE_BASIC flags (" .. hex(resource, 2) .. ")"
    end
    tree:add(xcp_info, comm_mode_basic_field, info_string)
    tree:add(xcp_info, max_cto_field, "max_cto: " .. max_cto)
    tree:add(xcp_info, max_dto_field, "max_dto: " .. max_dto)
    tree:add(xcp_info, proto_version_field, "proto_version: " .. proto_version)
    tree:add(xcp_info, transport_version_field, "transport_version: " .. transport_version)
end

function decode_res_get_status(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local status_field = buffer(1, 1)
    local status = status_field:uint()
    local protection_field = buffer(2, 1)
    local protection = protection_field:uint()
    local state_number_field = buffer(3, 1)
    local state_number = state_number_field:uint()
    local session_configuration_id_field = buffer(4, 2)
    local session_configuration_id = parse_number(session_configuration_id_field, comm_mode_basic)
    local info_string = "Session status: "
    if band(status, 0xcd) == 0 then
        info_string = info_string .. "0  "
    end
    if band(status, 0x1) ~= 0 then
        info_string = info_string .. "STORE_CAL_REQ, "
    end
    if band(status, 0x4) ~= 0 then
        info_string = info_string .. "STORE_DAQ_REQ, "
    end
    if band(status, 0x8) ~= 0 then
        info_string = info_string .. "CLEAR_DAQ_REQ, "
    end
    if band(status, 0x40) ~= 0 then
        info_string = info_string .. "DAQ_RUNNING, "
    end
    if band(status, 0x80) ~= 0 then
        info_string = info_string .. "RESUME, "
    end
    if band(status, 0x32) ~= 0 then
        info_string = info_string .. "unknown status flags (" .. hex(band(status, 0x32), 2) .. "), "
    end
    tree:add(xcp_info, status_field, info_string:sub(1, -3))
    info_string = "Protection status: "
    if band(protection, 0x1d) == 0 then
        info_string = info_string .. "0  "
    end
    if band(protection, 0x1) ~= 0 then
        info_string = info_string .. "CAL/PAG, "
    end
    if band(protection, 0x4) ~= 0 then
        info_string = info_string .. "DAQ, "
    end
    if band(protection, 0x8) ~= 0 then
        info_string = info_string .. "STIM, "
    end
    if band(protection, 0x10) ~= 0 then
        info_string = info_string .. "PGM, "
    end
    if band(protection, 0xe2) ~= 0 then
        info_string = info_string ..
            "unknown protection flags (" .. hex(band(protection, 0xe2), 2) .. "), "
    end
    tree:add(xcp_info, protection_field, info_string:sub(0, -3))
    tree:add(xcp_info, state_number_field, "state number: " .. state_number)
    tree:add(xcp_info, session_configuration_id_field, "session configuration id: " .. session_configuration_id)
end

function decode_res_get_comm_mode_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local optional_field = buffer(2, 1)
    local optional = optional_field:uint()
    local max_bs_field = buffer(4, 1)
    local max_bs = max_bs_field:uint()
    local min_st_field = buffer(5, 1)
    local min_st = min_st_field:uint()
    local queue_size_field = buffer(6, 1)
    local queue_size = queue_size_field:uint()
    local drv_version_field = buffer(7, 1)
    local drv_version = drv_version_field:uint()
    local info_string = "optional: "
    if band(optional, 0x03) == 0 then
        info_string = info_string .. "0   "
    end
    if band(optional, 0x01) ~= 0 then
        info_string = info_string .. "MASTER_BLOCK_MODE, "
    end
    if band(optional, 0x02) ~= 0 then
        info_string = info_string .. "INTERLEAVED_MODE, "
    end
    if band(optional, 0xfc) ~= 0 then
        info_string = info_string .. "unknown OPTIONAL flags (" .. hex(band(optional, 0xfc), 2) .. "), "
    end
    tree:add(xcp_reserved, buffer(1, 1))
    tree:add(xcp_info, optional_field, info_string:sub(0, -3))
    tree:add(xcp_reserved, buffer(3, 1))
    tree:add(xcp_info, max_bs_field, "MAX_BS: " .. max_bs)
    tree:add(xcp_info, min_st_field, "MIN_ST: " .. min_st)
    tree:add(xcp_info, queue_size_field, "queue size: " .. queue_size)
    tree:add(xcp_info, drv_version_field, "XCP driver version: " .. drv_version)
end

function decode_res_get_id(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local length_field = buffer(4, 4)
    local length = parse_number(length_field, comm_mode_basic)
    local transfer_mode = band(mode, 1) ~= 0
    local compressed_encrypted = band(mode, 2) ~= 0
    local unknown_mode_flags = band(mode, 0xfc)
    if transfer_mode then
        tree:add(xcp_info, mode_field, "Transfer mode: immediate")
    else
        tree:add(xcp_info, mode_field, "Transfer mode: UPLOAD")
    end
    if compressed_encrypted then
        tree:add(xcp_info, mode_field, "Compressed and/or encrypted")
    else
        tree:add(xcp_info, mode_field, "Plain text")
    end
    if unknown_mode_flags ~= 0 then
        tree:add(xcp_info, mode_field, "Unknown mode flags (" .. hex(unknown_mode_flags, 2) .. ")")
    end
    tree:add(xcp_reserved, buffer(2, 2))
    tree:add(xcp_info, length_field, "Length in Bytes: " .. length)
    if transfer_mode and length > 0 then
        local data_field = buffer(8)
        local data = data_field:bytes():raw()
        tree:add(xcp_data, data_field, data)
    end
end

function decode_res_set_request(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    cmd_pkt.DAQ_SELECTED = {}
end

function decode_res_get_seed(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local mode = cmd_pkt.GET_SEED__MODE
    local length_field = buffer(1, 1)
    local length = length_field:uint()
    local seed_field = buffer(2)
    local seed = seed_field:bytes():raw()
    if length == 0 then
        tree:add(xcp_info, length_field, "Resource is unprotected")
    else
        if mode == 0 then
            tree:add(xcp_info, length_field, "Total length: " .. length)
        elseif mode == 1 then
            tree:add(xcp_info, length_field, "Remaining length: " .. length)
        else
            tree:add(xcp_info, "Unknown mode: " .. hex(mode, 2)):set_generated()
        end
        tree:add(xcp_data, seed_field, seed)
    end
end

function decode_res_unlock(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local protection_field = buffer(1, 1)
    local protection = protection_field:uint()
    local info_string = "Protection status: "
    if band(protection, 0x1d) == 0 then
        info_string = info_string .. "0  "
    end
    if band(protection, 0x1) ~= 0 then
        info_string = info_string .. "CAL/PAG, "
    end
    if band(protection, 0x4) ~= 0 then
        info_string = info_string .. "DAQ, "
    end
    if band(protection, 0x8) ~= 0 then
        info_string = info_string .. "STIM, "
    end
    if band(protection, 0x10) ~= 0 then
        info_string = info_string .. "PGM, "
    end
    if band(protection, 0xe2) ~= 0 then
        info_string = info_string ..
            "unknown protection flags (" .. hex(band(protection, 0xe2), 2) .. "), "
    end
    tree:add(xcp_info, protection_field, info_string:sub(0, -3))
end

function decode_res_upload(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local offset = 1
    if address_granularity == 1 then
        offset = 2
        tree:add(xcp_reserved, buffer(1, 1), "WORD Alignment")
    elseif address_granularity == 3 then
        offset = 4
        tree:add(xcp_reserved, buffer(1, 3), "DWORD Alignment")
    end
    local nElem = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "N_ELEM", nil)
    local data_field
    if nElem == nil then
        -- Interpret the rest of the entire packet as data field if N_ELEM was not found
        -- in the previous cmd_upload packet
        data_field = buffer(offset) 
    else
        data_field = buffer(offset, nElem * 2^address_granularity)
    end
    local data = data_field:bytes():raw()
    tree:add(xcp_data, data_field, data)
end

function decode_res_build_checksum(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local checksumType_field = buffer(1, 1)
    local checksumType = checksumType_field:uint()
    local checksum_field = buffer(4, 4)
    local checksum = parse_number(checksum_field, comm_mode_basic)
    local checksumType_string = "Unknown (" .. hex(checksumType, 2) .. ")"
    if checksumType <= 9 and checksumType > 0 then
        local checksumTypes = { "ADD_11", "ADD_12", "ADD_14", "ADD_22", "ADD_24", "ADD_44", "CRC_16", "CRC_16_CITT",
                                "CRC_32" }
        checksumType_string = checksumTypes[checksumType]
    elseif checksumType == 0xff then
        checksumType_string = "User defined (0xff)"
    end
    tree:add(xcp_info, checksumType_field, "Checksum type: " .. checksumType_string)
    tree:add(xcp_reserved, buffer(2, 2))
    tree.add(xcp_info, checksum_field, "Checksum: " .. hex(checksum, 8))
end

function decode_res_transport_layer_cmd__user_cmd(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local data_field = buffer(1)
    local data = data_field:bytes():raw()
    tree:add(xcp_data, data_field, data)
end

function decode_res_get_cal_page(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local pageNum_field = buffer(3, 1)
    local pageNum = pageNum_field:uint()
    tree:add(xcp_reserved, buffer(1, 1))
    tree:add(xcp_reserved, buffer(2, 1))
    tree:add(xcp_info, pageNum_field, "Logical data page number: " .. pageNum)
end

function decode_res_get_pag_processor_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local maxSegment_field = buffer(1, 1)
    local maxSegment = maxSegment_field:uint()
    local pagProperties_field = buffer(2, 1)
    local pagProperties = pagProperties_field:uint()
    tree:add(xcp_info, maxSegment_field, "Number of segments: " .. maxSegment)
    if band(pagProperties, 1) == 1 then
        tree:add(xcp_info, pagProperties_field, "FREEZE supported")
    else
        tree:add(xcp_info, pagProperties_field, "FREEZE not supported")
    end
    if band(pagProperties, 0xfe) ~= 0 then
        tree:add(xcp_info, pagProperties_field, "Unknown PAG_PROPERTIES flags: " .. hex(band(pagProperties, 0xfe), 2))
    end
end

function decode_res_get_segment_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local mode = cmd_pkt.GET_SEGMENT_INFO__MODE
    local segInfo = cmd_pkt.GET_SEGMENT_INFO__SEGMENT_INFO
    tree:add(xcp_info, "Mode: " .. mode):set_generated()
    tree:add(xcp_info, "Segment Info: " .. segInfo):set_generated()
    if mode == 0 then
        local basicInfo_field = buffer(4, 4)
        local basicInfo = parse_number(basicInfo_field, comm_mode_basic)
        tree:add(xcp_reserved, buffer(1, 1))
        tree:add(xcp_reserved, buffer(2, 2))
        if segInfo == 0 then
            tree:add(xcp_info, basicInfo_field, "Address: " .. hex(basicInfo, 8))
        elseif segInfo == 1 then
            tree:add(xcp_info, basicInfo_field, "Length: " .. basicInfo)
        else
            tree:add(xcp_info, basicInfo_field, "Unknown info (type " .. hex(segInfo) .. "): " .. hex(basicInfo, 8))
        end
    elseif mode == 1 then
        local maxPages_field = buffer(1, 1)
        local maxPages = maxPages_field:uint()
        local addrExt_field = buffer(2, 1)
        local addrExt = addrExt_field:uint()
        local maxMapping_field = buffer(3, 1)
        local maxMapping = maxMapping_field:uint()
        local compressionMethod_field = buffer(4, 1)
        local compressionMethod = compressionMethod_field:uint()
        local encryptionMethod_field = buffer(5, 1)
        local encryptionMethod = encryptionMethod_field:uint()
        tree:add(xcp_info, maxPages_field, "Max pages: " .. maxPages)
        tree:add(xcp_info, addrExt_field, "Address extension: " .. addrExt)
        tree:add(xcp_info, maxMapping_field, "Max mapped ranges: " .. maxMapping)
        tree:add(xcp_info, compressionMethod_field, "Compression method: " .. hex(compressionMethod, 2))
        tree:add(xcp_info, encryptionMethod_field, "Encryption method: " .. hex(encryptionMethod, 2))
    elseif mode == 2 then
        local mappingInfo_field = buffer(4, 4)
        local mappingInfo = parse_number(mappingInfo_field, comm_mode_basic)
        tree:add(xcp_reserved, buffer(1, 1))
        tree:add(xcp_reserved, buffer(2, 2))
        if segInfo == 0 then
            tree:add(xcp_info, mappingInfo_field, "Source address: " .. hex(mappingInfo, 8))
        elseif segInfo == 1 then
            tree:add(xcp_info, mappingInfo_field, "Destination address: " .. hex(mappingInfo, 8))
        elseif segInfo == 2 then
            tree:add(xcp_info, mappingInfo_field, "Length: " .. mappingInfo)
        else
            tree:add(xcp_info, mappingInfo_field,
                "Unknown info (type " .. hex(segInfo) .. "): " .. hex(mappingInfo_field, 8))
        end
    else
        tree:add(xcp_info, "Unknown Mode: " .. hex(mode, 2)):set_generated()
        tree:add(xcp_data, buffer(1), buffer(1):bytes():raw())
    end
end

function decode_res_get_page_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local pageProperties_field = buffer(1, 1)
    local pageProperties = pageProperties_field:uint()
    local initSegment_field = buffer(2, 1)
    local initSegment = initSegment_field:uint()
    local unknown_props = band(pageProperties, 0xc0)
    local propsString = "Page properties: "
    if band(pageProperties, 1) ~= 0 then
        propsString = propsString .. "ECU_ACCESS_WITHOUT_XCP, "
    end
    if band(pageProperties, 2) ~= 0 then
        propsString = propsString .. "ECU_ACCESS_WITH_XCP, "
    end
    if band(pageProperties, 4) ~= 0 then
        propsString = propsString .. "XCP_READ_ACCESS_WITHOUT_ECU, "
    end
    if band(pageProperties, 8) ~= 0 then
        propsString = propsString .. "XCP_READ_ACCESS_WITH_ECU, "
    end
    if band(pageProperties, 16) ~= 0 then
        propsString = propsString .. "XCP_WRITE_ACCESS_WITHOUT_ECU, "
    end
    if band(pageProperties, 32) ~= 0 then
        propsString = propsString .. "XCP_WRITE_ACCESS_WITH_ECU, "
    end
    if unknown_props ~= 0 then
        propsString = propsString .. "UNKNOWN (" .. hex(unknown_props, 2) .. "), "
    end
    propsString = string.sub(propsString, 1, -3)
    tree:add(xcp_info, pageProperties_field, propsString)
    tree:add(xcp_info, initSegment_field, "Init Segment: " .. initSegment)
end

function decode_res_get_segment_mode(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local mode_field = buffer(2, 1)
    local mode = mode_field:uint()
    local freeze = band(mode, 1) ~= 0
    local unknown_mode_flags = band(mode, 0xfe)
    tree:add(xcp_reserved, buffer(1, 1))
    if freeze then
        buffer:add(xcp_info, mode_field, "Mode: FREEZE")
    elseif unknown_mode_flags == 0 then
        buffer:add(xcp_info, mode_field, "Mode: 0")
    end
    if unknown_mode_flags ~= 0 then
        buffer:add(xcp_info, mode_field, "Mode: unknown (" .. hex(unknown_mode_flags, 2) .. ")")
    end
end

function decode_res_get_daq_list_mode(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local mode_field = buffer(1, 1)
    local mode = mode_field:uint()
    local eventChannelNr_field = buffer(4, 2)
    local eventChannelNr = parse_number(eventChannelNr_field, comm_mode_basic)
    local prescaler_field = buffer(6, 1)
    local prescaler = prescaler_field:uint()
    local prio_field = buffer(7, 1)
    local prio = prio_field:uint()
    local modeString = "Current mode: "
    if band(mode, 1) ~= 0 then
        modeString = modeString .. "SELECTED, "
    end
    if band(mode, 2) ~= 0 then
        modeString = modeString .. "direction=STIM, "
    else
        modeString = modeString .. "direction=DAQ, "
    end
    if band(mode, 4) ~= 0 then
        modeString = modeString .. "UNKNOWN (0x04), "
    end
    if band(mode, 8) ~= 0 then
        modeString = modeString .. "DTO_CTR, "
    end
    if band(mode, 16) ~= 0 then
        modeString = modeString .. "TIMESTAMP, "
        cmd_pkt.TIMESTAMP_ENABLED = true
    else
        cmd_pkt.TIMESTAMP_ENABLED = false
    end
    if band(mode, 32) ~= 0 then
        modeString = modeString .. "PID_OFF, "
    end
    if band(mode, 64) ~= 0 then
        modeString = modeString .. "RUNNING, "
    end
    if band(mode, 128) ~= 0 then
        modeString = modeString .. "RESUME, "
    end
    modeString = string.sub(modeString, 1, -3)
    tree:add(xcp_info, mode_field, modeString)
    tree:add(xcp_reserved, buffer(2, 2))
    tree:add(xcp_info, eventChannelNr_field, "Current event channel number: " .. eventChannelNr)
    tree:add(xcp_info, prescaler_field, "Current prescaler: " .. prescaler)
    tree:add(xcp_info, prio_field, "Current DAQ list priority: " .. prio)
end

function decode_res_start_stop_daq_list(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local firstPid_field = buffer(1, 1)
    local firstPid = firstPid_field:uint()
    tree:add(xcp_info, firstPid_field, "First PID: " .. firstPid)
    cmd_pkt.FIRST_PID = { table.unpack(find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "FIRST_PID", {})) }
    cmd_pkt.FIRST_PID[cmd_pkt.DAQ_LIST_NR] = firstPid
end

function decode_res_get_daq_clock__ev_time_sync(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local extended_format = find_stored_data(pinfo.private.xcp_conversation, pinfo.number,
        "TIME_SYNCHRONIZATION_PROPERTIES__extended")
    local max_cto = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "MAX_CTO")

    local isResponse = buffer(0, 1).uint() ==
        0xff -- pos. response for 0xdc GET_DAQ_CLOCK; otherwise event 0x08 EV_TIME_SYNC
    if isResponse then
        if max_cto == 8 then
            extended_format = false -- unlike the event, the response does not have a special format for extended=true, max_cto=8
        end
        tree:add(xcp_reserved, buffer(1, 1))
    end

    local triggerInfo_field = buffer(2, 1)
    local triggerInfo = triggerInfo_field:uint()
    local triggerInfo_string = "Trigger info: "
    local timeOfSampling = band(rshift(triggerInfo, 3), 0x3)
    local unknown_triggerInfo = band(triggerInfo, 0xe0)
    local triggerInitiator = band(triggerInfo, 0x7)
    local initiators = {
        [0] = "HW trigger",
        "external time sync event",
        "GET_DAQ_CLOCK_MULTICAST (direct)",
        "GET_DAQ_CLOCK_MULTICAST (bridged)",
        "SYNC_STATE changed",
        "leap second",
        "ECU reset",
        "reserved (7)"
    }
    local initiatorString = "Trigger initiator: " .. initiators[triggerInitiator]
    if isResponse then
        if triggerInitiator ~= 0 then
            tree:add(xcp_info, triggerInfo_field, initiatorString .. " (ignored)")
        end
    else
        if extended_format then
            tree:add(xcp_info, triggerInfo_field, initiatorString)
        else
            tree:add(xcp_reserved, triggerInfo_field)
        end
    end
    if extended_format or isResponse then
        local samplingPoints = { [0] = "processing", "low jitter", "TX", "RX" }
        local samplingPointString = "Time of sampling: " .. samplingPoints[timeOfSampling]
        tree:add(xcp_info, triggerInfo_field, samplingPointString)
        if unknown_triggerInfo ~= 0 then
            tree:add(xcp_info, triggerInfo_field, "Unknown flags in TRIGGER_INFO: " .. hex(unknown_triggerInfo, 2))
        end
    end

    local payloadFmt_mcastClkCounter_field = buffer(3, 1)
    local payloadFmt = payloadFmt_mcastClkCounter_field:uint()
    local fmt_xcp_slv = band(payloadFmt, 3)
    local fmt_grandm = band(rshift(payloadFmt, 2), 3)
    local fmt_ecu = band(rshift(payloadFmt, 4), 3)
    local cluster_identifier_present = band(rshift(payloadFmt, 6), 1)
    local unknownFmtFlag = rshift(payloadFmt, 7) ~= 0
    local daqClockMulticastCounter = payloadFmt_mcastClkCounter_field:uint()

    if extended_format then
        if max_cto == 8 then
            local timestamp_field = buffer(4, 4)
            local timestamp = parse_number(timestamp_field, comm_mode_basic)
            tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "DAQ clock multicast counter: " .. daqClockMulticastCounter)
            tree:add(xcp_info, timestamp_field, "Timestamp: " .. timestamp)
        else
            local offset = 4
            local bad_format = 0
            local formats = { "DWORD", "DLONG" }
            local slaveClock_field = nil
            local slaveClock = nil
            local gramdmasterClock_field = nil
            local gramdmasterClock = nil
            local ecuClock_field = nil
            local ecuClock = nil

            if fmt_xcp_slv == 3 then
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "Unknown XCP slave clock timestamp format: 3")
                bad_format = offset
            elseif fmt_xcp_slv > 0 then
                slaveClock_field = buffer(offset, fmt_xcp_slv * 4)
                slaveClock = parse_number(slaveClock_field)
                offset = offset + fmt_xcp_slv * 4
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "XCP slave clock timestamp format: " .. formats
                [fmt_xcp_slv])
            else
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "XCP slave clock timestamp format: absent")
            end
            if fmt_grandm == 3 then
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "Unknown Grandmaster-synced clock timestamp format: 3")
                bad_format = offset
            elseif fmt_grandm > 0 then
                gramdmasterClock_field = buffer(offset, fmt_grandm * 4)
                gramdmasterClock = parse_number(gramdmasterClock_field)
                offset = offset + fmt_grandm * 4
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field,
                    "Grandmaster-synced clock timestamp format: " .. formats[fmt_grandm])
            else
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "Grandmaster-synced clock format: timestamp absent")
            end
            if fmt_ecu == 3 then
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "Unknown ECU clock timestamp format: 3")
                bad_format = offset
            elseif fmt_ecu > 0 then
                ecuClock_field = buffer(offset, fmt_ecu * 4)
                ecuClock = parse_number(ecuClock_field)
                offset = offset + fmt_ecu * 4
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "ECU clock timestamp format: " .. formats[fmt_ecu])
            else
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "ECU clock timestamp format: absent")
            end
            if cluster_identifier_present then
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "Cluster identifier present")
            else
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "Cluster identifier absent")
            end
            if unknownFmtFlag then
                tree:add(xcp_info, payloadFmt_mcastClkCounter_field, "Unknown payload format flag: 0x80")
            end
            if slaveClock_field then
                tree:add(xcp_info, slaveClock_field, "XCP slave clock timestamp: " .. tostring(slaveClock))
            end
            if gramdmasterClock_field then
                tree:add(xcp_info, gramdmasterClock_field, "Grandmaster-synced clock timestamp: " .. tostring(gramdmasterClock))
            end
            if ecuClock_field then
                tree:add(xcp_info, ecuClock_field, "ECU clock timestamp: " .. tostring(ecuClock))
            end
            if bad_format == offset then
                tree:add(xcp_info, buffer(bad_format),
                    "Bad payload format specifier (see above), can't parse the rest of the payload")
                return
            end
            if cluster_identifier_present then
                local clusterIdentifier_field = buffer(offset, 2)
                local clusterIdentifier = parse_number(clusterIdentifier_field, comm_mode_basic)
                offset = offset + 2
                local daqClockMulticastCounter_field = buffer(offset, 1)
                daqClockMulticastCounter = daqClockMulticastCounter_field:uint()
                offset = offset + 1
                tree:add(xcp_info, clusterIdentifier_field, "Cluster identifier: " .. hex(clusterIdentifier, 4))
                tree:add(xcp_info, daqClockMulticastCounter_field, "DAQ clock multicast counter: " .. daqClockMulticastCounter)
            end
            if buffer:len() > offset then
                local syncState_field = buffer(offset, 1)
                local syncState = syncState_field:uint()
                local slaveSyncState = band(syncState, 7)
                local slaveSyncStates = {
                    [0] = "synchronizing",
                    "synchronized",
                    "syntonizing",
                    "syntonized",
                    "reserved (4)",
                    "reserved (5)",
                    "reserved (6)",
                    "not supported"
                }
                local gmSyncState = band(rshift(syncState, 3), 1)
                local gmSyncStates = { [0] = "not yet synchronized", "synchronized" }
                local ecuSyncState = band(rshift(syncState, 4), 3)
                local ecuSyncStates = { [0] = "not synchronized", "synchronized", "unknown", "reserved (3)" }
                local unknownSyncBits = band(syncState, 0xc0)
                local slaveClockObservability = find_stored_data(pinfo.private.xcp_conversation, pinfo.number,
                    "TIME_CORRELATION_PROPERTIES__slaveClock", 0)
                local gramdmasterClockObservability = find_stored_data(pinfo.private.xcp_conversation, pinfo.number,
                    "TIME_CORRELATION_PROPERTIES__gmClock", 0)
                local ecuClockObservability = find_stored_data(pinfo.private.xcp_conversation, pinfo.number,
                    "TIME_CORRELATION_PROPERTIES__ecuClock", 0)
                local node = tree:add(xcp_info, syncState_field, "Slave clock sync state: " .. slaveSyncStates[slaveSyncState])
                if slaveClockObservability ~= 1 then
                    node:append_text(" (ignored)")
                end
                node = tree:add(xcp_info, syncState_field, "Gramdmaster-synced clock sync state: " .. gmSyncStates[gmSyncState])
                if gramdmasterClockObservability == 0 then
                    node:append_text(" (ignored)")
                end
                node = tree:add(xcp_info, syncState_field, "ECU clock sync state: " .. ecuSyncStates[ecuSyncState])
                if ecuClockObservability == 0 then
                    node:append_text(" (ignored)")
                end
                if unknownSyncBits ~= 0 then
                    tree:add(xcp_info, syncState_field, "Unknown bits in Sync state: " .. hex(unknownSyncBits, 2))
                end
            end
        end
    else
        -- legacy format
        if isResponse then
            tree:add(xcp_info, triggerInfo_field, triggerInfo_string)
            tree:add(xcp_info, payloadFmt_mcastClkCounter_field,
                "Payload format: " .. hex(payloadFmt, 2) .. " (ignored in legacy or max_cto=8 format)")
        else
            tree:add(xcp_reserved, payloadFmt_mcastClkCounter_field)
        end
        local timestamp_field = buffer(4, 4)
        local timestamp = parse_number(timestamp_field, comm_mode_basic)
        tree:add(xcp_info, timestamp_field, "timestamp: " .. timestamp)
    end
end

function decode_res_read_daq(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    local bitOffset_field = buffer(1, 1)
    local bitOffset = bitOffset_field:uint()
    local elementSize_field = buffer(2, 1)
    local elementSize = elementSize_field:uint()
    local addrExt_field = buffer(3, 1)
    local addrExt = addrExt_field:uint()
    local address_field = buffer(4, 4)
    local address = parse_number(address_field, comm_mode_basic)
    tree:add(xcp_info, bitOffset_field, "Bit offset: " .. bitOffset)
    tree:add(xcp_info, elementSize_field, "Element size: " .. elementSize .. AG_TYPES[address_granularity])
    tree:add(xcp_info, addrExt_field, "Address extension: " .. hex(addrExt, 2))
    tree:add(xcp_info, address_field, "Address: " .. hex(address, 8))
end

function decode_res_get_daq_processor_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local daqProps_field = buffer(1, 1)
    local daqProps = daqProps_field:uint()
    local maxDaq_field = buffer(2, 2)
    local maxDaq = parse_number(maxDaq_field, comm_mode_basic)
    local maxEvtChannel_field = buffer(4, 2)
    local maxEvtChannel = parse_number(maxEvtChannel_field, comm_mode_basic)
    local minDaq_field = buffer(6, 1)
    local minDaq = minDaq_field:uint()
    local daqKeyByte_field = buffer(7, 1)
    local daqKeyByte = daqKeyByte_field:uint()
    local infoString = "DAQ properties: "
    if band(daqProps, 1) ~= 0 then
        infoString = infoString .. "dynamic, "
    else
        infoString = infoString .. "static, "
    end
    if band(daqProps, 2) ~= 0 then
        infoString = infoString .. "prescaler supported, "
    else
        infoString = infoString .. "prescaler not supported, "
    end
    if band(daqProps, 4) ~= 0 then
        infoString = infoString .. "RESUME supported, "
    else
        infoString = infoString .. "RESUME not supported, "
    end
    if band(daqProps, 8) ~= 0 then
        infoString = infoString .. "bitwise stimulation supported, "
    else
        infoString = infoString .. "bitwise stimulation not supported, "
    end
    if band(daqProps, 16) ~= 0 then
        infoString = infoString .. "time-stamped mode supported, "
        cmd_pkt.TIMESTAMP_SUPPORTED = true
    else
        infoString = infoString .. "time-stamped mode not supported, "
        cmd_pkt.TIMESTAMP_SUPPORTED = false
    end
    if band(daqProps, 32) ~= 0 then
        infoString = infoString .. "PID_OFF supported, "
    else
        infoString = infoString .. "PID_OFF not supported, "
    end
    if band(daqProps, 192) == 0 then
        infoString = infoString .. "no overload indication"
    elseif band(daqProps, 192) == 64 then
        infoString = infoString .. "overload indication in MSB of PID"
    elseif band(daqProps, 192) == 128 then
        infoString = infoString .. "overload indication by event packet"
    else
        infoString = infoString .. "invalid overload indication type (both event and MSB)"
    end
    tree:add(xcp_info, daqProps_field, infoString)
    tree:add(xcp_info, maxDaq_field, "Max DAQ: " .. maxDaq)
    if maxEvtChannel == 0 then
        tree:add(xcp_info, maxEvtChannel_field, "Max event channel: 0 (unknown)")
    else
        tree:add(xcp_info, maxEvtChannel_field, "Max event channel: " .. maxEvtChannel)
    end
    tree:add(xcp_info, minDaq_field, "Min DAQ (#predefined): " .. minDaq)
    local optimisationType = band(daqKeyByte, 0xf)
    local optimisationTypes = {
        [0] = "OM_DEFAULT",
        "OM_ODT_TYPE_16",
        "OM_ODT_TYPE_32",
        "OM_ODT_TYPE_64",
        "OM_ODT_TYPE_ALIGNMENT",
        "OM_MAX_ENTRY_SIZE"
    }
    if optimisationType > 5 then
        tree:add(xcp_info, daqKeyByte_field, "Unknown optimisation type: " .. hex(optimisationType, 1))
    else
        tree:add(xcp_info, daqKeyByte_field, "Optimisation type: " .. optimisationTypes[optimisationType])
    end
    local addrExtConstraint = band(rshift(daqKeyByte, 4), 3)
    local addrExtConstraints = {
        [0] = "can be different within one ODT",
        "must be the same within one ODT",
        "(invalid constraint)",
        "must be the same within one DAQ"
    }
    tree:add(xcp_info, daqKeyByte_field, "Address extensions " .. addrExtConstraints[addrExtConstraint])
    local idType = rshift(daqKeyByte, 6)
    local idTypes = {
        [0] = "Absolute",
        "Relative (DAQ as BYTE)",
        "Relative (DAQ as WORD, unaligned)",
        "Relative (DAQ as WORD, aligned)"
    }
    tree:add(xcp_info, daqKeyByte_field, "ID type: " .. idTypes[idType])
    cmd_pkt.DAQ_IDTYPE = idType
end

function decode_res_get_daq_resolution_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local odtGranularityDaq_field = buffer(1, 1)
    local odtGranularityDaq = odtGranularityDaq_field:uint()
    local odtEntrySizeDaq_field = buffer(2, 1)
    local odtEntrySizeDaq = odtEntrySizeDaq_field:uint()
    local odtGranularityStim_field = buffer(3, 1)
    local odtGranularityStim = odtGranularityStim_field:uint()
    local odtEntrySizeStim_field = buffer(4, 1)
    local odtEntrySizeStim = odtEntrySizeStim_field:uint()
    local timestampMode_field = buffer(5, 1)
    local timestampMode = timestampMode_field:uint()
    local timestampTicks_field = buffer(6, 2)
    local timestampTicks = parse_number(timestampTicks_field, comm_mode_basic)
    tree:add(xcp_info, odtGranularityDaq_field, "ODT granularity for DAQ: " .. odtGranularityDaq)
    tree:add(xcp_info, odtEntrySizeDaq_field, "ODT entry size for DAQ: " .. odtEntrySizeDaq)
    tree:add(xcp_info, odtGranularityStim_field, "ODT granularity for STIM: " .. odtGranularityStim)
    tree:add(xcp_info, odtEntrySizeStim_field, "ODT entry size for STIM: " .. odtEntrySizeStim)

    local suffix = ""
    if not find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "TIMESTAMP_SUPPORTED", true) then
        suffix = " (ignored)"
    end
    local timestampSize = band(timestampMode, 7)
    local timestampFixed = band(timestampMode, 8) ~= 0
    cmd_pkt.TIMESTAMP_FIXED = timestampFixed
    local timestampUnit = rshift(timestampMode, 4)
    local timestampUnits = {
        [0] = "1ns",
        "10ns",
        "100ns",
        "1µs",
        "10µs",
        "100µs",
        "1ms",
        "10ms",
        "100ms",
        "1s",
        "1ps",
        "10ps",
        "100ps",
        "unknown (0xd)",
        "unknown (0xe)",
        "unknown (0xf)"
    }
    cmd_pkt.TIMESTAMP_SIZE = timestampSize
    if timestampSize == 3 then
        tree:add(xcp_info, timestampMode_field, "Timestamp size: 3 (not allowed)" .. suffix)
    else
        tree:add(xcp_info, timestampMode_field, "Timestamp size: " .. timestampSize .. suffix)
    end
    if timestampFixed then
        tree:add(xcp_info, timestampMode_field, "Timestamp fixed" .. suffix)
    else
        tree:add(xcp_info, timestampMode_field, "Timestamp not fixed" .. suffix)
    end
    tree:add(xcp_info, timestampMode_field, "Timestamp unit: " .. timestampUnits[timestampUnit] .. suffix)
    tree:add(xcp_info, timestampTicks_field, "Ticks per unit: " .. timestampTicks .. suffix)
end

function decode_res_get_daq_list_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local daqListProperties_field = buffer(1, 1)
    local daqListProperties = daqListProperties_field:uint()
    local maxOdt_field = buffer(2, 1)
    local maxOdt = maxOdt_field:uint()
    local maxOdtEntries_field = buffer(3, 1)
    local maxOdtEntries = maxOdtEntries_field:uint()
    local fixedEvent_field = buffer(4, 2)
    local fixedEvent = parse_number(fixedEvent_field, comm_mode_basic)
    if band(daqListProperties, 1) ~= 0 then
        tree:add(xcp_info, daqListProperties_field, "DAQ list configurations is fixed")
    else
        tree:add(xcp_info, daqListProperties_field, "DAQ list configurations can be changed")
    end
    if band(daqListProperties, 2) ~= 0 then
        tree:add(xcp_info, daqListProperties_field, "Event Channel is fixed")
    else
        tree:add(xcp_info, daqListProperties_field, "Event Channel can be changed")
    end
    local daqListType = band(rshift(daqListProperties, 2), 3)
    if daqListType == 0 then
        tree:add(xcp_info, daqListProperties_field, "Invalid DAQ list type: 0")
    elseif daqListType == 1 then
        tree:add(xcp_info, daqListProperties_field, "DAQ list type: DAQ only")
    elseif daqListType == 2 then
        tree:add(xcp_info, daqListProperties_field, "DAQ list type: STIM only")
    else
        tree:add(xcp_info, daqListProperties_field, "DAQ list type: both")
    end
    local unknownBits = band(daqListProperties, 0xf0)
    if unknownBits ~= 0 then
        tree:add(xcp_info, daqListProperties_field, "Unknown bits in DAQ list properties:" .. hex(unknownBits, 2))
    end
    tree:add(xcp_info, maxOdt_field, "Number of ODTs: " .. maxOdt)
    tree:add(xcp_info, maxOdtEntries_field, "Number of entries per ODT: " .. maxOdtEntries)
    tree:add(xcp_info, fixedEvent_field, "Fixed event channel: " .. fixedEvent)
end

function decode_res_get_daq_event_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local daqEventProperties_field = buffer(1, 1)
    local daqEventProperties = daqEventProperties_field:uint()
    local maxDaqList_field = buffer(2, 1)
    local maxDaqList = maxDaqList_field:uint()
    local evtChanNameLen_field = buffer(3, 1)
    local evtChanNameLen = evtChanNameLen_field:uint()
    local evtChanTimeCycle_field = buffer(4, 1)
    local evtChanTimeCycle = evtChanTimeCycle_field:uint()
    local evtChanTimeUnit_field = buffer(5, 1)
    local evtChanTimeUnit = evtChanTimeUnit_field:uint()
    local evtChanPrio_field = buffer(6, 1)
    local evtChanPrio = evtChanPrio_field:uint()
    local evtChanType = band(rshift(daqEventProperties, 2), 3)
    local consistencyLevel = rshift(daqEventProperties, 6)
    local unknownBits = band(daqEventProperties, 0x33)
    if evtChanType == 0 then
        tree:add(xcp_info, daqEventProperties_field, "Invalid Event channel type: 0")
    elseif evtChanType == 1 then
        tree:add(xcp_info, daqEventProperties_field, "Event channel type: DAQ only")
    elseif evtChanType == 2 then
        tree:add(xcp_info, daqEventProperties_field, "Event channel type: STIM only")
    else
        tree:add(xcp_info, daqEventProperties_field, "Event channel type: both")
    end
    if consistencyLevel == 0 then
        tree:add(xcp_info, daqEventProperties_field, "Consistency on ODT level")
    elseif consistencyLevel == 1 then
        tree:add(xcp_info, daqEventProperties_field, "Consistency on DAQ level")
    elseif consistencyLevel == 2 then
        tree:add(xcp_info, daqEventProperties_field, "Consistency on Event Channel level")
    else
        tree:add(xcp_info, daqEventProperties_field, "Unknown consistency specification: DAQ|Event (0xc0)")
    end
    if unknownBits ~= 0 then
        tree:add(xcp_info, daqEventProperties_field, "Unknown bits in Event properties: " .. hex(unknownBits, 2))
    end
    tree:add(xcp_info, maxDaqList_field, "Max. number of DAQ lists: " .. maxDaqList)
    tree:add(xcp_info, evtChanNameLen_field, "Name length: " .. evtChanNameLen)
    tree:add(xcp_info, evtChanTimeCycle_field, "Time cycle: " .. evtChanTimeCycle)
    local timeUnits = {
        [0] = "1ns",
        "10ns",
        "100ns",
        "1µs",
        "10µs",
        "100µs",
        "1ms",
        "10ms",
        "100ms",
        "1s",
        "1ps",
        "10ps",
        "100ps"
    }
    tree:add(xcp_info, evtChanTimeUnit_field, "Time unit: " .. timeUnits[band(evtChanTimeUnit, 0x0f)])
    local highNibble = band(evtChanTimeUnit, 0xf0)
    if highNibble ~= 0 then
        tree:add(xcp_info, evtChanTimeUnit_field, "Unknown bits in time unit field: " .. hex(highNibble))
    end
    tree:add(xcp_info, evtChanPrio_field, "Priority: " .. evtChanPrio)
end

function decode_res_program_start(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local commModePgm_field = buffer(2, 1)
    local commModePgm = commModePgm_field:uint()
    local maxCtoPgm_field = buffer(3, 1)
    local maxCtoPgm = maxCtoPgm_field:uint()
    local maxBsPgm_field = buffer(4, 1)
    local maxBsPgm = maxBsPgm_field:uint()
    local minStPgm_field = buffer(5, 1)
    local minStPgm = minStPgm_field:uint()
    local qSizePgm_field = buffer(6, 1)
    local qSizePgm = qSizePgm_field:uint()

    tree:add(xcp_reserved, buffer(1, 1))
    if band(commModePgm, 1) ~= 0 then
        tree:add(xcp_info, commModePgm_field, "Master block mode available")
    else
        tree:add(xcp_info, commModePgm_field, "Master block mode not available")
    end
    if band(commModePgm, 2) ~= 0 then
        tree:add(xcp_info, commModePgm_field, "Interleaved mode available")
    else
        tree:add(xcp_info, commModePgm_field, "Interleaved mode not available")
    end
    if band(commModePgm, 0x40) ~= 0 then
        tree:add(xcp_info, commModePgm_field, "Slave block mode available")
    else
        tree:add(xcp_info, commModePgm_field, "Slave block mode not available")
    end
    local unknownBits = band(commModePgm, 0xbc)
    if unknownBits ~= 0 then
        tree:add(xcp_info, commModePgm_field, "Unknown bits in COMM_MODE_PGM: " .. hex(unknownBits, 2))
    end
    tree:add(xcp_info, maxCtoPgm_field, "MAX_CTO: " .. maxCtoPgm)
    tree:add(xcp_info, maxBsPgm_field, "MAX_BS: " .. maxBsPgm)
    tree:add(xcp_info, minStPgm_field, "MIN_ST: " .. minStPgm)
    tree:add(xcp_info, qSizePgm_field, "QUEUE_SIZE: " .. qSizePgm)
end

function decode_res_get_pgm_processor_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local pgmProps_field = buffer(1, 1)
    local pgmProps = pgmProps_field:uint()
    local maxSector_field = buffer(2, 1)
    local maxSector = maxSector_field:uint()
    local mode = band(pgmProps, 3)
    local compression = band(rshift(pgmProps, 2), 3)
    local encryption = band(rshift(pgmProps, 4), 3)
    local nonSeq = rshift(pgmProps, 6)
    if mode == 0 then
        tree:add(xcp_info, pgmProps_field, "Invalid clear/programming mode: 0")
    elseif mode == 1 then
        tree:add(xcp_info, pgmProps_field, "Clear/programming mode supported: absolute")
    elseif mode == 2 then
        tree:add(xcp_info, pgmProps_field, "Clear/programming mode supported: functional")
    elseif mode == 3 then
        tree:add(xcp_info, pgmProps_field, "Clear/programming mode supported: both")
    end
    if compression == 0 then
        tree:add(xcp_info, pgmProps_field, "Compression not supported")
    elseif compression == 1 then
        tree:add(xcp_info, pgmProps_field, "Compression supported but not required")
    elseif compression == 2 then
        tree:add(xcp_info, pgmProps_field, "Compression not supported but still required")
    elseif compression == 3 then
        tree:add(xcp_info, pgmProps_field, "Compression supported and required")
    end
    if encryption == 0 then
        tree:add(xcp_info, pgmProps_field, "Encryption not supported")
    elseif encryption == 1 then
        tree:add(xcp_info, pgmProps_field, "Encryption supported but not required")
    elseif encryption == 2 then
        tree:add(xcp_info, pgmProps_field, "Encryption not supported but still required")
    elseif encryption == 3 then
        tree:add(xcp_info, pgmProps_field, "Encryption supported and required")
    end
    if nonSeq == 0 then
        tree:add(xcp_info, pgmProps_field, "Non-sequential programming not supported")
    elseif nonSeq == 1 then
        tree:add(xcp_info, pgmProps_field, "Non-sequential programming supported but not required")
    elseif nonSeq == 2 then
        tree:add(xcp_info, pgmProps_field, "Non-sequential programming not supported but still required")
    elseif nonSeq == 3 then
        tree:add(xcp_info, pgmProps_field, "Non-sequential programming supported and required")
    end
    tree:add(xcp_info, maxSector_field, "Total number of sectors: " .. maxSector)
end

function decode_res_get_sector_info(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local csn_field = buffer(1, 1)
    local csn = csn_field:uint()
    tree:add(xcp_info, csn_field, "Clear Sequence Number: " .. csn)
    if cmd_pkt.GET_SECTOR_INFO__MODE == 2 then
        local nameLength_field = buffer(2, 1)
        local nameLength = nameLength_field:uint()
        tree:add(xcp_info, nameLength_field, "Name length: " .. nameLength)
    else
        local psn_field = buffer(2, 1)
        local psn = psn_field:uint()
        local pm_field = buffer(3, 1)
        local pm = pm_field:uint()
        local secInfo_field = buffer(4, 4)
        local secInfo = parse_number(secInfo_field, comm_mode_basic)
        tree:add(xcp_info, psn_field, "Program Sequence Number: " .. psn)
        if pm == 0 then
            tree:add(xcp_info, pm_field, "Programming method: absolute access mode")
        elseif pm >= 0x80 then
            tree:add(xcp_info, pm_field, "Programming method: user defined (" .. hex(pm, 2) .. ")")
        else
            tree:add(xcp_info, pm_field, "Programming method: invalid (" .. hex(pm, 2) .. ")")
        end
        if cmd_pkt.GET_SECTOR_INFO__MODE == 0 then
            tree:add(xcp_info, secInfo_field, "Start address: " .. hex(secInfo, 8))
        elseif cmd_pkt.GET_SECTOR_INFO__MODE == 1 then
            tree:add(xcp_info, secInfo_field, "Length: " .. secInfo)
        else
            tree:add(xcp_info, "Unknown mode: " .. cmd_pkt.GET_SECTOR_INFO__MODE):set_generated()
            tree:add(xcp_info, secInfo_field, "Sector info: " .. secInfo)
        end
    end
end

function decode_res_time_correlation_properties(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    local slaveConfig_field = buffer(1, 1)
    local slaveConfig = slaveConfig_field:uint()
    local observableClocks_field = buffer(2, 1)
    local observableClocks = observableClocks_field:uint()
    local syncState_field = buffer(3, 1)
    local syncState = syncState_field:uint()
    local clockInfo_field = buffer(4, 1)
    local clockInfo = clockInfo_field:uint()
    local clusterId_field = buffer(6, 2)
    local clusterId = parse_number(clusterId_field, comm_mode_basic)

    local responseFmt = band(slaveConfig, 3)
    local daqTsRelation = band(slaveConfig, 4) ~= 0
    local timeSyncBridge = band(rshift(slaveConfig, 3), 3)
    local unknownSlvCfgBits = band(slaveConfig, 0xe0)
    if responseFmt == 0 then
        tree:add(xcp_info, slaveConfig_field, "Response format: legacy")
    elseif responseFmt == 1 then
        tree:add(xcp_info, slaveConfig_field, "Response format: extended; event only for TRIGGER_INITIATOR 2 and 3")
    elseif responseFmt == 2 then
        tree:add(xcp_info, slaveConfig_field, "Response format: extended; event for all TRIGGER_INITIATOR values")
    else
        tree:add(xcp_info, slaveConfig_field, "Unknown response format 3")
    end
    if daqTsRelation then
        tree:add(xcp_info, slaveConfig_field, "Timestamps related to ECU clock")
    else
        tree:add(xcp_info, slaveConfig_field, "Timestamps related to XCP slave clock")
    end
    if timeSyncBridge == 0 then
        tree:add(xcp_info, slaveConfig_field, "Time Sync Bridge: not available")
    elseif timeSyncBridge == 1 then
        tree:add(xcp_info, slaveConfig_field, "Time Sync Bridge: disabled")
    elseif timeSyncBridge == 2 then
        tree:add(xcp_info, slaveConfig_field, "Time Sync Bridge: enabled")
    else
        tree:add(xcp_info, slaveConfig_field, "Time Sync Bridge: reserved (3)")
    end
    if unknownSlvCfgBits ~= 0 then
        tree:add(xcp_info, slaveConfig_field, "Unknown bits in Slave configuration: " .. hex(unknownSlvCfgBits, 2))
    end

    local slaveClock = band(observableClocks, 3)
    local gmClock = band(rshift(observableClocks, 2), 3)
    local ecuClock = band(rshift(observableClocks, 4), 3)
    local unknownObsClkBits = band(observableClocks, 0xc0)

    if slaveClock == 0 then
        tree:add(xcp_info, observableClocks_field, "Slave clock: free running")
    elseif slaveClock == 1 then
        tree:add(xcp_info, observableClocks_field, "Slave clock: syntonizable/synchronizable")
    elseif slaveClock == 2 then
        tree:add(xcp_info, observableClocks_field, "Slave clock: not available")
    else
        tree:add(xcp_info, observableClocks_field, "Slave clock: reserved (3)")
    end
    if gmClock == 0 then
        tree:add(xcp_info, observableClocks_field, "Grandmaster-synced clock: not available")
    elseif gmClock == 1 then
        tree:add(xcp_info, observableClocks_field, "Grandmaster-synced clock: random-read possible")
    elseif gmClock == 2 then
        tree:add(xcp_info, observableClocks_field, "Grandmaster-synced clock: no random read, only EV_TIME_SYNC")
    else
        tree:add(xcp_info, observableClocks_field, "Grandmaster-synced clock: reserved (3)")
    end
    if ecuClock == 0 then
        tree:add(xcp_info, observableClocks_field, "ECU clock: not available")
    elseif ecuClock == 1 then
        tree:add(xcp_info, observableClocks_field, "ECU clock: random-read possible")
    elseif ecuClock == 2 then
        tree:add(xcp_info, observableClocks_field, "ECU clock: no random read, only EV_TIME_SYNC")
    else
        tree:add(xcp_info, observableClocks_field, "ECU clock: used for timestamps but not explicitly readable")
    end
    if unknownObsClkBits ~= 0 then
        tree:add(xcp_info, observableClocks_field, "Unknown bits in OBSERVABLE_CLOCKS: " .. hex(unknownObsClkBits, 2))
    end
    cmd_pkt.TIME_CORRELATION_PROPERTIES__slaveClock = slaveClock
    cmd_pkt.TIME_CORRELATION_PROPERTIES__gmClock = gmClock
    cmd_pkt.TIME_CORRELATION_PROPERTIES__ecuClock = ecuClock

    local slaveSyncState = band(syncState, 7)
    local slaveSyncStates = {
        [0] = "synchronizing",
        "synchronized",
        "syntonizing",
        "syntonized",
        "reserved (4)",
        "reserved (5)",
        "reserved (6)",
        "not supported"
    }
    local node = tree:add(xcp_info, syncState_field, "Slave clock sync state: " .. slaveSyncStates[slaveSyncState])
    if slaveClock ~= 1 then
        node:append_text(" (ignored)")
    end
    local gmSyncState = band(rshift(syncState, 3), 1)
    local gmSyncStates = { [0] = "not yet synchronized", "synchronized" }
    node = tree:add(xcp_info, syncState_field, "Gramdmaster-synced clock sync state: " .. gmSyncStates[gmSyncState])
    if gmClock == 0 then
        node:append_text(" (ignored)")
    end
    local ecuSyncState = band(rshift(syncState, 4), 3)
    local ecuSyncStates = { [0] = "not synchronized", "synchronized", "unknown", "reserved (3)" }
    node = tree:add(xcp_info, syncState_field, "ECU clock sync state: " .. ecuSyncStates[ecuSyncState])
    if ecuClock == 0 then
        node:append_text(" (ignored)")
    end
    local unknownSyncBits = band(syncState, 0xc0)
    if unknownSyncBits ~= 0 then
        tree:add(xcp_info, syncState_field, "Unknown bits in Sync state: " .. hex(unknownSyncBits, 2))
    end

    local unknownInfoBits = band(clockInfo, 0xe0)
    local infoString = ""
    if band(clockInfo, 1) ~= 0 then
        infoString = infoString .. "Slave clock, "
    end
    if band(clockInfo, 2) ~= 0 then
        infoString = infoString .. "Grandmaster-synced clock, "
    end
    if band(clockInfo, 4) ~= 0 then
        infoString = infoString .. "Clock relation, "
    end
    if band(clockInfo, 8) ~= 0 then
        infoString = infoString .. "ECU clock, "
    end
    if band(clockInfo, 16) ~= 0 then
        infoString = infoString .. "ECU grandmaster clock, "
    end
    if unknownInfoBits ~= 0 then
        infoString = infoString .. "Unknown bits (" .. hex(unknownInfoBits, 2) .. "), "
    end
    infoString = string.sub(infoString, 1, -3)
    tree:add(xcp_info, clockInfo_field, "Information available at MTA: " .. infoString)
    tree:add(xcp_reserved, buffer(5, 1))
    tree:add(xcp_info, clusterId_field, "Cluster ID: " .. hex(clusterId, 4))

end

RES_DECODERS = {
    [0xFF]=decode_res_connect,
    [0xFD]=decode_res_get_status,
    [0xFB]=decode_res_get_comm_mode_info,
    [0xFA]=decode_res_get_id,
    [0xF9]=decode_res_set_request,
    [0xF8]=decode_res_get_seed,
    [0xF7]=decode_res_unlock,
    [0xF5]=decode_res_upload,
    [0xF3]=decode_res_build_checksum,
    [0xF2]=decode_res_transport_layer_cmd__user_cmd,
    [0xF1]=decode_res_transport_layer_cmd__user_cmd,
    [0xEA]=decode_res_get_cal_page,
    [0xE9]=decode_res_get_pag_processor_info,
    [0xE8]=decode_res_get_segment_info,
    [0xE7]=decode_res_get_page_info,
    [0xE5]=decode_res_get_segment_mode,
    [0xDF]=decode_res_get_daq_list_mode,
    [0xDE]=decode_res_start_stop_daq_list,
    [0xDC]=decode_res_get_daq_clock__ev_time_sync,
    [0xDB]=decode_res_read_daq,
    [0xDA]=decode_res_get_daq_processor_info,
    [0xD9]=decode_res_get_daq_resolution_info,
    [0xD8]=decode_res_get_daq_list_info,
    [0xD7]=decode_res_get_daq_event_info,
    [0xD2]=decode_res_program_start,
    [0xCE]=decode_res_get_pgm_processor_info,
    [0xCD]=decode_res_get_sector_info,
    [0xC6]=decode_res_time_correlation_properties,
}

function decode_res(buffer, pinfo, tree)
    local comm_mode_basic = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "COMM_MODE_BASIC", 0)
    local cmd_pid = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "CMD")
    local cmd_pktnum = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "pinfo.number")
    tree:append_text(" Response to " .. COMMAND_NAMES[cmd_pid])
    tree:add(xcp_type, buffer(0, 1), "Command Response")
    local cmd_pkt = {}
    if cmd_pktnum ~= nil then
        tree:add(xcp_request, cmd_pktnum):set_generated()
        cmd_pkt = conversations[pinfo.private.xcp_conversation][cmd_pktnum]
    end
    if cmd_pid ~= nil then
        tree:add(xcp_cmd, cmd_pid):set_generated()
        local cmd_name = COMMAND_NAMES[cmd_pid]
        if cmd_name then
            pinfo.cols.info:set("XCP pos. response to " .. cmd_name)
        else
            pinfo.cols.info:set("XCP pos. response to unknown command " .. hex(cmd_pid, 2))
        end
    end

    local decoder = RES_DECODERS[cmd_pid]
    if decoder then
        decoder(buffer, pinfo, tree, cmd_pkt, comm_mode_basic)
    end
end

function decode_err(buffer, pinfo, tree)
    local err_code = buffer(1, 1):le_uint()
    local comm_mode_basic = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "COMM_MODE_BASIC", 0)
    local address_granularity = band(rshift(comm_mode_basic, 1), 0x3)
    if err_code == 0 then
        pinfo.cols.info:set("SYNCH response")
        tree:append_text(" Response to SYNCH")
        tree:add(xcp_type, buffer(0, 2), "SYNCH")
        return
    end
    local cmd_pid = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "CMD")
    local cmd_pktnum = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "pinfo.number")
    local cmd_name = COMMAND_NAMES[cmd_pid]
    local err_name = ERR_CODES[err_code]
    local info_string = "XCP Error: "
    if err_name then
        info_string = info_string .. err_name
    else
        info_string = "Unknown " .. info_string .. hex(err_code, 2)
    end
    if cmd_name then
        info_string = info_string .. " (in response to " .. cmd_name .. ")"
    elseif cmd_pid then
        info_string = info_string .. " (in response to unknown command" .. hex(cmd_pid, 2) .. ")"
    end
    pinfo.cols.info:set(info_string)

    if cmd_pid == 0xc6 then
        -- if the command was not successful, it did not change whether extended or legacy format is used
        local cmd_pktnum = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "pinfo.number")
        conversations[pinfo.private.xcp_conversation][cmd_pktnum]["TIME_SYNCHRONIZATION_PROPERTIES__extended"] = nil
    end
    tree:add(xcp_type, buffer(0, 1), "Error")
    tree:add(xcp_request, cmd_pktnum):set_generated()
    tree:add(xcp_cmd, cmd_pid):set_generated()
    tree:add(xcp_err, buffer(1, 1), err_code)
    if err_code == 0x22 then
        -- ERR_OUT_OF_RANGE
        if cmd_pid == 0xF3 then
            -- BUILD_CHECKSUM
            local mtaBlockSizeAlign_field = buffer(2, 2)
            local mtaBlockSizeAlign = parse_number(mtaBlockSizeAlign_field, comm_mode_basic)
            tree:add(xcp_info, mtaBlockSizeAlign_field, "MTA_BLOCK_SIZE_ALIGN: " .. mtaBlockSizeAlign)
            local maxAllowedBlockSize_field = buffer(4, 4)
            local maxAllowedBlockSize = parse_number(maxAllowedBlockSize_field, comm_mode_basic)
            tree:add(xcp_info, maxAllowedBlockSize_field,
                "Maximum allowed block size: " .. maxAllowedBlockSize .. AG_TYPES[address_granularity])
        end
    elseif err_code == 0x31 then
        -- ERR_GENERIC
        local implementationSpecificDeviceErrorCode_field = buffer(2, 2)
        local implementationSpecificDeviceErrorCode = parse_number(implementationSpecificDeviceErrorCode_field,
            comm_mode_basic)
        tree:add(xcp_info, implementationSpecificDeviceErrorCode_field,
            "implementation-specific device error code: " .. implementationSpecificDeviceErrorCode)
    elseif err_code == 0x29 then
        -- ERR_SEQUENCE
        if cmd_pid == 0xef or cmd_pid == 0xca then
            -- DOWNLOAD_NEXT, PROGRAM_NEXT
            local numExpected_field = buffer(2, 1)
            local numExpected = numExpected_field:uint()
            tree:add(xcp_info, numExpected_field, "Number of expected data Elements: " .. numExpected)
        end
    end
end

function decode_ev(buffer, pinfo, tree)
    local event_code = buffer(1, 1):le_uint()
    local event_name = EV_CODES[EV_CODES]
    if not event_name then
        event_name = "Unknown event " .. hex(event_code, 2)
    end
    tree:append_text(" " .. event_name)
    pinfo.cols.info:set("XCP " .. event_name)
    local comm_mode_basic = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "COMM_MODE_BASIC", 0)

    tree:add(xcp_type, buffer(0, 1), "Event")
    tree:add(xcp_ev, buffer(1, 1), event_code)
    if event_code == 0x00 then
        -- EV_RESUME_MODE
        local sessionConfigurationId_field = buffer(2, 2)
        local sessionConfigurationId = parse_number(sessionConfigurationId_field, comm_mode_basic)
        tree:add(xcp_info, sessionConfigurationId_field, "sessionConfigurationId: " .. sessionConfigurationId)
        if buffer:len() >= 8 then
            local timestamp_field = buffer(4, 4)
            local timestamp = parse_number(timestamp_field, comm_mode_basic)
            tree:add(xcp_info, timestamp_field, "timestamp: " .. timestamp)
        end
        -- events 1 thru 7 have no payload
    elseif event_code == 0x08 then
        -- EV_TIME_SYNC
        decode_res_get_daq_clock__ev_time_sync(buffer, pinfo, tree, {}, comm_mode_basic)
    elseif event_code == 0x09 then
        -- EV_STIM_TIMEOUT
        local infoType_field = buffer(2, 1)
        local infoType = infoType_field:uint()
        local failureType_field = buffer(3, 1)
        local failureType = failureType_field:uint()
        local number_Field = buffer(4, 2)
        local number = parse_number(number_Field, comm_mode_basic)

        local failureType_string = ""
        if failureType == 0 then
            failureType_string = "Timeout"
        elseif failureType == 1 then
            failureType_string = "DTO_CTR check failed"
        elseif failureType <= 127 then
            failureType_string = "Reserved (" .. hex(failureType) .. ")"
        else
            failureType_string = "User defined (" .. hex(failureType) .. ")"
        end

        local infoType_string = "unknown"
        if infoType == 0 then
            infoType_string = "Event channel"
        elseif infoType == 1 then
            infoType_string = "DAQ list"
        else
            infoType_string = "Unknown"
        end
        tree:add(xcp_info, infoType_field, "Info type: " .. infoType_string)
        tree:add(xcp_info, failureType_field, "Failure type: " .. failureType_string)
        tree:add(xcp_info, number_Field, infoType_string .. " number: " .. number)

        -- events 0x0a and 0x0b have no payload
    elseif event_code == 0x0c then
        -- EV_ECU_STATE_CHANGE
        local state_field = buffer(2, 1)
        local state = state_field:uint()
        tree:add(xcp_info, state_field, "state: " .. state)
        -- events 0x0d thru 0xfd are not defined
    elseif event_code == 0xfe or event_code == 0xff then
        -- EV_USER, EV_TRANSPORT
        tree:add(xcp_data, buffer(2))
    end
end

function decode_serv(buffer, pinfo, tree)
    tree:add(xcp_type, buffer(0, 1), "Service Request")
    local requestCode_field = buffer(1, 1)
    local requestCode = requestCode_field:uint()
    tree:add(xcp_serv, requestCode_field, requestCode)
    pinfo.cols.info:set("XCP Service Request")
    if requestCode == 1 then
        tree:add(xcp_info, buffer(2):string())
    end
end

function decode_daq_stim(buffer, pinfo, tree, mode)
    pinfo.cols.info:set("XCP " .. mode)
    tree:append_text(" " .. mode)
    local pid_field = buffer(0, 1)
    tree:add(xcp_type, pid_field, mode)

    local pkt_data = {}
    conversations[pinfo.private.xcp_conversation][pinfo.number] = pkt_data
    local comm_mode_basic = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "COMM_MODE_BASIC", 0)
    local timestamp_size = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "TIMESTAMP_SIZE", 0)
    local timestamp_fixed = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "TIMESTAMP_FIXED", false)
    local timestamp_supported = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "TIMESTAMP_SUPPORTED", false)
    local timestamp_enabled = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "TIMESTAMP_ENABLED", false)
    local dto_ctr = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "DTO_CTR", {})
    local first_pid = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "FIRST_PID", {})
    local daq_running = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "DAQ_RUNNING", {})
    local prev_odt = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "ODT", 255)

    -- TODO: when introducing new transport layers, support for PID_OFF might be needed
    local idType = find_stored_data(pinfo.private.xcp_conversation, pinfo.number, "DAQ_IDTYPE", 99)
    if idType > 3 then
        tree:add(xcp_info, "DAQ ID type not known, can't interpret DAQ header"):set_generated()
        tree:add(xcp_data, buffer)
        return
    end
    local pid = pid_field:uint()
    local offset = idType + 1
    local daq = -1
    if idType == 0 then
        tree:add(xcp_info, pid_field, "absolute ODT: " .. pid)
        for daq_, hasCounter in pairs(dto_ctr) do
            if hasCounter and daq_running[daq_] and pid == first_pid[daq_] then
                local ctr_field = buffer(offset, 1)
                offset = offset + 1
                local ctr = ctr_field:uint()
                tree:add(xcp_info, ctr_field, "Counter: " .. ctr)
            end
        end
    else
        tree:add(xcp_info, pid_field, "relative ODT: " .. pid)
        local daq_field = nil
        if idType == 1 then
            daq_field = buffer(1, 1)
        elseif idType == 2 then
            daq_field = buffer(1, 2)
        else
            -- 3
            tree:add(xcp_reserved, buffer(1, 1))
            daq_field = buffer(2, 2)
        end
        daq = parse_number(daq_field, comm_mode_basic)
        tree:add(xcp_info, daq_field, "DAQ list: " .. daq)
        if pid <= prev_odt and dto_ctr[daq] then
            -- assumption: ODTs per DAQ list are transferred/captured in ascending order
            local ctr_field = buffer(offset, 1)
            if idType == 3 then
                ctr_field = buffer(1, 1)
            else
                offset = offset + 1
            end
            local ctr = ctr_field:uint()
            tree:add(xcp_info, ctr_field, "Counter: " .. ctr)
        end
        if timestamp_fixed or (timestamp_supported and timestamp_enabled) then
            if pid <= prev_odt then
                -- assumption: ODTs per DAQ list are transferred/captured in ascending order
                local timestamp_field = buffer(offset, timestamp_size)
                offset = offset + timestamp_size
                local timestamp = parse_number(timestamp_field, comm_mode_basic)
                tree:add(xcp_info, timestamp_field, "Timestamp: " .. timestamp)
            end
        end
    end
    pkt_data.DAQ = daq
    pkt_data.ODT = pid
    tree:add(xcp_data, buffer(offset))
end

function xcpProto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then
        return
    end

    pinfo.cols.protocol = xcpProto.name
    local pid = buffer(0, 1):le_uint()
    if conversations[pinfo.private.xcp_conversation] == nil then
        conversations[pinfo.private.xcp_conversation] = {}
    end

    if pinfo.private.xcp_dir == "CMD"
    then
        if pid >= 0xc5 then
            decode_cmd(buffer, pinfo, tree)
        else
            decode_daq_stim(buffer, pinfo, tree, "STIM")
        end
    elseif pinfo.private.xcp_dir == "RES"
    then
        if pid == 0xFF then
            decode_res(buffer, pinfo, tree)
        elseif pid == 0xFE then
            decode_err(buffer, pinfo, tree)
        elseif pid == 0xFD then
            decode_ev(buffer, pinfo, tree)
        elseif pid == 0xFC then
            decode_serv(buffer, pinfo, tree)
        else
            decode_daq_stim(buffer, pinfo, tree, "DAQ")
        end
    end
end

return xcpProto
