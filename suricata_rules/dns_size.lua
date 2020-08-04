function init(args)
    local needs = {}
    needs["payload"] = tostring(true)
    return needs
end

-- Extracts an unsigned short from the payload at a given offet.
function get_short(offset)
    local upper_byte = payload:byte(offset)
    local lower_byte = payload:byte(offset + 1)
    return tonumber(upper_byte) * 256 + tonumber(lower_byte)
end

function match(args)
    payload = args["payload"]
    if payload == nil then
        print("DNS payload empty! Aborting...")
        return 0
    end

    -- Obtain the protocol being used: TCP or UDP.
    local _, _, _, proto, _, _ = SCPacketTuple()
    
    -- If it's DNS over TCP, compare the length specified in the first two bytes to the actual length.
    if proto == 6 then
        -- RFC 7766 specifies the length is reported in the first two bytes of the DNS layer.
        dns_size = get_short(1)

        -- Check to ensure reported lenghth is the same as actual length. Subtract 2 for the length field itself.
        if dns_size ~= (string.len(payload) - 2) then
            return 1
        end

        -- Otherwise, the size is valid.
        return 0

    -- If it's DNS over UDP, ensure that the size is no greater than 512 (no EDNS) or no greater than specified (EDNS).
    elseif proto == 17 then

        -- We add 8 to account for the UDP header.
        local actual_udp_len = string.len(payload) + 8    

        -- Look for Additonal RRs which may contain the EDNS(0) OPT preudo-RR.
        local additional_rrs = get_short(11)
        if additional_rrs > 0 then
            -- We're looking for 0x00 0x00 0x29 for the NAME and TYPE fields. RFC requires these values for the OPT RR.
            local s, e = string.find(payload, "\000\000\041", 13)    -- First 12 bytes are fixed-length fields.
            if s then
                local edns_max_len = get_short(e + 1)

                -- Flag if the packet exceeds either the specified EDNS size or 4096.
                if actual_udp_len > edns_max_len or actual_udp_len > 4096 then
                    return 1
                end
            end

        -- Otherwise, the DNS packet is not using EDNS(0) and thus should not exceed 512 bytes.
        elseif actual_udp_len > 512 then
            return 1
        end

        -- If neither size condition is triggered, don't flag.
        return 0
    end

    -- Something has clearly gone wrong.
    return 0
end
