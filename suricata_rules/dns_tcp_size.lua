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
        print("TCP payload empty! Aborting...")
        return 0
    end

    -- RFC 7766 specifies the length is reported in the first two bytes of the DNS layer.
    dns_size = get_short(1)

    -- Check to ensure reported lenghth is the same as actual length. Subtract 2 for the length field itself.
    if dns_size ~= (string.len(payload) - 2) then
	    return 1
    end

    -- Otherwise, the size is valid.
    return 0
end
