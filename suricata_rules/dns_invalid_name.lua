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

-- Only *, -, _, 0-9, A-Z, and a-z should be present in a domain name.
is_valid_char = {
    [42] = true,    -- '*' (Used in wildcards).
    [45] = true,    -- '-'
    [95] = true,    -- '_' (Used in SRV records).
}

-- 0 through 9.
for i = 48, 57  do is_valid_char[i] = true end

-- A through Z.
for i = 65, 90  do is_valid_char[i] = true end

-- a through z.
for i = 97, 122 do is_valid_char[i] = true end

-- Checks whether a domain name is too long or contains invalid characters, terminating on a null or pointer.
function check_name(offset, upper_bound)
    local hit_upper_bound = false
    local name_length = 0

    -- We accept domain names up to 256 instead of 255 to accommodate the leading "." we're implying in our logic.
    while name_length <= 256 and offset <= upper_bound do
        local x = tonumber(payload:byte(offset))

        -- Terminate name on null.
        if x == 0 then
            offset = offset + 1
            break
        end

        -- Terminate name on pointer. Treck classifies any label where the first two bits aren't 00 as pointers.
        if x > 63 then
            -- Pointers contribute at least two bytes (1 for the ".", at least 1 for the name being pointed to).
            name_length = name_length + 2

            offset = offset + 2
            break
        end

        -- For standard labels, check every character.
        for i = 1, x do
            if not is_valid_char[tonumber(payload:byte(offset + i))] then
                return false, hit_upper_bound, offset
            end
        end

        -- Add the label length to the running total, plus an extra 1 for the "." separating labels.
        name_length = name_length + x + 1
      
        -- Jump to the start of the next label.
        offset = offset + x + 1 
    end

    -- Truncate if necessary.
    if offset > upper_bound then
        hit_upper_bound = true
        name_length = name_length - (offset - upper_bound)
        offset = upper_bound
    end

    -- Names longer than 255 bytes are invalid.
    if name_length > 256 then
        return false, hit_upper_bound, offset
    end

    -- Return values are (<VALID?>, <HIT_UPPER_BOUND?>, <NEW_OFFSET>)
    return true, hit_upper_bound, offset
end

-- Lookup table that associates RR types with the location of domain names in their RDATA.
name_loc_in_rdata = {
--  TYPE #      FUNCTION THAT GETS OFFSET OF DOMAIN NAME IN RDATA                       TYPE NAME
-------------------------------------------------------------------------------------------------
    [2]     =   function (start_of_rdata) return start_of_rdata         end,        --  NS
    [5]     =   function (start_of_rdata) return start_of_rdata         end,        --  CNAME
    [6]     =   function (start_of_rdata) return start_of_rdata         end,        --  SOA
    [12]    =   function (start_of_rdata) return start_of_rdata         end,        --  PTR
    [15]    =   function (start_of_rdata) return start_of_rdata + 2     end,        --  MX
    [24]    =   function (start_of_rdata) return start_of_rdata + 18    end,        --  SIG
    [30]    =   function (start_of_rdata) return start_of_rdata         end,        --  NXT
    [33]    =   function (start_of_rdata) return start_of_rdata + 6     end,        --  SRV
    [36]    =   function (start_of_rdata) return start_of_rdata + 2     end,        --  KX
    [39]    =   function (start_of_rdata) return start_of_rdata         end,        --  DNAME
    [45]    =   function (start_of_rdata)                                           --  IPSECKEY
                    local gateway_type = tonumber(payload:byte(start_of_rdata + 1))

                    -- IPSECKEY's RDATA only contains a name if GATEWAY TYPE is 3
                    if gateway_type == 3 then return start_of_rdata + 3
                    else return nil end
                end,
    [46]    =   function (start_of_rdata) return start_of_rdata + 18    end,        --  RRSIG
    [47]    =   function (start_of_rdata) return start_of_rdata         end,        --  NSEC
    [55]    =   function (start_of_rdata)                                           --  HIP
                    local hit_length = tonumber(payload:byte(start_of_rdata))
                    local pk_length  = get_short(start_of_rdata + 2)
                    return start_of_rdata + 4 + hit_length + pk_length
                end,
    [249]   =   function (start_of_rdata) return start_of_rdata         end,        --  TKEY
    [250]   =   function (start_of_rdata) return start_of_rdata         end,        --  TSIG
    [257]   =   function (start_of_rdata)                                           --  CAA
                    -- TAG LENGTH is 1 byte, comes after single-byte FLAGS field.
                    local tag_lenth = tonumber(payload:byte(start_of_rdata + 1))

                    -- TAG field follows after TAG LENGTH field and is case-insensitive.
                    local tag = string.lower(string.sub(payload, start_of_rdata + 2, start_of_rdata + 6))

                    -- A domain name may exist in the VALUE field if TAG is either "issue" or "issuewild".
                    if tag_lenth >= 5 and tag == "issue" then
                        -- If the domain name is not present, the first character of the VALUE field will be a ';'.
                        if payload:byte(start_of_rdata + 2 + tag_lenth) == 59 then return nil

                        -- Otherwise, the name begins at the start of the VALUE field.
                        else return start_of_rdata + 2 + tag_lenth end
                    end
                end,
}

function match(args)
    payload = args["payload"]
    if payload == nil then
        print("DNS payload empty! Aborting...")
        return 0
    end

    -- Normalize the DNS payload by removing the length bytes for DNS over TCP.
    local _, _, _, proto, _, _ = SCPacketTuple()
    if proto == 6 then
        table.remove(payload, 1)
        table.remove(payload, 1)
    end

    -- Get the number of Questions.
    local questions = get_short(5)

    -- Get the number of RRs.
    local answer_rrs     = get_short(7)
    local auth_rrs       = get_short(9)
    local additional_rrs = get_short(11)
    local total_rrs = answer_rrs + auth_rrs + additional_rrs

    local valid          = true     -- Flag for whether the current packet is valid.
    local end_of_payload = false    -- Flag for whether we've hit the end of our payload buffer.

    -- The first 12 bytes of DNS are fixed-length fields, so we start searching for questions/records at offset = 13.
    local offset = 13

    -- Process QNAME field for each Question.
    for i = 1, questions do
        valid, end_of_payload, offset = check_name(offset, string.len(payload))
        if not valid then
            return 1
        elseif end_of_payload then
            return 0
        end

        -- Skip over the CLASS and TYPE fields of the Question.
        offset = offset + 4
    end

    -- Process NAME field and optionally RDATA fields for each RR.
    for i = 1, total_rrs do
        valid, end_of_payload, offset = check_name(offset, string.len(payload))
        if not valid then
            return 1
        elseif end_of_payload then
            return 0
        end
    
        -- Get the record TYPE.
        local type = get_short(offset)
        offset = offset + 8

        -- Get the RDLEGNTH.
        local rdlength = get_short(offset)
        offset = offset + 2

        -- Save the start and end of the RDATA field.
        local start_of_rdata = offset
        local end_of_rdata = start_of_rdata + rdlength - 1

        -- Ensure there is enough data left in the payload for the specified RDATA length.
        if end_of_rdata > string.len(payload) then
            return 0
        end

        -- Only process RDATA if it contains a domain name.
        if name_loc_in_rdata[type] then
            local start_of_name = name_loc_in_rdata[type](start_of_rdata)
            local hit_end_of_rdata = false
            valid, hit_end_of_rdata, offset = check_name(start_of_name, end_of_rdata)
            if not valid then return 1 end

            -- SOA records have two domain names back-to-back.
            if type == 6 and not hit_end_of_rdata then
                valid, _, offset = check_name(offset, end_of_rdata)
                if not valid then return 1 end

            -- HIP records can contain an arbitrary number of domain names back-to-back.
            elseif type == 55 then
                while not hit_end_of_rdata do
                    valid, hit_end_of_rdata, offset = check_name(offset, end_of_rdata)
                    if not valid then return 1 end
                end
            end
        end

        -- Jump to the start of the next record.
        offset = end_of_rdata + 1
    end

    -- Return 0 if no invalid names are found.
    return 0
end
