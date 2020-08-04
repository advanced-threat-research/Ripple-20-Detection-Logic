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

    -- Normalize the DNS payload by removing the length bytes for DNS over TCP.
    local _, _, _, proto, _, _ = SCPacketTuple()
    if proto == 6 then
        table.remove(payload, 1)
        table.remove(payload, 1)
    end

    -- Get the number of Answer RRs.
    local answer_rrs = get_short(7)

    -- Exit if no Answer RRs are present.
    if answer_rrs == 0 then
        return 0
    end

    -- Arrays that hold (s)tart and (e)nd bytes for the 4-byte fingerprint used to identify each CNAME record.
    local s = {}
    local e = {}

    -- The number of CNAME records should never exceed the number of Answer RRs.
    for i = 1, answer_rrs do
        s[i] = 0
        e[i] = 0
    end

    -- The first 12 bytes of DNS are fixed-length fields, so we can start searching for records at offset = 13.
    local offset = 13

    -- Find each CNAME record.
    local cname_count = 0
    for i = 1, answer_rrs do

        -- We're looking for 0x00 0x05 0x00 0x01 bytes to indicate TYPE=CNAME, CLASS=IN.
        s[i], e[i] = string.find(payload, "\000\005\000\001", offset)
        if s[i] == nil then
            break
        end

        -- TTL field is 4 bytes and RDLENGTH field is 2 bytes, so we can jump ahead at least 7 bytes.
        offset = e[i] + 7
        if offset > string.len(payload) then
            break
        end
        cname_count = cname_count + 1
    end

    -- Exit if no CNAME records are present.
    if cname_count == 0 then
        return 0
    end

    -- For each CNAME record, flag any where the actual length of RDATA > RDLENGTH.
    for i = 1, cname_count do
        -- e[i] points to last byte of the CLASS field, which is followed by TTL field (4 bytes), followed by RDLENGTH.
        local rdlength = get_short(e[i] + 5)

        -- The offset to the start of the label we're looking at. RDATA goes after RDLENGTH, so we start 1 byte past it.
        offset = e[i] + 7

        -- We want to break out as soon as we compute a length > RDLENGTH or an offset past the end of the payload.
        local actual_length = 0
        while actual_length <= rdlength and offset <= string.len(payload) do
            local x = tonumber(payload:byte(offset))

            -- Treck terminates writing to the payload upon hitting a null.
            if x == 0 then
                break

            -- Treck treats any label whose first byte > 0xCF as a compression pointer.
            elseif x > 63 then

                -- According to RFC1035, a DNS name can only be:
                -- * a sequence of labels ending in a zero octet
                -- * a pointer
                -- * a sequence of labels ending with a pointer
                -- So we stop counting after accounting for the first pointer hit.
                actual_length = actual_length + 2
                break
            end

            -- Otherwise, it's a standard label. Total size added = length byte + length specified in length byte.
            local label_length = x + 1

            -- In the case where label_length goes past the end of the payload, set label_length to the remaining bytes.
            if (offset + label_length) > string.len(payload) then
                label_length = string.len(payload) - offset + 1
            end

            -- Add the length of this label to our running total for RDATA.
            actual_length = actual_length + label_length

            -- Move to the start of the next label.
            offset = offset + label_length
        end

        -- Flag any packet containing a CNAME record where len(RDATA) > RDLENGTH, as this will trigger CVE-2020-11901.
        if actual_length > rdlength then
            return 1
        end
    end

    -- Otherwise, return 0 if no CNAME records are flagged.
    return 0
end
