function init(args)
    local needs = {}
    needs["payload"] = tostring(true)
    return needs
end

-- Extracts an unsigned short from the DNS payload at a given offet.
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

    -- Thresholds for flagging - change as needed.
    TOTAL_THRESHOLD       = 40
    CONSECUTIVE_THRESHOLD = 3

    local total       = 0   -- Total number of pointers found in the packet.
    local consecutive = 0   -- Maximum number of consecutive pointers found in the packet.
    local prev_offset = 1   -- The offset of the last pointer we found, to keep track of consecutives.
    local cur_offset  = 1   -- Our current offset into the DNS payload payload.

    -- Break out if we reach either of our thresholds or run out of bytes in our payload, whichever comes first.
    while cur_offset < string.len(payload) and total < TOTAL_THRESHOLD and consecutive < CONSECUTIVE_THRESHOLD do
        local cur_byte = tonumber(payload:byte(cur_offset))

        -- Treck interprets any label starting with a byte > 63 as a pointer, so any byte > 63 could be a pointer.
        if cur_byte > 63 then
            -- Lower 14 bits of the pointer specify its offset, which is zero-indexed, while Lua is one-indexed.
            local ptr_offset = (get_short(cur_offset) % 0x4000) + 1

            -- Compression pointers cannot point to an offset past their current location. They can only "point back".
            if ptr_offset < cur_offset then
                -- Inside this branch, we consider this and the following byte to be a pointer, and add 1 to our total.
                total = total + 1

                -- Pointers right next to each other count towards our consecutive threshold.
                if (cur_offset - prev_offset) == 2 then
                    consecutive = consecutive + 1
                else
                    consecutive = 0
                end
                prev_offset = cur_offset

                -- Since compression pointers are made up of two bytes, we iterate an extra time.
                cur_offset = cur_offset + 1
            end
        end
        cur_offset = cur_offset + 1
    end

    -- We flag any DNS packet that breaks either of our thresholds.
    if total >= TOTAL_THRESHOLD or consecutive >= CONSECUTIVE_THRESHOLD then
        return 1
    end

    return 0
end
