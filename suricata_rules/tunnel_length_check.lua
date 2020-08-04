function init (args)
   local needs = {}
   needs["packet"] = tostring(true)
   return needs
end

function string.tohex(str)
   return (str:gsub('.', function (c)
		       return string.format('%02X ', string.byte(c))
   end))
end

function match(args)
   local b = args['packet']
   if b == nil then
      print ("buffer empty! Aborting..")
      return 0
   end

   --find beginning of inner packet
   --start from IP protocol field in header
   s,e	= string.find(b,"\004")
   --inner packet should start 18 bytes later
   inner_packet = string.sub(b, s+18)

   --inner packet should be ipv4 with length of 20 bytes
   --first nibble of packet should be 0x4, second should
   --be 0x5 – combined to a byte this is 0x45
   packet_preamble = inner_packet:byte(1)
   if packet_preamble ~= 0x45 then
      return 0
   end

   --probably a better way to do this, but for now, this works
   --two byte field, so high byte gets multiplied by 16^2
   packet_len_high = tonumber(inner_packet:byte(25))*256
   packet_len_low = tonumber(inner_packet:byte(26))

   --get lengths to compare
   listed_length = packet_len_high + packet_len_low

   --data field starts 26 bytes after start of encapsulation
   --20 bytes of IP header, 6 bytes of UDP header, then payload
   --because 1-indexed, it starts at 27
   actual_length = string.len(string.sub(inner_packet, 27))

   --actual length should be exactly equal to length field in 
   --header, though in practice exploitation requires it be longer
   if actual_length > listed_length then
      --print (string.tohex(inner_packet))
      return 1
   end
   
   return 0
end
