**Ripple20 Critical Vulnerabilities -- Detection Logic and Signatures**
=======================================================================

McAfee Advanced Threat Research

*Steve Povolny, Douglas McKee, Mark Bereza, D. Kevin McGrath*

This document has been prepared by McAfee Advanced Threat Research in
collaboration with JSOF who discovered and responsibly [disclosed the
vulnerabilities](https://www.jsof-tech.com/ripple20/). It is intended to
serve as a joint research effort to produce valuable insights for
network administrators and security personnel, looking to further
understand these vulnerabilities to defend against exploitation. The
signatures produced here should be thoroughly considered and vetted in
staging environments prior to being used in production and may benefit
from specific tuning to the target deployment. There are technical
limitations to this work, including the fact that more complex methods
of detection might be required to detect these vulnerabilities. For
example, multiple layers of encapsulation may obfuscate the exploitation
of the flaws and increase the difficulty of detection.

We have also provided packet captures taken from the vulnerability
Proof-of-Concepts as artifacts for testing and deployment of either the
signatures below or customized signatures based on the detection logic.
Signatures and Lua Scripts are located on ATR's
[Github](https://github.com/advanced-threat-research/Ripple-20-Detection-Logic)
page**,** as well as inline and in the appendix of this document
respectively.

As of this morning (August 5^th^), JSOF has presented additional
technical detail and exploitation analysis at [BlackHat
2020](https://www.blackhat.com/us-20/briefings/schedule/index.html#hacking-the-supply-chain--vulnerabilities-haunt-tens-of-millions-of-critical-devices-19493),
on the two most critical vulnerabilities in DNS.

*The information provided herein is subject to change without notice,
and is provided "AS IS", with all faults, without guarantee or warranty
as to the accuracy or applicability of the information to any specific
situation or circumstance and for use at your own risk. Additionally, we
cannot guarantee any performance or efficacy benchmarks for any of the
signatures.*

Integer Overflow in tfDnsExpLabelLength Leading to Heap Overflow and RCE
------------------------------------------------------------------------

**CVE:** CVE-2020-11901 (Variant 1)\
**CVSS:** 9\
**Protocol(s):** DNS over UDP (and likely DNS over TCP)\
**Port(s):** 53

**Vulnerability description:**

In the Treck stack, DNS names are calculated via the function
tfDnsExpLabelLength. A bug exists in this function where the computation
is performed using an unsigned short, making it possible to overflow the
computed value with a specially constructed DNS response packet. Since
tfDnsExpLabelLength computes the full length of a DNS name after it is
decompressed, it is possible to induce an overflow using a DNS packet
far smaller than 2^16^ bytes. In some code paths, tfGetRawBuffer is
called shortly after tfDnsExpLabelLength, allocating a buffer on the
heap where the DNS name will be stored using the size computed by
tfDnsExpLabelLength, thus leading to a heap overflow and potential RCE.

While newer versions of the Treck stack will stop copying the DNS name
into the buffer as soon as a character that isn't alphanumeric or a
hyphen is reached, older versions do not have this restriction and
further use predictable transaction IDs for DNS queries, making this
vulnerability easier to exploit.\
\
**Limitations or special considerations for detection:**

Ideally, detection logic for this vulnerability would involve
independently computing the uncompressed length of all DNS names
contained within incoming DNS responses. Unfortunately, this may be
computationally expensive for a device to perform for every incoming DNS
response, especially since each one may contain many DNS names. Instead,
we must rely on a combination of heuristics.

Furthermore, it is currently unclear whether exercising this
vulnerability is possible when using EDNS(0) or DNS over TCP. We
recommend assuming it is possible for the purposes of implementing
detection logic. During our testing, an inconsistency in how Suricata
handled DNS over TCP was discovered -- in some cases it was correctly
identified as DNS traffic and in other cases, it was not. Consequently,
two rules have been created to determine the size of DNS over TCP
traffic. The second rule uses the TCP primitive instead of the DNS
primitive; however, the second rule will only be evaluated if not
flagged by the first rule.

Because the Suricata rule in dns_invalid_size.rules uses the DNS
responses' EDNS UDP length, which may be controlled by the attacker, a
second upper limit of 4096 bytes is enforced.

**Recommended detection criteria:**

-   The device must be capable of processing DNS traffic and matching
    responses to their corresponding requests.

-   The device must be capable of identifying individual DNS names
    within individual DNS packets.

-   The device should flag any DNS responses whose size exceeds what is
    "expected". The expected size depends on the type of DNS packet
    sent:

    -   For DNS over TCP, the size should not exceed the value specified
        in the first two bytes of the TCP payload.

    -   For DNS over UDP *with* EDNS(0), the size should not exceed the
        value negotiated in the request, which is specified in the CLASS
        field of the OPT RR, if present.

    -   For DNS over UDP *without* EDNS(0), the size should not exceed
        512 bytes.

    -   These are all checked in dns_invalid_size.rules, which invokes
        either dns_size.lua or dns_tcp_size.lua for the logic.

-   The device should flag DNS responses containing DNS names exceeding
    255 bytes (prior to decompression).

    -   This is checked in dns_invalid_name.rules, which invokes
        dns_invalid_name.lua for the logic.

-   The device should flag DNS responses containing DNS names comprised
    of characters besides a-z, A-Z, 0-9, "-", "\_", and "\*".

    -   This is also checked in dns_invalid_name.rules, which invokes
        dns_invalid_name.lua for the logic.

-   The device should flag DNS responses containing a large number of
    DNS compression pointers, particularly pointers one after the other.
    The specific tolerance will depend on the network.

    -   The device should count all labels starting with the bits 0b10,
        0b01, or 0b11 against this pointer total, as vulnerable versions
        of the Treck stack (incorrectly) classify all labels where the
        first two bits aren't 0b00 as compression pointers. In the Lua
        script, we treat any value above 63 (0x3F) as a pointer for this
        reason, as any value in that range will have at least one of
        these bits set.

    -   The specific thresholds were set to 40 total pointers in a
        single DNS packet or 4 consecutive pointers for our
        implementation of this rule. These values were chosen since they
        did not seem to trigger any false positives in a very large test
        PCAP but should be altered as needed to suit typical traffic for
        the network the rule will be deployed on. The test for
        consecutive pointers is especially useful since each domain name
        should only ever have one pointer (at the very end), meaning we
        should never be seeing many pointers in a row in normal traffic.

    -   This is implemented in dns_heap_overflow_variant_1.lua, which is
        invoked by dns_heap_overflow.rules.

-   Implementation of the detection logic above has been split up
    amongst several Suricata rule files since only the pointer counting
    logic is specific to this vulnerability. Detection of exploits
    leveraging this vulnerability are enhanced with the addition of the
    DNS layer size check, domain name compressed length check, and
    domain name character check implemented in the other rules, but
    these are considered to be "helper" signatures and flagging one of
    these does not necessarily indicate an exploitation attempt for this
    specific vulnerability.

**False positive conditions (signatures detecting non-malicious
traffic):**

Networks expecting non-malicious traffic containing DNS names using
non-alphanumeric characters or an abnormally large number of DNS
compression pointers may generate false positives. Unfortunately,
checking for pointers in only the domain name fields is insufficient, as
a malicious packet could use a compression pointer that points to an
arbitrary offset within said packet, so our rule instead checks every
byte of the DNS layer. Consequently, Treck's overly liberal
classification of DNS compression pointers means that our rule will
often misclassify unrelated bytes in the DNS payload as pointers.

In our testing, we ran into false positives with domain names containing
spaces or things like "https://\". Per the RFCs, characters such as ":"
and "/" should not be present in domain names but may show up from time
to time in real, non-malicious traffic. The list of acceptable
characters should be expanded as needed for the targeted network to
avoid excessive false positives. That being said, keeping the list of
acceptable characters as small as possible will make it more difficult
to sneak in shellcode to leverage one of the Ripple20 DNS
vulnerabilities.

False positives on the DNS size rules may occur when DNS over TCP is
used if Suricata does not properly classify the packet as a DNS packet
-- something that has occurred multiple times during our testing. This
would cause the second size check to occur, which assumes that all
traffic over port 53 is DNS traffic and processes the payload
accordingly. As a result, any non-DNS traffic on TCP port 53 may cause
false positives in this specific case. It is recommended the port number
in the rule be adjusted for any network where a different protocol is
expected over port 53.

Fragmentation of DNS traffic over TCP may also introduce false
positives. If the streams are not properly reconstructed at the time the
rules execute on the DNS payload, byte offsets utilized in the attached
Lua scripts could analyze incorrect data. Fragmentation in DNS response
packets is not common on a standard network unless MTU values have been
set particularly low. Each rule should be evaluated independently prior
to use in production based on specific network requirements and
conditions.

**False negative conditions (signatures failing to detect
vulnerability/exploitation):**

False negatives are more likely as this detection logic relies on
heuristics due to computation of the uncompressed DNS name length being
too computationally expensive. Carefully constructed malicious packets
may be able to circumvent the suggested pointer limitations and still
trigger the vulnerability.

**Signature(s):**

dns_invalid_size.rules:

alert dns any any ‑\> any any (msg:\"DNS packet too large\"; flow:to_client; flowbits:set,flagged; lua:dns_size.lua; sid:2020119014; rev:1;)

*Lua script (dns_size.lua) can be found in Appendix A*

alert tcp any 53 -\> any any (msg:\"DNS over TCP packet too large\";
flow:to_client,no_frag; flowbits:isnotset,flagged; lua:dns_tcp_size.lua;
sid:2020119015; rev:1;)

*Lua script (dns_tcp_size.lua) can be found in Appendix A*

dns_invalid_name.rules:

alert dns any any -\> any any (flow:to_client; msg:\"DNS response
contains invalid domain name\"; lua:dns_invalid_name.lua;
sid:2020119013; rev:1;)

*Lua script (dns_invalid_name.lua) can be found in Appendix A*

dns_heap_overflow.rules:

\# Variant 1

alert dns any any -\> any any (flow:to_client; msg:\"Potential DNS heap
overflow exploit (CVE-2020-11901)\";
lua:dns_heap_overflow_variant_1.lua; sid:2020119011; rev:1;)

*Lua script (dns_heap_overflow_variant_1.lua) can be found in Appendix
A*

RDATA Length Mismatch in DNS CNAME Records Causes Heap Overflow
---------------------------------------------------------------

**CVE:** CVE-2020-11901 (Variant 2)\
**CVSS:** 9\
**Protocol(s):** DNS/UDP (and likely DNS/TCP)\
**Port(s):** 53

**Vulnerability description:**

In some versions of the Treck stack, a vulnerability exists in the way
the stack processes DNS responses containing CNAME records. In such
records, the length of the buffer allocated to store the DNS name is
taken from the RDLENGTH field, while the data written is the full,
decompressed domain name, terminating only at a null byte. As a result,
if the size of the decompressed domain name specified in RDATA exceeds
the provided RDLENGTH in a CNAME record, the excess is written past the
end of the allocated buffer, resulting in a heap overflow and potential
RCE.\
\
**Limitations or special considerations for detection:**

Although exploitation of this vulnerability has been confirmed using
malicious DNS over UDP packets, it has not been tested using DNS over
TCP and it is unclear if such packets would exercise the same vulnerable
code path. Until this can be confirmed, detection logic should assume
both vectors are vulnerable.

**Recommended detection criteria:**

-   The device must be capable of processing incoming DNS responses.

-   The device must be capable of identifying CNAME records within DNS
    responses

-   The device should flag all DNS responses where the actual size of
    the RDATA field for a CNAME record exceeds the value specified in
    the same record's RDLENGTH field.

    -   In this case, the "actual size" corresponds to how vulnerable
        versions of the Treck stack compute the RDATA length, which
        involves adding up the size of every label until either null
        byte, a DNS compression pointer, or the end of the payload is
        encountered. The Treck stack will follow and decompress the
        pointer that terminates the domain name, if present, but the
        script does not as this computation is simply too expensive, as
        mentioned previously.

**False positive conditions (signatures detecting non-malicious
traffic):**

False positives should be unlikely, but possible in scenarios where
network devices send non-malicious traffic where RDLENGTH is not equal
to the size of RDATA, thereby breaking RFC 1035.

**False negative conditions (signatures failing to detect
vulnerability/exploitation):**

Since the detection logic does not perform decompression when computing
the "actual size" of RDATA, it will fail to detect malicious packets
that contain domain names whose length only exceeds RDLENGTH after
decompression. Unfortunately, coverage for this case is non-trivial as
such packets are actually RFC-compliant. According to RFC 1035, section
4.1.4:

> If a domain name is contained in a part of the message subject to a
> length field (such as the RDATA section of an RR), and compression is
> used, the length of the compressed name is used in the length
> calculation, rather than the length of the expanded name.

Besides the computational overhead, enforcing such a check would likely
result in very high false positive rates.

**Signature(s):**

dns_heap_overflow.rules:

\# Variant 2

alert dns any any -\> any any (flow:to_client; msg:\"Potential DNS heap
overflow exploit (CVE-2020-11901)\";
lua:dns_heap_overflow_variant_2.lua; sid:2020119012; rev:1;)\
*Lua script (dns_heap_overflow_variant_2.lua) can be found in [Appendix
A](#dns_heap_overflow_variant_2.lua)*

Write Out-of-Bounds Using Routing Header Type 0
-----------------------------------------------

**CVE:** CVE-2020-11897\
**CVSS:** 10\
**Protocol(s):** IPv6\
**Port(s):** N/A

**Vulnerability description:**

When processing IPv6 incoming packets, an inconsistency parsing the IPv6
routing header can be triggered where the header length is checked
against the total packet and not against the fragment length. This means
that if we send fragmented packets with the overall size greater than or
equal to the specified routing header length, then we process the
routing header under the assumption that we have enough bytes in our
current fragment (where we have enough bytes in the overall reassembled
packet only). Thus, using routing header type 0 (RH0) we can force read
and write into out-of-bounds memory location.

There is also a secondary side effect where we can get an info leak in a
source IPv6 address in an ICMP parameter returned from the device.\
\
**Limitations or special considerations for detection:**

The RFC for RH0 defines the length field as equal to "two times the
number of addresses in the header." For example, if the routing header
length is six, then there are three IPv6 addresses expected in the
header. Upon reconstruction of the fragmented packets, the reported
number of addresses is filled with data from the fragments that follow.
This creates "invalid" IPv6 addresses in the header and potentially
malforms the next layer of the packet. During exploitation, it would
also be likely for the next layer of the packet to be malformed.
Although ICMP can be used to perform an information leak, it is possible
for the next layer to be any type and therefore vary in length.
Verification of the length of this layer could therefore be very
expensive and non-deterministic.

**Recommended detection criteria:**

-   The device must be capable of processing fragmented IPv6 traffic

-   The device should inspect fragmented packets containing Routing
    Header type 0 (RH0). If a RH0 IPv6 packet is fragmented, then the
    vulnerability is likely being exploited

-   If the length of the IPv6 layer of a packet fragment containing the
    RH0 header is less than the length reported in the routing header,
    then the vulnerability is likely being exploited

-   Upon reconstruction of the fragmented packets, if the header of the
    layer following IPv6 is malformed, the vulnerability may be being
    exploited

**Notes:**

The routing header type 0 was deprecated in IPv6 traffic in RFC 5095 as
of December 2007. As a result, it may be feasible simply to detect
packets using this criterion. False positives may be possible in this
scenario for legacy devices or platforms. Suricata already provides a
default rule for this scenario which has been added below. According to
the RFC, routers are not supposed to fragment IPv6 packets and must
support an MTU of 1280, which would always contain all of the RH0
header, unless an unusual amount of header extensions or an unusually
large header is used. If this is followed, then a packet using the RH0
header should never be fragmented across the RH0 extension header bounds
and any RH0 packet fragmented in this manner should be treated as
potentially malicious. Treating any fragmented RH0 packet as potentially
malicious may be sufficient. Furthermore, treating any fragmented RH0
packet with fragments size below a threshold as well as IPv6 packets
with multiple extension headers or an unusually large header above a
threshold may provide high accuracy detection.

**False positive conditions (signatures detecting non-malicious
traffic)**:

If all detection criteria outlined above are used, false positives
should be minimal since the reported length of a packet should match its
actual length and the next header should never contain malformed data.
If only routing header type 0 is checked, false positives are more
likely to occur. In the additional provided rule, false positives should
be minimal since RH0 is deprecated and the ICMP header should never have
invalid checksums or unknown codes.

**False negative conditions (signatures failing to detect
vulnerability/exploitation)**:

False negatives may occur if the signature is developed overly specific
to the layer following IPv6, for example, ICMP. An attacker could
potentially leverage another layer and still exploit the vulnerability
without the information leak; however, this would still trigger the
default RH0 rule. In the second rule below, false negatives are likely
to occur if:

-   An attacker uses a non-ICMP layer following the IPv6 layer

-   A valid ICMP code is used

-   The checksum is valid, and the payload is less than or equal to 5
    bytes (this value can be tuned in the signature)

**Signature(s):**

Ipv6_rh0.rules:

alert ipv6 any any -\> any any (msg:\"SURICATA RH Type 0\";
decode-event:ipv6.rh_type_0; classtype:protocol-command-decode;
sid:2200093; rev:2;)

alert ipv6 any any -\> any any (msg:\"IPv6 RH0 Treck CVE-2020-11897\";
decode-event:ipv6.rh_type_0; decode-event:icmpv6.unknown_code;
icmpv6-csum:invalid; dsize:\>5; sid:2020118971; rev:1;)

IPv4/UDP Tunneling Remote Code Execution
----------------------------------------

**CVE:** CVE-2020-11896

**CVSS:** 10.0\
**Protocol(s):** IPv4/UDP\
**Port(s):** Any

**Vulnerability description:**

The Treck TCP/IP stack does not properly handle incoming IPv4-in-IPv4
packets with fragmented payload data. This could lead to remote code
execution when sending multiple specially crafted tunneled UDP packets
to a vulnerable host.

The vulnerability is a result of an incorrect trimming operation when
the advertised total IP length (in the packet header) is strictly less
than the data available. When sending tunneled IPv4 packets using
multiple fragments with a small total IP length value, the TCP/IP stack
would execute the trimming operation. This leads to a heap overflow
situation when the packet is copied to a destination packet allocated
based on the smaller length. When the tunneled IPv4 packets are UDP
packets sent to a listening port, there's a possibility to trigger this
exploit if the UDP receive queue is non-empty. This can result in an
exploitable heap overflow situation, leading to remote code execution in
the context in which the Treck TCP/IP stack runs.

**Recommended detection criteria:**

In order to detect an ongoing attack, the following conditions should be
met *if encapsulation can be unpacked*:

-   The UDP receive queue must be non-empty

-   Incoming UDP packets must be fragmented

    -   Flag MF = 1 with any offset, or

    -   Flag MF = 0 with non-zero offset

-   Fragmented packets must have encapsulated IPv4 packet (upon
    assembly)\
    protocol = 0x4 (IPIP)

-   Encapsulated IPv4 packet must be split across 2 packet fragments.

-   Reassembled (inner-most) IPv4 packet has incorrect data length
    stored in IP header.

The fourth condition above is required to activate the code-path which
is vulnerable, as it spreads the data to be copied across multiple
in-memory buffers. The final detection step is the source of the buffer
overflow, as such, triggering on this may be sufficient.

Depending on the limitations of the network inspection device in
question, a looser condition could be used, though it may be more prone
to false positives.

In order to detect an ongoing attack *if encapsulation cannot be
unpacked*:

-   The UDP receive queue must be non-empty

-   Incoming UDP packets must be fragmented

    -   Flag MF = 1 with any value in offset field, or

    -   Flag MF = 0 with any non-zero value in offset field

-   Final fragment has total fragment length longer than offset field.

The final condition shown above is not something that should be seen in
a normal network.

Fragmentation, when it occurs, is the result of data overflowing the MTU
of a given packet type. This indicates the final fragment should be no
larger than any other fragment -- and in practice would likely be
smaller. The inverse, where the final fragment is somehow larger than
previous fragments, indicates that the fragmentation is not the result
of MTU overflow, but instead something else. In this case, malicious
intent.

As network monitors in common usage are likely to have the ability to
unpack encapsulation, only that ruleset is provided.

**Limitations or special considerations for detection:**

The Treck stack supports (at least) two levels of tunneling. Each tunnel
level can be IPv4-in-IPv4, IPv6-in-IPv4, or IPv4-in-IPv6. The above
logic is specific to the IPv4-in-IPv4, single level of tunneling case.
In cases of deeper nesting, either a recursive check or a full
unwrapping of all tunneling layers will be necessary.

**False positive conditions (signatures detecting non-malicious
traffic):**

False positives should be minimal if all detection criteria outlined
above are used in the case where the tunneling can be unpacked. In the
case where tunneling cannot be unpacked, this is unlikely to trigger
many false positives in the presence of standards compliant
applications. Fragmentation as seen here is simply not common.

**False negative conditions (signatures failing to detect
vulnerability/exploitation):**

False negatives could occur with deeper levels of nesting, or nesting of
IPv6.

**Signature(s):**

ipv4_tunneling.rules:

alert ip any any -\> any any (msg:\"IPv4 TUNNELING EXPLOIT
(CVE‑2020‑11896)\"; ip_proto:4; lua:tunnel_length_check.lua;
sid:2020118961; rev:1;)

*Lua script (tunnel_length_check.Lua) can be found in Appendix A*

*\
*

**Appendix A**
==============

Appendix A contains Lua scripts that are required for usage with
corresponding Suricata signatures. These scripts are also located on
McAfee ATR's [Github](https://github.com/advanced-threat-research).

dns_tcp_size.lua:
-----------------

**function** init(args)

**local** needs = {}

needs\[\"payload\"\] = tostring(**true**)

**return** needs

**end**

*\-- Extracts an unsigned short from the payload at a given offset.*

**function** get_short(offset)

**local** upper_byte = payload:byte(offset)

**local** lower_byte = payload:byte(offset + 1)

**return** tonumber(upper_byte) \* 256 + tonumber(lower_byte)

**end**

**function** match(args)

payload = args\[\"payload\"\]

**if** payload == **nil** **then**

print(\"TCP payload empty! Aborting\...\")

**return** 0

**end**

*\-- RFC 7766 specifies the length is reported in the first two bytes of
the DNS layer.*

dns_size = get_short(1)

*\-- Check to ensure reported length is the same as actual length.
Subtract 2 for the length field itself.*

**if** dns_size \~= (string.len(payload) - 2) **then**

**return** 1

**end**

*\-- Otherwise, the size is valid.*

**return** 0

**end**

**\
**

dns_size.lua:
-------------

**function** init(args)

**local** needs = {}

needs\[\"payload\"\] = tostring(**true**)

**return** needs

**end**

*\-- Extracts an unsigned short from the payload at a given offset.*

**function** get_short(offset)

**local** upper_byte = payload:byte(offset)

**local** lower_byte = payload:byte(offset + 1)

**return** tonumber(upper_byte) \* 256 + tonumber(lower_byte)

**end**

**function** match(args)

payload = args\[\"payload\"\]

**if** payload == **nil** **then**

print(\"DNS payload empty! Aborting\...\")

**return** 0

**end**

*\-- Obtain the protocol being used: TCP or UDP.*

**local** \_, \_, \_, proto, \_, \_ = SCPacketTuple()

*\-- If TCP, compare the length specified in the first two bytes to the
actual length.*

**if** proto == 6 **then**

*\-- RFC 7766 specifies the length is reported in the first two bytes of
the DNS layer.*

dns_size = get_short(1)

*\-- Check to ensure reported length is the same as actual length.
Subtract 2 for the length field itself.*

**if** dns_size \~= (string.len(payload) - 2) **then**

**return** 1

**end**

*\-- Otherwise, the size is valid.*

**return** 0

*\-- If UDP, ensure that the size is no greater than 512 (no EDNS) or no
greater than specified (EDNS).*

**elseif** proto == 17 **then**

*\-- We add 8 to account for the UDP header.*

**local** actual_udp_len = string.len(payload) + 8

*\-- Look for Additional RRs which may contain the EDNS(0) OPT
pseudo-RR.*

**local** additional_rrs = get_short(11)

**if** additional_rrs \> 0 **then**

*\-- We\'re looking for 0x00 0x00 0x29 for the NAME and TYPE fields (OPT
RR).*

**local** s, e = string.find(payload, \"**\\000\\000\\041**\", 13) *\--
First 12 bytes are fixed-length fields.*

**if** s **then**

**local** edns_max_len = get_short(e + 1)

*\-- Flag if the packet exceeds either the specified EDNS size or 4096.*

**if** actual_udp_len \> edns_max_len **or** actual_udp_len \> 4096
**then**

**return** 1

**end**

**end**

*\-- Otherwise, the DNS packet is not using EDNS(0) and thus should not
exceed 512 bytes.*

**elseif** actual_udp_len \> 512 **then**

**return** 1

**end**

*\-- If neither size condition is triggered, don\'t flag.*

**return** 0

**end**

*\-- Something has clearly gone wrong.*

**return** 0

**end**

**\
**

dns_invalid_name.lua:
---------------------

**function** init (args)

**local** needs = {}

needs\[\"payload\"\] = tostring(**true**)

**return** needs

**end**

*\-- Extracts an unsigned short from the payload at a given offset.*

**function** get_short(offset)

**local** upper_byte = payload:byte(offset)

**local** lower_byte = payload:byte(offset + 1)

**return** tonumber(upper_byte) \* 256 + tonumber(lower_byte)

**end**

*\-- Only \*, -, \_, 0-9, A-Z, and a-z should be present in a domain
name.*

is_valid_char = {

\[42\] = **true**, *\-- \'\*\' (Used in wildcards).*

\[45\] = **true**, *\-- \'-\'*

\[95\] = **true**, *\-- \'\_\' (Used in SRV records).*

}

*\-- 0 through 9.*

**for** i = 48, 57 **do** is_valid_char\[i\] = **true** **end**

*\-- A through Z.*

**for** i = 65, 90 **do** is_valid_char\[i\] = **true** **end**

*\-- a through z.*

**for** i = 97, 122 **do** is_valid_char\[i\] = **true** **end**

*\-- Checks whether a domain name is too long or contains invalid
characters, terminating on a null or pointer.*

**function** check_name(offset, upper_bound)

**local** hit_upper_bound = **false**

**local** name_length = 0

*\-- We accept domain names up to 256 instead of 255 to accommodate the
leading \".\" we\'re implying in our logic.*

**while** name_length \<= 256 **and** offset \<= upper_bound **do**

**local** x = tonumber(payload:byte(offset))

*\-- Terminate name on null.*

**if** x == 0 **then**

offset = offset + 1

**break**

**end**

*\-- Terminate name on pointer. Treck classifies any label where the
first two bits aren\'t 00 as pointers.*

**if** x \> 63 **then**

*\-- Pointers contribute at least two bytes (1 for the \".\", at least 1
for the name being pointed to).*

name_length = name_length + 2

offset = offset + 2

**break**

**end**

*\-- For standard labels, check every character.*

**for** i = 1, x **do**

**if** **not** is_valid_char\[tonumber(payload:byte(offset + i))\]
**then**

**return** **false**, hit_upper_bound, offset

**end**

**end**

*\-- Add the label length to the running total, plus an extra 1 for the
\".\" separating labels.*

name_length = name_length + x + 1

*\-- Jump to the start of the next label.*

offset = offset + x + 1

**end**

*\-- Truncate if necessary.*

**if** offset \> upper_bound **then**

hit_upper_bound = **true**

name_length = name_length - (offset - upper_bound)

offset = upper_bound

**end**

*\-- Names longer than 255 bytes are invalid.*

**if** name_length \> 256 **then**

**return** **false**, hit_upper_bound, offset

**end**

*\-- Return values are (\<VALID?\>, \<HIT_UPPER_BOUND?\>,
\<NEW_OFFSET\>)*

**return** **true**, hit_upper_bound, offset

**end**

*\-- Lookup table that associates RR types with the location of domain
names in their RDATA.*

name_loc_in_rdata = {

*\-- TYPE \# FUNCTION THAT GETS OFFSET OF DOMAIN NAME IN RDATA TYPE
NAME*

*\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--*

\[2\] = **function** (start_of_rdata) **return** start_of_rdata **end**,
*\-- NS*

\[5\] = **function** (start_of_rdata) **return** start_of_rdata **end**,
*\-- CNAME*

\[6\] = **function** (start_of_rdata) **return** start_of_rdata **end**,
*\-- SOA*

\[12\] = **function** (start_of_rdata) **return** start_of_rdata
**end**, *\-- PTR*

\[15\] = **function** (start_of_rdata) **return** start_of_rdata + 2
**end**, *\-- MX*

\[24\] = **function** (start_of_rdata) **return** start_of_rdata + 18
**end**, *\-- SIG*

\[30\] = **function** (start_of_rdata) **return** start_of_rdata
**end**, *\-- NXT*

\[33\] = **function** (start_of_rdata) **return** start_of_rdata + 6
**end**, *\-- SRV*

\[36\] = **function** (start_of_rdata) **return** start_of_rdata + 2
**end**, *\-- KX*

\[39\] = **function** (start_of_rdata) **return** start_of_rdata
**end**, *\-- DNAME*

\[45\] = **function** (start_of_rdata) *\-- IPSECKEY*

**local** gateway_type = tonumber(payload:byte(start_of_rdata + 1))

*\-- IPSECKEY\'s RDATA only contains a name if GATEWAY TYPE is 3*

**if** gateway_type == 3 **then** **return** start_of_rdata + 3

**else** **return** **nil** **end**

**end**,

\[46\] = **function** (start_of_rdata) **return** start_of_rdata + 18
**end**, *\-- RRSIG*

\[47\] = **function** (start_of_rdata) **return** start_of_rdata
**end**, *\-- NSEC*

\[55\] = **function** (start_of_rdata) *\-- HIP*

**local** hit_length = tonumber(payload:byte(start_of_rdata))

**local** pk_length = get_short(start_of_rdata + 2)

**return** start_of_rdata + 4 + hit_length + pk_length

**end**,

\[249\] = **function** (start_of_rdata) **return** start_of_rdata
**end**, *\-- TKEY*

\[250\] = **function** (start_of_rdata) **return** start_of_rdata
**end**, *\-- TSIG*

\[257\] = **function** (start_of_rdata) *\-- CAA*

*\-- TAG LENGTH is 1 byte, comes after single-byte FLAGS field.*

**local** tag_lenth = tonumber(payload:byte(start_of_rdata + 1))

*\-- TAG field follows after TAG LENGTH field and is case-insensitive.*

**local** tag = string.lower(string.sub(payload, start_of_rdata + 2,
start_of_rdata + 6))

*\-- A domain name may exist in the VALUE field if TAG is either
\"issue\" or \"issuewild\".*

**if** tag_lenth \>= 5 **and** tag == \"issue\" **then**

*\-- If a domain name is not present, the first character of the VALUE
field will be a \';\'.*

**if** payload:byte(start_of_rdata + 2 + tag_lenth) == 59 **then**
**return** **nil**

*\-- Otherwise, the name begins at the start of the VALUE field.*

**else** **return** start_of_rdata + 2 + tag_lenth **end**

**end**

**end**,

}

**function** match(args)

payload = args\[\"payload\"\]

**if** payload == **nil** **then**

print (\"DNS payload empty! Aborting\...\")

**return** 0

**end**

*\-- Normalize the DNS payload by removing the length bytes for DNS over
TCP.*

**local** \_, \_, \_, proto, \_, \_ = SCPacketTuple()

**if** proto == 6 **then**

table.remove(payload, 1)

table.remove(payload, 1)

**end**

*\-- Get the number of Questions.*

**local** questions = get_short(5)

*\-- Get the number of RRs.*

**local** answer_rrs = get_short(7)

**local** auth_rrs = get_short(9)

**local** additional_rrs = get_short(11)

**local** total_rrs = answer_rrs + auth_rrs + additional_rrs

**local** valid = **true** *\-- Flag for whether the current packet is
valid.*

**local** end_of_payload = **false** *\-- Flag for whether we\'ve hit
the end of our payload buffer.*

*\-- The first 12 bytes are fixed-length fields, so we start searching
for questions/records at offset = 13.*

**local** offset = 13

*\-- Process QNAME field for each Question.*

**for** i = 1, questions **do**

valid, end_of_payload, offset = check_name(offset, string.len(payload))

**if** **not** valid **then**

**return** 1

**elseif** end_of_payload **then**

**return** 0

**end**

*\-- Skip over the CLASS and TYPE fields of the Question.*

offset = offset + 4

**end**

*\-- Process NAME field and optionally RDATA fields for each RR.*

**for** i = 1, total_rrs **do**

valid, end_of_payload, offset = check_name(offset, string.len(payload))

**if** **not** valid **then**

**return** 1

**elseif** end_of_payload **then**

**return** 0

**end**

*\-- Get the record TYPE.*

**local** type = get_short(offset)

offset = offset + 8

*\-- Get the RDLEGNTH.*

**local** rdlength = get_short(offset)

offset = offset + 2

*\-- Save the start and end of the RDATA field.*

**local** start_of_rdata = offset

**local** end_of_rdata = start_of_rdata + rdlength - 1

*\-- Ensure there is enough data left in the payload for the specified
RDATA length.*

**if** end_of_rdata \> string.len(payload) **then**

**return** 0

**end**

*\-- Only process RDATA if it contains a domain name.*

**if** name_loc_in_rdata\[type\] **then**

**local** start_of_name = name_loc_in_rdata\[type\](start_of_rdata)

**local** hit_end_of_rdata = **false**

valid, hit_end_of_rdata, offset = check_name(start_of_name,
end_of_rdata)

**if** **not** valid **then** **return** 1 **end**

*\-- SOA records have two domain names back-to-back.*

**if** type == 6 **and not** hit_end_of_rdata **then**

valid, \_, offset = check_name(offset, end_of_rdata)

**if** **not** valid **then** **return** 1 **end**

*\-- HIP records can contain an arbitrary number of domain names
back-to-back.*

**elseif** type == 55 **then**

**while** **not** hit_end_of_rdata **do**

valid, hit_end_of_rdata, offset = check_name(offset, end_of_rdata)

**if** **not** valid **then** **return** 1 **end**

**end**

**end**

**end**

*\-- Jump to the start of the next record.*

offset = end_of_rdata + 1

**end**

*\-- Return 0 if no invalid names are found.*

**return** 0

**end\
**

dns_heap_overflow_variant_1.lua:
--------------------------------

**function** init(args)

**local** needs = {}

needs\[\"payload\"\] = tostring(**true**)

**return** needs

**end**

*\-- Extracts an unsigned short from the DNS payload at a given offset.*

**function** get_short(offset)

**local** upper_byte = payload:byte(offset)

**local** lower_byte = payload:byte(offset + 1)

**return** tonumber(upper_byte) \* 256 + tonumber(lower_byte)

**end**

**function** match(args)

payload = args\[\"payload\"\]

**if** payload == **nil** **then**

print(\"DNS payload empty! Aborting\...\")

**return** 0

**end**

*\-- Normalize the DNS payload by removing the length bytes for DNS over
TCP.*

**local** \_, \_, \_, proto, \_, \_ = SCPacketTuple()

**if** proto == 6 **then**

table.remove(payload, 1)

table.remove(payload, 1)

**end**

*\-- Thresholds for flagging - change as needed.*

TOTAL_THRESHOLD = 40

CONSECUTIVE_THRESHOLD = 3

**local** total = 0 *\-- Total number of pointers found in the packet.*

**local** consecutive = 0 *\-- Maximum number of consecutive pointers
found in the packet.*

**local** prev_offset = 1 *\-- The offset of the last pointer we found,
to keep track of consecutives.*

**local** cur_offset = 1 *\-- Our current offset into the DNS payload.*

*\-- Break out if we reach either of our thresholds or run out of bytes
in our payload, whichever comes first.*

**while** cur_offset \< string.len(payload) **and** total \<
TOTAL_THRESHOLD **and** consecutive \< CONSECUTIVE_THRESHOLD **do**

**local** cur_byte = tonumber(payload:byte(cur_offset))

*\-- Treck interprets any label starting with a byte \> 63 as a
pointer.*

**if** cur_byte \> 63 **then**

*\-- Lower 14 bits of the pointer specify its offset, which is
zero-indexed, while Lua is one-indexed.*

**local** ptr_offset = (get_short(cur_offset) % 0x4000) + 1

*\-- Compression pointers cannot point to an offset past their current
location.*

**if** ptr_offset \< cur_offset **then**

*\-- Inside this branch, we consider this and the following byte to be a
pointer.*

total = total + 1

*\-- Pointers right next to each other count towards our consecutive
threshold.*

**if** (cur_offset - prev_offset) == 2 **then**

consecutive = consecutive + 1

**else**

consecutive = 0

**end**

prev_offset = cur_offset

*\-- Since compression pointers are made up of two bytes, we iterate an
extra time.*

cur_offset = cur_offset + 1

**end**

**end**

cur_offset = cur_offset + 1

**end**

*\-- We flag any DNS packet that breaks either of our thresholds.*

**if** total \>= TOTAL_THRESHOLD **or** consecutive \>=
CONSECUTIVE_THRESHOLD **then**

**return** 1

**end**

**return** 0

**end**

**\
**

dns_heap_overflow_variant_2.lua:
--------------------------------

**function** init(args)

**local** needs = {}

needs\[\"payload\"\] = tostring(**true**)

**return** needs

**end**

*\-- Extracts an unsigned short from the payload at a given offset.*

**function** get_short(offset)

**local** upper_byte = payload:byte(offset)

**local** lower_byte = payload:byte(offset + 1)

**return** tonumber(upper_byte) \* 256 + tonumber(lower_byte)

**end**

**function** match(args)

payload = args\[\"payload\"\]

**if** payload == **nil** **then**

print(\"DNS payload empty! Aborting\...\")

**return** 0

**end**

*\-- Normalize the DNS payload by removing the length bytes for DNS over
TCP.*

**local** \_, \_, \_, proto, \_, \_ = SCPacketTuple()

**if** proto == 6 **then**

table.remove(payload, 1)

table.remove(payload, 1)

**end**

*\-- Get the number of Answer RRs.*

**local** answer_rrs = get_short(7)

*\-- Exit if no Answer RRs are present.*

**if** answer_rrs == 0 **then**

**return** 0

**end**

*\-- Arrays that hold (s)tart and (e)nd bytes for the 4-byte fingerprint
used to identify each CNAME record.*

**local** s = {}

**local** e = {}

*\-- The number of CNAME records should never exceed the number of
Answer RRs.*

**for** i = 1, answer_rrs **do**

s\[i\] = 0

e\[i\] = 0

**end**

*\-- The first 12 bytes of DNS are fixed-length fields, so we can start
searching for records at offset = 13.*

**local** offset = 13

*\-- Find each CNAME record.*

**local** cname_count = 0

**for** i = 1, answer_rrs **do**

*\-- We\'re looking for 0x00 0x05 0x00 0x01 bytes to indicate
TYPE=CNAME, CLASS=IN.*

s\[i\], e\[i\] = string.find(payload, \"**\\000\\005\\000\\001**\",
offset)

**if** s\[i\] == **nil** **then**

**break**

**end**

*\-- TTL field is 4 bytes and RDLENGTH field is 2 bytes, so we can jump
ahead at least 7 bytes.*

offset = e\[i\] + 7

**if** offset \> string.len(payload) **then**

**break**

**end**

cname_count = cname_count + 1

**end**

*\-- Exit if no CNAME records are present.*

**if** cname_count == 0 **then**

**return** 0

**end**

*\-- For each CNAME record, flag anywhere the actual length of RDATA \>
RDLENGTH.*

**for** i = 1, cname_count **do**

*\-- e\[i\] points to last byte of the CLASS field, followed by TTL (4
bytes), followed by RDLENGTH.*

**local** rdlength = get_short(e\[i\] + 5)

*\-- The offset to the start of the label we\'re looking at. RDATA goes
after RDLENGTH.*

offset = e\[i\] + 7

*\-- We want to break out as soon as we compute a length \> RDLENGTH or
as soon as we run out of bytes.*

**local** actual_length = 0

**while** actual_length \<= rdlength **and** offset \<=
string.len(payload) **do**

**local** x = tonumber(payload:byte(offset))

*\-- Treck terminates writing to the payload upon hitting a null.*

**if** x == 0 **then**

**break**

*\-- Treck treats any label whose first byte \> 0xCF as a compression
pointer.*

**elseif** x \> 63 **then**

*\-- According to RFC1035, a DNS name can only be:*

*\-- \* a sequence of labels ending in a zero octet*

*\-- \* a pointer*

*\-- \* a sequence of labels ending with a pointer*

*\-- So we stop counting after accounting for the first pointer hit.*

actual_length = actual_length + 2

**break**

**end**

*\-- Otherwise, it\'s a standard label. Size added = length byte +
length specified in length byte.*

**local** label_length = x + 1

*\-- In the case where label_length goes past the end of the payload,
truncate label_length.*

**if** (offset + label_length) \> string.len(payload) **then**

label_length = string.len(payload) - offset + 1

**end**

*\-- Add the length of this label to our running total for RDATA.*

actual_length = actual_length + label_length

*\-- Move to the start of the next label.*

offset = offset + label_length

**end**

*\-- Flag any packet containing a CNAME record where len(RDATA) \>
RDLENGTH.*

**if** actual_length \> rdlength **then**

**return** 1

**end**

**end**

*\-- Otherwise, return 0 if no CNAME records are flagged.*

**return** 0

**end\
**

tunnel_length_check.lua:
------------------------

function init (args) local needs = {}

> needs\[\"packet\"\] = tostring(true) return needs

end

function match(args)

> local b = args\[\'packet\'\]
>
> if b == nil then
>
> print (\"buffer empty! Aborting..\")
>
> return 0
>
> end
>
> \--find beginning of inner packet\
> \--start from IP protocol field in header\
> s,e = string.find(b,\"\\004\")\
> \--inner packet should start 18 bytes later\
> inner_packet = string.sub(b, s+18)
>
> \--inner packet should be ipv4 with length of 20 bytes\
> \--first nibble of packet should be 0x4, second should\
> \--be 0x5 -- combined to a byte this is 0x45
>
> \--assumes 20 byte IP header -- this should be modified to support
>
> \--larger headers as necessary, as RFC allows up to 60 bytes
>
> packet_preamble = inner_packet:byte(1)
>
> if packet_preamble \~= 0x45 then
>
> return 0
>
> end
>
> \--probably a better way to do this, but for now, this works\
> \--two byte field, so high byte gets multiplied by 16\^2\
> packet_len_high = tonumber(inner_packet:byte(25))\*256\
> packet_len_low = tonumber(inner_packet:byte(26))
>
> \--get lengths to compare\
> listed_length = packet_len_high + packet_len_low
>
> \--data field starts 26 bytes after start of encapsulation\
> \--20 bytes of IP header, 6 bytes of UDP header, then payload\
> \--because 1-indexed, it starts at 27\
> actual_length = string.len(string.sub(inner_packet, 27))
>
> \--actual length should be exactly equal to length field in\
> \--header, though in practice exploitation requires it be longer\
> if actual_length \> listed_length then
>
> return 1
>
> end
>
> return 0

end
