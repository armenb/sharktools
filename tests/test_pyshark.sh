#!/bin/sh -x
#
# NB: The test below is designed to work with Wireshark > 1.2; to test with
# older versions of Wireshark, replace all instances of the dissector name
# "frame.len" with "frame.pkt_len"

# Make bash exit on error
set -e

PYTHON="python"

export PYTHONPATH=../src
test -e $PYTHONPATH/pyshark.so

$PYTHON -c "import pyshark; b = pyshark.read('capture1.pcap', [ \
'frame.number', 'ip.version', 'tcp.seq', 'udp.dstport', \
'frame.len' \
], 'ip.version eq 4'); print b[2]"

$PYTHON -c "import pyshark; b = pyshark.read('capture1.pcap', [ \
'frame.number', 'ip.version', 'tcp.seq', 'udp.dstport', \
'frame.len' \
], 'ip.version eq 4', 'udp.port==60000,aodv'); print b[2]"

$PYTHON -c "import pyshark; c = pyshark.read('capture1.pcap', [ \
'frame.number', 'frame.time', 'frame.time_relative', \
'frame.len', 'frame.protocols' \
], '' ); print c[8]"

$PYTHON -c "import pyshark; c = pyshark.read('capture1.pcap', [ \
'frame.number', 'frame.time', 'frame.time_delta', \
'frame.time_delta_displayed', 'frame.time_relative', \
'frame.len', 'frame.cap_len', 'frame.marked', 'frame.protocols' \
], 'ip' ); print c[2]"

$PYTHON -c "import pyshark; c = pyshark.read('capture1.pcap', [ \
'frame.number', 'eth.lg', 'eth.ig', 'eth.trailer', 'ip.version', \
'ip.dsfield.dscp', 'ip.dsfield.ect', 'ip.dsfield.ce', \
'ip.len', 'ip.id', 'ip.flags.rb', 'ip.flags.df', 'ip.flags.mf', \
'ip.frag_offset', 'ip.ttl', 'ip.proto', \
'ip.checksum', 'ip.checksum_good', 'ip.checksum_bad', \
'data.data', 'ip.hdr_len' \
], 'ip' ); print c[6]"

