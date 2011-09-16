#!/bin/sh -x

# Make bash exit on error
set -e

export MATLABPATH=../src
test -e $MATLABPATH/matshark.mexa64

matlab -nodisplay -nojvm -r "b = matshark('capture1.pcap', { \
'frame.number', 'ip.version', 'tcp.seq', 'udp.dstport', \
'frame.len' \
}, 'ip.version eq 4'); display(b(3)); pause(1e-6); exit"

matlab -nodisplay -nojvm -r "b = matshark('capture1.pcap', { \
'frame.number', 'ip.version', 'tcp.seq', 'udp.dstport', \
'frame.len' \
}, 'ip.version eq 4', 'udp.port==60000,aodv'); display(b(3)); pause(1e-6); exit"

matlab -nodisplay -nojvm -r "c = matshark('capture1.pcap', { \
'frame.number', 'frame.time', 'frame.time_relative', \
'frame.len', 'frame.protocols' \
}, '' ); display(c(9)); pause(1e-6); exit"

matlab -nodisplay -nojvm -r "c = matshark('capture1.pcap', { \
'frame.number', 'frame.time', 'frame.time_delta', \
'frame.time_delta_displayed', 'frame.time_relative', \
'frame.len', 'frame.cap_len', 'frame.marked', 'frame.protocols' \
}, 'ip.version eq 4'); display(c(3)); pause(1e-6); exit"

matlab -nodisplay -nojvm -r "c = matshark('capture1.pcap', { \
'frame.number', 'eth.lg', 'eth.ig', 'eth.trailer', 'ip.version', \
'ip.dsfield.dscp', 'ip.dsfield.ect', 'ip.dsfield.ce', \
'ip.len', 'ip.id', 'ip.flags.rb', 'ip.flags.df', 'ip.flags.mf', \
'ip.frag_offset', 'ip.ttl', 'ip.proto', \
'ip.checksum', 'ip.checksum_good', 'ip.checksum_bad', \
'data.data', 'ip.hdr_len' \
}, 'ip' ); display(c(7)); pause(1e-6); exit"
