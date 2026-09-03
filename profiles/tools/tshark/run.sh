#!/bin/bash
# Profile: tshark packet analyzer.
[ "$1" = "--check" ] && { command -v tshark >/dev/null; exit; }
tshark -r test.pcap -V > /dev/null
