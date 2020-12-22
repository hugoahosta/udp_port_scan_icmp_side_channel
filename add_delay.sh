#!/bin/bash
tc qdisc replace dev enp0s8 root netem delay 10s

