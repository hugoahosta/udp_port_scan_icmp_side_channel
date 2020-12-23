#!/bin/bash
tc qdisc add dev enp0s8 root netem delay 10s

