#!/bin/bash

for index in {0..10}
do
	dig -t A www.unical.it. @192.168.56.10 +timeout=30
	sleep 1
done

