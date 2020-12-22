#!/bin/bash

for index in {0..10}
do
	dig -t A 0.www.orf.at @192.168.56.10 +timeout=30
done

