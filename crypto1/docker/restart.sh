#!/bin/bash
while true
do
    ps -ef | grep "crypto" | grep -v "grep"
    if [ "$?" -eq 1 ]
        then
        ./run.sh 
    fi
    sleep 1
done