#! /bin/bash
redis-cli -r 1000000 set foo bar &
redis-cli -n 12 -r 1000000 set foo bar