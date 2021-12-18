#!/bin/bash

`ps aux | grep  -ie EVM | awk '{print "kill " $2}'`
