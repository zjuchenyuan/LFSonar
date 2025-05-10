#!/bin/bash
set -ex
mkdir keys
ssh-keygen -b 4096 -t rsa -f ./keys/readwrite -q -N ""
ssh-keygen -b 4096 -t rsa -f ./keys/deployread -q -N ""
ssh-keygen -b 4096 -t rsa -f ./keys/otheruser -q -N ""
ssh-keygen -b 4096 -t rsa -f ./keys/anonymous -q -N ""
chmod 600 keys/*
