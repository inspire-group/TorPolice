#!/usr/bin/env python
import time, sys, datetime,numpy
import hashlib, os, urllib2, binascii
import pdb

# README: the implementation for solving puzzles

seed_len = 64
nonce_len = 64

AA = '192.168.0.1'

seed = hashlib.sha1(os.urandom(seed_len)).hexdigest()

puzzle_level = 1
median_time = []

for puzzle_level in range(1,30):
    print puzzle_level
    t_0 = []
    for i in range(100):
        start = datetime.datetime.now()
        nonce = hashlib.sha1(os.urandom(nonce_len)).hexdigest()
        while True:
            trial = hashlib.sha1(os.urandom(nonce_len)).hexdigest()
            stub = seed + nonce + AA + trial
            puzzle = bin(int(hashlib.sha1(stub).hexdigest(),16))[2:]
            #print puzzle
            if puzzle[-puzzle_level:] == '0'*puzzle_level:
                end = datetime.datetime.now()
                break
        delta = (end-start).total_seconds()*1000
        t_0.append(delta)

    median_time.append(numpy.median(t_0))
    print median_time

pdb.set_trace()




