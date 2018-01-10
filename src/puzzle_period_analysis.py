#!/usr/bin/env python

import random, math, numpy, pdb
import rtt


# 1. latency: uniformly distributed among 0,P_a/2
# 2. N: the number of puzzles that can be soloved in one time unit. Uniformly distributed among [1,K], where K is the ability diffenence ratio

# Thought: we can show the percentage bounding is very necessary: automated bots will use 100%, normal clients use at most 5%


'''
p_a = 1000.0 


f = open('puzzle_varying_K.data', 'w+')
#f = open('puzzle_varying_latency.data', 'w+')

for petl in numpy.arange(0.01, 1.01, 0.05): 
    K_latency = 2.0
    #K = 20

    puzzle_solved_for_K = []
    for K in [1,10,20,50]: 
    #for K_latency in [1.0,2.0,4.0,8.0]: 
        expectation = 1.0 * K / 2 * (p_a - p_a/2/K_latency)

        puzzle_solved_count = []
        for client in range(100000): 
            latency = random.uniform(0, p_a/K_latency)
            N = random.uniform(1,K)

            # normalized to the expectation
            puzzle_solved = N * (p_a-latency) / expectation

            puzzle_solved_count.append(puzzle_solved)

        # compute the percentile rank 
        puzzle_solved_count = sorted(puzzle_solved_count)
        puzzle_solved_for_K.append(puzzle_solved_count[int(petl*len(puzzle_solved_count))])

    # write data    
    f.writelines('%.3f %.3f %.3f %.3f %.3f\n' % (petl, puzzle_solved_for_K[0], puzzle_solved_for_K[1], puzzle_solved_for_K[2], puzzle_solved_for_K[3]))


f.close()

K = 20
K_latency = 2
f = open('puzzle_varying_CPU_bound.data', 'w+')
for petl in numpy.arange(0.01, 1.01, 0.05): 
    puzzle_solved_for_CPU = []
    for CPU in [0.01,0.02,0.03,0.05]: 
        expectation = 1.0*K / 2 * p_a/2/K_latency * CPU / 0.01

        puzzle_solved_count = []
        for client in range(100000): 
            latency = random.uniform(0, p_a/K_latency)
            N = random.uniform(1,K)

            # normalized to the expectation
            expected_puzzle_solved = math.floor(N * (p_a-latency) / expectation)

            puzzle_solved_count.append(expected_puzzle_solved)

        # compute the percentile rank 
        puzzle_solved_count = sorted(puzzle_solved_count)
        puzzle_solved_for_CPU.append(puzzle_solved_count[int(petl*len(puzzle_solved_count))])

    # write data    
    f.writelines('%.3f %.3f %.3f %.3f %.3f\n' % (petl, puzzle_solved_for_CPU[0], puzzle_solved_for_CPU[1], puzzle_solved_for_CPU[2], puzzle_solved_for_CPU[3]))

f.close() 


# f = (p - p_c) * N(d, S)

# p_c is the worst case latency, which is a constant.
# N(d,S) is uniform distribution

L = 100.0
K = 50.0

p_K50_L100= []

for p in range(100, 201, 10):

    puzzle_solved_count = []
    for client in range(100000):  
        N = random.uniform(1,K)

        # normalized to the expectation
        expected_puzzle_solved = N * (p - L) 

        puzzle_solved_count.append(expected_puzzle_solved)

    # compute the percentile rank 
    puzzle_solved_count = sorted(puzzle_solved_count)
    petl = 0.05
    p_K50_L100.append(puzzle_solved_count[int(petl*len(puzzle_solved_count))])


p_K10_L100= []
for p in range(100, 201, 10):

    puzzle_solved_count = []
    for client in range(100000): 
        N = random.uniform(1,K)

        # normalized to the expectation
        expected_puzzle_solved = N * (p - L) 

        puzzle_solved_count.append(expected_puzzle_solved)

    # compute the percentile rank 
    puzzle_solved_count = sorted(puzzle_solved_count)
    petl = 0.05
    p_K10_L100.append(puzzle_solved_count[int(petl*len(puzzle_solved_count))])


p_K50_Luniform= []
for p in range(100, 201, 10): 

    puzzle_solved_count = []
    for client in range(100000): 
        N = random.uniform(1,K)

        # normalized to the expectation
        expected_puzzle_solved = N * (p - random.uniform(0,L)) 

        puzzle_solved_count.append(expected_puzzle_solved)

    # compute the percentile rank 
    puzzle_solved_count = sorted(puzzle_solved_count) 
    petl = 0.05
    p_K50_Luniform.append(puzzle_solved_count[int(petl*len(puzzle_solved_count))])



p_K50_Luniform= []
for p in range(100, 201, 10): 

    puzzle_solved_count = []
    for client in range(100000): 
        N = random.uniform(1,K)

        # normalized to the expectation
        expected_puzzle_solved = N * (p - random.uniform(0,L)) 

        puzzle_solved_count.append(expected_puzzle_solved)

    # compute the percentile rank 
    puzzle_solved_count = sorted(puzzle_solved_count) 
    petl = 0.05
    p_K50_Luniform.append(puzzle_solved_count[int(petl*len(puzzle_solved_count))])

f = open('puzzle_varying_p.data', 'w+')
index = 0
for p in range(100,201,10):
    f.writelines('%.3f %.3f %.3f %.3f\n' % (p, p_K10_L100[index], p_K50_L100[index], p_K50_Luniform[index]))
    index += 1

f.close()



# CPU bound improves fairness
p = 150
K = 50
L = 100

f = open('puzzle_varying_CPU_bound.data', 'w+')
p_K10_Luniform_CPU_p150 = []
for CPU in numpy.arange(0.01, 0.11, 0.02): 

    puzzle_for_client = []
    puzzle_for_bot = []
    for i in range(100000): 
        puzzle_for_client.append(random.uniform(0,K) * (p - random.uniform(0,L)))
        puzzle_for_bot.append(random.uniform(0,K) * (p/CPU - random.uniform(0,L)))

    puzzle_for_client = sorted(puzzle_for_client)
    puzzle_for_bot = sorted(puzzle_for_bot)
    client_5petl = puzzle_for_client[int(0.05 * len(puzzle_for_client))]
    bot_5petl = puzzle_for_bot[int(0.05 * len(puzzle_for_bot))]
    p_K10_Luniform_CPU_p150.append(bot_5petl / client_5petl) 


p = 200

p_K10_Luniform_CPU_p200 = []
for CPU in numpy.arange(0.01, 0.11, 0.02): 

    puzzle_for_client = []
    puzzle_for_bot = []
    for i in range(100000): 
        puzzle_for_client.append(random.uniform(0,K) * (p - random.uniform(0,L)))
        puzzle_for_bot.append(random.uniform(0,K) * (p/CPU - random.uniform(0,L)))

    puzzle_for_client = sorted(puzzle_for_client)
    puzzle_for_bot = sorted(puzzle_for_bot)
    client_5petl = puzzle_for_client[int(0.05 * len(puzzle_for_client))]
    bot_5petl = puzzle_for_bot[int(0.05 * len(puzzle_for_bot))]
    p_K10_Luniform_CPU_p200.append(bot_5petl / client_5petl)



index = 0
for i in numpy.arange(0.01, 0.11, 0.02): 
    f.writelines('%.3f %.3f %.3f \n' % (i, p_K10_Luniform_CPU_p150[index], p_K10_Luniform_CPU_p200[index]))
    index += 1

f.close() 
'''

RTT_values = rtt.result
RTT_values = sorted(RTT_values)
RTT_99th = RTT_values[int(0.99 * len(RTT_values))]
RTT_50th = RTT_values[int(0.5 * len(RTT_values))]
print RTT_99th

# two devices
# on MAC: t_p = 0.323485/1000000, on iphone6 t_p = 5.975/1000000

t_p_MAC = 0.323485 / 1000000.0 * 1000 # in ms
t_p_phone = 5.975 / 1000000.0 * 1000 # in ms


puzzle_on_MAC_5th = []
puzzle_on_MAC_95th = []
puzzle_on_MAC_99th = []
puzzle_on_MAC_1th = []
puzzle_on_phone_5th = []
puzzle_on_phone_95th = []
puzzle_on_phone_99th = []
puzzle_on_phone_1th = []

for p in range(400,2001,50): # in ms
    #print p 
    N = int((p - RTT_99th) / t_p_phone)
    p_p = 1.0 - math.pow(0.01, 1.0/N)

    # on MAC
    # Each device sample X latency; then pick the 5th percentile
    puzzle_count_for_RTTs = []
    X = 10000
    for i in range(X):
        latency = random.choice(RTT_values)
        attempt = int( 1.0 * (p - latency) / t_p_MAC )
        puzzle_count = attempt * p_p 

        puzzle_count_for_RTTs.append(puzzle_count)

    puzzle_count_for_RTTs = sorted(puzzle_count_for_RTTs)
    puzzle_on_MAC_1th.append(puzzle_count_for_RTTs[int(0.01*X)])
    puzzle_on_MAC_5th.append(puzzle_count_for_RTTs[int(0.05*X)])
    puzzle_on_MAC_95th.append(puzzle_count_for_RTTs[int(0.95*X)])
    puzzle_on_MAC_99th.append(puzzle_count_for_RTTs[int(0.99*X)])
 
 
    # on phone
    puzzle_count_for_RTTs = []
    for i in range(X):
        latency = random.choice(RTT_values)
        attempt = int( 1.0 * (p - latency) / t_p_phone ) 
        puzzle_count = attempt * p_p 
        puzzle_count_for_RTTs.append(puzzle_count) 

    puzzle_count_for_RTTs = sorted(puzzle_count_for_RTTs)
    puzzle_on_phone_1th.append(puzzle_count_for_RTTs[int(0.01*X)])
    puzzle_on_phone_5th.append(puzzle_count_for_RTTs[int(0.05*X)])
    puzzle_on_phone_95th.append(puzzle_count_for_RTTs[int(0.95*X)])
    puzzle_on_phone_99th.append(puzzle_count_for_RTTs[int(0.99*X)])


f = open('puzzle_count_1th_5th.data', 'w+')
index = 0
for p in range(400,2001,50): # in ms
    f.writelines('%.3f %.3f %.3f %.3f %.3f\n' % (p, puzzle_on_MAC_1th[index], puzzle_on_MAC_5th[index], puzzle_on_phone_1th[index], puzzle_on_phone_5th[index]))
    index += 1

f.close() 

    
f = open('puzzle_count_95th_99th.data', 'w+')
index = 0
for p in range(400,2001,50): # in ms
    f.writelines('%.3f %.3f %.3f %.3f %.3f\n' % (p, puzzle_on_MAC_95th[index], puzzle_on_MAC_99th[index], puzzle_on_phone_95th[index], puzzle_on_phone_99th[index]))
    index += 1

f.close() 
