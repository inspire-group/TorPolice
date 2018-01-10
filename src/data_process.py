#!/usr/bin/env python

import numpy
import circuit_creation_latency

building_time_with_cap = circuit_creation_latency.result['with_cap']
building_time_without_cap = circuit_creation_latency.result['without_cap']

f = open('circuit_building_overhead.data.new.new', 'w+')
for breaker in numpy.arange(0.4, 1.6, 0.01):
    counter_with_cap = 0
    for time_spent in building_time_with_cap:
        if time_spent < breaker:
            counter_with_cap += 1

    counter_without_cap = 0
    for time_spent in building_time_without_cap:
        if time_spent < breaker:
            counter_without_cap += 1

    f.writelines('%.3f %.3f %.3f\n' % (breaker, 1.0*counter_with_cap/len(building_time_with_cap), 1.0*counter_without_cap/len(building_time_without_cap)))

f.close()
