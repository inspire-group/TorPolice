#!/usr/bin/env python

import StringIO
import time, random, pdb, numpy, pprint

import pycurl, functools

import stem.control

from Crypto.PublicKey import RSA, DSA
from Crypto import Random
from Crypto.Hash import SHA256, SHA
import uuid
from Crypto.Signature import PKCS1_v1_5


RELAY_ID = '379FB450010D17078B3766C2273303C358C3A442'
SOCKS_PORT = 9050
CONNECTION_TIMEOUT = 30  # timeout before we give up on a circuit
#global CIRCUIT_LEN 


def query(url):
    """
    Uses pycurl to fetch a site using the proxy on the SOCKS_PORT.
    """

    output = StringIO.StringIO()

    query = pycurl.Curl()
    query.setopt(pycurl.URL, url)
    query.setopt(pycurl.PROXY, 'localhost')
    query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
    query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
    query.setopt(pycurl.CONNECTTIMEOUT, CONNECTION_TIMEOUT)
    query.setopt(pycurl.WRITEFUNCTION, output.write)

    try:
      query.perform()
      return output.getvalue()
    except pycurl.error as exc:
        raise ValueError("Unable to reach %s (%s)" % (url, exc))



# The AAs
def generate_generic_cap():
    random_generator = Random.new().read
    global key
    key = RSA.generate(1024, random_generator) # The key is the key pair
    global pub_key 
    pub_key = key.publickey()
    message = str(RELAY_ID) + str(time.time()) + str(uuid.uuid1())
    h = SHA.new(str(message)).hexdigest()
    signature = key.sign(h, 32) # 32 for compatibility
    global C_gen
    C_gen = (h,) + signature
    

# The RelayManager
def sig_verify():
    message = C_gen
    rece_sig = message[1]
    rece_h = message[0]
    if not pub_key.verify(rece_h, (rece_sig,)):
        raise ValueError('Verification failed!')

    #print 'VERIFICATION'


# the event callback has bugs: trigger event multiple times
def circuit_created_with_cap(circuit):
    global CIRCUIT_LEN
    #print CIRCUIT_LEN
    if len(circuit.path) == 1 and CIRCUIT_LEN < 1:
        print 'FIRST RELAY'
        for i in range(8):
            sig_verify()
        CIRCUIT_LEN = 1
    elif len(circuit.path) == 2 and CIRCUIT_LEN < 2:
        print 'SECOND RELAY'
        for i in range(8):
            sig_verify()
        CIRCUIT_LEN = 2
    elif len(circuit.path) == 3 and CIRCUIT_LEN < 3:
        print 'FINAL RELAY'
        for i in range(8):
            sig_verify()
        CIRCUIT_LEN = 3
    elif len(circuit.path) > 3:
        raise ValueError("Circuit has more than 3 hops")

# the event callback has bugs: trigger event multiple times
def circuit_created_without_cap(circuit):
    global CIRCUIT_LEN
    #print CIRCUIT_LEN
    if len(circuit.path) == 1 and CIRCUIT_LEN < 1:
        print 'FIRST RELAY'
        CIRCUIT_LEN = 1
    elif len(circuit.path) == 2 and CIRCUIT_LEN < 2:
        print 'SECOND RELAY'
        CIRCUIT_LEN = 2
    elif len(circuit.path) == 3 and CIRCUIT_LEN < 3:
        print 'FINAL RELAY'
        CIRCUIT_LEN = 3
    elif len(circuit.path) > 3:
        raise ValueError("Circuit has more than 3 hops")


# create circuit together with capability
def circuit_create_together_with_cap(controller, path):
    controller.add_event_listener(circuit_created_with_cap, stem.control.EventType.CIRC)
    start_time = time.time()
    circuit_id = controller.new_circuit(path, await_build = True)

    while CIRCUIT_LEN < 3:
        if time.time() - start_time > 10.0:
            break

    end = time.time()
    controller.close_circuit(circuit_id)
    return end - start_time


# create circuit together without capability
def circuit_create_together_without_cap(controller, path):
    controller.add_event_listener(circuit_created_without_cap, stem.control.EventType.CIRC)
    start_time = time.time()
    circuit_id = controller.new_circuit(path, await_build = True)

    while CIRCUIT_LEN < 3:
        if time.time() - start_time > 10.0:
            break

    end = time.time()
    controller.close_circuit(circuit_id)
    return end - start_time


# create circuit hop by hop
def circuit_create_by_hop(controller, path):
    build_count = 0
    circuit_id = 0

    start_time = time.time()
    while build_count < 3:
        if build_count == 0:
            build_count = 1

            for i in range(8):
                sig_verify()

            circuit_id = controller.new_circuit([path[0]], await_build=True)
            print circuit_id
        elif build_count == 1:
            build_count = 2

            for i in range(8):
                sig_verify()

            circuit_id = controller.extend_circuit(circuit_id, [path[1]], await_build=True)
            print circuit_id
        elif build_count == 2:
            build_count = 3

            for i in range(8):
                sig_verify()

            circuit_id = controller.extend_circuit(circuit_id, [path[2]], await_build=True)
            print circuit_id

        if time.time() - start_time > 10.0:
            break

    end = time.time()
    controller.close_circuit(circuit_id)
    return end - start_time



# create circuit hop by hop and fetch a web page
def circuit_create_by_hop_and_send_traffic(controller, path):
    controller.add_event_listener(circuit_created_with_cap, stem.control.EventType.CIRC)
    build_count = 0
    circuit_id = 0

    while CIRCUIT_LEN < 3:
        if CIRCUIT_LEN == 0 and build_count == 0:
            build_count = 1
            #print path[0]
            circuit_id = controller.new_circuit([path[0]], await_build = True)
        elif CIRCUIT_LEN == 1 and build_count == 1:
            build_count = 2
            #print path[1]
            circuit_id = controller.extend_circuit(circuit_id, [path[1]], await_build = True)
        elif CIRCUIT_LEN == 2 and build_count == 2:
            build_count = 3
            #print path[2]
            circuit_id = controller.extend_circuit(circuit_id, [path[2]], await_build = True)


    def attach_stream(stream):
        if stream.status == 'NEW':
          controller.attach_stream(stream.id, circuit_id)

    controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)

    wait = 0
    while CIRCUIT_LEN < 3:
        wait

    try:
        start_time = time.time()
        controller.set_conf('__LeaveStreamsUnattached', '1')  # leave stream management to us

        check_page = query('https://yahoo.com/')
        #check_page = query('http://bbs.hupu.com/bxj/')
        end = time.time()
        
        controller.close_circuit(circuit_id)
        print(controller.get_info('circuit-status'))
        return end - start_time

    finally:
        controller.remove_event_listener(attach_stream)
        controller.reset_conf('__LeaveStreamsUnattached')


# build circuits and fetch pages
def scan(controller, path):
    """
    Fetch check.torproject.org through the given path of relays, providing back
    the time it took.
    """

    circuit_id = controller.new_circuit(path, await_build = True)

    def attach_stream(stream):
        print stream.target_address
        if stream.status == 'NEW':
          controller.attach_stream(stream.id, circuit_id)


    controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)
    controller.add_event_listener(circuit_created_with_cap, stem.control.EventType.CIRC)


    try:
        #print 'begining fetch'
        start_time = time.time()
        controller.set_conf('__LeaveStreamsUnattached', '1')  # leave stream management to us

        check_page = query('https://yahoo.com/')
        

        return time.time() - start_time
    finally:
        controller.remove_event_listener(attach_stream)
        controller.reset_conf('__LeaveStreamsUnattached')



with stem.control.Controller.from_port(port = 9051) as controller:
    controller.authenticate()

    relay_fingerprints = [desc.fingerprint for desc in controller.get_network_statuses()]

    #scan(controller, [])

    generate_generic_cap()

    # measure circuit building overhead
    # Use the same set of path
    building_time_without_cap = []
    building_time_with_cap = []
    for counter in range(500):
        print counter + 1
        #guard = random.choice(relay_fingerprints)
        #middle = random.choice(relay_fingerprints)
        #exit = random.choice(relay_fingerprints)
        #path = [guard, middle, exit]
        #print path

        # With cap
        CIRCUIT_LEN = 0
        try:
            time_taken_with_cap = circuit_create_together_with_cap(controller, path=None)
            if time_taken_with_cap < 10.0:
                print('With cap %0.2f seconds' % (time_taken_with_cap))
                building_time_with_cap.append(time_taken_with_cap)
        except Exception as exc:
            print('%s' % (exc))

        # Without cap
        CIRCUIT_LEN = 0
        try:
            time_taken_without_cap = circuit_create_together_without_cap(controller, path=None)
            if time_taken_without_cap < 10.0:
                print('Without cap %0.2f seconds' % (time_taken_without_cap))
                building_time_without_cap.append(time_taken_without_cap)
        except Exception as exc:
            print('%s' % (exc))

    pdb.set_trace()

    json_result = {'with_cap': building_time_with_cap, 'without_cap': building_time_without_cap}
    ff = open('circuit_creation_latency.py', 'w+')
    pprint.pprint(json_result, ff)
    ff.close()

