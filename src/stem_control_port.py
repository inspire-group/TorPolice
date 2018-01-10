#!/usr/bin/env python

import time, datetime, functools
from stem.control import Controller, EventType

from Crypto.PublicKey import RSA, DSA
from Crypto import Random
from Crypto.Hash import SHA256, SHA
import uuid
#from Crypto.Signature import PKCS1_v1_5

import pdb, numpy



class TorControlPort:
    def __init__(self):
        self.controller = Controller.from_port(port = 9051)
        self.controller.authenticate("123456")  # provide the password here if you set one


    def guard_change(self):
        print 'guard changed'

    def circuit_create(self):
        print 'circuit change'
        time.sleep(10)

# 1. send a create cell to one relay, the relay needs to verify the capability
# 2. We can extend one circuit step by step. 
# 3. We can measure the time needed for creating a circuit. 
# 4. For the partial blind signature: we can use the benchmark from BRAIDS
class CircuitBuilder:
    def __init__(self):
        pass

# Attackers with limited 
# We initiate may client instances to launch circuits
# 1. How to perform the relay selection?
# 2. the extend_circuit seems do not trigger the circuit change event
class Client:
    def __init__(self, guard, middle, exit, relay_manager):
        self.controller = Controller.from_port(port = 9051)
        self.controller.authenticate("123456")  # provide the password here if you set one
        circuit_event_handler = functools.partial(RM_circuit_extented, self)
        self.controller.add_event_listener(circuit_event_handler, EventType.CIRC) # event 

        self.guard = guard
        self. middle = middle
        self.exit = exit
        self.relays = [guard, middle, exit]
        self.hop_count = 0
        self.circuit_id = 0

    def circuit_build(self):
        if self.hop_count == 0:
            #self.circuit_id = self.controller.new_circuit([self.guard], await_build = True)
            self.circuit_id = self.controller.new_circuit([self.guard])
        elif self.hop_count < 3:
            self.controller.extend_circuit(self.circuit_id, [self.relays[self.hop_count]])


    def verification_finished(self):
        print 'verified'
        self.hop_count += 1
        #print 'id: ' + str(self.circuit_id)
        self.circuit_build()
        #self.controller.get_info('circuit-status')


# The RelayManager: performs signature verification
class RelayManager:
    def __init__(self):
        pass

    def sig_verify(self, message, pub_key):
        rece_sig = message[1]
        rece_h = message[0]
        return pub_key.verify(rece_h, (rece_sig,))


def RM_circuit_extented(client, event):
    print 'extended'
    #perform verification
    client.verification_finished()

def circuit_extented(event):
    print 'EXTENDED'
    


# The TTP: generating the P_in and P_out
class TTP:
    def __init__(self):
        # create its key pairs
        random_generator = Random.new().read
        self.key = RSA.generate(1024, random_generator) # The key is the key pair
        self.pub_key = self.key.publickey()
        
    def generate_P_in(self, user_id):
        return uuid.uuid5(uuid.NAMESPACE_DNS, str(user_id))

    def generate_P_out(self, message):
        # message needs to be converted to hash before signing
        #h = SHA256.new(str(message)).hexdigest() 
        h = SHA.new(str(message)).hexdigest()
        signature = self.key.sign(h, 32) # 32 for compatibility
        P_out = (h,) + signature
        return P_out


    def generate_generic_cap(self, relay_id):
        message = str(relay_id) + str(time.time()) + str(uuid.uuid1())
        h = SHA.new(str(message)).hexdigest()
        signature = self.key.sign(h, 32) # 32 for compatibility
        C_gen = (h,) + signature
        return C_gen

    def sig_DSA(self, key):
        message = 'hello'
        h = SHA.new(message).digest()
        k = Random.random.StrongRandom().randint(1,key.q-1)
        sig = key.sign(h,k)
        if not key.verify(h,sig):
            print 'not'



# measure the circuit creating delay
def measure_circuit_creation_latency():
    start = datetime.datetime.now()
    finished = False
    while True:
        circuits = str.split(TorControlPort.controller.get_info('circuit-status'), '\n')
        for c in circuits:
            c_id = str.split(c, ' ')[0]
            if c_id == new_circuit_id:
                c_status = str.split(c, ' ')[1]
                if c_status == 'BUILT':
                    finished = True

                break
        if finished:
            break
    end = datetime.datetime.now()
    interval = end - start
    print interval.total_seconds()

def circuit_create(event):
    print 'caocaocao'

def circuit_create_new(event):
    print 'dddddddd'

#if __name__ == "__main__":
with Controller.from_port() as controller:
    #controller.authenticate()
    #controller.add_event_listener(circuit_extented, EventType.CIRC)
    #TorControlPort = TorControlPort()
    #TorControlPort.controller.add_event_listener(circuit_extented, EventType.CIRC)
    #TorControlPort.controller.add_event_listener(circuit_create, EventType.BUILDTIMEOUT_SET)
    #TorControlPort.controller.add_event_listener(circuit_create, EventType.NOTICE)

    guard = 'E9C8154418544764619D2CCD0596B355D7DFF236'
    middle = '2224E7AF8101885850EC7F2F9EB99F823E8014BE'
    exit = 'AD368442E9FF33C08C7407DF2DA7DB958F406CE2'
    #new_circuit_id = TorControlPort.controller.new_circuit()
    #circuit_id = controller.new_circuit([guard])
    #time.sleep(5)
    #controller.extend_circuit(circuit_id, [middle])
    #time.sleep(5)
    #controller.extend_circuit(circuit_id, [exit])
    #time.sleep(5)

    #TorControlPort.controller.new_circuit()
    #controller.add_event_listener(guard_change, EventType.CIRC)
    #TorControlPort.controller.add_event_listener(circuit_create, EventType.CIRC)
    #print TorControlPort.controller.new_circuit(['E9C8154418544764619D2CCD0596B355D7DFF236', '7D693C2A9C3B0B2D69F473AF1C0E1CBE05EAD412'])
    #controller.get_circuit('12')
    #controller.extend_circuit('0', ['E9C8154418544764619D2CCD0596B355D7DFF236'])
    #controller.extend_circuit('20', ['E9C8154418544764619D2CCD0596B355D7DFF236', '7D693C2A9C3B0B2D69F473AF1C0E1CBE05EAD412'])
    #print(TorControlPort.controller.get_info('circuit-status'))
            
    #print(TorControlPort.controller.get_info('info/names'))
    #print(TorControlPort.controller.get_info('events/names'))
    #time.sleep(5)

    TTP = TTP()
    RelayManager = RelayManager()
    #Client = Client(guard, middle, exit, RelayManager)
    #controller.close_circuit('10')
    #controller.close_circuit('100')
    #print(controller.get_info('circuit-status'))

    generation_overhead = []
    #verification_overhead = []
    #overall_overhead = []

    u_c = 0
    while u_c < 10:
        u_c += 1

        counter = 0
        start = datetime.datetime.now()
        while counter < 1000:
            counter += 1
            user_id = uuid.uuid1()
            P_in = TTP.generate_P_in(user_id)
            P_out = TTP.generate_P_out(P_in)
            #if not RelayManager.sig_verify(P_out, TTP.pub_key):
                #pdb.set_trace()

        end = datetime.datetime.now()

        generation_overhead.append((end-start).total_seconds())

    print numpy.mean(generation_overhead)
    print numpy.std(generation_overhead)
    print numpy.median(generation_overhead)

