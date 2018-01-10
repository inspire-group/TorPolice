#!/usr/bin/env python 

from Crypto.PublicKey import RSA, DSA
from Crypto import Random
from Crypto.Hash import SHA256, SHA
import uuid, time, datetime
from Crypto.Signature import PKCS1_v1_5
import numpy


# The TTP: generating the capabilities
class TTP:
    def __init__(self):
        # create its key pairs
        random_generator = Random.new().read
        self.key = RSA.generate(1024, random_generator) # The key is a key pair
        self.pub_key = self.key.publickey()
        random_generator = Random.new().read
        self.another_key = RSA.generate(1024, random_generator) # The key is a key pair

        
    def generate_P_in(self, user_id):
        return uuid.uuid5(uuid.NAMESPACE_DNS, str(user_id))

    def generate_P_out(self, message):
        # message needs to be converted to hash before signing
        #h = SHA256.new(str(message)).hexdigest() 
        h = SHA.new(str(message)).hexdigest()
        signature = self.key.sign(h, 32) # 32 for compatibility
        P_out = (h,) + signature
        return P_out


    def generate_generic_cap(self, message):
        if not self.key.can_blind():
            raise ValueError('cannot blind signature')
        else:
            #h = SHA.new(str(message)).hexdigest()
            signature = self.key.sign(message, 32) # 32 for compatibility
            C_gen = (message,) + signature
            return C_gen


    def blind_signature(self):
        if not self.key.can_blind():
            raise ValueError('cannot blind signature')
        else:
            h = SHA.new(str('hahaha')).hexdigest()
            blind_message = self.pub_key.blind(h, 322)
            signature = self.key.sign(blind_message, 32)[0] # 32 for compatibility

            unblind = self.pub_key.unblind(signature, 3222)

            verify = self.key.verify(h, (unblind,))
            print verify



# The RelayManager: performs signature verification
class RelayManager:
    def __init__(self):
        self.blind_factor = 3233L

    def unblind_cap(self, cap, pub_key):
        rece_sig = cap[1]
        unblind_cap = pub_key.unblind(rece_sig, self.blind_factor)

        return unblind_cap

    def sig_verify(self, unblind_cap, pub_key, message):
        return pub_key.verify(message, (unblind_cap,))
    
    def blind_message(self, message, pub_key):
        return pub_key.blind(message, self.blind_factor)
    



if __name__ == "__main__":
    RelayManager = RelayManager()
    TTP = TTP()

    relay_id = uuid.uuid1()
    message = str(relay_id) + str(time.time()) + str(uuid.uuid1())

    # blind: using TTP's public key to blind with a secrect blind factor
    blind_message = RelayManager.blind_message(message, TTP.pub_key)

    # capability generation for blind_message
    cap = TTP.generate_generic_cap(blind_message)


    # unblind cap, which will be sent to relays
    unblindedCap = RelayManager.unblind_cap(cap, TTP.pub_key)

    # signature verification performed by relays
    verify = RelayManager.sig_verify(unblindedCap, TTP.pub_key, message)


    print verify # If Ture, it will be verified

    #Please overlook the following since it is only used to measure the overhead
    blind_overhead = []
    unblind_overhead = []
    sign_overhead = []
    verify_overhead = []

    batch_count = 1000
    iter_count = 100

    u_c = 0
    while u_c < iter_count:
        u_c += 1

        counter = 0
        start = datetime.datetime.now()
        while counter < batch_count:
            blind_message = RelayManager.blind_message(message, TTP.pub_key)
            counter += 1

        end = datetime.datetime.now()
        blind_overhead.append((end-start).total_seconds())


    # pre-capability generation
    u_c = 0
    while u_c < iter_count:
        u_c += 1

        counter = 0
        start = datetime.datetime.now()
        while counter < batch_count:
            cap = TTP.generate_generic_cap(blind_message)
            counter += 1

        end = datetime.datetime.now()
        sign_overhead.append((end-start).total_seconds())


    # unblind pre-cap to produce cap
    u_c = 0
    while u_c < iter_count:
        u_c += 1

        counter = 0
        start = datetime.datetime.now()
        while counter < batch_count:
            unblindedCap = RelayManager.unblind_cap(cap, TTP.pub_key)
            counter += 1

        end = datetime.datetime.now()
        unblind_overhead.append((end-start).total_seconds())

    # verification overhead
    u_c = 0
    while u_c < iter_count:
        u_c += 1

        counter = 0
        start = datetime.datetime.now()
        while counter < batch_count:
            verify = RelayManager.sig_verify(unblindedCap, TTP.pub_key, message)
            counter += 1

        end = datetime.datetime.now()
        verify_overhead.append((end-start).total_seconds())



    # verification
    print numpy.mean(blind_overhead)
    print numpy.std(blind_overhead)
    print numpy.median(blind_overhead)
    print numpy.mean(sign_overhead)
    print numpy.std(sign_overhead)
    print numpy.median(sign_overhead)
    print numpy.mean(unblind_overhead)
    print numpy.std(unblind_overhead)
    print numpy.median(unblind_overhead)
    print numpy.mean(verify_overhead)
    print numpy.std(verify_overhead)
    print numpy.median(verify_overhead)

