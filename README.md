# TorPolice
This repository contains code for TorPolice: Towards Enforcing Service-Defined Access Policies in Anonymous Systems. 

TorPolice is the first privacy-preserving access control framework for Tor, which enables abuse-plagued service providers such as Yelp to enforce access rules to police and throttle malicious requests coming from Tor while still providing service to legitimate Tor users. Further, TorPolice equips Tor with global access control for relays, enhancing Tor’s resilience to botnet abuse. We show that TorPolice preserves the privacy of Tor users, implement a prototype of TorPolice, and perform extensive evaluations to validate our design goals.

The code includes three parts: the blinding, creation, unbliding and verification of capability using RSA encryption techniques, the puzzle mechanism used for capability acquisition and performance evaluations on a simulated Tor network.
