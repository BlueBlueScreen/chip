# Chip
It's a project that realizes chip(ipake instance in python)
***
  
In an unmanned scenario, to ensure secure communication between devices and between the device owner (user) and the device, the commonly adopted method is to equip each device with the same password or key. Then, using symmetric cryptography-based authentication key negotiation, the identities of the parties are mutually authenticated, and a common session key is obtained, which is used to encrypt subsequent communication content to ensure the security of the communication. In such a case, if one device is compromised or falls into the hands of an adversary, the security of all devices is compromised. In 2022, Cremer first proposed a solution to this problem, known as the identity-bound authenticated key agreement protocol. This protocol satisfies the condition that even if one device is captured by an adversary, the adversary can only impersonate that specific device, but not deceive by impersonating other devices.

Cremer realizes his scheme called chip in cpp [chipandcrisp](https://github.com/search?q=chipandcrisp&type=repositories) In this work, we choose to realizes chip in python.
