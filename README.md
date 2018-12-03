# Outline

- Introduction
  - SSL details
  - History of SSL
- Details of Implementation
  - Python 3
  - Negotiation
    - Package
    - Public Key Encryption
      - RSA
      - Blum-Goldwasser
    - Symmetric Cipher
      - DES
    - Hash
      - SHA-1
  - Certification Key Exchange
    - Select private key
    - send public keys
  - Talking
    - Encrypting
  - Disconnection
    - Send Challenge and reply
- Details of Security
  - Semantic Security
    - random padding
  - De-Auth attacks
    - disconnecting without challenge is bad behavior
  - Replay Attacks
    - Nonces
  - DOS attacks
    - No more than Cmax connection requests, cooldown.
  - State machine
- Conclusion

## How to run

We provide a local test (doesn't include socket programming) and a remote test versions.

### Local Test Version
Simply run
```
python3 local_test.py
```
You are expected to see a detailed communication between Alice and Bob.

### Remote Test Version
The scenario is set between Alice and Bob (A make up sad story).
Alice wants to talk to Bob, but Bob doesn't want to replay. An autoreply system is running on Bob's machine.

* If Bob is online (you run Bob.py first)
The following message are expected to see near the end of the communication.

Alice's screen
```
receive: COM_MSG
receive: Good to go
send: Hi Bob, this is Alice, how are you doing?
==========================
--------------------------
receive: COM_MSG
receive: Sorry, I cannot hear you.
send: Hi Bob, how are you doing? Can you hear me?
==========================
--------------------------
receive: COM_MSG
receive: I'm going to take a shower. See you tomorrow!
send: What?
==========================
--------------------------
receive: COM_MSG
receive: Autoreply, I'm taking a shower
send: What?
==========================
--------------------------
receive: COM_MSG
receive: Autoreply, I'm taking a shower
==========================
--------------------------
receive: DISCON_CLG
Bob left as expected
```

* If Bob is offline (you run Alice.py first), you will see
```
Bob is not online, maybe tomorrow.
```


## Some Important Files and Their Functions
- ```User_Class.py``` contains the user class which takes care of everything. It includes certification, nonce, packet generation/interpretation, etc. But it doesn't include HMAC, any encryption algorithms, SHA1, and User_Info_DB.
- ```Constants.py``` contains all the package structures, some constants used in the communication. This file is not expected to be changed, otherwise, there will be a mis-alignment between the client and the server.
- ```User_Info_DB_Class.py``` implements a user behavior recorder. If a user/ip has some bad behaviors, say DoS Attack, expired certification, wrong HMAC, etc, one record will be added to the recorder.
- ```local_test.py``` is a local test version of the customized SSL. It doesn't involve socket programming.
- ```Alice.py``` and ```Bob.py``` are the remote test programs. Play with them.

## Last but not Least
- We design a Challenge strategy to prevent De-auth Attack. The strategy is described in the *whiteHatReport.pdf* section
*2.4.1 Challeng Strategy*.
- For the state machine used for auto-response (not necessarily the auto-reply, just send a reply package), because the strategy is pretty complicated, you are welcomed to read the code of function  ```respond_state_machine(self, pkg_rev, ip)``` in ```User_Class.py```. It is explained with comments.
