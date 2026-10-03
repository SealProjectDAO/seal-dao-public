
Infra
- we need to have [ Tor & I2P ] support so that noces can be built and run without direct internet access
- we need a MerkleTTP/S protocol with [ Tor & I2P ] / and local http:127.0.0.1 proxy on top of CryptoDNS
 How this works:
 * CryptoDNs support mapping from name to IP, Tor, I2P address + some set of signatures/hashes [ merkle roots etc. ] [can be multiple of them if operation mode is R/O, other wise must be a host with certificate signed by name owner; using dot name split => user will have default config with some
 root names, and then we will use public SQL keys with write only /reserve mechanisms - you cannot hold a name forever without paying
 mind you, and holder of a given root name can add his own rules ], in all case end users can configure their roots  
 * R/O mode: all public, given a file path provide the file contents as well as the merkle proof [so that who stores the data does NOT matter, files to have extra rnad salt to allow for practical future erasure if need be ]
 [ nota: propose several versions of something - right to be forgotten: cf. previous exercise at right to be forgotten, eviction of
  old data via micro payment from specific account and mandatory eviction on accoutn exhaustion, account can chenge at each new version ]
 * extension to file servers using encrypted contents and encryption keys per user group / MPC and/or shared keys 
- we need a browser plugin for browser such as Firefox/brave/Safari that exposes a simple js/ts API 
- consider adding js/tx API for use from node
- desirable:navigation bar plugin so we can type in the seal contract address and use the integrated web app
 and/or access remote website directly 
Longer term plan: port to windows => make sure we avoid non-portable construct , add support for Edge

- x402 extension to SEAL [proposal etc. ]
- x402 like extension for service provision via MerkleTTP/S end points 

Wallet/
completion => add an iOS Wallet to run in emulator for now

use ../rust-secure-memory-public 

polish the Wallet => we want to be able to run simple webapps or mabe electron style controls from an app from withn the Wallet apps
[ when practical, ideally the GUI/destop at least, as well as phone apps should support it ]. 

improve DEX GUI components ~ 

list of apps, and description for each app
------------------------------------------

* Secure messaging     

* Collaborative docs (CRDT)         
=> look for web enabled office suites

* Decentralized storage pointers [ !! careful about security rules, no non-pqc end points bordel ]

* Task/project management

* Password manager / secrets  

* Note-taking / knowledge base   

* Stablecoin payments / remittances 

* Decentralized feeds / RSS  

* Decentralized identity / credentials

* copy trading 

* "kindle"
 
* distributed AI

* software license manager

* distributed GIT - radicle with PQC

N.B. local running mode ~ [  ] 

PLAN in detail for each, with many phases and steps 