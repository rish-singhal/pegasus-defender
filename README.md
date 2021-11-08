# Pegasus: Modular defence against attacks leveraging SDN

## Introduction

### What is Pegasus?

![](https://i.imgur.com/S8jZJAy.jpg)

**Pegasus is one stop solution for gaurding against possible adverserial attacks.** And it does this by providing a range of modules which can be used for the behaviour of controller. For example, one can use it to mitigate DDoS attacks (based on Entropy methods).

When the OpenFlow enabled switch boots up it connects itself with the Pegasus controller. And in the case of multiple switches one can use multiple controller for various usecases as described next.

Due to the modular nature of the Pegasus controller, it is really easy to design and add new modules fast and in efficient manner.

### Modules Implemented
We implemented the following modules implemented.

#### 1. Hub - A simple Layer 1 device :: BASICS

In this the SDN enabled switch simply forwards all the packets coming towards itself to all the other switch ports. (Remember: **excluding the ingress port**)

#### 2. Switch - A Layer 2 device (works on MAC addresses) :: BASICS

This also works similar to a Hub initally but with time learns the ports through which some source hosts sends packets.

Whenever a new packet which does not follow any rule in the Actions Table arrives it sends this message to the **Pegasus Controller** which commands the switch to broadcast the message. With time, our **Pegasus Controller** learns the port to host map and then **deploys** appropriate rules in the switch.

#### 3. Firewall

Firewall module right now enforces blocking rules for all the directed communication between specified source and destion addresses. Apart from this, all the outgoing communication from a list of hosts can be blocked.

Due to the modular nature of the implementation and the ease to scale up the program more specially designed rules can be added.

#### 4. Host Quarantine

This module quarantines all the to-and-fro communication from the malicious hosts going through our SDN switch. In addition to that, it redirects whatever flow is coming in towards the malicious host itself.

#### 5. HTTP Blocker

As the name suggests, it blocks all the incoming HTTP messages towards the switch to mitiage possible attacks such as

1. *Yatagai, T., Isohara, T., & Sasase, I. (2007, August). Detection of HTTP-GET flood attack based on analysis of page access behavior. In 2007 IEEE Pacific rim conference on communications, computers and signal processing (pp. 232-235). IEEE.*
2. *Hirakawa, T., Ogura, K., Bista, B. B., & Takata, T. (2016, September). A defense method against distributed slow http dos attack. In 2016 19th international conference on network-based information systems (NBiS) (pp. 152-158). IEEE.*

and more.

#### 6. Reflector Net

![](https://i.imgur.com/0uPCLLl.jpg)

This reflects all the traffic coming from the **malicious host** to a honey pot where the packets won't move any futher or further inspection can be done. But the **malicious host** would think the messages are going towards the right direction.

This is basically **DECEPTION**


#### 7. DDoS Defender based on Entropy

This module implements as the name suggests DDoS defence. This can be achieved by breaking the roles of the Defender into two parts
1. **DDoS Detection**
2. **DDoS Mitigation**

The second part is implemented by making the switch shutdown or to drop all the incoming packets for some TIME_LIMIT before it starts again fresh.

The first part is the main part, we thought and research about various resources on internet for possible ideas and then settled with the **Entropy based DDoS detection**. There exists other ways too using ML models but that can be easily added as another module to the project.

**Entropy based DDoS detection, intuitively is the more the entropy of the network flowing through the switch the more are the chances of the network to be in DDoS attack.**

**Entropy** is calculated as:
$$
\sum_{i = 1}^{n} - P_i \log{P_i}
$$

where 
$$
P_i = \frac{\text{Total number of packets going towards a destion host } H_i}{\sum_{i=1}^n{\text{Total number of packets going towards a destion host } H_i}}
$$

If this value is less than some **THRESHOLD**, then we say the network possibly under DDoS attack according to

*Omar, T., Ho, A., & Urbina, B. Detection of DDoS in SDN Environment Using Entropy-based Detection.*


### Benefits of using Pegasus

1. Modular Nature of Pegagus Code Base
2. Scalability of the Code
3. One Stop Solution for guard against various possible adverserial attacks.
4. and much more...

## Technology Used
**Language:** Python
**Framework:** [POX](https://openflow.stanford.edu/display/ONL/POX+Wiki.html)
**Network Simulation:** [Mininet](http://mininet.org)
**Tools:** [Wireshark](https://www.wireshark.org)

## Directory Structure
```bash
.
├── README.md
├── scripts
│   └── ddos.sh
└── src
    ├── constants.py
    ├── __init__.py
    ├── lib
    │   └── entropy.py
    ├── main.py
    └── pegasus
        ├── common.py
        ├── __init__.py
        └── modules
            ├── ddos_entropy.py
            ├── firewall.py
            ├── http_blocker.py
            ├── hub.py
            ├── quarantine.py
            ├── reflector_net.py
            └── switch.py
```

## Instructions

Before moving further make sure to install **mininet** through http://mininet.org/download/

**1. Move the project folder in the POX folder** (which comes installed with miniet)

```bash
$ mv project pox/pox/project
```

**2. Navigate to `/pox` folder**

**3. To run Pegasus controller (in DEBUG LOG MODE):**

```bash
$ ./pox.py log.level --DEBUG project.src.main
```

![](https://i.imgur.com/5Ga17fR.png)


**4. Run Mininet (3-host 1-switch topology)**

```bash
$ sudo mn --topo single,3 --mac --switch ovsk --controller remote
```

![](https://i.imgur.com/mOz2jkz.png)



**5. Select one of the given default modules**

![](https://i.imgur.com/4ZWCyox.png)

For example to choose Firewall, type in "3"
```bash
> 3 [ENTER]
```

and that's it !!

#### To simulate DDoS attack

```bash
$ xterm h1 h2
```

Execute this command on both **h1 and h2**

```bash
while :
    do
        iperf -c [dest_ip_addr] -t [time period]
    done
```

for example 

```bash
while :
    do
        iperf -c 10.0.0.3 -t 5
    done
```

## Working Screenshots

### 1. Hub - A simple Layer 1 Device

![](https://i.imgur.com/pai7F0i.png)


In this the SDN enabled switch simply forwards all the packets coming towards itself to all the other switch ports. (Remember: **excluding the ingress port**)

And one can see that no packets are dropped and all are able to communicate with others.

### 2. Switch - A Layer 2 Device

#### Case 1: When the port corresponding to destionation is not known initially

![](https://i.imgur.com/TidrJZa.png)

Our controller deploys the flows according the learned host to switch port mapping in the SDN enabled switch.

#### Case 2: When the rule is already deployed in the switch

![](https://i.imgur.com/s8MHX2J.png)

This time the switch does it all on its own** without messaging** the controller.

### 3. Firewall

![](https://i.imgur.com/fDIK2gC.png)

(**Note:** there is a typo in the above screenshot, it should be `00:00:00:00:00:03` instead of `00:00:00:00:03`)
1. **List of addresses** to block as highlighted in yellow. This blocks all the outgoing communication from the hosts (basically blocking the **malicious hosts**).
2. **List of (src, dst) addresses** to block a specific directed communication from **src** to **dst**.

![](https://i.imgur.com/P3dDcBq.png)

![](https://i.imgur.com/eQOkUF8.png)

### 4. Host Quarantine

![](https://i.imgur.com/0hqXx6j.png)

The host is set to quarantined and hence, all the incoming packets are redirected back. (**Note**: one can also go by dropping the packets)

### 5. HTTP Blocker

![](https://i.imgur.com/ulxdtoi.png)


In this we basically loop over all the `blacklisted_ipaddrs` and block the TCP/IPv4 packets.

This is important, as some attacks can be done using HTTP protocol. Examples:

1. *Yatagai, T., Isohara, T., & Sasase, I. (2007, August). Detection of HTTP-GET flood attack based on analysis of page access behavior. In 2007 IEEE Pacific rim conference on communications, computers and signal processing (pp. 232-235). IEEE.*
2. *Hirakawa, T., Ogura, K., Bista, B. B., & Takata, T. (2016, September). A defense method against distributed slow http dos attack. In 2016 19th international conference on network-based information systems (NBiS) (pp. 152-158). IEEE.*

and more.

### 6. Reflector Net

![](https://i.imgur.com/v81edhJ.png)

Sends all the incoming flow from **blacklisted_ipaddrs** to an **outgress port going towards honey pot.**

### 7. DDoS Defender based on Entropy

![](https://i.imgur.com/pgi7ukO.png)

This is the implementation of how the entropy is calculated. Further, if it is greater than some threashold then all the communication through the DSN switch will terminate for certain time period.

![](https://i.imgur.com/NDmZqIZ.png)


## Authors

[Rishabh Singhal](https://rish-singhal.github.io)
[Aman Rojjha](https://sarcasticnastik.github.io/)

## Resources
1. *Omar, T., Ho, A., & Urbina, B. Detection of DDoS in SDN Environment Using Entropy-based Detection.*
2. *Yatagai, T., Isohara, T., & Sasase, I. (2007, August). Detection of HTTP-GET flood attack based on analysis of page access behavior. In 2007 IEEE Pacific rim conference on communications, computers and signal processing (pp. 232-235). IEEE.*
2. *Hirakawa, T., Ogura, K., Bista, B. B., & Takata, T. (2016, September). A defense method against distributed slow http dos attack. In 2016 19th international conference on network-based information systems (NBiS) (pp. 152-158). IEEE.*
3. [POX Wiki](https://openflow.stanford.edu/display/ONL/POX+Wiki.html#POXWiki-PacketIn)
4. [OpenFlow Tutorial](https://github.com/mininet/openflow-tutorial/wiki/Learn-Development-Tools)
5. [Mininet](http://mininet.org)

