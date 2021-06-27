

# fullNetworkSnifferApp



This python3 #APP will be run on the local network to monitor and capture packets from various protocols depending on the user input provided, and it will do so automatically.
To make the ##HTTP packet filter easy to understand, the script was written to filtered the packet and capture the username and the password entered only.

In addition to storing the captured packets on a ##local file, a copy of each captured packet will be sent to the user's ##email address.

There is two codes script, one contains all of the code comments, which allows you to gain a better understanding of the code flow, and another contains only the code all you need is to update your email and the email that can allow the app to send the result. You will also need to make changes to the email security of the email address from which you wish to send the results in order for the less secure apps to be able to access the app in the email settings.

## This script will capture packets from four protocols and it can be updated to capture more.

1. ARP
2. ICMP 
3. BOOTP 
4. HTTP.

## Dependencies
Install Scapy
```
apt install python3-scapy
```

install the scapy http library from the terminal:
```
pip install scapy-http
```

install email
```
pip install email
```

install email-to
```
pip install email-to
```


## Installation

```
git clone https://github.com/Angellito10/Network-Sniffer-APP.git
```
## Usage

```
sudo python3 networkSniffer.py 
sudo python fileName.py
```

**All steps Requires "root" privileges.**
## 1- Run the script

```sudo python networkSniffer.py ```

![GitHub Logo](https://github.com/Angellito10/Network-Sniffer-APP/blob/main/img/1.png)

All of the currently active interfaces on the device will be displayed, and you will be required to choose which one you want to use to run the application ?
and then the interface will set to PROMISC mode.

## 2- packet capturing

The number of packets you want to capture can be entered, or it can be left at zero, which means the capteure will be infinity.
When capturing packets, the time spent capturing will be used to increase the amount of management available to the app. If the time is 10 and the number of packets is infinity, the app will capture one-tenth of a packet and then terminate.

![GitHub Logo](https://github.com/Angellito10/Network-Sniffer-APP/blob/main/img/2.png)


## 3- Protocol and file setting
Now you have the option of selecting which protocol you want to capture packets from: ICMP, ARP, BOOTP, and HTTP are all supported.

After that, enter the name of the file on which you want to store the packet, and the packet will be sent to the email address that you specified in the app configuration. 

![GitHub Logo](https://github.com/Angellito10/Network-Sniffer-APP/blob/main/img/3.png)



Inconclusion, you can modify the scrip to do more tasks. 
