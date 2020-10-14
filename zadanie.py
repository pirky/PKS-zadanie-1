from scapy.all import *
from binascii import hexlify
import operator
import sys

ieee = {}  # Dictionary s info o aky typ IEEE ide
ethernet = {}  # Dictionary s info o aky typ Ethernetu ide
ipv4 = {}   # Dictionary s info o aky protokol v IPv4 ide


def load_dictionaries():  # Načítanie zo súboru ethernet, ieee typov a ipv4 protokolov
    global ieee
    global ethernet
    global ipv4
    file = open("eth_ieee.txt", "r")
    for line in file:
        arr = line.split(":")
        if int(arr[0]) > 1500:
            ethernet[int(arr[0])] = arr[1]
        elif int(arr[0]) < 256:
            ieee[int(arr[0])] = arr[1]
    file.close()
    file = open("ipv4_protocols.txt", "r")
    for line in file:
        arr = line.split(":")
        ipv4[int(arr[0])] = arr[1]
    file.close()


def printing_packet(pkt):  # Vypísanie celého protokolu po bajtoch
    for i in range(len(pkt) * 2):
        if i % 2 == 0:
            print(end=' ')
        if i % 32 == 0:
            print()
        elif i % 16 == 0:
            print(" ", end='')
        print(str(hexlify(bytes(pkt))[i: i + 1])[2: -1], end='')


def lengths(pkt):  # Vyráta dĺžku rámca pcap API, aj rámca prenášaného po médiu
    print("dĺžka rámca poskytnutá pcap API –", len(pkt), "B")
    if len(pkt) < 60:
        print("dĺžka rámca prenášaného po médiu – 64 B")
    else:
        print("dĺžka rámca prenášaného po médiu –", len(pkt) + 4, "B")


def type_of_packet(pkt):  # Zistenie typu protokola
    if int(str(hexlify(bytes(pkt))[24: 28])[2: -1], 16) > 1500:
        print("Ethernet II")
    elif str(hexlify(bytes(pkt))[28: 32])[2: -1] == "ffff":
        print("IEEE 802.3 - Raw")
    else:
        if int(str(hexlify(bytes(pkt))[28: 30])[2: -1], 16) == 170:
            print("IEEE 802.3 LLC + SNAP")
        elif int(str(hexlify(bytes(pkt))[28: 30])[2: -1], 16) < 256:
            print("IEEE 802.3 LLC")


def mac_addresses(pkt):  # Vypísanie MAC adries paketu
    print("Zdrojová MAC adresa: ", end='')
    for i in range(12, 24):
        if i % 2 == 0:
            print(" ", end='')
        print(str(hexlify(bytes(pkt))[i: i + 1])[2: -1].upper(), end='')

    print("\nCieľová MAC adresa: ", end='')
    for i in range(0, 12):
        if i % 2 == 0:
            print(" ", end='')
        print(str(hexlify(bytes(pkt))[i: i + 1])[2: -1].upper(), end='')

    print()


def print_IPv4(pkt, all_addresses):  # Vypísanie IP adries pre IPv4 protokol a protokol v ňom
    global ipv4
    print("zdrojová IP adresa: {}.{}.{}.{}".format(bytes(pkt)[26], bytes(pkt)[27], bytes(pkt)[28], bytes(pkt)[29]))
    print("cieľová IP adresa: {}.{}.{}.{}".format(bytes(pkt)[30], bytes(pkt)[31], bytes(pkt)[32], bytes(pkt)[33]))
    if int(str(hexlify(bytes(pkt))[46: 48])[2: -1], 16) in ipv4.keys():
        print(ipv4.get(int(str(hexlify(bytes(pkt))[46: 48])[2: -1], 16)), end='')
        if bytes(pkt)[30: 34] in all_addresses:
            all_addresses[bytes(pkt)[30: 34]] = all_addresses[bytes(pkt)[30: 34]] + 1
        else:
            all_addresses[bytes(pkt)[30: 34]] = 1
    return all_addresses


def ethertype(pkt, all_addresses):  # Zistí ethertype ethernetu
    global ethernet
    if int(str(hexlify(bytes(pkt))[24: 28])[2: -1], 16) in ethernet.keys():
        print(ethernet.get(int(str(hexlify(bytes(pkt))[24: 28])[2: -1], 16)), end='')
        if int(str(hexlify(bytes(pkt))[24: 28])[2: -1], 16) == 2048:
            all_addresses = print_IPv4(pkt, all_addresses)
    else:
        print("Unknown Ethertype")
    return all_addresses


def snap_type(pkt):  # Zistí ethertype SNAP-u
    global ethernet
    if int(str(hexlify(bytes(pkt))[40: 44])[2: -1], 16) in ethernet.keys():
        print(ethernet.get(int(str(hexlify(bytes(pkt))[40: 44])[2: -1], 16)), end='')
    else:
        print("Unknown Ethertype")


def ieee_type(pkt):  # Zistí SAP ieee
    global ieee
    if int(str(hexlify(bytes(pkt))[28: 30])[2: -1], 16) in ieee.keys():
        print(ieee.get(int(str(hexlify(bytes(pkt))[28: 30])[2: -1], 16)), end='')
    else:
        print("Unknown type of IEEE", end='')


def inner_protocol(pkt, all_addresses):  # Zistí vnútorný protokol
    global ethernet
    global ieee
    if int(str(hexlify(bytes(pkt))[24: 28])[2: -1], 16) > 1500:
        all_addresses = ethertype(pkt, all_addresses)
    elif str(hexlify(bytes(pkt))[28: 32])[2: -1] == "ffff":
        print("IPX")
    elif str(hexlify(bytes(pkt))[28: 30])[2: -1] == "aa":
        snap_type(pkt)
    elif int(str(hexlify(bytes(pkt))[28: 30])[2: -1], 16) < 256:
        ieee_type(pkt)
    else:
        print("Unknown protocol", end='')
    return all_addresses


def list_of_IP(all_addresses):  # Vypíše všetky jedinečné IP adresy
    print("\n\nZoznam IP adries všetkých prijímajúcich uzlov:")

    for address in all_addresses:
        print("{}.{}.{}.{}".format(bytes(address)[0], bytes(address)[1], bytes(address)[2], bytes(address)[3]))
    most_used = max(all_addresses.items(), key=operator.itemgetter(1))[0]

    print("\nAdresa uzla s najväčším počtom prijatých paketov:")
    print("{}.{}.{}.{}   {} paketov".format(bytes(most_used)[0], bytes(most_used)[1], bytes(most_used)[2],
                                            bytes(most_used)[3], all_addresses[most_used]))


def print_info(pkt, all_addresses):    # Vypíše informácie o jednom pakete
    lengths(pkt)
    type_of_packet(pkt)
    mac_addresses(pkt)
    all_addresses = inner_protocol(pkt, all_addresses)
    printing_packet(pkt)
    return all_addresses


def first(raw_data):
    counter = 1
    all_addresses = {}
    for pkt in raw_data:
        # if counter > 12:
        #    break
        print("\n\nRámec", counter)
        all_addresses = print_info(pkt, all_addresses)
        counter += 1
    list_of_IP(all_addresses)


def start():
    load_dictionaries()
    # path_file = input("Zadaj cestu k .pcap súboru: ")
    path_file = "vzorky_pcap_na_analyzu/trace-20.pcap"
    file_out = open("output.txt", "w")
    command = 1
    # command = int(input("Stlač:\t1 pre výstup do konzoly\n\t\t2 pre výstup do súboru\n"))
    if command == 2:
        sys.stdout = file_out
    raw_data = rdpcap(path_file)
    first(raw_data)
    file_out.close()


start()
