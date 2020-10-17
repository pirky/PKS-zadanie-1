from scapy.all import *
from binascii import hexlify
import operator
import sys

ieee = {}  # Dictionary s info o aky typ IEEE ide
ethernet = {}  # Dictionary s info o aky typ Ethernetu ide
ipv4 = {}  # Dictionary s info o aky protokol v IPv4 ide
tcp_ports = {}  # Dictionary s info o aky well-known tcp port ide


class Structure:    # complete -> 0 = nekompletna, 1 = kompletna, 2 = bez zaciatku
    def __init__(self, complete, sip, sport, dip, dport):
        self.complete = complete
        self.sip = sip
        self.sport = sport
        self.dip = dip
        self.dport = dport
        self.arr_coms = []

    def add_pkt(self, number):
        self.arr_coms.append(number)


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
    file = open("tcp.txt", "r")
    for line in file:
        arr = line.split(":")
        tcp_ports[arr[0]] = arr[1][:-1]
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


def print_info(pkt, all_addresses):  # Vypíše informácie o jednom pakete
    lengths(pkt)
    type_of_packet(pkt)
    mac_addresses(pkt)
    all_addresses = inner_protocol(pkt, all_addresses)
    printing_packet(pkt)
    return all_addresses


def all_packets(raw_data):  # Vypíše všetky údaje potrebné pre 1., 2. a 3. bod zadania
    counter = 1
    all_addresses = {}
    for pkt in raw_data:
        if counter > 12:
            break
        print("\n\nRámec", counter)
        all_addresses = print_info(pkt, all_addresses)
        counter += 1
    list_of_IP(all_addresses)


def tcp_print(raw_data, comms):
    print()


def flag_function(raw_data, comm, number):
    ihl = int(str(hexlify(bytes(raw_data[comm.arr_coms[number]]))[29:30])[2: -1]) * 4
    return bytes(raw_data[comm.arr_coms[number]])[27 + ihl]


def tcp_comms(raw_data, comms):
    counter = -1
    for comm in comms:
        counter += 1
        if len(comm.arr_coms) < 3:
            continue

        flag1 = flag_function(raw_data, comm, 0)
        flag2 = flag_function(raw_data, comm, 1)
        flag3 = flag_function(raw_data, comm, 2)
        if flag1 == 2 and flag2 == 18 and flag3 == 16:   # 3-way SYN handshake
            print("Komunikacia ", counter)
            comm.complete = 0
            print("ma zaciatok")
        else:
            continue

        flag = flag_function(raw_data, comm, -1)
        if flag == 4 or flag == 20:   # RST ukoncenie, RST+ACK
            comm.complete = 1
            print("ma RST koniec")
            continue

        flag1 = flag_function(raw_data, comm, -4)
        flag2 = flag_function(raw_data, comm, -3)
        flag3 = flag_function(raw_data, comm, -2)
        flag4 = flag_function(raw_data, comm, -1)
        if flag1 == 17 and flag2 == 16 and flag3 == 17 and flag4 == 16:  # 4-way FIN
            comm.complete = 1
            print("ma 4-way FIN")
            continue
        if flag2 == 17 and flag3 == 17 and flag4 == 16:  # 3-way FIN
            comm.complete = 1
            print("ma 3-way FIN")


def tcp_together(raw_data, spec_packets):
    comms = []
    for i in range(len(spec_packets)):
        ihl = int(str(hexlify(bytes(raw_data[spec_packets[i]]))[29:30])[2: -1]) * 8
        sip = hexlify(bytes(raw_data[spec_packets[i]]))[52: 60]
        sport = hexlify(bytes(raw_data[spec_packets[i]]))[28 + ihl: 32 + ihl]
        dip = hexlify(bytes(raw_data[spec_packets[i]]))[60: 68]
        dport = hexlify(bytes(raw_data[spec_packets[i]]))[32 + ihl: 36 + ihl]
        if len(comms) == 0:
            pkt = Structure(0, sip, sport, dip, dport)
            comms.append(pkt)
            pkt.add_pkt(spec_packets[i])
        else:
            counter = 0
            new = 1
            for structure in comms:
                if (sip == structure.sip and sport == structure.sport and dip == structure.dip and
                    dport == structure.dport) or (sip == structure.dip and sport == structure.dport
                                                  and dip == structure.sip and dport == structure.sport):
                    comms[counter].arr_coms.append(spec_packets[i])
                    new = 0
                    break
                counter += 1
            if new == 1:
                pkt = Structure(2, sip, sport, dip, dport)
                comms.append(pkt)
                pkt.add_pkt(spec_packets[i])
    tcp_comms(raw_data, comms)


def tcp(raw_data, protocol):
    global tcp_ports
    spec_packets = []
    position = 0
    for pkt in raw_data:
        ihl = int(str(hexlify(bytes(pkt))[29:30])[2: -1], 16) * 8
        if str(hexlify(bytes(pkt))[24: 28])[2: -1] == "0800" and str(hexlify(bytes(pkt))[46: 48])[2: -1] == "06" \
                and (str(hexlify(bytes(pkt))[28 + ihl: 32 + ihl])[2: -1] == tcp_ports[protocol]
                     or str(hexlify(bytes(pkt))[32 + ihl: 36 + ihl])[2: -1] == tcp_ports[protocol]):
            spec_packets.append(position)
        position += 1
    tcp_together(raw_data, spec_packets)


def start():
    load_dictionaries()
    # path_file = input("Zadaj cestu k .pcap súboru: ")
    path_file = "vzorky_pcap_na_analyzu/trace-20.pcap"
    raw_data = rdpcap(path_file)
    file_out = open("output.txt", "w")
    command = 1
    # command = int(input("Stlač:\t1 pre výstup do konzoly\n\t\t2 pre výstup do súboru\n"))
    if command == 2:
        sys.stdout = file_out
    #    print("""Pre daný výpis napíš:
    #    all - pre zobrazenie všetkých rámcov a jedinečných IP adries
    #    http - pre výpis HTTP komunikácie
    #    https - pre výpis HTTPS komunikácie
    #    telnet - pre výpis TELNET komunikácie
    #    ssh - pre výpis SSH komunikácie
    #    ftp-control - pre výpis FTP riadiace komunikácie
    #    ftp-data - pre výpis FTP dátové komunikácie
    #    tftp - pre výpis TFTP komunikácie
    #    icmp - pre výpis ICMP komunikácie
    #    arp - pre výpis ARP dvojíc komunikácie""")
    #    option = input()
    option = "http"
    if option == "all":
        all_packets(raw_data)
    elif option == "tftp":
        print("tftp")
    elif option == "icmp":
        print("icmp")
    elif option == "arp":
        print("arp")
    else:
        tcp(raw_data, option)
    file_out.close()


start()
