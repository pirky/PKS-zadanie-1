from scapy.all import *
from binascii import hexlify
import operator
import sys

ieee = {}  # Dictionary s info o aky typ IEEE ide
ethernet = {}  # Dictionary s info o aky typ Ethernetu ide
ipv4 = {}  # Dictionary s info o aky protokol v IPv4 ide
tcp_ports = {}  # Dictionary s info o aky well-known tcp port ide
all_addresses = {}  # Dictionary so vsetkymi DIP adresami
udp_ports = {}  # Dictionary s info o aky well-known udp port ide
icmp_types = {}   # Dictionary s info o aky type ide


class Structure:  # complete -> 0 = nekompletna, 1 = kompletna, 2 = bez zaciatku
    def __init__(self, complete, sip, sport, dip, dport):
        self.complete = complete
        self.sip = sip
        self.sport = sport
        self.dip = dip
        self.dport = dport
        self.arr_coms = []

    def add_pkt(self, number):
        self.arr_coms.append(number)


class StructureTftp:
    def __init__(self, sport, dport, end):
        self.sport = sport
        self.dport = dport
        self.end = end
        self.arr_coms = []

    def add_pkt(self, number):
        self.arr_coms.append(number)


def load_dictionaries():  # Načítanie zo súboru ethernet, ieee typov a ipv4 protokolov
    global ieee
    global ethernet
    global ipv4
    global udp_ports
    global icmp_types
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
    file = open("tcp.txt", "r")
    for line in file:
        arr = line.split(":")
        tcp_ports[arr[0]] = arr[1][:-1]
    file.close()
    file = open("udp.txt", "r")
    for line in file:
        arr = line.split(":")
        udp_ports[arr[0]] = arr[1][:-1]
    file.close()
    file = open("icmp.txt", "r")
    for line in file:
        arr = line.split(":")
        icmp_types[int(arr[0])] = arr[1][:-1]
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


def print_IPv4(pkt):  # Vypísanie IP adries pre IPv4 protokol a protokol v ňom
    global ipv4
    global all_addresses
    print("zdrojová IP adresa: {}.{}.{}.{}".format(bytes(pkt)[26], bytes(pkt)[27], bytes(pkt)[28], bytes(pkt)[29]))
    print("cieľová IP adresa: {}.{}.{}.{}".format(bytes(pkt)[30], bytes(pkt)[31], bytes(pkt)[32], bytes(pkt)[33]))
    if int(str(hexlify(bytes(pkt))[46: 48])[2: -1], 16) in ipv4.keys():
        print(ipv4.get(int(str(hexlify(bytes(pkt))[46: 48])[2: -1], 16)), end='')
        if bytes(pkt)[30: 34] in all_addresses:
            all_addresses[bytes(pkt)[30: 34]] = all_addresses[bytes(pkt)[30: 34]] + 1
        else:
            all_addresses[bytes(pkt)[30: 34]] = 1


def ethertype(pkt):  # Zistí ethertype ethernetu
    global ethernet
    if int(str(hexlify(bytes(pkt))[24: 28])[2: -1], 16) in ethernet.keys():
        print(ethernet.get(int(str(hexlify(bytes(pkt))[24: 28])[2: -1], 16)), end='')
        if int(str(hexlify(bytes(pkt))[24: 28])[2: -1], 16) == 2048:
            print_IPv4(pkt)
    else:
        print("Unknown Ethertype")


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


def inner_protocol(pkt):  # Zistí vnútorný protokol
    global ethernet
    global ieee
    if int(str(hexlify(bytes(pkt))[24: 28])[2: -1], 16) > 1500:
        ethertype(pkt)
    elif str(hexlify(bytes(pkt))[28: 32])[2: -1] == "ffff":
        print("IPX")
    elif str(hexlify(bytes(pkt))[28: 30])[2: -1] == "aa":
        snap_type(pkt)
    elif int(str(hexlify(bytes(pkt))[28: 30])[2: -1], 16) < 256:
        ieee_type(pkt)
    else:
        print("Unknown protocol", end='')


def list_of_IP():  # Vypíše všetky jedinečné IP adresy
    print("\n\nZoznam IP adries všetkých prijímajúcich uzlov:")
    global all_addresses
    for address in all_addresses:
        print("{}.{}.{}.{}".format(bytes(address)[0], bytes(address)[1], bytes(address)[2], bytes(address)[3]))
    most_used = max(all_addresses.items(), key=operator.itemgetter(1))[0]

    print("\nAdresa uzla s najväčším počtom prijatých paketov:")
    print("{}.{}.{}.{}   {} paketov".format(bytes(most_used)[0], bytes(most_used)[1], bytes(most_used)[2],
                                            bytes(most_used)[3], all_addresses[most_used]))


def print_info(pkt):  # Vypíše informácie o jednom pakete
    lengths(pkt)
    type_of_packet(pkt)
    mac_addresses(pkt)
    inner_protocol(pkt)
    printing_packet(pkt)


def all_packets(raw_data):  # Vypíše všetky údaje potrebné pre 1., 2. a 3. bod zadania
    counter = 1
    global all_addresses
    all_addresses.clear()
    for pkt in raw_data:
        print("\n\nRámec", counter)
        print_info(pkt)
        counter += 1
    list_of_IP()


def print_comms(raw_data, i, protocol):
    print("Rámec ", i + 1)
    lengths(raw_data[i])
    type_of_packet(raw_data[i])
    mac_addresses(raw_data[i])
    inner_protocol(raw_data[i])
    print(protocol.upper())
    ihl = int(str(hexlify(bytes(raw_data[i]))[29:30])[2: -1]) * 8
    print("zdrojový port: ", int(hexlify(bytes(raw_data[i]))[28 + ihl: 32 + ihl], 16))
    print("cieľový port: ", int(hexlify(bytes(raw_data[i]))[32 + ihl: 36 + ihl], 16))
    printing_packet(raw_data[i])
    print("\n")


def tcp_print(raw_data, comms, protocol):
    complete = 0
    incomplete = 0
    for comm in comms:
        if comm.complete == 0:
            print("-------------------------------\n"
                  "Výpis nekompletnej komunikácie:\n"
                  "-------------------------------")
            if len(comm.arr_coms) > 20:
                print("\nVýpis v skrátenej forme iba prvých 10 a posledných 10 rámcov\n")
            counter = 0
            for i in comm.arr_coms:
                if len(comm.arr_coms) > 20 and 9 < counter < len(comm.arr_coms) - 10:
                    counter += 1
                    continue
                print_comms(raw_data, i, protocol)
                counter += 1
            incomplete = 1
            break
    if incomplete == 0:
        print("Nekompletná komunikácia sa tu nenachádza")
    for comm in comms:
        if comm.complete == 1:
            print("-------------------------------\n"
                  "Výpis kompletnej komunikácie:\n"
                  "-------------------------------")
            if len(comm.arr_coms) > 20:
                print("\nVýpis v skrátenej forme iba prvých 10 a posledných 10 rámcov\n")
            counter = 0
            for i in comm.arr_coms:
                if len(comm.arr_coms) > 20 and 9 < counter < len(comm.arr_coms) - 10:
                    counter += 1
                    continue
                print_comms(raw_data, i, protocol)
                counter += 1
            complete = 1
            break
    if complete == 0:
        print("Kompletná komunikácia sa tu nenachádza")


def flag_function(raw_data, comm, number):
    ihl = int(str(hexlify(bytes(raw_data[comm.arr_coms[number]]))[29:30])[2: -1]) * 4
    return bytes(raw_data[comm.arr_coms[number]])[27 + ihl]


def tcp_comms(raw_data, comms, protocol):
    for comm in comms:
        if len(comm.arr_coms) < 3:
            continue
        # print("-------------------------------------------------")
        flag1 = flag_function(raw_data, comm, 0)
        flag2 = flag_function(raw_data, comm, 1)
        flag3 = flag_function(raw_data, comm, 2)
        if flag1 == 2 and flag2 == 18 and flag3 == 16:  # 3-way SYN handshake
            # print("zaciatok")
            comm.complete = 0
        else:
            # print("bullshit")
            continue

        flag = flag_function(raw_data, comm, -1)
        if flag == 4 or flag == 20:  # RST ukoncenie, RST+ACK
            # print("RST ukoncenie")
            comm.complete = 1
            continue

        flag1 = flag_function(raw_data, comm, -4)
        flag2 = flag_function(raw_data, comm, -3)
        flag3 = flag_function(raw_data, comm, -2)
        flag4 = flag_function(raw_data, comm, -1)
        if flag1 == 17 and flag2 == 16 and flag3 == 17 and flag4 == 16:  # 4-way FIN
            # print("4-way FIN")
            comm.complete = 1
            continue
        if flag2 == 17 and flag3 == 17 and flag4 == 16:  # 3-way FIN
            comm.complete = 1
            # print("3-way FIN")
    tcp_print(raw_data, comms, protocol)


def tcp_together(raw_data, spec_packets, protocol):
    comms = []
    for i in range(len(spec_packets)):
        ihl = int(str(hexlify(bytes(raw_data[spec_packets[i]]))[29:30])[2: -1]) * 8
        sip = hexlify(bytes(raw_data[spec_packets[i]]))[52: 60]
        sport = hexlify(bytes(raw_data[spec_packets[i]]))[28 + ihl: 32 + ihl]
        dip = hexlify(bytes(raw_data[spec_packets[i]]))[60: 68]
        dport = hexlify(bytes(raw_data[spec_packets[i]]))[32 + ihl: 36 + ihl]
        if len(comms) == 0:
            pkt = Structure(2, sip, sport, dip, dport)
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
    tcp_comms(raw_data, comms, protocol)


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
    tcp_together(raw_data, spec_packets, protocol)


def tftp_print(raw_data, comms, protocol):
    position = 1
    for comm in comms:
        print(" ------------------------"
              "\n     Komunikácia {}:\n".format(position),
              "------------------------")
        if comm.end == "error":
            print("Komunikácia skončila errorom.\n")
        elif comm.end == "normal":
            print("Komunikácia skončila normálne, bez erroru.\n")
        if len(comm.arr_coms) > 20:
            print("\nVýpis v skrátenej forme iba prvých 10 a posledných 10 rámcov\n")
        counter = 0
        for i in comm.arr_coms:
            if len(comm.arr_coms) > 20 and 9 < counter < len(comm.arr_coms) - 10:
                counter += 1
                continue
            print_comms(raw_data, i, protocol)
            counter += 1
        position += 1


def tftp(raw_data, protocol):
    global udp_ports
    comms = []
    position = 0
    running_comm = 0    # 0 -> nebeži, 1 -> beži, 2 -> ACK a končí
    first = 1
    comm_length = 0
    for pkt in raw_data:
        ihl = int(str(hexlify(bytes(pkt))[29:30])[2: -1], 16) * 8
        if str(hexlify(bytes(pkt))[24: 28])[2: -1] == "0800" and str(hexlify(bytes(pkt))[46: 48])[2: -1] == "11":
            sport = hexlify(bytes(pkt))[28 + ihl: 32 + ihl]
            dport = hexlify(bytes(pkt))[32 + ihl: 36 + ihl]
            if running_comm == 1 and (dport == comms[-1].sport or sport == comms[-1].sport):
                comms[-1].add_pkt(position)
                opcode = int(str(hexlify(bytes(pkt))[44 + ihl: 48 + ihl])[2:-1], 16)
                length = int(str(hexlify(bytes(pkt))[36 + ihl: 40 + ihl])[2:-1], 16)
                if opcode == 3 and first == 1:
                    comm_length = int(str(hexlify(bytes(pkt))[36 + ihl: 40 + ihl])[2:-1], 16)
                    comms[-1].dport = sport
                    first = 0
                elif opcode == 5:
                    running_comm = 0
                    comms[-1].end = "error"
                elif opcode == 3 and comm_length > length:
                    running_comm = 2
            elif running_comm == 2:
                comms[-1].add_pkt(position)
                running_comm = 0
            elif str(hexlify(bytes(pkt))[32 + ihl: 36 + ihl])[2: -1] == udp_ports[protocol]:
                comms.append(StructureTftp(sport, dport, "normal"))
                comms[-1].add_pkt(position)
                running_comm = 1
        position += 1
    tftp_print(raw_data, comms, protocol)


def icmp(raw_data, protocol):
    global icmp_types
    position = 0
    for pkt in raw_data:
        if str(hexlify(bytes(pkt))[24: 28])[2: -1] == "0800" and str(hexlify(bytes(pkt))[46: 48])[2: -1] == "01":
            print("Rámec ", position + 1)
            lengths(pkt)
            type_of_packet(pkt)
            mac_addresses(pkt)
            ihl = int(str(hexlify(bytes(pkt))[29:30])[2: -1]) * 8
            print(protocol.upper(), "->", icmp_types[bytes(pkt)[14 + int(ihl/2)]])
            print("zdrojový port: ", int(hexlify(bytes(pkt))[28 + ihl: 32 + ihl], 16))
            print("cieľový port: ", int(hexlify(bytes(pkt))[32 + ihl: 36 + ihl], 16))
            printing_packet(pkt)
            print("\n")
        position += 1


def start():
    load_dictionaries()
    # path_file = input("Zadaj cestu k .pcap súboru: ")
    path_file = "vzorky_pcap_na_analyzu/trace-15.pcap"
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
    option = "tftp"
    if option == "all":
        all_packets(raw_data)
    elif option == "tftp":
        tftp(raw_data, option)
    elif option == "icmp":
        icmp(raw_data, option)
    elif option == "arp":
        print("arp")
    else:
        tcp(raw_data, option)
    file_out.close()


start()
