#!/usr/bin/python
import requests
from requests import Request, Session
import time
import pyglet
import datetime
import socket
from struct import *
import pcapy
import sys
import os
import re
print os.path.dirname(sys.argv[0])
pyglet.resource.reindex()
pyglet.lib.load_library('avbin')
pyglet.have_avbin=True

print "/!\\/!\\/!\\/!\\ do NOT START this program if you are playing on a server./!\\/!\\/!\\/!\\"
print "/!\\/!\\/!\\/!\\ do NOT START this program if you are playing on a server./!\\/!\\/!\\/!\\"
print "/!\\/!\\/!\\/!\\ do NOT START this program if you are playing on a server./!\\/!\\/!\\/!\\"
def finddevice():
    ftoread = 1
    # list all devices
    devices = pcapy.findalldevs()
    try:
        myfile = open("setting", "r") # or "a+", whatever you need
    except IOError:
        print "If you want, you can make a file named setting in the same folder location, and put the number you usually put, like that you won't have to do it manually anymore\n"
        ftoread = 0;
    needit = 1
    if ftoread == 1:
        try:
            number = myfile.readline()
            if number:
                if int(number) > -1 and int(number) < len(devices):
                    dev = devices[int(number)]
                    needit = 0
                else:
                    print "Check your file named setting, The number in the file setting must be between 0 and " + str(len(devices)) +"\n"
            else:
                print "If you want, you can make a file named setting, and put the number you usually put, like that you won't have to do it manually anymore\n"
                    
        except Exception as e: 
            print "Err! Tell me if it happens! and tell the error message" + str(e)
    if needit == 1:
        print "Step 0, once you find which one it will be always the same unless you switch from wifi to ethernet, need to find the correct device"
        while 1:
            quest="Enter a number between 0 and " + str(len(devices)-1) +":"
            dev = raw_input(quest) #OHGOD
            
            if dev.isdigit():
                if int(dev) > -1 and int(dev) < len(devices):
                    dev = devices[int(dev)]
                    break
    print "Now you have to try to join the server by clicking on it in fiveM, if it works you will get success message"
    print "If nothing happens, close program and restart it and choose another number"
    cap = pcapy.open_live(dev, 443, 1, 0)

    # start sniffing packets
    while (1):
        (header, packet) = cap.next()
        # print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        res=parse_packet(packet)
        if res:
            return res
            break

# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


# function to parse a packet
def parse_packet(packet):
    try:
        # parse ethernet header
        eth_length = 14
    
        eth_header = packet[:eth_length]
        if ( len(eth_header)!=14):
            return
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        if eth_protocol == 8:
            ip_header = packet[eth_length:20 + eth_length]
            iph = unpack('!BBHHHBBH4s4s', ip_header)
    
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
    
            iph_length = ihl * 4
    
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
            if protocol == 6:
                t = iph_length + eth_length
                tcp_header = packet[t:t + 20]
                tcph = unpack('!HHLLBBHHH', tcp_header)
    
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
    
                if (dest_port == 30120 or dest_port == 30140 or dest_port == 30160 or dest_port==29934):
                    h_size = eth_length + iph_length + tcph_length * 4
                    data_size = len(packet) - h_size
                    data = packet[h_size:]  
                    print ">>>HEYY<<"+data;
                    
                    guidres = data.split("guid=")
                    if len(guidres) >= 2:
                        guidres = guidres[1]
                        guidres = guidres.split("&")
                        guidres = guidres[0]
                        namoune = data.split("name=")
                        if len(namoune) >= 2:
                            namoune = namoune[1]
                            namoune = namoune.split("&")
                            if len(namoune) >=2:
                                namoune = namoune[0]
                                data = data.split("authTicket=")
                                if len(data) >= 2:
                                    data = data[1]
                                    data = data.split("&")
                                    if len(data) >=2:
                                        data = data[0]
                                        print "Found it ! Good job, you can stop trying to join manually now, the time is OVER"
                                        res = []
                                        res.append(namoune)
                                        res.append(guidres)
                                        res.append(data)
                                        return res
    except Exception as e:
        print "Exception>>>" +str(e)
        pass
                        
def getinfo(port = 120): # donne nombre de joueurs online
    udp_port = UDP_PORT + port
    try:
        sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP
        sock.sendto(MESSAGE, (UDP_IP, udp_port))
        sock.settimeout(1)

        data, addr = sock.recvfrom(1024)
        data = data.split("sv_maxclients", 1)[1]
        data = data.split("clients\\")[1]
        data = data.split("\\", 1)[0]
        data = int(data)
    except socket.timeout:
        data = -1
    return int(data);

def waitingqueue(port = 120): # donne position dans la queue et tente de se co
    try:
        url = 'http://149.56.28.211:30120/client'
        headersCO = {
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'None',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'CitizenFX/1',

            'Content-Length': '546',
            'Host': '149.56.28.211:30120',
        }
        nb = 110
        response = requests.post(url, headers=headersCO,data=dataAUTH)
        try:
            nb = int(response.content.split("/")[0].split("are")[1])
        except IndexError:
            nb = 300
    except Exception:
        nb = 310
    if int(nb) < 180:
        print ("port"+str(port)+"("+str(nb)+")"),
    if "spam" in response.content:
        print "port"+str(port)+">>Warning message: you are spamming too much" 
    return int(nb);

resu = finddevice()
dataAUTH = (
    ('authTicket',resu[2]),
    ('guid',resu[1]),
    ('method','initConnect'),
    ('name',resu[0]),
    ('protocol','5'),
)
UDP_IP = "149.56.28.211"
UDP_PORT = 30000
MESSAGE = "ffffffff676574696e666f20787878".decode('hex')
req120fini = 0
while 1:
    print "\n=========Start loop (Serv 120):" + str(datetime.datetime.now())
    try:
        if req120fini != 1:
            resinfoserv120 = getinfo(120)
            if resinfoserv120 == -1:
                resinfoserv120 = getinfo(120)
            resWaitingQueue = waitingqueue(120)
            
            if req120fini == 0 and resinfoserv120 < 24 and (resinfoserv120 + resWaitingQueue) < 25 and resWaitingQueue < 5:  #hey sinon <24 donc faut claps et si <24 dans queue
                    s1 = pyglet.resource.media('clapping.ogg');
                    s1.play()
                    time.sleep(1)
                    s1 = pyglet.resource.media('clapping.ogg');
                    s1.play()
                    time.sleep(1)
                    s1 = pyglet.resource.media('clapping.ogg');
                    s1.play()
                    time.sleep(1)
                    s1 = pyglet.resource.media('clapping.ogg');
                    s1.play()                    
                    print "Serv 120, the number of people in the server + your positions < 25, it means you will join."
                    print "\nNeed to check you are here, do not want to slow down the queue, be fast to answer that. If 1:30 passed, rip your position"
                    raw_input("Press Enter to continue...")
                    req120fini = 1 # on va rentrer, on fait manuel
                    continue
            if (resWaitingQueue < 5): #  On regarde sa reponse si down ou pas. > 300 : still down, pas eu de reponse
                s1 = pyglet.resource.media('clapping.ogg');
                s1.play()
                time.sleep(1)
                s1 = pyglet.resource.media('clapping.ogg');
                s1.play()
                time.sleep(1)
                s1 = pyglet.resource.media('clapping.ogg');
                s1.play()
                time.sleep(1)
                s1 = pyglet.resource.media('clapping.ogg');
                s1.play()
                print "\nNeed to check you are here, do not want to slow down the queue, be fast to answer that. If 1:30 passed, rip your position"
                raw_input("Press Enter to continue...")
                print "Serv 120, soon, we are going in hype!"
                req120fini = 1
                continue
        else:
            s1 = pyglet.resource.media('nyaa.wav');
            s1.play()
            time.sleep(1)
            s1 = pyglet.resource.media('nyaa.wav');
            s1.play()
            print "Don't forget to click on the server in fiveM!"
    except Exception as e:
        print "exception !!"
        print e
    time.sleep(30)