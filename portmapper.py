
import threading
import socket
import struct

import dpkt # pip install dpkt

# Issues:
# improve error handling
# make functions for registry and threads manipulation
# cleanup dead threads
# RPC Version is not checked
# maybe use select and non blocking socket send recv

##########  configuration  ##########
mapperport    = 111
proxyport     = 8738         # 0x2222
maxproxyports = 32
#####################################

maxproxyport = proxyport+maxproxyports

"""
This Implementation aims to replace an existing portmapper. 
Portmappers gennerally have nondeterministic service ports for registered programs. 
This makes port mapping difficult and impossible in docker on windows. 

This implemetation is partly reverse engeneered from a portmapper environment. 
It handles RPC procedures: getport, set, unset. 

It is mostly a prove of concept for a generic solution that allows to run applications which rely on a portmapper to be containerized for linux and windows. 

On Docker Desktop (windows 10 wsl2) seems to be port 111 already in use by docker. We can use the port by binding the port with the public ip of the machine. 
"""

# wsl
# docker run -p 10.158.101.108:111:111/tcp -p 10.158.101.108:111:111/udp -p8738-8770:8738-8770  -it -v"$(pwd)":/host/scm -v ~/.ssh/id_rsa:/home/builduser/.my-key:ro --rm --name buildimage buildimage ssh-agent bash -c "ssh-add ~/.my-key; bash"
# docker exec -it nsbuild python3 scm/portmapper.py 


""" 
wireshark filter: 
tcp.port == 111  || udp.port == 111  

RPC_frame (Typical): 
(4B TCP only fragment (msb_lastmsg...fragsize))
4B XID
4B (Call(0) Resp(1))
4B version (2)
4B program (100000 portmap)
4B prog version (2)
4B procedure (getport (3) )
16B credentials/len/verifier/len (0...0)

portmap req frame: 
4B progID (1213852190)
4B version (2)
4B proto (tcp (6))
4B port (0)
"""


TCP = 6
UDP = 17
PORTMAP = 100000
# rpc procedures
GETPORT = 3
SET     = 1
UNSET   = 2

threads = {}
registry = {}
portlist = [e for e in range(proxyport,maxproxyport)]
id = 0

help = """
q    Quit
p    PortList
t    Threads
r    Registry
h    Help
d    Debug print
s    less verbose
"""

def silentprint(*args,**kw):
    return

dprint = silentprint

class hexdump:
    # https://gist.github.com/NeatMonster/c06c61ba4114a2b31418a364341c26c0
    def __init__(self, buf, off=0):
        self.buf = buf
        self.off = off

    def __iter__(self):
        last_bs, last_line = None, None
        for i in range(0, len(self.buf), 16):
            bs = bytearray(self.buf[i : i + 16])
            line = "{:08x}  {:23}  {:23}  |{:16}|".format(
                self.off + i,
                " ".join(("{:02x}".format(x) for x in bs[:8])),
                " ".join(("{:02x}".format(x) for x in bs[8:])),
                "".join((chr(x) if 32 <= x < 127 else "." for x in bs)),
            )
            if bs == last_bs:
                line = "*"
            if bs != last_bs or line != last_line:
                yield line
            last_bs, last_line = bs, line
        yield "{:08x}".format(self.off + len(self.buf))

    def __str__(self):
        return "\n".join(self)

    def __repr__(self):
        return "\n".join(self)

def genfragment(last, rpc):
    lastB = 0
    if last: 
        lastB = 0x80
    buf = struct.pack("!BBH", lastB, 0, len(rpc))
    return buf

def parseFrameTCP(frame): 
    # for TCP we only need to handle fragment header seperately
    fragment = frame[:4]
    frameresp = parseFrame(frame[4:])

    # create frame with leading fragment
    fragment = genfragment(1, frameresp)
    frame = fragment + frameresp
    return frame

def parseFrame(frame):
    # get interresting values from frame
    rpcreq = dpkt.rpc.RPC(frame)
    pmapreq = dpkt.pmap.Pmap(rpcreq.call.data)
    xid = rpcreq.xid
    rpcprog=None
    rpcprocedure = None
    if rpcreq.dir == 0:  # call
        rpcprog = rpcreq.call.prog
        rpcprocedure = rpcreq.call.proc
    else: 
        print("RPC not a CALL")
        return None

    if rpcprog != PORTMAP:
        print("RPC not for PORTMAP")
        return None

    # check  what to do  
    """ if set: register set-port and open listen sock or rcv_from thread on port in public range
        if traffic on comes in forward to set-port (bidirectional)
        if getport: input: program protocol  return port of desired protocol
        if unset unregister set-port and terminate listening thread.     
    """
    pmapResponse = None
    if rpcprocedure == GETPORT: 
        pmapResponse = rpcGetport(pmapreq)
    elif rpcprocedure == SET: 
        pmapResponse = rpcSet(pmapreq)
    elif rpcprocedure == UNSET: 
        pmapResponse = rpcUnset(pmapreq)
    else:
        print("Procedure %d not supported"%(rpcprocedure))
        # TODO: create error response unsupported proc
        return None

    # TODO: improve error handling
    if pmapResponse: 
        rpcresponse = createRPCResponse(xid,pmapResponse)
    else: 
        rpcresponse = createRPCResponse(xid,createPmapResponse(0),dpkt.rpc.PROG_UNAVAIL)
    
    # we wrap the response in an rpc frame
    return rpcresponse

def rpcGetport(pmapreq): 
    prog = pmapreq.prog
    prot = pmapreq.prot

    #get port from registry (prog,prot) or error (unknown prog) if not found
    port = getportfromreg(prog,prot)

    pmapres = None
    if port: 
        pmapres = createPmapResponse(port)
    return pmapres

def rpcSet(pmapreq):
    newport = pmapreq.port
    prog = pmapreq.prog
    prot = pmapreq.prot

    # register program port and protocol 
    #     start proxy port forwarder of desired protokol (TCP or UDP)
    regerror = register(prog,prot,newport)

    if not regerror:
        pmapResponse = createPmapResponse(1)
    else: 
        pmapResponse = createPmapResponse(0)
    return pmapResponse

def rpcUnset(pmapreq): 
    # unregister and remove proxy listener when connection was shutdown
    prog = pmapreq.prog
    error = unregister(prog)
    if error:
        print("Could not unregister prog:",prog)
        return None
    return createPmapResponse(1) 

def createPmapResponse(answer): 
    return struct.pack("!I", answer)

def createRPCResponse(xid, portmap, acceptstat=dpkt.rpc.SUCCESS ): 
    #create respose
    rpcrepl = dpkt.rpc.RPC()
    rpcrepl.xid = xid
    rpcrepl.dir = dpkt.rpc.REPLY

    reply1 = dpkt.rpc.RPC.Reply()
    # reply1.stat = MSG_ACCEPTED

    accept1 = dpkt.rpc.RPC.Reply.Accept()
    accept1.verf = dpkt.rpc.RPC.Auth()
    accept1.stat = acceptstat
    if accept1.stat: 
        accept1.low = 0
        accept1.high = 0

    # assamble RPC frame
    rpcrepl.data = reply1
    reply1.data = accept1
    # insert portmap data 
    accept1.data = portmap

    rpcbuf = bytes(rpcrepl)
    return rpcbuf

def register(prog,prot,newport):
    # start proxy port forwarder of desired protokol (TCP or UDP)
    # register program port and protocol and thread
    global registry
    global id

    threadids = []

    # we create both endpoints. The one public proxiport and the one to our service newport
    # TODO: this might be exausted so an error should be in the rpc frame
    proxyport = portlist.pop(0)
    if prot == UDP:
        threadfu = recvThrFuUDP,recvThrFuUDP
        s = serverudp(proxyport)
        sf = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    elif prot == TCP:
        threadfu = listening
        s = servertcp(proxyport)
        sf = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    else: 
        return 1  # unknown protocol

    # the thread moves data from public(proxy) to registered service but for tcp it is the listening thread
    id += 1
    t = threading.Thread(target=threadfu, args=[id]) 
    #             [fRun, sc, addr,    sf,   t, id]
    threads[id] = [True, s,  newport, sf, t, id]
    threadids.append(id)

    # maybe we need another thread here for UDP. The thread moves data from registered service to public(proxy) 
    #id += 1
    #t = threading.Thread(target=threadfu[1], args=[id]) 
    #threads[id] = [True, sf, proxyport, s, t, id]
    #threadids.append(id)

    # register the prog with the information
    registry[prog,prot] = [prog, prot, proxyport, newport, threadids]
    
    # all are registered so we start the threads
    for tid in threadids: 
        # [fRun, sc, addr, sf,  t, id]
        threads[tid][4].start()

    return 0

def findThreadinReg(tid):
    for k,v in registry.items(): 
        if tid in v[4]: 
            return k
    return None

def appendThreadinReg(ptid,tid):
    k = findThreadinReg(ptid)
    if k: 
        v = registry[k]
        v[4].append(tid)
        return registry[k]
    return None

def getportfromreg(prog,prot):
    global registry
    port = None
    try:
        reg = registry[prog,prot]
        # [prog, prot, newport, threadids]
        port = reg[2] # in normalportmappers this would be newport but we announce proxyport
    except:
        print("Program", prog,"Protocol" ,prot, "not found in registry")
    return port 

def unregister(prog):
    global registry
    res = 1
    dk = []
    threadids = []
    # find all registrations of program in registry
    for k,v in registry.items(): 
        if prog in v: 
            dk.append(k)
            res = 0
            threadids += v[4]
    # now we need to close the listening soket of the poblic proxy port otherwise we could not get a free port in public range
    for tid in threadids:
        fRun, sc, addr, sf,  t, id = threads[tid]
        threads[tid][0] = False
        ip,port = sc.getsockname()
        # we put the released port back into the pool
        sc.close()
        portlist.append(port)
        print("Freed up port: %d"%(port))
        # sf.shotdown(socket.SHUT_WR) this is not the right way for listening sock or maybe it is?
        # sc.close() sf.close()

    # remove registry entry
    for k in dk: 
        del registry[k]
    return res

def listening(ownid):
    global id
    fRun,   s,   port,   sf,   t,   _ = threads[ownid]

    while threads[ownid][0]:
        # listen until incomming connection
        print("%d: listening on:"%(ownid), s)
        s.listen(1)
        
        # accept connection
        try:
            sc, addr = s.accept()
        except:
            print("%d: listening sock was closed"%(ownid))
            break

        print("%d: accepted"%(ownid), addr)

        print("%d: create recv thread"%(id))
        id += 1
        t = threading.Thread(target=recvThrFu, args=[id])
        #             [fRun, sc, addr, sf,   t, id]
        threads[id] = [True, sc, None, sf, t, id]

        # if we have a forwarding socket then we connect to it now and put the connected socket in the arguments for the threads
        forwardaddr = None
        if sf and port: 
            forwardaddr = ('localhost', port)
            print("%d: connecting to forwarding port: "%(id), forwardaddr)
            sf.connect(forwardaddr)
            print("%d: create forwarding thread"%(id))
            id += 1
            ft = threading.Thread(target=recvThrFu, args=[id])
            #             [fRun, sc, addr, sf,   t, id]
            threads[id] = [True, sf, None, sc, ft, id]

            # we register both threads in registry (forwarding threads are spawned by rpc set)
            #print(appendThreadinReg(ownid,id-1))
            #print(appendThreadinReg(ownid,id))

            ft.start()
        t.start()
    print("%d: TCP listener Thread ended for socket: %s "%(ownid, s))

def recvThrFu(id):
    _,   sc, addr, sf, t, _ = threads[id]
    forward_sock = sf
    while threads[id][0]:
        dprint ("%d: ready to receive from: "%(id), sc)
        try: 
            frame = sc.recv(1024)
        except: 
            # TODO: cleanup this error handling
            print("recv socket broke", sc)
            _,   sc, addr, sf, t, _ = threads[id]
            sc.close()
            sf.close()
            threads[id][0] = False
            break
        dprint ("%d: received on: "%(id), sc, ':\n%s'%(hexdump(frame).__repr__()))
        if len(frame) == 0:
            print ("%d: Closing connection: "%(id), sc)
            try: 
                sc.shutdown(socket.SHUT_WR)
                sc.close()
            except Exception as e:
                print (f"exception while closing connection{sc}:  {e}")
            if forward_sock: 
                try: 
                    forward_sock.shutdown(socket.SHUT_WR)
                    forward_sock.close()
                except Exception as e:
                    print (f"exception while closing connection{sc}:  {e}")
            threads[id][0] = False
            break
        if forward_sock:
            forward_sock.send(frame)
        else:
            # we dont process if we forward 
            frameResponse = parseFrameTCP(frame)
            if frameResponse:
                dprint("reply: \n%s"%(hexdump(frameResponse)))
                sc.send(frameResponse)
    print ("%s: TCP stopped receving"%(id))

def recvThrFuUDP(id):
    #[fRun, sc,   addr,  sf,   t,     id]
    _     ,  s,   port,  sf,    _,      _ = threads[id]

    # TODO: there might be a forwarding needed for UDP. Then a secondary thread with switched sockets would be required. 
    while threads[id][0]:
        print("%s: Waiting on UDP recv on: %s" %(id,s))
        try:  
            data, addr = s.recvfrom(1024) # buffer size is 1024 bytes
        except: 
            print("%s: socket was closed")
            break
        dprint("%s: ---> Received from %s \nUDP message: \n%s" %(id,addr,hexdump(data)))
        
        if len(data) == 0:
            print (f"closing connection: {s}")
            threads[id][0] = False
            break

        resp = parseFrame(data)
        if resp: 
            dprint("%s: <--- Response to %s \nUDP message: \n%s" %(id, addr, hexdump(data)))
            s.sendto(resp, addr)
        else: 
            dprint("%s: XXXX NO Response to %s"%(id, addr))
    print("%s: UDP Thread ended of sock: %s "%(id, s))

def servertcp(port):
    s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    print("bind TCP port:", port)
    try: 
        s.bind(('',port))
    except Exception as e: 
        print("port not bindable: ", e)
    return s

def serverudp(port):
    s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM)
    print("bound: UDP", port)
    s.bind(('',port))
    return s

def main():
    global threads
    global id 
    global dprint

    stcp = servertcp (mapperport)
    id += 1
    tcplt = threading.Thread(target=listening, args=[id])
    #             [fRun, sc,   sfaddr,  sf,   t,    id]
    threads[id] = [True, stcp,  None,  None, tcplt, id]

    sudp = serverudp(mapperport)
    id += 1
    udpt = threading.Thread(target=recvThrFuUDP, args=[id]) 
    #             [fRun, sc,   addr,  sf,   t,   id]
    threads[id] = [True, sudp, None, None, udpt, id]

    tcplt.start()
    udpt.start()

    fRecvRunning = True
    while fRecvRunning:
        rawin = ''
        rawin = input().encode()
        print(rawin)
        if rawin == b'h':
            print(help)
        elif rawin == b'q':
            print("stopping connection")
            fRecvRunning = False
        elif rawin == b'p':
            print("Portlist: ")
            for e in portlist: print(e)
        elif rawin == b'r':
            print("Registry: ")
            for e in registry.items(): print(e)
        elif rawin == b't':
            print("Threads: ")
            for e in threads.items(): print(e)
        elif rawin == b's':
            dprint = silentprint
        elif rawin == b'd':
            dprint = print
        else : 
            print(help)

    for k,v in threads.items(): 
        fRun, sc, addr, sf, t, id = v
        print("Cleanup ending thread",id)
        threads[id][0] = False # set fRun to false so the thread will exit its loop
        try: 
            # sc.shutdown(socket.SHUT_WR)
            sc.close()
            #if sf: sf.shutdown(socket.SHUT_WR)
            if sf: sf.close()
        except Exception as e: 
            print(e)
            pass
        t.join()
        print("Cleanup ended Thread id:",id)
    print ("end")

if __name__== "__main__": 
    main()
