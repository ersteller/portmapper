# Portmapper
Portmapper implementation in python for use in docker containers

This Implementation aims to replace an existing portmapper and may help to containerize. 
Portmappers gennerally have nondeterministic service ports for registered programs. 
This makes port mapping difficult and impossible in docker on windows. 

This implemetation is partly reverse engeneered from a portmapper environment. 

It handles RPC procedures: getport, set, unset. 

It is mostly a prove of concept for a generic solution that allows to run applications which rely on a portmapper to be containerized for linux and windows. 

## Requirements
`pip install dpkt`

## Configuration
There are only a few config options. 
```
##########  configuration  ##########
mapperport    = 111
proxyport     = 8738         # 0x2222
maxproxyports = 32
#####################################
```
* mapperport    is the port a port mapper service is expected to run. 
* proxyport     is the start port of a range of mappable ports used for exposing the mapped service. 
* maxproxyports is the number of paralell registered services and marks the length of the proxyport range. 

## TODOs:
* proxy ports as a command line argument
* improve error handling
* Make functions for registry and threads manipulation
* Cleanup dead threads
* RPC Version is not checked
* Maybe use select and non blocking socket send recv

## Notes: 
On Docker Desktop (windows 10 WSL2) seems to be port 111 already in use by docker. 

```bash
$ docker run -it -p 111:111 ubuntu
docker: Error response from daemon: driver failed programming external connectivity on endpoint romantic_feynman (043adc0da496b74650d26611b08e118004ab62a5b541a64061240d26a255ab76): listen tcp4 0.0.0.0:111: bind: address already in use.
ERRO[0001] error waiting for container: context canceled
```
We can use the port by binding the port with the public ip of the machine. 

### WSL example container run command
```
docker run -p 10.158.101.108:111:111/tcp -p 10.158.101.108:111:111/udp -p8738-8770:8738-8770  -it -v"$(pwd)":/host/scm -v ~/.ssh/id_rsa:/home/builduser/.my-key:ro --rm --name buildimage buildimage ssh-agent bash -c "ssh-add ~/.my-key; bash"
docker exec -it buildimage python3 scm/portmapper.py 
```
​
