# PCAN Gateway Plugin Packages


Target Device :
 [PCAN-Ethernet Gateway](https://www.peak-system.com/PCAN-Ethernet-Gateway-FD-DR.538.0.html?&L=1) 

<br>

## PCAN-Ethernet Gateway Configuration

in [user manual](https://www.peak-system.com/produktcd/Pdf/English/PCAN-Ethernet-Gateway-FD-DR_UserMan_eng.pdf), custom gateway procol is presented.

in Route Configuration Page, add Routing IP Addresses both side(CAN->Ethernet, Ethernet->CAN)


<br>

## Install Plugin Package

```shell

# install from PyPI
$ pip3 install python-pcan-gatewaybus

or 

# local installation
$ git clone https://github.com/ys-oh/python-can-gatewaybus
$ cd python-can-gatewaybus
$ pip3 install . 

```



## Usage 


```python
import can

bus = can.Bus(bustype='gateway', channel='<local ip>:<local port>,<remote ip>:<remote port>')

...

```

or

```python
import can
can.rc['interface'] = 'gateway'
can.rc['channel'] = '<local ip>:<local port>,<remote ip>:<remote port>'

bus = can.Bus()

...

```

in 'channel' argument represent Route Addres in PCAN-Ethernet Gateway Routing Configurations.

<br>

<b>local address (ip:port)</b> 
- receive address from PCAN-Ethernet Gateway
- e.g. 192.168.1.1:4000

<br>

<b>remote address (ip:port)</b>
- transmit address to PCAN-Ethernet Gateway
- e.g. 192.168.1.10:3999 

<br><br>

if you config routing in Device (device ip : 192.168.1.1)

    Transmit Channel (CAN->Ethernet) : TCP, 192.168.1.1:3999
    Recieve Channle (Ethernet->CAN) : TCP, :4000


your channel is

    ...
    can.rc['channel'] = '192.168.1.1:3999,192.168.1.1:4000'
    ...


---