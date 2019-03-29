#Cisco security assessment tool
#Author: Hamidreza Talebi


from netmiko import ConnectHandler
from pprint import pprint

router = {"device_type": "cisco_ios",
           "host": "192.168.0.10",
           "user": "hamid",
           "pass": "cisco",
           "secret":"cisco"
           }


net_connect = ConnectHandler(ip=router["host"],
                             username=router["user"],
                             password=router["pass"],
                             device_type=router["device_type"],
                             secret=router["secret"])

net_connect.enable()

def VersionCheck():
    interface_cli = net_connect.send_command("show version | in Version")
    version= str(interface_cli).split(", ")[2].split(" ")[1].split(".")[0]
    if (version< "15"):
        print("--> You have to upgrade your IOS ")
    else:
        print("--> Your IOS version is " + version +" ** PASS! **")

def TimeoutCheck():
    interface_cli = net_connect.send_command("show run | in exec-timeout")
    if (interface_cli!=""):
        timeout= str(interface_cli).split(" ")[2]
        if(timeout!=""):
            if(timeout!="-1"):
                if (int(timeout)>0):
                    print("--> Your timeout is: " + timeout + " ** PASS! **") 
                else:
                    print("--> You should change your timeout to more than 0")
        else:
            print("--> You should change your timeout to more than 0")

    
def ServicePass():
     interface_cli = net_connect.send_command("sh run | in service password-encryption")
     if(interface_cli!=""):
         print("--> You have 'service password-encryption' ** PASS! **")
     else:
         print("--> Use this command: 'service password-encryption' to secure your password")

def UserPasswordCheck():
     interface_cli = net_connect.send_command("sh run | se username")
     if(interface_cli!=""):
         find_secret= str(interface_cli).split(" ")[2]
         print("--> You can use 'secret' command instead of 'password' to secure your username.\n\t\t Sample command < username YourUsername secret YourPassword > ")
     elif(find_secret=="secret"):
         print("--> Your username is using secret command ** PASS! **")
     else:
         print("--> You don't have any username in your device ** PASS! **")

def SSHVersionCheck():
    interface_cli = net_connect.send_command("sh run | in ip ssh version")
    if(interface_cli!=""):
        find_SSHVersion= str(interface_cli).split(" ")[3]
        if(find_SSHVersion=="2"):
            print("--> SSH version is 2.0  **  PASS! **")
        else:
            print("--> You have to upgrade your SSH to version 2.0. SSH 1.0 is not Secure")

def SSHTimeoutCheck():
    interface_cli = net_connect.send_command("sh run | in ip ssh time-out")
    if(interface_cli!=""):
        find_SSHTime= str(interface_cli).split(" ")[3]
        if(find_SSHTime!=""):
            print("--> SSH Timeout is set  **  PASS! **")
    else:
        print("--> You can set SSH timeout with this command \n\t\t <ip ssh time-out 60>")

def SSHAuthCheck():
    interface_cli = net_connect.send_command("sh run | in ip ssh authentication-retries")
    if(interface_cli!=""):
        find_SSHAuth= str(interface_cli).split(" ")[3]
        if(find_SSHAuth!=""):
            print("--> SSH auth-retries is set  **  PASS! **")
    else:
        print("--> You can set SSH authetication-retries with this command \n\t\t <ip ssh authentication-retries 5>")

def PortSecCheck():
    interface_cli = net_connect.send_command("sh run | in port-security")
    if(interface_cli!=""):
        print("--> port-security is set  **  PASS! **")
    else:
        print('''--> You can set Port-Security on your device 
        Sample Code:      
            Port-Security for Range of ports
            SW1(config)# int range fa0/1-24  
            SW1(config-if)# switchport mode access
            SW1(config-if)# switchport port-security maximum 2
            SW1(config-if)# switchport port-security voilation shutdown
            SW1(config-if)# switchport port-security
            =================================================
            Port-Security for one port with Secific MAC
            SW1(config)# int range fa0/1
            SW1(config-if)# switchport port-security mac-address 1000.2000.3000
            =================================================
            Port-Security with Auto Recovery
            SW1(config)# errdisable recovery cause psecure-violation
            SW1(config)# errdisable recovery interval 30


            ''')

def KeepaliveCheck():
    interface_cli = net_connect.send_command("sh run | in service tcp-keepalives-in")
    interface_cli2 = net_connect.send_command("sh run | in service tcp-keepalives-out")
    if(interface_cli!="" or interface_cli2!=""):
        print("--> Keep alive is set  **  PASS! **")
    else:
        print('''--> You can set keep alive to terminate incomplete session on your device 
        Sample Code:   
               SW1(config)# service tcp-keepalives-in
               SW1(config)# service tcp-keepalives-out  
         ''')
                              
def DefaultVlan1():
     interface_cli = net_connect.send_command("sh run | in vlan 1")
     if(interface_cli!=""):
         print("--> Vlan 1 is not used  **  PASS! **")
     else:
         print('''--> Try to use another Vlan number. Vlan 1 is a default Vlan and some attackers use this vlan
            to attack your device
            ''')
def SNMPCheck():
     interface_cli = net_connect.send_command("sh run | in snmp-server community")
     interface_cli_view = net_connect.send_command("sh run | in snmp-server view")
     if(interface_cli!=""):
         print("--> Upgrade your SNMP to Version 3")
     elif(interface_cli_view!=""):
         print('''--> Your device SNMP is Version 3  **  PASS! **

            ''')
     else:
         print(''' --> SNMP is not set on your device  **  PASS! **
            
            ''')

def IPVerifyCheck():
     interface_cli = net_connect.send_command("sh run | in ip verify source port-security")
     if(interface_cli!=""):
         print("--> ip verify source is set on your device **  PASS! **")
     else:
         print(''' --> To prevent IP Spoofing attack use this command in your interface
                    (config) # int gi0/0
                    (config-if)# ip verify source port-security
            ''')

def StormControlCheck():
     interface_cli = net_connect.send_command("sh run | in storm-control")
     if(interface_cli!=""):
         print("--> storm-control is set on your device **  PASS! **")
     else:
         print(''' --> To control Packets Flood  use this command in your interface
                    (config) # int gi0/0
                    (config-if)# storm-control broadcast level pps/bps 500(max) 100(min)
            ''')
def IPHttpHttpsCheck():
     interface_cli = net_connect.send_command("sh run | in ip http server")
     interface_cli_https = net_connect.send_command("sh run | in ip http secure-server")
     if(interface_cli!=""):
         find_no= str(interface_cli).split(" ")[0]
         if(find_no!="no"):
             print(''' --> Your device http (port 80) is enable. If you are not using it, 
                    We recommend disable it:
                    (config) # no ip http server        
            ''')
         else:
             print("--> http check **  PASS! **")

     elif(interface_cli_https!= ""):
         find_no= str(interface_cli_https).split(" ")[0]
         if(find_no!="no"):
             print(''' --> Your device https (port 443) is enable. If you are not using it, 
                    We recommend disable it:
                    (config) # no ip http secure-server
            ''')
         else:
             print("--> https check **  PASS! **")
     else:
         print("--> http/https check **  PASS! **")

def DHCPSnoopingCheck():
     interface_cli = net_connect.send_command("sh run | in dhcp snooping")
     if(interface_cli!=""):
         print('''--> DHCP Snooping is set on your device  **  PASS! **     
            ''')
     else:
          print('''--> DHCP Snooping is not set on your device:

          DHCP snooping acts like a firewall between untrusted hosts and trusted DHCP servers. DHCP snooping performs the following activities:
         -Validates DHCP messages received from untrusted sources and filters out invalid messages.
         -Builds and maintains the DHCP snooping binding database, which contains information about untrusted hosts with leased IP addresses.
         -Uses the DHCP snooping binding database to validate subsequent requests from untrusted hosts.
         
         For enabling DCHP Snooping:
         SW#config t
         SW(config)#ip dhcp snooping
         =======================================================
         For the Vlan
         SW#config t
         SW(config)#ip dhcp snooping vlan vlan-list

            ''')

def ARPSnoopingCheck():
     interface_cli = net_connect.send_command("sh run | in arp snooping")
     if(interface_cli!=""):
         print('''--> ARP Snooping is set on your device  **  PASS! **     
            ''')
     else:
          print('''--> ARP Snooping is not set on your device:
         For enabling ARP Snooping on vlan:
         SW#config t
         SW(config)#ip arp inspection vlan VlanID
         =======================================================
         For enabling on the interface
         SW(config)# int fa0/1
         SW(config)#ip arp inspection trust

            ''')
    


VersionCheck()
TimeoutCheck()
ServicePass()
UserPasswordCheck()
SSHVersionCheck()
SSHTimeoutCheck()
SSHAuthCheck()
PortSecCheck()
KeepaliveCheck()
DefaultVlan1()
SNMPCheck()
IPVerifyCheck()
StormControlCheck()
IPHttpHttpsCheck()
DHCPSnoopingCheck()
ARPSnoopingCheck()

