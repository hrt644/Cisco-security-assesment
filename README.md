# Cisco Configuration Assesment Tool
 This tool evaluate security assessment in Cisco Routers and Switches. The assessment includes:
 <ul>
 <li>IOS Version</li>
 <li>Time-out session</li>
 <li>Password Encryption</li>
 <li>Service Encryption</li>
 <li>SSH Version</li>
  <li>Port Security </li>
 <li>SSH Authetication</li>
 <li>SNMP </li>
 <li>Storm Control</li>
 <li>Http/Https </li>
  <li>DHCP Snooping </li>
 <li>ARP Snooping</li>
 <li>Default Vlan </li>
 </ul>


<h3>prerequisites:</h3>

1- Install python 3.7
    Download Python 3.7: https://www.python.org/downloads/
    
    
2- Install this command:   <b>pip install netmiko</b><br />
   For more information about netmiko refer to this link: https://pypi.org/project/netmiko/  <br />
   
3- set your device IP, usernamne, password and secret in route:
<br />
<pre>
router = {"device_type": "cisco_ios",
           "host": "192.168.0.10",
           "user": "hamid",
           "pass": "cisco",
           "secret":"cisco"
           }
</pre>   
   
