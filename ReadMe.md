# Dns Deceit Pentration Testing 
##Description
This program is designed to faking DNS answer packet.It sends RAW eth packet through netcard. And answering all DNS question packet by listening port 53. The IP address in the answer can be changed in the program.
##Dependence
*	Windows only
*	Winpcap driver 4.1.2 is required.
 And the developer pack of Winpcap is required to compile the program. The path of the pack should be designated in the project file._Known compatibility issues with Winpcap 4.1.3._
*	IPhelper API
##Usage
1.compile the program
2.write config_DNS.txt file in the same folder of the executable file. The first line of the file follow the rule of Winpcap filter file. And the second line is the IP address you want to wirte in the answer packet.Here is an example.
`ip proto udp and dst port 53 `
`192.168.1.1` 
3.run the program choose the netcard.
##Lisence
The program is under MIT lisence.