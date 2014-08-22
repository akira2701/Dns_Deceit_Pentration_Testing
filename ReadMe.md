# Dns Deceit Pentration Testing 
##Description
This program is designed to faking DNS answer packet.It sends RAW eth packet through netcard. And answering all DNS question packet by listening port 53. The IP address in the answer can be changed in the program.
##Dependence
*Windows only
*Winpcap driver 4.1.2 is required.
 And the developer pack of Winpcap is required to compile the program. The path of the pack should be designated in the project file._Known compatibility issues with Winpcap 4.1.3.
 *IPhelp API
 ##Lisence
 MIT