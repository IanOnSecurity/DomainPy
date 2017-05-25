#!/usr/bin/env python
#declare global variables
global hostingInfo
global registrantInformation
global showInformationDuringRunTime
#initialize global variables
hostingInfo={}
registrantInformation={}
showInformationDuringRunTime=0
#import sys for command-line arguments and access to std***
#import subprocess to access use of command-line  commands such as grep and host
import sys, re, time
from subprocess import PIPE, Popen, check_output



def userHandler(userInput):
	if userInput == 'c':
		p1=Popen("clear",shell=True)
		print "Please enter what you would like to do: "


def domainHandler(userInput='None',userFile='None'):
	nameList= []

	for i in range(len(sys.argv)):
		if sys.argv[i]=='-d':
			nameList.append(sys.argv[i+1])
		if sys.argv[i]=='-f' and '-c' in sys.argv:
			for j in range(len(sys.argv)):
				if sys.argv[j]=='-c':
					fileTitle=sys.argv[j+1]
					myFile = open(fileTitle,"r")
					continuedFile = myFile.readlines()
					myFile.close()

			for k in range(len(continuedFile)):
				if k == len(continuedFile)-1:
					nameList.append(continuedFile[k].split(","))
			print nameList
			fileTitle=sys.argv[k+1]
			myFile=open(fileTitle,'r')
			pickupFileContents=myFile.readlines()
			myFile.close()
                        for k in range(len(continuedFile)):
                                if k == len(continuedFile)-1:
                                        continuedFile[k].split(",")
					


		elif sys.argv[i] == '-f':
			fileTitle=sys.argv[i+1]
                        myFile = open(fileTitle,"r")
                        fileContents = myFile.readlines()
                        myFile.close()
                        for line in fileContents:
				nameList.append(line.strip())


	if userFile!='None':
		myFile = open(userFile,"r")
                fileContents = myFile.readlines()
                myFile.close()
                for line in fileContents:
                	nameList.append(line.strip())
		print "File Loaded."
	if userInput!='None':
		nameList.append(userInput)
	hostFunction(nameList)



#iterate through the domains, and find out the IP addresses that they are hosted at
def hostFunction(domainList):
	for domain in domainList:
		p3=Popen(["host","-t","a",domain],stdout=PIPE)
		hostingInfo[domain]=p3.communicate()[0]
		hostingInfo[domain]=hostingInfo[domain].rsplit(" ", 1)[-1].strip()
		domainString =str(domainList.index(domain))+", " +  domain + ', ' + hostingInfo[domain]+"\n"
		for arg in range(len(sys.argv)):
			if sys.argv[arg]=='-w':
				writeOutFile=open(sys.argv[arg+1],'a+')
				writeOutFile.write(domainString)
				writeOutFile.close()

#look through the definitions of the domains, strip out any extraneous characters, and run whois <domain> | grep <information>
def registrationDefiner():
	for domain in hostingInfo.keys():
	#whois 54.144.193.140 | egrep -n -m 5 "NetName|OrgName|CIDR|RegDate|Updated"
		p1=Popen(["whois", hostingInfo[domain]],stdout=PIPE)
		p2=Popen(["egrep","-i","netname|netrange|Orgname|CIDR|inetnum|mail|e-mail"], stdin=p1.stdout, stdout=PIPE)
		p1.stdout.close()
		registrantInformation[domain]=p2.communicate()[0].strip()
		domainString =str(hostingInfo.keys().index(domain)) + ", " + domain + ", " + registrantInformation[domain]+"\n"
		for arg in range(len(sys.argv)):
			if sys.argv[arg]=='-w' and '-ip' not in sys.argv:
				writeOutFile = open(sys.argv[arg+1],'a+')
				writeOutFile.write(domainString)
				writeOutFile.close()
#break out the registrant information into lists. using split to create the list for each domain, and to get rid of the newline character
def theFormatters():
	for domain in registrantInformation:
		registrantInformation[domain] = registrantInformation[domain].split("\n")

#for all of the domains, and the single registrant list, cut that ONE (1) list into many lists of: [field,value]
	for domain in hostingInfo:
		for i in range(len(registrantInformation[domain])):
			registrantInformation[domain][i] = registrantInformation[domain][i].split(":")

#some more testing lines below
#print registrantInformation
#print hostingInfo


#start trying to figure out how to handle non-resolving domains


def informationPrintout():
	domainCounter=0
	if showInformationDuringRunTime<=1:
		print "********~~~~~~~~********~~~~~~~~********"
	while True:
		for domain in registrantInformation:
			if showInformationDuringRunTime <=1:
				print "\n" + domain
			myLetterCheck = (hostingInfo[domain].isupper() or hostingInfo[domain].islower())
			#if hostingInfo[domain][0:2]=='2(':
			if myLetterCheck == True:
				if showInformationDuringRunTime <= 1:
					print "Here is why there is no hosted information found: " + hostingInfo[domain]
				domainCounter+=1
				continue
			else:
				if showInformationDuringRunTime <= 1 :
					print "This domain was found to be hosted at: " + hostingInfo[domain]
				for i in range(len(registrantInformation[domain])):
					lineInfo = ""
					for j in range(len(registrantInformation[domain][i])):
						lineInfo +=  registrantInformation[domain][i][j]
					if showInformationDuringRunTime == 0:
						print lineInfo
				domainCounter+=1
		if domainCounter == len(registrantInformation.keys()):
			break
	if showInformationDuringRunTime <= 1:
		print "\n********~~~~~~~~********~~~~~~~~********"


def statsFun():
	print "Number of domains: " + str(len(hostingInfo.keys()))
	domainWithIP = 0
	discoverIP = 0
	dinersIP = 0
	techAdminIP = 0
	registrantInfoString = ","
	for i in range(len(hostingInfo.keys())):
		for j in registrantInformation[hostingInfo.keys()[i]]:
			for k in j:
				registrantInfoString+=k+","
		domainReport=str(i+1) +","+hostingInfo.keys()[i] +","+hostingInfo[hostingInfo.keys()[i]]+","+registrantInfoString
		registrantInfoString=","
		print domainReport
		myIPCheck = (hostingInfo[hostingInfo.keys()[i]].isupper() or hostingInfo[hostingInfo.keys()[i]].islower())
		if myIPCheck==False:
			domainWithIP += 1
		if 'discover'.upper() in str(hostingInfo[hostingInfo.keys()[i]]) or 'discover' in str(hostingInfo[hostingInfo.keys()[i]]) or 'Discover' in str(hostingInfo[hostingInfo.keys()[i]]):
			discoverIP += 1
#	print "Number of domains that have (D|d)(iscover|ISCOVER) in the WHOIS record: " + str(discoverIP)
#	print "Number of domains that are hosted: " + str(domainWithIP)



def main():
	domainHandler()
        registrationDefiner()
        theFormatters()
#	print hostingInfo
#	print registrantInformation
        informationPrintout()

if '-cl' in sys.argv or 'command-line' in sys.argv:
	if '-ss' in sys.argv:
		showInformationDuringRunTime=2
	main()
	if '-qs' in sys.argv:
		statsFun()

while '-cl' not in sys.argv:

	interaction=raw_input("""
*********************************************
*    Welcome to my registration machine!    *
*Please specify a what you would like to do.*
*                                           *
* d - specify your domain                   *
* p - print current global variables        *
* r - run the program in full mode          *
* c - run the clear command-line argument   *
* v - show the whois information at runtime *
* s - hide the whois information at runtime *
* f - specify file for import               *
*                                           *
* qs - to show quickstats on domains        *
* quit - turn off the program               *
*********************************************

Select: """
)

	if interaction=='c':
		userHandler(interaction)
		continue
	elif interaction=="" or interaction=='quit' or interaction=='exit':
		break

	elif interaction=='d' or interaction=='domain':
		interaction=raw_input("What domain would you like to search: ")
		domainHandler(interaction)

	elif interaction=='p' or interaction=='print':
		print hostingInfo
		print registrantInformation

	elif interaction=='run' or interaction=='r':
		main()

	elif interaction=='file' or interaction=='f':
		fileName = raw_input("Please specify a file: ")
		domainHandler(userInput='None',userFile=fileName)

	elif interaction=='stats' or interaction=='qs' or '-qs' in sys.argv:
		statsFun()

	elif interaction=='verbose' or interaction=='v':
		if showInformationDuringRunTime > 0 :
			print "Whois information will be shown during runtime."
			showInformationDuringRunTime=0
		else:
			print "Whois information was already being shown."

	elif interaction=='suppress' or interaction=='s':
		if showInformationDuringRunTime == 0:
			print "Whois information will be suppressed during runtime."
			showInformationDuringRunTime=1
		elif showInformationDuringRunTime == 2:
			print "Whois information will be shown, minimally."
			showInformationDuringRunTime=1
		else:
			print "Whois information was already suppressed."
	elif interaction=='silence' or interaction=='ss' or '-ss' in sys.argv:
		if '-ss' in sys.argv:
			showInformationDuringRunTime = 2
		elif showInformationDuringRunTime<2:
			print "All runtime information will be silenced."
			showInformationDuringRunTime=2
		else:
			print "Runtime output has already been silenced."
	else:
		print "That was not a working input, please see menu for more options."
