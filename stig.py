#!/usr/bin/python
#!/usr/bin/env python

###########################################################################################################


# stig.py
#
# Copyright (c) 2012, 2016, Oracle and/or its affiliates. All rights reserved.
#
# NAME
#      stig.py - <one-line expansion of the name>
#
# DESCRIPTION
#      <short description of component this file declares/defines>
#
# NOTES
#      -> This script can only be run by root user 
#      -> This script will harden OS configuration files. It has following option:
#      *  help  : Display help message"
#      *  check : Check for presence of STIG violations within the system"
#      *  fix   : Fixes STIG violations reported by check option"
#      *  force : Force can be used only with fix option. It force script to rerun again
#                 even if it had already ran in the past on the system"
#      *  enable: Enables SSH root login
#      *  disable:Disables SSH root login

#      Every run of script generate a log file in dir /opt/oracle/oak/log/nodename/stig/
#      The log for check is created at /opt/oracle/oak/log directory
#      The log for fix   is created at /opt/oracle/oak/log directory
	# 12.1.2.8
	# Fixed Disable / Enable SSH issues
	# Added 'stig.py fix rollback'
	# Added 'stig.py fix restore_prev'
	# Implementing Rollback at files level for the system files before STIG fix vulnerabilities are executed
	# Implemented Restore previous fix run state
	# 12.1.2.7
	# 68 new OL6 Enhancements Added
	# Following were done for 12.1.2.6
	# OL6 Migration, Fix GEN000800, All bugs reported for OL6 migration
	# ---------------------------------------------------------------------------
	# Following were done for 12.1.2.4
	# Creation of stig.log - to include LOG/TRACING of commands
	# Creation of STIG options in sync with other ODA commands interface
	# Fix issue with validating invalid accounts, version control, 
	# Enhancement: 21078550 : MAKE STIG SCRIPT FLEXIBLE 
	# Disable max login for 14 character/set to 8
	# Enable Tracing and Logging
	# STIGID : GEN001210, 1270,1290, 1310, 1361, 1369, 1374, 1390, 1394  
	# STIGID : GEN001430, 1590, 1730, 1810, 2230
	# Password Echo
	# ---------------------------------------------------------------------------
	# Following were done for 12.1.2.3
	# Bug fix    :  Issue with maxlogin message
	# Bug fix    :	Issue in changing directory permissions for tuple list
	# 		STIG Version Number,Check_Dir, Find_UID
	#		File check status
	# OL Chnages : STIGID : LNX00800, LNX00720, LNX00660, LNX00640, LNX00620 
	# OL Chnages : STIGID : LNX00500, LNX00480, LNX00440, LNX00420, LNX00400 
	# OL Chnages : STIGID : LNX00320(reboot), GEN003080-2 
	# OL Changes : STIGID : 1368, LNX001431, LNX001432, LNX001433, 
	# OL Changes : STIGID : 1200, 1300, 1362, 1364
	# OL Changes : STIGID :  800,  850,  880,  900
	# OL Changes : STIGID : 1120, 1190
	# OL Bug fix : 11-Jan-2015
	# Following were done for 12.1.2.2
	# OL Changes - Login checks, GID ref checks
	# OL Changes - OEL support,ACL check, Duplicate username/UID check
	# OL Changes - set maxloging		: 17-Dec-2014
	# RHEL enhancements enhancements	: 15-Dec-2014
###########################################################################################################

# Global Variables
Major			= '12.1.2'
Minor			= '10'
Period			= '.'
STIG_SCRIPT_VERSION 	= ' '
STIG_Log_File		= ' '
Log_Dir			= '/opt/oracle/oak/log'
G_Count			= 0
AUDIT_RULE_SET		= 0
#Log_Dir			= '/scratch/mrvachar/view_storage/mrvachar_mrvachar/oak/src/stig/log'
is_VM			= 0
RESTART_INITTAB		= 0
RESTART_SENDMAIL	= 0
RESTART_SSHD		= 0
RESTART_OAKD		= 0
REEXAMINE_INITTAB	= 0
PARAM_VALUE 		= 0
GRUB_CONF		= ' '
pattern_Present		= 0
pattern_Absent		= 0
pattern_Commented 	= 0
Host_Name		= ''
exists_flag		= False
check_num_violations	= 0
num_violations_fixed	= 0
ol6_Flag		= 'FALSE'
check_command_Count 	= 0
#Import Libraries/Modules
####   The oda_perror module is for enabling ODA specific error messages in Oracle Standard format
#import oda_perror

# Import standard python libraries
import subprocess
import sys
import socket
import time
import datetime
import os
import fnmatch
import commands
# from stig_include import Get_Sysctl_Parameter_Value
#######################################################################################
# Function to display the STIG Usage
def Stig_Check_Usage():
	subprocess.call(['tput', 'setaf', '4'])
	print	'\n\tUsage for STIG with check option:\n'
	print	'\t------------------------------------------------------------------------------------------------------------------\n'
	print	'\t-h | -? | -help\t	: Provides help for STIG scripts for options with check'
	print
	print	'\tall\t		: Checks and informs the security vulnerability for all deployed'
	print 
	print	'\tperm\t		: Checks and informs the security vulnerability for all permissions classification deployed'
	print 
	print	'\tconf\t		: Checks and informs the security vulnerability for all configuration parameters classification deployed'
	print 
	print	'\taudit\t		: Checks and informs the security vulnerability for all auditing classifications deployed'
	print 
	print	'\taccount\t		: Checks and informs the security vulnerability for all accounts classification deployed'
	print 
	print	'\tfs\t		: Checks and informs the security vulnerability for all file systems classification deployed'
	print
	print	'\tgrub\t		: Checks and informs the security vulnerability for enable/disable of grub password deployed'
	print 
	print	'\taccess\t		: Checks and informs the security vulnerability for all access classifications deployed'
	print 
	print	'\t------------------------------------------------------------------------------------------------------------------\n'
	subprocess.call(['tput', 'sgr0'])

def Stig_Fix_Usage():
	subprocess.call(['tput', 'setaf', '4'])
	print	'\n\tUsage for STIG with fix option:'
	print	'\t------------------------------------------------------------------------------------------------------------------\n'
	print	'\t-h | -? | -help\t	: Provides help regarding options with fix'
	print
	print	'\tall\t		: Fixes and informs the security vulnerability for all'
	print
	print	'\tperm\t		: Fixes and informs the security vulnerability for all permissions classification deployed'
	print 
	print	'\tconf\t		: Fixes and informs the security vulnerability for all configuration parameters classification deployed'
	print 
	print	'\taudit\t		: Fixes and informs the security vulnerability for all auditing classifications deployed'
	print 
	print	'\taccount\t		: Fixes and informs the security vulnerability for all accounts classification deployed'
	print 
	print	'\tfs\t		: Fixes and informs the security vulnerability for all file systems classification deployed'
	print
	print	'\tgrub\t		: Fixes and informs the security vulnerability for enable/disable of grub password deployed'
	print 
	print	'\taccess\t		: Fixes and informs the security vulnerability for all access classifications deployed'
	print 
	print	'\tforce\t		: Enables rerun of the script for security vulnerability fix for all classifications '
	print	'				  This option must be exercised along with fix option only'
	print
	print   '\trollback\t	: Gets the system files at System Imaged (without stig modifications) state'
	print 	'				  This option must be exercised along with fix option only'
	print
	print   '\trestore_prev\t	: Gets the system files state the files prior to previous security vulnerability fix'
	print 	'				  This option must be exercised along with fix option only'
	print
	print	'\t------------------------------------------------------------------------------------------------------------------\n'
	subprocess.call(['tput', 'sgr0'])
	
def Stig_Usage():
	#global ODA_Print_Error(*Variable_Args)
	subprocess.call(['tput', 'setaf', '4'])
	print	'\n\tUsage for STIG (Security Technical Implementation Guide):\n'
	print	'\t------------------------------------------------------------------------------------------------------------------\n'
	print	'\tSTIG checks and corrects violations within Oracle Database Appliance'
	print
	print	'\t<First Parameter>       : -h | -? | -help | -v | -V | -version | check | fix | enable | disable'
	print
	print	'\t<Second Parameter>      : all | force | perm | conf | account | fs | access | grub | audit | rollback | restore_prev' 
	print
	print	'\tExample                 : ./stig.py <First Parameter> <Second Parameter> ' 
	print
	print	'\tSTIG script Parameter Information:' 
	print	'\t---------------------------------' 
	print
	print	'\t-h                      : Provides information regarding STIG scripts'
	print
	print	'\t-v                      : Provides STIG script version information'
	print
	print	'\tenable                  : Enables direct ssh root login on the system'
	print
	print	'\tdisable                 : Disables direct ssh root login on the system'
	print
	print	'\tcheck                   : Checks and lists the STIG violations on the system'
	print	'\tcheck -h                : Provides options help available with check'
	print
	print	'\tfix                     : Fixes or Corrects the STIG violations reported on the system'
	print	'\tfix -h                  : Provides options help  available with fix'
	print
	print	'\t------------------------------------------------------------------------------------------------------------------\n'
	####   The oda_perror module : To invoke 
	#oda_perror.ODA_Print_Error(50000)
	subprocess.call(['tput', 'sgr0'])

# Function to error out if the user has supplied incorrect arguments

def Invalid_Arguments(argv):

	Display_STIG_Script_Version()
	subprocess.call(['tput', 'setaf', '4'])
	print	'\n'
	#oda_perror.ODA_Print_Error(50001)
	subprocess.call(['tput', 'sgr0'])
	print
	if (argv[1] == 'check'):
		Stig_Check_Usage()
		sys.exit(0)
	if (argv[1] == 'fix'):
		Stig_Fix_Usage()
		sys.exit(0)
		
	if ((argv[1] == 'check') and ((argv[2] == '-h') or (argv[2] == '-help') or (argv[2] == '-?') or (argv[2] == '?'))):
		Stig_Check_Usage()
	elif ((argv[1] == 'fix') and ((argv[2] == '-h') or (argv[2] == '-help') or (argv[2] == '-?') or (argv[2] == '?'))):
		Stig_Fix_Usage()
	elif ((argv[1] == 'fix') and ((argv[2] != 'force') and (argv[2] != '-h') and (argv[2] != '-help') and (argv[2] != '-?') and (argv[2] != '?') and (argv[2] != '-H') and  (argv[2] != '-all') and (argv[2] != 'perm') and (argv[2] != 'conf') and (argv[2] != 'account') and (argv[2] != 'fs') and (argv[2] != 'grub') and (argv[2] != 'audit') and (argv[2] != 'access') and (argv[2] != 'rollback') and (argv[2] != 'restore_prev'))):
		Stig_Fix_Usage()
	elif ((argv[1] == 'check') and ((argv[2] != '-h') and (argv[2] != '-help') and (argv[2] != '-?') and (argv[2] != '?') and (argv[2] != '-H') and  (argv[2] != 'all') and (argv[2] != 'perm') and (argv[2] != 'conf') and (argv[2] != 'account') and (argv[2] != 'fs') and (argv[2] != 'grub') and (argv[2] != 'audit') and (argv[2] != 'access'))):
		Stig_Check_Usage()
	else:
		Stig_Usage()
	sys.exit(0)

# Function to check if you are executing the STIG Script in Dom0 or Dom1
# IF Dom0 - Do not execute the STIG script
# IF Dom1 - Execute the STIG script

def Check_If_VM_Dom0():
	
	global is_VM
	HYPERVISORUUID =	'/sys/hypervisor/uuid'
	if os.path.exists(HYPERVISORUUID) == True:
		cat_Cmd = 'cat ' + HYPERVISORUUID + ' | grep -q "0000-0000-0000"'
		check = os.system(cat_Cmd)
		if check == 0:
			print '\tINFO: You are within Dom0 environment, Exiting....execute STIG scripts from Dom1'
			#oda_perror.ODA_Print_Error(50002)
			sys.exit(0)
		else:
			is_VM = 1

# Function to set the STIG Script version
# We need to provide an interface to change the script version 
# The variable STIG_SCRIPT_VERSION is global

def Set_STIG_Script_Version():

	global STIG_SCRIPT_VERSION
	STIG_SCRIPT_VERSION=Major+Period+Minor
 	#print STIG_SCRIPT_VERSION	
 	return  STIG_SCRIPT_VERSION	

# Function to display the STIG Script version

def Display_STIG_Script_Version():
	global STIG_SCRIPT_VERSION
	print
	subprocess.call(['tput', 'setaf', '4'])
 	print '\tINFO: STIG Version is -> %s ' % STIG_SCRIPT_VERSION	
	subprocess.call(['tput', 'sgr0'])

# Function to get the host name on which the stig script will be run

def Get_Host_Name():

	global Log_Dir
	global Host_Name
	#Host_Name = socket.gethostbyaddr(socket.gethostname())
	Host_Name = str.lower(socket.gethostname())
	#print Host_Name
	Log_Dir = Log_Dir+'/'+Host_Name+'/stig/'
	#print '\tThe STIG Log Directory is :  ', Log_Dir
	return (Log_Dir, Host_Name)

# Function to display the STIG Script message 

def Display_STIG_Script_Msg(argv):

	global STIG_Log_File	
	subprocess.call(['tput', 'setaf', '4'])
	global Log_Dir	
	try:
		fptr = open(STIG_Log_File, 'w') 
		Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
		Write_To_File_Str = Date_Str + ' ' + ' : \t: Running STIG Script Version ' + STIG_SCRIPT_VERSION

		print '\n\tINFO: Writing to STIG Log file %s ' % STIG_Log_File 
		print '\n\tINFO: Running STIG Script Version %s  ' % STIG_SCRIPT_VERSION

		fptr.write(Write_To_File_Str + '\n\n')
		fptr.close()

	except IOError:
		#oda_perror.ODA_Print_Error(50003)
		return

	except:
		#oda_perror.ODA_Print_Error(50003)
    		raise
		return

	subprocess.call(['tput', 'sgr0'])

	
# Function to Create the STIG Log Directory for Check and Fix

def Create_STIG_Log_Dir(argv):

	if ((argv == 'check') or (argv == 'fix')):
		d =  os.path.dirname(Log_Dir)
		if not os.path.exists(d):
			os.makedirs(d)  # The user has to be root to be successful
			#print 'log dir created'
			#print Log_Dir

# This function is used to fix the STIG Violation
def Fix_STIG_Violations(argv):

	global GRUB_CONF
	global RESTART_OAKD
	global pattern_Commented
	global AUDIT_RULE_SET

	subprocess.call(['tput', 'setaf', '4'])

	#Set_Tracing_Commands_File(argv)

	print
	print '\tINFO: Fixing STIG Violations ........ \n'
	print
	print_Str = '\n' + '\n=========================Executing the command : stig.py fix <options> ==============================================\n' 
	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	print_Str = '\n' + '\nLOGGING OF STIG FIX STATUS AND TRACING OF COMMANDS EXECUTED TO FIX THE STIG VULNERABILITIES : '+ Date_Str + '\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	print_Str = '\n' + '\n=====================================================================================================================\n\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)

	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	UName = 'uname -n'
	q=subprocess.Popen(UName, shell=True, stdout=subprocess.PIPE)
	uname_Code = (q.communicate())[0]
	print_Str = Date_Str + '  : Fixing the STIG Violations which were reported through fix option on the system ' + uname_Code
        Cmd = 'printf ' +  '"'+print_Str+'"'  + ' | ' + 'tee -a ' + " >> " + STIG_Log_File 
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	Code = r.communicate()[0]
	if Code < 0:
		#oda_perror.ODA_Print_Error(50004)
		print 'Update to STIG Log file could not be made...error writing to the file'
	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	print_Str = '\n'+Date_Str + '  : The following details can also be found on the file '+'\n'
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File 
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	print_Str = '\n'+Date_Str + '  : List of STIG Violations fixed by the script are ...' +'\n\n'
        Cmd = 'printf ' +  '"'+print_Str+'"'  + ' | ' + 'tee -a ' +  " >> " + STIG_Log_File 
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)

  	# Set font to normal
	subprocess.call(['tput', 'sgr0'])

  	# Set path for grub.conf file
	Set_Grub_Conf_File_Name()
	# Take backup of all the configuration files which will be modified by the script

	#Take_Conf_File_Backup()

	Check_OL6()

	do_All = ''
	num_Args = len(argv)

	if (num_Args == 3):
		if (argv[2] == 'force' or argv[2] == 'all'):
			do_All = 'all'

	if (num_Args == 2):
		do_All = 'all';

	if (do_All == 'all' or argv[2] == 'grub'):	
  		INFO="Enable password for grub"
  		STIG_ID="LNX00140"
		file_Name=GRUB_CONF
  		Enable_Grub_Password(file_Name, STIG_ID, INFO)	
	
	# FIX all configuration related Security vulnerabilities
	if(do_All == 'all' or argv[2] == 'conf'):

  		INFO="The IPv6 protocol is disabled"
 		STIG_ID="OL6-00-000098"
		file_Name='/etc/modprobe.d/modprobe.conf'
  		Comment_Line_Matching_Pattern("^[[:space:]]*net.ipv6.conf.all.disable_ipv6",'/etc/sysctl.conf', STIG_ID, "") 
  		Comment_Line_Matching_Pattern("^[[:space:]]*net.ipv6.conf.default.disable_ipv6", '/etc/sysctl.conf', STIG_ID, "") 
		Check_Pattern_Presence_In_File("options.*ipv6.*disable=1",file_Name)
		if not pattern_Present:
	  		Insert_New_Line_In_File("options*ipv6" ,"options ipv6 disable=1", file_Name,STIG_ID, INFO)
	
 		INFO="The timeout interval for SSH idle daemon set to correct value"
  		STIG_ID="OL6-00-000230"
		file_Name = '/etc/ssh/sshd_config'
		Get_Parameter_Value("^[[:space:]]*ClientAliveInterval[[:space:]]+", file_Name, "2") 
		if PARAM_VALUE  < 900:
			Comment_Line_Matching_Pattern("^[[:space:]]*ClientAliveInterval.*",file_Name, STIG_ID, "")
	  		Insert_New_Line_In_File("^[[:space:]]*ClientAliveInterval.*" ,"ClientAliveInterval  900", file_Name,STIG_ID, INFO)
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")
 		INFO="The timeout count for SSH idle daemon set to zero"
  		STIG_ID="OL6-00-000231"
		file_Name = '/etc/ssh/sshd_config'
		Get_Parameter_Value("^[[:space:]]*ClientAliveCountMax[[:space:]]+", file_Name, "2") 
		if PARAM_VALUE  != 0:
			Comment_Line_Matching_Pattern("^[[:space:]]*ClientAliveCountMax.*",file_Name, STIG_ID, "")
	  		Insert_New_Line_In_File("^[[:space:]]*ClientAliveCountMax.*" ,"ClientAliveCountMax  0", file_Name,STIG_ID, INFO)
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")

  		INFO="Disable SSH daemon user environment settings"
  		STIG_ID="OL6-00-000241"
       		file_Name="/etc/ssh/sshd_config" 
  		Modify_Parameter_In_File("^[[:space:]]*", "PermitUserEnvironment","no", file_Name, STIG_ID, INFO) 

		INFO="System does not permit interactive boot"
		STIG_ID="OL6-00-000070"
		file_Name='/etc/sysconfig/init'
  		Check_Pattern_Presence_In_File( '^[[:space:]]*PROMPT=no',file_Name)
		if not pattern_Present:
			sed_Cmd = "sed -i -e 's/PROMPT=yes/PROMPT=no/g'" + ' ' + file_Name 
			Fix = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE)
			Fix1 = Fix.communicate()[0]
			if Fix1 > 0:
                		Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
			else:
                		Log_Info ("True", STIG_ID, INFO, "FAILED")
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")

  		INFO="Installing screen rpm on the system"
  		STIG_ID="OL6-00-000071"
  		Install_RPM("screen", STIG_ID, INFO)

		INFO="xinetd service is disabled"
		STIG_ID="OL6-00-000203"
		Out1 = 0
		Out2 = 0
		Out_A = 0
		Out_B = 0
		#Previous_Success = 0
		if (os.path.exists('/etc/init.d/xinetd') == True):
			Out_Check = subprocess.Popen("chkconfig xinetd --list", shell=True, stdout=subprocess.PIPE)
			Out_A = Out_Check.communicate()[0].find('on')
			if Out_A > 0:
				Out_Check1 = subprocess.Popen("chkconfig xinetd off", shell=True, stdout=subprocess.PIPE)
				Out1 = Out_Check1.communicate()[0].find('on')
				if Out1 < 0:
                			Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
					#Previous_Success=1
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")
		
		'''
		Out_Check = subprocess.Popen("service xinetd status", shell=True, stdout=subprocess.PIPE)
		Out_B = Out_Check.communicate()[0].find('running')
		if Out_B > 0:
			Out_Check2 = subprocess.Popen("service xinetd stop", shell=True, stdout=subprocess.PIPE)
			Out2 = Out_Check2.communicate()[0].find('running')
			if Out2 < 0 or Previous_Success == 1:
                		Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")
		'''

		INFO="atd service is disabled"
		STIG_ID="OL6-00-000262"
		Out1 = 0
		Out2 = 0
		Out_A = 0
		Out_B = 0
		Previous_Success = 0
		Out_Check = subprocess.Popen("chkconfig atd --list", shell=True, stdout=subprocess.PIPE)
		Out_A = Out_Check.communicate()[0].find('on')
		if Out_A > 0:
			Out_Check1 = subprocess.Popen("chkconfig atd off", shell=True, stdout=subprocess.PIPE)
			Out1 = Out_Check1.communicate()[0].find('on')
			if Out1 < 0:
				Previous_Success=1
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")
		Out_Check = subprocess.Popen("service atd status", shell=True, stdout=subprocess.PIPE)
		Out_B = Out_Check.communicate()[0].find('running')
		if Out_B > 0:
			Out_Check2 = subprocess.Popen("service atd stop", shell=True, stdout=subprocess.PIPE)
			Out2 = Out_Check2.communicate()[0].find('running')
			if Out2 < 0 or Previous_Success == 1:
                		Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")

		INFO="ntpdate service is disabled"
		STIG_ID="OL6-00-000265"
		Out1 = 0
		Out2 = 0
		Out_A = 0
		Out_B = 0
		Previous_Success = 0
		Out_Check = subprocess.Popen("chkconfig ntpdate --list", shell=True, stdout=subprocess.PIPE)
		Out_A = Out_Check.communicate()[0].find('on')
		if Out_A > 0:
			Out_Check1 = subprocess.Popen("chkconfig ntpdate off", shell=True, stdout=subprocess.PIPE)
			Out1 = Out_Check1.communicate()[0].find('on')
			if Out1 < 0:
				Previous_Success=1
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")
		Out_Check = subprocess.Popen("service ntpdate status", shell=True, stdout=subprocess.PIPE)
		Out_B = Out_Check.communicate()[0].find('running')
		if Out_B > 0:
			Out_Check2 = subprocess.Popen("service ntpdate stop", shell=True, stdout=subprocess.PIPE)
			Out2 = Out_Check2.communicate()[0].find('running')
			if Out2 < 0 or Previous_Success == 1:
                		Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")

		INFO="System is configured with SMB client for connecting to samba client"
		STIG_ID="OL6-00-000272"
		file_Name='/etc/samba/smb.conf'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*client.*signing.*=.*mandatory", file_Name) 
		if not pattern_Present:
  			Insert_New_Line_In_File ("^[[:space:]]*client.*signing.*=.*mandatory", "client signing = mandatory", file_Name, STIG_ID, INFO) 

		INFO="postfix service is enabled"
		STIG_ID="OL6-00-000287"
		Out_Check = subprocess.Popen("service postfix status", shell=True, stdout=subprocess.PIPE)
		time.sleep(2)
		Out_B = Out_Check.communicate()[0].find('stopped')
		if Out_B >= 0:
			Out_Check2 = subprocess.Popen("service postfix start", shell=True, stdout=subprocess.PIPE)
			Out2 = Out_Check2.communicate()[0].find('running')
			if Out2 >=  0:
                		Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
		else:
                	Log_Info ("True", STIG_ID, INFO, "ALREADY DONE")

		INFO="Process core dumps are not disabled"
		STIG_ID="OL6-00-000308"
		file_Name='/etc/security/limits.conf'
  		Check_Pattern_Presence_In_File( '^[[:space:]]*.*hard.*core.*0',file_Name)
		if not pattern_Present:
  			Insert_New_Line_In_File ("^[[:space:]]*hard.*core.*0", "*  hard  core  0 ", file_Name, STIG_ID, INFO) 

		INFO="Account inactivity is set to appropriate value"
		STIG_ID="OL6-00-000334-5"
		file_Name='/etc/default/useradd'
  		Check_Pattern_Presence_In_File( '^[[:space:]]*INACTIVE=35',file_Name)
		if not pattern_Present:
  			Comment_Line_Matching_Pattern ("^[[:space:]]*INACTIVE=.*", file_Name, STIG_ID, INFO) 
  			Insert_New_Line_In_File ("^[[:space:]]*INACTIVE=.*", "INACTIVE=35", file_Name, STIG_ID, INFO) 
		# The STIGs 342,343,344 are commented for the issues pertaining to SSH
		'''
		INFO="The umask for bash shell is set to appropriate value"
		STIG_ID="OL6-00-000342"
  		Check_Pattern_Presence_In_File ("^[[:space:]]*umask.*077", '/etc/bashrc') 
		if not pattern_Present:
  			Insert_New_Line_In_File ("^[[:space:]]*umask.*077", "umask 077", '/etc/bashrc', STIG_ID, INFO) 

		INFO="The umask for csh shell is set to appropriate value"
		STIG_ID="OL6-00-000343"
  		Check_Pattern_Presence_In_File ("^[[:space:]]*umask.*077", '/etc/csh.cshrc') 
		if not pattern_Present:
  			Insert_New_Line_In_File ("^[[:space:]]*umask.*077", "umask 077", '/etc/csh.cshrc', STIG_ID, INFO) 

		INFO="The umask for /etc/profile is set to appropriate value"
		STIG_ID="OL6-00-000344"
  		Check_Pattern_Presence_In_File ("^[[:space:]]*umask.*077", '/etc/profile') 
		if not pattern_Present:
  			Insert_New_Line_In_File ("^[[:space:]]*umask.*077", "umask 077", '/etc/profile', STIG_ID, INFO) 
		'''

		# The STIG IDs OL6-00-000357 and OL6-00-000372 are commented as they
		# causing failures to create database and dbstorage in 12.1.2.7
		''' Begin Comment
		global G_Count
		INFO="Excessive login failures beyond 15 minute interval is disabled"
		STIG_ID="OL6-00-000357"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*auth.*required.*fail_interval*", file_Name) 
		if not pattern_Present:
			# For Before, it is set to 0
			# For After, it is set to 1
			Insert_Before_Or_After_the_Match("auth.*sufficient.*pam_unix.so.*", 'auth        required      pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900', file_Name, STIG_ID, INFO, 0)
			Insert_Before_Or_After_the_Match("auth.*sufficient.*pam_unix.so.*", 'auth        [default=die]  pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900', file_Name, STIG_ID, INFO, 1)
			Insert_Before_Or_After_the_Match("account.*required.*pam_unix.so.*", 'account      required      pam_faillock.so', file_Name, STIG_ID, INFO, 1)
			Insert_Before_Or_After_the_Match("auth.*sufficient.*pam_unix.so.*", 'auth        required      pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900', "/etc/pam.d/password-auth", STIG_ID, INFO, 0)
			Insert_Before_Or_After_the_Match("auth.*sufficient.*pam_unix.so.*", 'auth        [default=die]  pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900', "/etc/pam.d/password-auth", STIG_ID, INFO, 1)
			Insert_Before_Or_After_the_Match("account.*required.*pam_unix.so.*", 'account      required      pam_faillock.so', "/etc/pam.d/password-auth", STIG_ID, INFO, 1)
			if G_Count == 6:
                		Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
        		else:
                		Log_Info ("True", STIG_ID, INFO, "FAILED")

		#	else:
  		#Modify_Parameter_In_File ("^[[:space:]]*", "fail_interval", "900", file_Name, STIG_ID, INFO)
		G_Count = 0
		INFO="OS is configured to log unsuccessful logon/access"
		STIG_ID="OL6-00-000372"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Presence_In_File( 'pam_lastlog.so',file_Name)
		if not pattern_Present:
			Insert_Before_Or_After_the_Match("session.*required.*pam_limits.so.*", 'session	required	pam_lastlog.so showfailed', file_Name, STIG_ID, INFO, 1)
			if G_Count == 1:
                		Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
        		else:
                		Log_Info ("True", STIG_ID, INFO, "FAILED")
		End Comment'''
		# End of comments for 12.1.2.7

		INFO="The /etc/security/opasswd file created"
		STIG_ID="GEN000800"
		if (os.path.exists('/etc/security/opasswd')==False):
			os.system('touch /etc/security/opasswd')
			os.system('chown root:root /etc/security/opasswd')
			os.system('chmod 600 /etc/security/opasswd')
                	Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")
			write_to_Check_Tracing('Created /etc/security/opasswd with owner as "root" with 0600 permission',0)
		else:
			os.system('chown root:root /etc/security/opasswd')
			os.system('chmod 600 /etc/security/opasswd')
                	Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			write_to_Check_Tracing('File /etc/security/opasswd owner is changed to "root" with 0600 permission',0)

		'''	
		INFO="Global settings in system-auth are  applied in the pam.d definition files"
		STIG_ID="GEN000600-2"
		if (os.path.exists('/etc/pam.d/system-auth')==True):
			path = os.path.islink('/etc/pam.d/system-auth') 
			if (path == False):
				os.symlink('/etc/pam.d/system-auth', 'system-auth-ac')
				if (os.path.islink('system-auth-ac')==True):
                			Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")
				else:
                			Log_Info('False', STIG_ID, INFO, "FAILED")
			else:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
		else:
			INFO="The global settings in /etc/pam.d/system-auth file are not created, contact System Administrators to correct security vulnerabilities"
                	Log_Info('False', STIG_ID, INFO, "FAILED")
		'''

		INFO="The maxlogin parameter is set to 10"
  		STIG_ID="GEN000450"
		file_Name='/etc/security/limits.conf'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*.*hard.*maxlogins.*10", file_Name) 
		if not pattern_Present:
  			Comment_Line_Matching_Pattern ("^[[:space:]]*.*hard.*maxlogins*", file_Name, STIG_ID, "The maxlogins parameter is not set to desired value, commenting it...") 
  			Insert_New_Line_In_File ("^[[:space:]]*.*hard.*maxlogins.*", "*  hard  maxlogins  10", file_Name, STIG_ID, INFO) 
		
		if (os.path.exists('/etc/ntp.conf')==True):
			FILES_LIST = ['/etc/ntp.conf', '/usr/sbin/sshd']
			INFO_LIST=[' time synchronization ', ' network service daemon ']
			STIG_ID_LIST = ['GEN000253','GEN001190'] 
		else:
			FILES_LIST = ['/usr/sbin/sshd']
			INFO_LIST=[' network service daemon ']
			STIG_ID_LIST = ['GEN001190'] 
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'fix')

		STIG_ID_LIST = ['GEN001210','GEN001210','GEN001210','GEN001210','GEN001210','GEN001210','GEN001210'] 
		FILES_LIST = ['/etc/','/bin/','/usr/bin/', '/usr/lbin','/usr/usb/', '/sbin','/usr/sbin']
		INFO_LIST = ['/etc/','/bin/','/usr/bin/', '/usr/lbin','/usr/usb/', '/sbin','/usr/sbin']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'fix')
		
		STIG_ID_LIST = ['GEN001270','GEN001290','GEN001290','GEN001290','GEN001310','GEN001310'] 
		FILES_LIST = ['/var/log/','/usr/share/man/','/usr/share/info/', '/usr/share/infopage/','/usr/lib/','/lib/']
		INFO_LIST = ['/var/log/','/usr/share/man/','/usr/share/info/', '/usr/share/infopage/','/usr/lib/','/lib/']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'fix')

		STIG_ID_LIST = ['GEN001361','GEN001365','GEN001369','GEN001374','GEN001390','GEN001394'] 
		FILES_LIST = ['/var/yp/','/etc/resolv.conf','/etc/hosts', '/etc/nsswitch.conf','/etc/passwd','/etc/group']
		INFO_LIST = ['/var/yp/','/etc/resolv.conf','/etc/hosts', '/etc/nsswitch.conf','/etc/passwd','/etc/group']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'fix')

		STIG_ID_LIST = ['GEN001430','GEN001590','GEN001590','GEN001810','GEN002230'] 
		FILES_LIST = ['/etc/shadow','/etc/rc*','/etc/init.d','/etc/skel','/etc/shells']
		INFO_LIST = ['/etc/shadow','/etc/rc*','/etc/init.d','/etc/skel','/etc/shells']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'fix')

		STIG_ID_LIST = ['GEN001730','GEN001730','GEN001730','GEN001730','GEN001730']
		FILES_LIST = ['/etc/bashrc','/etc/chs.cshrc','/etc/csh.login','/etc/csh.logout','/etc/environment']
		INFO_LIST = ['/etc/bashrc','/etc/chs.cshrc','/etc/csh.login','/etc/csh.logout','/etc/environment']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'fix')

		STIG_ID_LIST = ['GEN001730','GEN001730','GEN001730','GEN001730']
		FILES_LIST = ['/etc/ksh.kshrc','/etc/profile','/etc/suid_profile','/etc/profile.d/*']
		INFO_LIST = ['/etc/ksh.kshrc','/etc/profile','/etc/suid_profile','/etc/profile.d/*']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'fix')
	
		'''
		INFO="The ACL for time synchronization file is removed"
		STIG_ID="GEN000253"
		file_Name='/etc/ntp.conf'
		if (os.path.exists('/etc/ntp.conf')==True):
			Check_ACL_exist(file_Name)
			if exists_flag  == False:
				write_to_Check_Tracing('Verified : The ACL for time synchronization file has already been removed',0)
        	        	Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				acl_cmd = 'setfacl --remove-all ' + file_Name 
				out = os.system(acl_cmd)
				if out == 0:
					str_acl = 'Executing the command : ' + acl_cmd +' \n\tThe ACL for time synchronization file removed'
					write_to_Check_Tracing(str_acl,0)
                        		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO="The ACL for network service daemons removed"
		STIG_ID="GEN00001190"
		file_Name='/usr/sbin/sshd'
		Check_ACL_exist(file_Name)
		if exists_flag  == False:
			write_to_Check_Tracing('Verified : The ACL for network services daemons has already been removed',0)
        	        Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
		else:
			acl_cmd = 'setfacl --remove-all ' + file_Name 
			out = os.system(acl_cmd)
			if out == 0:
				str_acl = 'Executing the command : ' + acl_cmd +'\n\tThe ACL for network services daemon is removed'
				write_to_Check_Tracing(str_acl,0)
                	        Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO="Linux Security Module is configured with SELINUX to limit the privileges of system services"
		STIG_ID="GEN000000-LNX00800"
		file_Name="/etc/sysconfig/selinux"
		cmd = 'cat /etc/sysconfig/selinux  | grep -v "^#" | egrep -q "SELINUX=enforcing"'
		str_selinux = 'Verifying if '+ INFO + '\n\t Executing the command : ' + cmd
		write_to_Check_Tracing(str_selinux,0)
		out1=subprocess.call(cmd, shell=True)
		if out1 != 0: 
			Info = "Commenting SELINX to limit the privileges of system services"
  			Comment_Line_Matching_Pattern ("^[[:space:]]*SELINUX=.*", file_Name, STIG_ID, Info) 
  			Insert_New_Line_In_File ("^[[:space:]]SELINUX.*", "SELINUX=enforcing", file_Name, STIG_ID, INFO)
		else:
			str_selinux = '\tLinux Security Module SELINUX is already configured'
			write_to_Check_Tracing(str_selinux, 0)
        	        Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
		time.sleep(5)

		INFO="Linux Security Module is configured with SELINUXTYPE to limit the privileges of system services"
		cmd = 'cat /etc/sysconfig/selinux  | grep -v "^#" | egrep -q "SELINUXTYPE=targeted"'
		str_selinux = 'Verifying if '+ INFO + '\n\tExecuting the command : ' + cmd
		write_to_Check_Tracing(str_selinux,0)
		out2=subprocess.call(cmd, shell=True)
		if out2 != 0:
			cmd = 'cat /etc/sysconfig/selinux  | grep -v "^#" | egrep -q "SELINUXTYPE=strict"'
			str_selinux = 'Verifying if SELINUXTYPE=strict  : ' + cmd
			write_to_Check_Tracing(str_selinux,0)
			out3=subprocess.call(cmd, shell=True)
			if out3 != 0:
  				Insert_New_Line_In_File ("^[[:space:]]SELINUXTYPE.*", "SELINUXTYPE=targeted", file_Name, STIG_ID, INFO) 
		'''

		INFO="Configured a supplemental group for users permitted to switch to the root"
		STIG_ID="GEN000850"
        	Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
		file_Name='/etc/pam.d/su'
		if (os.path.exists(file_Name)==False):
			Log_Info('False', STIG_ID, "The /etc/pam.d/su file not configured, please contact System Administrtor", "FAILED")
		else:
        		Check_Pattern_Presence_In_File( "^[[:space:]]*auth.*[[:space:]]*required.*[[:space:]]*pam_wheel.so", file_Name)
        		if pattern_Present:
				str = '\tConfigured a supplemental group for users permitted to switch to the root'
				write_to_Check_Tracing(str, 0)
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
  				Insert_New_Line_In_File ("^[[:space:]]*.*auth.*required.*pam_wheel.so*", "auth	required	pam_wheel.so", file_Name, STIG_ID, INFO) 

		time.sleep(5)
	
		INFO="The successful logins are logged"
		STIG_ID="GEN000440"
		if (os.path.exists('/var/log/wtmp') == False): 
			os.system('touch /var/log/wtmp')
			write_to_Check_Tracing('Verified : Successful logins are logged',0)
 			Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")
		INFO="The unsuccessful logins are logged"
		if (os.path.exists('/var/log/btmp') == False): 
			os.system('touch /var/log/btmp')
			write_to_Check_Tracing('Verified : Unsuccessful logins are logged',0)
 			Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")
	
	  	INFO="Commenting of sendmail decode command"
 		STIG_ID="GEN004640"
		file_Name='/etc/aliases'
  		Comment_Line_Matching_Pattern ("^[[:space:]]*decode:[[:space:]]*root", file_Name, STIG_ID, INFO) 

  		INFO="sendmail version is hidden."
 		STIG_ID="GEN004560"
		file_Name='/etc/mail/sendmail.cf'
		if (os.path.exists('/etc/mail/sendmail.cf') == True):
  			Comment_Line_Matching_Pattern ("^[[:space:]]*0.*SmtpGreetingMessage=.*Sendmail.*", file_Name, STIG_ID, INFO) 

  		INFO="Disabling the 'uucp' service" 
  		STIG_ID="LNX00320"
		file_Name='/etc/passwd'
  		Comment_Line_Matching_Pattern("^[[:space:]]*uucp:.*uucp",file_Name, STIG_ID, INFO) 


		INFO="CTRL-ALT-DELETE combination key is disabled"
  		STIG_ID="LNX00580"
		file_Name='/etc/inittab'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*ca::ctrlaltdel:/usr/bin/logger*", file_Name) 
		if not pattern_Present:
  			Insert_New_Line_In_File ("[[:space:]]*ca*ctrlaltdel*sbin*shutdown*-t3*r*now", "ca::ctrlaltdel:/usr/bin/logger -p security.info 'CTRL-ALT-DEL key is pressed'", file_Name, STIG_ID, INFO) 
	
		Check_Pattern_Presence_In_File ("^[[:space:]]*password.*minlen=14.*", file_Name) 
		if not pattern_Present:
  			INFO="Force atleast fourteen characters in password"
  			STIG_ID="GEN000580"
			file_Name='/etc/pam.d/system-auth'
  			Insert_Pattern_At_End_Of_Line( "^[[:space:]]*password.*requisite.*pam_cracklib.so.*", "minlen=14",file_Name, STIG_ID, INFO)

  		INFO="Force to have not more than three repeating characters in a password"
  		STIG_ID="GEN000680"
		file_Name='/etc/pam.d/system-auth'
  		Insert_Pattern_At_End_Of_Line("^[[:space:]]*password.*requisite.*pam_cracklib.so.*","maxrepeat=3",file_Name, STIG_ID, INFO) 

  		INFO="The difok parameter is set to 8"
  		STIG_ID="OL6-00-000060"
		file_Name='/etc/pam.d/system-auth'
  		Insert_Pattern_At_End_Of_Line("^[[:space:]]*password.*requisite.*pam_cracklib.so.*","difok=8",file_Name, STIG_ID, INFO) 

		if ol6_Flag == 'FALSE':
			INFO='Updating syslog.conf file to manage log messages'
			file_Name='/etc/syslog.conf'
		else:
			INFO='Updating rsyslog.conf file to manage log messages'
			file_Name='/etc/rsyslog.conf'
  		Insert_New_Line_In_File("^[[:space:]]*auth.*user.*/var/log/messages" ,"auth,user.*	/var/log/messages", file_Name, 'LNX000060', INFO)
  		Insert_New_Line_In_File("^[[:space:]]*kern.*/var/log/kern.log" ,"kern.*		/var/log/kern.log", file_Name, 'LNX000070', INFO)
  		Insert_New_Line_In_File("^[[:space:]]*daemon.*/var/log/daemon.log" ,"daemon.*		/var/log/daemon.log", file_Name, 'LNX000080', INFO)
  		Insert_New_Line_In_File("^[[:space:]]*syslog.*/var/log/syslog" ,"syslog.*	/var/log/syslog", file_Name, 'LNX000090', INFO)
  		Insert_New_Line_In_File("^[[:space:]]*lpr.*local[1-9].*/var/log/unused.log" ,"lpr,local1,local2,local3,local4,local5,local6.*	/var/log/unused.log", file_Name, 'LNX000100', INFO)

  		INFO="Uninstall RealVNC rpm from the system"
  		STIG_ID="2006-T-0013"
		if ol6_Flag == 'FALSE':
  			UN_Install_RPM("vnc-server", STIG_ID, INFO)
		else:
  			UN_Install_RPM("tigervnc-server", STIG_ID, INFO)

  		INFO="Uninstall rsh-server rpm from the system"
  		STIG_ID="GEN003825"
  		UN_Install_RPM("rsh-server", STIG_ID, INFO)

  		INFO="AIDE is installed on the system"
  		STIG_ID="OL6-00-000016"
  		#Install_RPM("aide", STIG_ID, INFO)
  		Check_For_Installed_RPM("aide")
		if not pattern_Present:
			Flag_Str = 'False'
			INFO = "Please contact your system administrator and install aide on your systems"
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
		else:
                	Log_Info('True', STIG_ID, INFO, "ALREADY DONE")

  		INFO="Uninstalling the xinetd package from the system"
  		STIG_ID="OL6-00-000204"
  		UN_Install_Package("xinetd", STIG_ID, INFO)

  		INFO="Disabling support for usb device in kernel"
  		STIG_ID="LNX00040"
		file_Name=GRUB_CONF
  		Insert_Pattern_At_End_Of_Line("^[[:space:]]*kernel.*\/vmlinuz.*" ,"-nousb", file_Name, STIG_ID, INFO)

 		INFO="Enable FAIL_DELAY in /etc/login.defs"
  		STIG_ID="GEN000480"
		file_Name = '/etc/login.defs'
		Check_Pattern_Presence_In_File("^[[:space:]]*FAIL_DELAY.*4",file_Name)
		if not pattern_Present:
			Comment_Line_Matching_Pattern("^[[:space:]]*FAIL_DELAY.*",file_Name, STIG_ID, INFO)
	  		Insert_New_Line_In_File("^[[:space:]]*FAIL_DELAY.*" ,"FAIL_DELAY        4", "/etc/login.defs",STIG_ID, INFO)

  		INFO="Enable login delay in /etc/pam.d/system-auth"
  		STIG_ID="GEN000480"
		file_Name='/etc/pam.d/system-auth'
  		Enable_Delay_In_Seconds(file_Name, STIG_ID, INFO)

 		INFO="Enable maximum age for a password reset to 60 days"
  		STIG_ID="GEN000700"
		file_Name='/etc/login.defs'
  		Modify_Parameter_In_File ("^[[:space:]]*", "PASS_MAX_DAYS", "60", file_Name, STIG_ID, INFO)

		INFO="Enable password change more than once in 24 hours"
  		STIG_ID="GEN000540"
		file_Name='/etc/login.defs'
  		Modify_Parameter_In_File("^[[:space:]]*","PASS_MIN_DAYS", "1",file_Name, STIG_ID, INFO)

		INFO="Enable minimum password length to at least 15 characters"
  		STIG_ID="OL6-00-000050"
		file_Name='/etc/login.defs'
  		Modify_Parameter_In_File("^[[:space:]]*", "PASS_MIN_LEN", "15", file_Name, STIG_ID, INFO) 

		# STIG GEN00120 is disabled as it causes database creation failure
		'''
  		INFO="Disable direct login as root from ssh. Enable SSH through STIG scripts to create database/dbstorage..."
  		STIG_ID="GEN001120"
       		file_Name="/etc/ssh/sshd_config" 
  		Modify_Parameter_In_File("^[[:space:]]*", "PermitRootLogin","no", file_Name, STIG_ID, INFO) 
		'''
	
		if ol6_Flag == 'FALSE':
			INFO="Disable ekshell supported from pam.rhost"
		  	STIG_ID="GEN002100"
			file_Name="/etc/pam.d/ekshell"
  			Delete_Line_Matching_Pattern("^[[:space:]]*auth.*pam_rhosts_auth.so", file_Name, STIG_ID, INFO) 

  		# Setup cron access for root and deny for all other.
  		INFO="Creation of file /etc/cron.allow and /etc/cron.deny"
  		STIG_ID="GEN002960"
  		Setup_Access_To_Cron_Job(STIG_ID, INFO)

		INFO="Set net.ipv4.conf.default.send_redirects"
  		STIG_ID="OL6-00-000080"
		file_Name='/etc/sysctl.conf'
		Modify_Sysctl_Conf_Parameter_To_New_Value('net.ipv4.conf.default.send_redirects', '0', '0', file_Name, STIG_ID, INFO)
		INFO="Set net.ipv4.conf.all.send_redirects"
  		STIG_ID="OL6-00-000081"
		file_Name='/etc/sysctl.conf'
		Modify_Sysctl_Conf_Parameter_To_New_Value('net.ipv4.conf.all.send_redirects', '0', '0', file_Name, STIG_ID, INFO)

		INFO="Set net.ipv4.conf.all.accept_source_route"
  		STIG_ID="OL6-00-000083"
		file_Name='/etc/sysctl.conf'
		Modify_Sysctl_Conf_Parameter_To_New_Value('net.ipv4.conf.all.accept_source_route', '0', '0', file_Name, STIG_ID, INFO)

		INFO="Set net.ipv4.conf.all.secure_redirects"
  		STIG_ID="OL6-00-000086"
		file_Name='/etc/sysctl.conf'
		Modify_Sysctl_Conf_Parameter_To_New_Value('net.ipv4.conf.all.secure_redirects', '0', '0', file_Name, STIG_ID, INFO)

		INFO="Set net.ipv4.conf.all.log_martians"
  		STIG_ID="OL6-00-000088"
		file_Name='/etc/sysctl.conf'
		Comment_Line_Matching_Pattern("^[[:space:]]*net.ipv4.conf.all.log_martians=.*",file_Name, STIG_ID, "")
		Modify_Sysctl_Conf_Parameter_To_New_Value('net.ipv4.conf.all.log_martians', '1', '1', file_Name, STIG_ID, INFO)
		#fp = open(file_Name,'r')
		#for line in fp.readlines():
		#	if line.startswith('#'):
		#		continue
		#	else:
		#		Comment_Line_Matching_Pattern("^[[:space:]]*net.ipv4.conf.all.log_martians=.*",file_Name, STIG_ID, "")
		#time.sleep(2)

		INFO="Set net.ipv4.icmp_echo_ignore_broadcasts"
		STIG_ID="OL6-00-000092"
		file_Name = '/etc/sysctl.conf'
		Modify_Sysctl_Conf_Parameter_To_New_Value('net.ipv4.icmp_echo_ignore_broadcasts', '1', '1', file_Name, STIG_ID, INFO)

		INFO="Set net.ipv4.icmp_ignore_bogus_error_responses"
		STIG_ID="OL6-00-000093"
		file_Name = '/etc/sysctl.conf'
		Modify_Sysctl_Conf_Parameter_To_New_Value('net.ipv4.icmp_ignore_bogus_error_responses', '1', '1', file_Name, STIG_ID, INFO)

		#INFO="Set net.ipv4.conf.all.rp_filter"
		#STIG_ID="OL6-00-000096"
		#file_Name = '/etc/sysctl.conf'
		#Modify_Sysctl_Conf_Parameter_To_New_Value('net.ipv4.conf.all.rp_filter', '1', '1', file_Name, STIG_ID, INFO)

		INFO="Set net.ipv4.tcp_max_syn_backlog"
  		STIG_ID="GEN003600"
		file_Name='/etc/sysctl.conf'
		Modify_Sysctl_Conf_Parameter_To_New_Value('net.ipv4.tcp_max_syn_backlog', '1280', '2048', file_Name, STIG_ID, INFO)

  		INFO="Uninstall tcpdump rpm from system"
  		STIG_ID="GEN003865"
  		UN_Install_RPM("tcpdump",STIG_ID, INFO)

	 	INFO="Disable sendmail help command"
  		STIG_ID="GEN004540"
		file_Name='/etc/mail/sendmail.cf'
		if (os.path.exists('/etc/mail/sendmail.cf') == True):
  			Comment_Line_Matching_Pattern ("^[[:space:]]*O.*HelpFile=.*helpfile", file_Name, STIG_ID, INFO) 
			time.sleep(10)
	
  		INFO="Disable sendmail version in banner"
 		STIG_ID="GEN0004560"
		if (os.path.exists('/etc/mail/sendmail.cf') == True):
  			Replace_Pattern_In_File("Sendmail.*;", " ", "/etc/mail/sendmail.cf", STIG_ID, INFO) 
		'''
		INFO="Minimum password length is set to fourteen characters"
 		STIG_ID="GEN000580"
  		Replace_Pattern_In_File("minlen=8", "minlen=14", "/etc/pam.d/system-auth", STIG_ID, INFO) 
		'''
  		INFO="The USB device is disabled"
 		STIG_ID="OL6-00-000503"
		file_Name='/etc/modprobe.d/*'
		Check_Pattern_Presence_In_File("install.*usb-storage.*/bin/true",file_Name)
		if not pattern_Present:
	  		Insert_New_Line_In_File("install*usb-storage" ,"install usb-storage /bin/true", "/etc/modprobe.d/modprobe.conf",STIG_ID, INFO)
  		INFO="The DCCP protocol is disabled"
 		STIG_ID="OL6-00-000124"
		file_Name='/etc/modprobe.d/*'
		Check_Pattern_Presence_In_File("install.*dccp.*/bin/true",file_Name)
		if not pattern_Present:
	  		Insert_New_Line_In_File("install*dccp" ,"install dccp /bin/true", "/etc/modprobe.d/modprobe.conf",STIG_ID, INFO)
  		INFO="The SCTP protocol is disabled"
 		STIG_ID="OL6-00-000125"
		file_Name='/etc/modprobe.d/*'
		Check_Pattern_Presence_In_File("install.*sctp.*/bin/true",file_Name)
		if not pattern_Present:
	  		Insert_New_Line_In_File("install*sctp" ,"install sctp /bin/true", "/etc/modprobe.d/modprobe.conf",STIG_ID, INFO)
  		INFO="The TIPC protocol is disabled"
 		STIG_ID="OL6-00-000127"
		file_Name='/etc/modprobe.d/*'
		Check_Pattern_Presence_In_File("install.*tipc.*/bin/true",file_Name)
		if not pattern_Present:
	  		Insert_New_Line_In_File("install*tipc" ,"install tipc /bin/true", "/etc/modprobe.d/modprobe.conf",STIG_ID, INFO)

  		INFO="Uninstalling the sendmail package from the system"
  		STIG_ID="OL6-00-000288"
  		UN_Install_Package("sendmail", STIG_ID, INFO)

	if (do_All == 'all' or argv[2] == 'access'):	
	
		INFO='The /etc/securetty file is owned by root'
		STIG_ID='GEN000000-LNX00640'
		if (os.path.exists('/etc/securetty')==True):
			cmd = "ls -l /etc/securetty | awk '{print $3}' | egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/securetty file is owneed by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chown root /etc/securetty")
				write_to_Check_Tracing('\tChanging the ownership of file /etc/securetty to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/security/access.conf file is owned by root'
		STIG_ID='GEN000000-LNX00400'
		if (os.path.exists('/etc/security/access.conf')==True):
			cmd = "ls -l /etc/security/access.conf | awk '{print $3}' | egrep -q root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/security/access.conf file is owneed by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chown root /etc/security/access.conf")
				write_to_Check_Tracing('\tChanging the ownership of file /etc/security/access.conf to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/sysctl.conf file is owned by root'
		STIG_ID='GEN000000-LNX00480'
		if (os.path.exists('/etc/sysctl.conf')==True):
			cmd = "ls -l /etc/sysctl.conf | awk '{print $3}' | egrep -q root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/sysctl.conf file is owneed by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chown root /etc/sysctl.conf")
				write_to_Check_Tracing('\tChanging the ownership of file /etc/sysctl.conf to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/sysctl.conf file group is owned by root'
		STIG_ID='GEN000000-LNX00500'
		if (os.path.exists('/etc/sysctl.conf')==True):
			cmd = "ls -l /etc/sysctl.conf | awk '{print $4}'  | egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/sysctl.conf file is group owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chgrp root /etc/sysctl.conf")
				write_to_Check_Tracing('\tChanging the group ownership of file /etc/sysctl.conf to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/resolv.conf file is owned by root'
		STIG_ID='GEN001362'
		if (os.path.exists('/etc/resolv.conf')==True):
			cmd = "ls -l /etc/resolv.conf | awk '{print $3}' |  egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/resolv.conf file is group owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chown root /etc/resolv.conf")
				write_to_Check_Tracing('\tChanging the group ownership of file /etc/resolv.conf to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/gshadow file is owned by root'
		STIG_ID='OL6-00-000036'
		if (os.path.exists('/etc/gshadow')==True):
			cmd = "ls -l /etc/gshadow | awk '{print $3}' | egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/gshadow.conf file is owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
        	        	Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chown root /etc/gshadow")
				write_to_Check_Tracing('\tChanging the ownership of file /etc/gshadow to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/gshadow file group is owned by root'
		STIG_ID='OL6-00-000037'
		if (os.path.exists('/etc/gshadow')==True):
			cmd = "ls -l /etc/gshadow | awk '{print $4}' |  egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/gshadow.conf file is group owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chgrp root /etc/gshadow")
				write_to_Check_Tracing('\tChanging the group ownership of file /etc/gshadow to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/shadow file is owned by root'
		STIG_ID='OL6-00-000033'
		if (os.path.exists('/etc/shadow')==True):
			cmd = "ls -l /etc/shadow | awk '{print $3}' | egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/shadow conf file is owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
        	        	Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chown root /etc/shadow")
				write_to_Check_Tracing('\tChanging the ownership of file /etc/shadow to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/shadow file group is owned by root'
		STIG_ID='OL6-00-000034'
		if (os.path.exists('/etc/shadow')==True):
			cmd = "ls -l /etc/shadow | awk '{print $4}' |  egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/shadow conf file is group owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chgrp root /etc/shadow")
				write_to_Check_Tracing('\tChanging the group ownership of file /etc/shadow to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/securetty file group is owned by root'
		STIG_ID='GEN000000-LNX00620'
		if (os.path.exists('/etc/securetty')==True):
			cmd = "ls -l /etc/securetty | awk '{print $4}' | egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/securetty file is group owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chgrp root /etc/securetty")
				write_to_Check_Tracing('\tChanging the group ownership of file /etc/gshadow to root',0)
               		 	Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO='The /etc/security/access.conf file group is owned by root'
		STIG_ID='GEN000000-LNX00420'
		if (os.path.exists('/etc/security/access.conf')==True):
			cmd = "ls -l /etc/security/access.conf | awk '{print $4}'  | egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/security/access.conf file is group owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chgrp root /etc/security/access.conf")
				write_to_Check_Tracing('\tChanging the group ownership of file /etc/security/access.conf to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")

		INFO="Enable remember password parameter in PAM configuration files."
  		STIG_ID="GEN000800"
		file_Name='/etc/pam.d/system-auth'
  		Insert_Pattern_At_End_Of_Line ("[[:space:]]*password.*sufficient.*pam_unix.so.*", "remember=5", file_Name, STIG_ID, INFO) 

		INFO='The /etc/ntp.conf file is owned by root'
		STIG_ID='GEN000250'
		if (os.path.exists('/etc/ntp.conf')==True):
			cmd = "ls -l /etc/ntp.conf | awk '{print $3}' | egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/ntp.conf file is owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
        	        	Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chown root /etc/ntp.conf")
				write_to_Check_Tracing('\tChanging the ownership of file /etc/ntp.conf to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")
		#else:
                #	Log_Info('True', STIG_ID, '/etc/ntp.conf file not configured, please check with System Administers to correct the system vulnerabilities', "FAILED")
		

		INFO='The /etc/ntp.conf file group is owned by root'
		STIG_ID='GEN000251'
		if (os.path.exists('/etc/ntp.conf')==True):
			cmd = "ls -l /etc/ntp.conf | awk '{print $4}' |  egrep -q  root"
			Str = 'Executing the command : ' + cmd + ' to check if /etc/ntp.conf file is group owned by root'
			write_to_Check_Tracing(Str,0)
			u = os.system(cmd)
			if u == 0:
                		Log_Info('True', STIG_ID, INFO, "ALREADY DONE")
			else:
				os.system("chown root /etc/ntp.conf")
				write_to_Check_Tracing('\tChanging the ownership of file /etc/ntp.conf to root',0)
                		Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")
		#else:
                # 	Log_Info('True', STIG_ID, '/etc/ntp.conf file not configured, please check with System Administers to correct the system vulnerabilities', "FAILED")
		INFO='The root login to virtual consoles are not allowed'
		STIG_ID='OL6-00-000027'
		write_to_Check_Tracing('Checking for root login acces to virtual consoles',0)
  		Comment_Line_Matching_Pattern ("vc", '/etc/securetty', STIG_ID, INFO) 

		INFO='The root login to serial consoles are not allowed'
		STIG_ID='OL6-00-000028'
		write_to_Check_Tracing('Checking for root login acces to serial consoles',0)
  		Comment_Line_Matching_Pattern ("ttyS", '/etc/securetty', STIG_ID, INFO) 

	# FIX all system account related Security vulnerabilities
	if(do_All == 'all' or argv[2] == 'account'):
	
		file_Name = '/etc/passwd'
		INFO="The duplicate accounts found on the system, contact System Administrators to correct security vulnerabilities"
		STIG_ID="GEN000300"
		Fix_Duplicate_Accounts(file_Name, 'cat /etc/passwd | grep -v "^#"  | cut -d: -f1 | uniq -d')
		if exists_flag  == True:
                	Log_Info('False', STIG_ID, INFO, "FAILED")
		
		INFO="The duplicate UIDs found on the system, contact System Administrators to correct security vulnerabilities"
		STIG_ID="GEN000320"
		Fix_Duplicate_Accounts(file_Name, 'cat /etc/passwd | grep -v "^#" | cut -d: -f3 | uniq -d')
		if exists_flag  == True:
                	Log_Info('False', STIG_ID, INFO, "FAILED")

		INFO="Multiple non-root accounts with UID=0 are to be disabled"
		STIG_ID="GEN000880"
		file_Name='/etc/passwd'
		fp = open(file_Name,'r')
		for line in fp.readlines():
			if line.startswith('#'):
				continue
			else:
				temp_line =  line.strip('\n')
				string_check = line.split(':')
				if (string_check[2] == '0' and string_check[0] != 'root'):
  					Comment_Line_Matching_Pattern ("^[[:space:]]*"+string_check[0]+"*"+string_check[2]+"*", file_Name, STIG_ID, INFO) 

		INFO="The GIDs are not cross referenced in /etc/passwd and /etc/shadow files, contact System Administrators to correct security vulnerabilities"
		STIG_ID="GEN000380"
		str = 'pwck -r | grep [delete line][no matching][invalid user name] | wc -l'
		write_to_Check_Tracing(str,0)
		Check_PWCK('pwck -r | grep "[delete line][no matching][invalid user name]" | wc -l')
		if exists_flag  == True:
                	Log_Info('False', STIG_ID, INFO, "FAILED")
		else:
			Log_Info('True', STIG_ID, "The /etc/passwd and /etc/shadow files are cross referenced completely", "SUCCESSFUL")
			write_to_Check_Tracing("The /etc/passwd and /etc/shadow files are cross referenced completely", 0)
	
        	INFO="Removing the 'nullok' options"
	        STIG_ID="GEN000560"
        	file_Name='/etc/pam.d/system-auth'
	        grep_nullok = 'egrep -q -e nullok ' + file_Name
		Str = 'Executing the command : ' + grep_nullok
		write_to_Check_Tracing(Str,0)
        	grep_Success = os.system(grep_nullok)
     	   	if grep_Success == 0:
                	nullok_replace = "sed -i 's/nullok//g' " + file_Name
                	u = os.system(nullok_replace)
                	if u == 0:
                        	#print 'nullok is removed from the system-auth file'
                        	write_to_Check_Tracing('\tnullok is removed from the system-auth file',0)
                       	 	Log_Info('True', STIG_ID, INFO, "SUCCESSFUL")
                	else:
                        	#print 'nullok is removed from the system-auth file'
                       	 	Log_Info('True', STIG_ID, INFO, "FAILED")
        	else:
                	Log_Info('True', STIG_ID, INFO, "ALREADY DONE")

		'''
		INFO="The root users with home directory / are set to /root"
		STIG_ID="GEN000880"
		file_Name='/etc/passwd'
		fps = open(file_Name,'r')
		for line in fps.readlines():
			if line.startswith('#'):
				continue
			else:
				temp_line =  line.strip('\n')
				string_check = line.split(':')
				if (string_check[0] == 'root' and string_check[5] == '/'):
					print line	
					#Incomplete fix
		fps.close()
		'''

  		INFO="Commenting privilege account name 'shutdown'"
  		STIG_ID="LNX00320"
		file_Name='/etc/passwd'
  		Comment_Line_Matching_Pattern("^[[:space:]]*shutdown:.*shutdown",file_Name, STIG_ID, INFO) 
  	
		INFO="Commenting privilege account name 'reboot'"
  		STIG_ID="GEN000000LNX00320"
		file_Name='/etc/passwd'
  		Comment_Line_Matching_Pattern("^[[:space:]]*reboot:.*reboot",file_Name, STIG_ID, INFO) 
	
 		INFO="Commenting privilege account name 'halt'"
  		STIG_ID="LNX00320"
		file_Name='/etc/passwd'
  		Comment_Line_Matching_Pattern("^[[:space:]]*halt:.*halt", file_Name,STIG_ID, INFO) 

		INFO="Commenting Ctrl-Alt-Del combination"
  		STIG_ID="LNX00580"
		file_Name='/etc/inittab'
  		Comment_Line_Matching_Pattern("^[[:space:]]*ca::ctrlaltdel:\/sbin\/shutdown",file_Name, STIG_ID, INFO)

 		INFO="Restrict console access to root User only"
  		STIG_ID="LNX0010"
  		Insert_New_Line_In_File("^[[:space:]]*-:ALL.*EXCEPT.*root:.*LOCAL" ,"-:ALL	EXCEPT	root:LOCAL", "/etc/security/access.conf",STIG_ID, INFO)
 	
		INFO="Restrict unauthorized access"
  		STIG_ID="LNX0020"
  		Insert_New_Line_Location("^[[:space:]]*account.*required.*pam_access.so", "account" ,"account    required	pam_access.so", "/etc/pam.d/login",STIG_ID, INFO, 0)

		INFO="Enable password for single user mode boot"
  		STIG_ID="GEN000020"
		file_Name='/etc/inittab'
  		Insert_New_Line_In_File("^[[:space:]]*ss:S.*sulogin", "ss:S:wait:/sbin/sulogin",file_Name, STIG_ID, INFO) 

		INFO="Commenting of non privilege account oprofile"
  		STIG_ID="GEN000340"
		file_Name='/etc/passwd'
  		Comment_Line_Matching_Pattern ("^[[:space:]]*oprofile:.*",file_Name, STIG_ID, INFO) 

		INFO="Commenting of non privilege account gopher"
  		STIG_ID="GEN000340"
		file_Name='/etc/passwd'
  		Comment_Line_Matching_Pattern ("^[[:space:]]*gopher:.*",file_Name, STIG_ID, INFO) 

  		INFO="Commenting of non privilege account avahi-autoipd"
  		STIG_ID="GEN000340"
		file_Name='/etc/passwd'
  		Comment_Line_Matching_Pattern( "^[[:space:]]*avahi-autoipd:.*",file_Name, STIG_ID, INFO)

		INFO="Enable locking of account after three unsuccessful attempts"
  		STIG_ID="GEN000460"
		file_Name='/etc/pam.d/system-auth'
  		Lock_Account_After_Three_Fail_Attempts(file_Name, STIG_ID, INFO)

  		INFO="Force at least one lower case character in password"
  		STIG_ID="GEN000600"
		file_Name='/etc/pam.d/system-auth'
  		Insert_Pattern_At_End_Of_Line("^[[:space:]]*password.*requisite.*pam_cracklib.so.*","lcredit=-1",file_Name, STIG_ID, INFO) 

		INFO="Force at least one upper case character in password"
  		STIG_ID="GEN000600"
		file_Name='/etc/pam.d/system-auth'
  		Insert_Pattern_At_End_Of_Line("^[[:space:]]*password.*requisite.*pam_cracklib.so.*","ucredit=-1",file_Name, STIG_ID, INFO)

		INFO="Force at least one numeric character in password"
  		STIG_ID="GEN000620"
		file_Name='/etc/pam.d/system-auth'
  		Insert_Pattern_At_End_Of_Line("^[[:space:]]*password.*requisite.*pam_cracklib.so.*","dcredit=-1",file_Name, STIG_ID, INFO)

		INFO="Force at least one special character in password"
  		STIG_ID="GEN000640"
		file_Name='/etc/pam.d/system-auth'
  		Insert_Pattern_At_End_Of_Line("^[[:space:]]*password.*requisite.*pam_cracklib.so.*","ocredit=-1",file_Name, STIG_ID, INFO)

  		INFO="Deletion of account"
  		UNNECESSARY_ACCOUNT_LIST=["ftp", "games", "news", "operator", "gopher"]
  		STIG_ID_LIST=["LNX00340", "LNX00340", "LNX00340", "LNX00340", "LNX00340", "LNX00340","LNX00340","LNX00340"] 
		file_Name='/etc/passwd'
  		Delete_Account(UNNECESSARY_ACCOUNT_LIST, STIG_ID_LIST, file_Name, INFO)

	# FIX : Fix all file system related system security vulnerabilities
	if ((do_All == 'all') or (argv[2] == 'fs')):

		cat_Cmd = '/usr/sbin/dmidecode ' + ' | grep -q domU'
		Str = 'Executing the command : ' + cat_Cmd
		check = os.system(cat_Cmd)
		if check != 0:
			# print 'should not be printed in VM env, should be printe only in BM'
  			INFO="Commenting /opt entry to include nodev for non-root local partitions"
 			STIG_ID="GEN0000030"
			file_Name = '/etc/fstab'
			Check_First_Occurance_Pattern_Is_Commented("*opt.*", file_Name) 
			if not pattern_Commented:
  				Comment_Line_Matching_Pattern (".*opt.*", file_Name, STIG_ID, INFO) 
  			INFO="Change /opt entry to include nodev for non-root local partitions"
  			Insert_New_Line_In_File("^[[:space:]]*/dev/VolGroupSys/LogVolOpt.*/opt.*ext3.*defaults.*nodev.*1.*2", "/dev/VolGroupSys/LogVolOpt	/opt	ext3	defaults,nodev	1 2",file_Name, STIG_ID, INFO) 

  			INFO="Commenting /u01 entry to include nodev for non-root local partitions"
 			STIG_ID="GEN0000040"
			Check_First_Occurance_Pattern_Is_Commented("*u01.*", file_Name) 
			if not pattern_Commented:
  				Comment_Line_Matching_Pattern (".*u01.*", file_Name, STIG_ID, INFO) 
  			INFO="Change /u01 entry to include nodev for non-root local partitions"
  			Insert_New_Line_In_File("^[[:space:]]*/dev/VolGroupSys/LogVolU01.*/u01.*ext3.*defaults.*nodev.*1.*2", "/dev/VolGroupSys/LogVolU01	/u01	ext3	defaults,nodev	1 2",file_Name, STIG_ID, INFO) 

  			INFO="Commenting tmpfs to include nodev, nosuid, noexec for tmpfs local partitions"
 			STIG_ID="GEN0000050"
			Check_First_Occurance_Pattern_Is_Commented("*tmpfs.*", file_Name) 
			if not pattern_Commented:
  				Comment_Line_Matching_Pattern ("^[[:space:]]*tmpfs.*", file_Name, STIG_ID, INFO) 
  			INFO="Change tmpfs entry to include nodev, nosuid and noexec for tmpfs local partitions"
  			Insert_New_Line_In_File("^[[:space:]]*tmpfs.*/dev/shm.*tmpfs.*defaults.*0.*0", "tmpfs 	/dev/shm	tmpfs	defaults,nodev,nosuid,noexec	0 0",file_Name, STIG_ID, INFO) 

	# FIX : Fix all audit related system security requirements
	if ((do_All == 'all') or (argv[2] == 'audit')):

  		INFO="Enabling auditing at boot by setting the kernel parameter"
  		STIG_ID="GEN000000-LNX00720"
		file_Name=GRUB_CONF
  		Insert_Pattern_At_End_Of_Line("^[[:space:]]*kernel.*\/vmlinuz.*" ,"audit=1", file_Name, STIG_ID, INFO)

		INFO="System is configured to audit for executing adjtimex system call"
  		STIG_ID="OL6-00-000165"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*adjtimex.*audit_time_rules.*", "-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules", file_Name, STIG_ID, INFO)

		INFO="System is configured to audit for executing clock_settime system call"
  		STIG_ID="OL6-00-000171"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*arch=b64.*clock_settime.*audit_time_rules.*", "-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules", file_Name, STIG_ID, INFO)

		INFO="System is configured to audit for executing localtime system call"
  		STIG_ID="OL6-00-000173"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*/etc/localtime.*audit_time_rules.*", "-w /etc/localtime -p wa -k audit_time_rules", file_Name, STIG_ID, INFO)

		INFO="System is configured to audit automatic account creation"
  		STIG_ID="OL6-00-000174(5,6,7)"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*/etc/group.*audit_account_changes.*", "-w /etc/group -p wa -k audit_account_changes", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*/etc/passwd.*audit_account_changes.*", "-w /etc/passwd -p wa -k audit_account_changes", file_Name, STIG_ID, "")
  		Insert_New_Line_In_File(".*/etc/gshadow.*audit_account_changes.*", "-w /etc/gshadow -p wa -k audit_account_changes", file_Name, STIG_ID, "")
  		Insert_New_Line_In_File(".*/etc/shadow.*audit_account_changes.*", "-w /etc/shadow -p wa -k audit_account_changes", file_Name, STIG_ID, "")
  		Insert_New_Line_In_File(".*/etc/security/opasswd.*audit_account_changes.*", "-w /etc/security/opasswd -p wa -k audit_account_changes", file_Name, STIG_ID, "")

		INFO="System is configured to audit MAC for SELinux"
  		STIG_ID="OL6-00-000183"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*/etc/selinux.*MAC-policy.*", "-w /etc/selinux -p wa -k MAC-policy", file_Name, STIG_ID, INFO)

		INFO="System is configured to audit DAC for chmod permissions"
  		STIG_ID="OL6-00-000184"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*chmod.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S chmod -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*chmod.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S chmod -F auid=0 -k perm_mod", file_Name, STIG_ID, "")

		INFO="System is configured to audit DAC for chown permissions"
  		STIG_ID="OL6-00-000185"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*chown.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*chown.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S chown -F auid=0 -k perm_mod", file_Name, STIG_ID, "")

		INFO="System is configured to audit DAC for fchmod permissions"
  		STIG_ID="OL6-00-000186"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*fchmod.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*fchmod.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S fchmod -F auid=0 -k perm_mod", file_Name, STIG_ID, "")

		INFO="System is configured to audit DAC for fchmodat permissions"
  		STIG_ID="OL6-00-000187"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*fchmodat.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*fchmodat.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S fchmodat -F auid=0 -k perm_mod", file_Name, STIG_ID, "")
		INFO="System is configured to audit DAC for fchown permissions"
  		STIG_ID="OL6-00-000188"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*fchown.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*fchown.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S fchown -F auid=0 -k perm_mod", file_Name, STIG_ID, "")

		INFO="System is configured to audit DAC for fchownat permissions"
  		STIG_ID="OL6-00-000189"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*fchownat.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*fchownat.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S fchownat -F auid=0 -k perm_mod", file_Name, STIG_ID, "")
		INFO="System is configured to audit DAC for fremovexattr permissions"
  		STIG_ID="OL6-00-000190"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*fremovexattr.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*fremovexattr.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod", file_Name, STIG_ID, "")
		INFO="System is configured to audit DAC for fsetxattr permissions"
  		STIG_ID="OL6-00-000191"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*fsetxattr.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*fsetxattr.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod", file_Name, STIG_ID, "")
		INFO="System is configured to audit DAC for lchown permissions"
  		STIG_ID="OL6-00-000192"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*lchown.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*lchown.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S lchown -F auid=0 -k perm_mod", file_Name, STIG_ID, "")

		INFO="System is configured to audit DAC for lremovexattr permissions"
  		STIG_ID="OL6-00-000193"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*lremovexattr.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*lremovexattr.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod", file_Name, STIG_ID, "")
		INFO="System is configured to audit DAC for lsetxattr permissions"
  		STIG_ID="OL6-00-000194"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*lsetxattr.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*lsetxattr.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -k perm_mod", file_Name, STIG_ID, "")
		INFO="System is configured to audit DAC for removexattr permissions"
  		STIG_ID="OL6-00-000195"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*removexattr.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 \ -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*removexattr.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S removexattr -F auid=0 -k perm_mod", file_Name, STIG_ID, "")
		INFO="System is configured to audit DAC for setxattr permissions"
  		STIG_ID="OL6-00-000196"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=b64.*setxattr.*auid!=4294967295.*perm_mod.*", "-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=b64.*setxattr.*auid=0.*perm_mod.*", "-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod", file_Name, STIG_ID, "")
		INFO="System is configured to audit successful file system mounts"
  		STIG_ID="OL6-00-000199"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=ARCH.*mount.*auid!=4294967295.*export.*", "-a always,exit -F arch=ARCH -S mount -F auid>=500 -F auid!=4294967295 -k export", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=ARCH.*mount.*auid=0.*export.*", "-a always,exit -F arch=ARCH -S mount -F auid=0 -k export", file_Name, STIG_ID, "")

		INFO="System is configured to audit successful user deletions"
  		STIG_ID="OL6-00-000200"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*always.*arch=ARCH.*rmdir.*unlink.*unlinkat.*rename.*renameat.*auid!=4294967295.*delete.*", "-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*always.*arch=ARCH.*rmdir.*unlink.*unlinkat.*rename.*renameat.*auid=0.*delete.*", "-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete", file_Name, STIG_ID, "")

		INFO="System is configured to audit changes to /etc/sudoers file"
  		STIG_ID="OL6-00-000201"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*/etc/sudoers.*actions.*", "-w /etc/sudoers -p wa -k actions", file_Name, STIG_ID, INFO)

		INFO="System is configured to audit changes to module management"
  		STIG_ID="OL6-00-000202"
		file_Name='/etc/audit/audit.rules'
  		Insert_New_Line_In_File(".*/sbin/insmod.*modules.*", "-w /sbin/insmod -p x -k modules", file_Name, STIG_ID, INFO)
  		Insert_New_Line_In_File(".*/sbin/rmmod.*modules.*", "-w /sbin/rmmod -p x -k modules", file_Name, STIG_ID, "")
  		Insert_New_Line_In_File(".*/sbin/modprobe.*modules.*", "-w /sbin/modprobe -p x -k modules", file_Name, STIG_ID, "")
  		Insert_New_Line_In_File(".*always.*arch=ARCH.*init_module.*delete_module.*modules.*", "-a always,exit -F arch=ARCH -S init_module -S delete_module -k modules ", file_Name, STIG_ID, "")

	# FIX : Fix all permissions related system security requirements
	if ((do_All == 'all') or (argv[2] == 'perm')):
  	
		INFO="Change of file permission"
  		FILES_LIST=["/etc/init.d/init.oak", "/opt/oracle/oak/install/init.oak"]
		str = 'Changing file permissions of ' + ", ".join(FILES_LIST) + ' files to 0744'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=['GEN001580','GEN001580']
		Change_File_Permissions(FILES_LIST, STIG_ID_LIST, '0744', '-rwxr--r--', INFO)

  		FILES_LIST=["/etc/resolv.conf","/etc/hosts"]
		str = 'Changing file permissions of ' + ", ".join(FILES_LIST) + ' files to 0644'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=['GEN001364','GEN001368']
		Change_File_Permissions(FILES_LIST, STIG_ID_LIST, '0644', '-rw-r--r--', INFO)

		grep_Cmd = 'egrep -q ' + '"'+ 'CHMOD.*744.*init.oak'+'"'+ ' ' +"/opt/oracle/oak/install/init.oak"
		write_to_Check_Tracing('Checking if : CHMOD 744 init.oak : entry exists in /opt/oracle/oak/install/init.oak file', 0)
		u = os.system(grep_Cmd)
		if u != 0:
			#print 'to set oakd flag after sed success'
			sed_Cmd = 'sed -i ' +  "'s/CHMOD.*init.oak/CHMOD 744 $ID\/init.oak/g'" + " /opt/oracle/oak/install/init.oak"
			str= 'Executing : ' + sed_Cmd + ' : to set CHMOD 744 init.oak'
			write_to_Check_Tracing(str,0)
			check = os.system(sed_Cmd)
			if check == 0:
				#print 'setting oakd restart flag'
				RESTART_OAKD = 1	

		INFO="Change of file permission"
  		FILES_LIST=["/etc/security/access.conf", "/etc/crontab","/etc/cron.deny","/etc/cron.allow","/etc/snmp/snmpd.conf","/etc/securetty","/boot/grub/grub.conf"] 
		str = 'Changing file permissions of ' + ", ".join(FILES_LIST) + ' files to 0600'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=["LNX00520","LNX00440","GEN003080","GEN003200","GEN005320","GEN000000-LNX00660", "OL6-00-000067"]
  		Change_File_Permissions(FILES_LIST, STIG_ID_LIST, "0600", "-rw-------", INFO)

  		INFO="Change of file permission"
		if ol6_Flag == 'FALSE':
			if (os.path.exists('/etc/ntp.conf')==True):
	  			FILES_LIST=["/etc/syslog.conf", "/etc/ntp.conf"]
  				STIG_ID_LIST=["GEN005390", "GEN000252"]
			else:
	  			FILES_LIST=["/etc/syslog.conf"]
  				STIG_ID_LIST=["GEN005390"]
		else:
			if (os.path.exists('/etc/ntp.conf')==True):
	  			FILES_LIST=["/etc/rsyslog.conf", "/etc/ntp.conf"]
  				STIG_ID_LIST=["GEN005390", "GEN000252"]
			else:
	  			FILES_LIST=["/etc/rsyslog.conf"]
  				STIG_ID_LIST=["GEN005390"]
		str = 'Changing file permissions of ' + ", ".join(FILES_LIST) + ' files to 0640'
		write_to_Check_Tracing(str,0)
  		Change_File_Permissions(FILES_LIST, STIG_ID_LIST,"0640", "-rw-r-----" ,INFO)

  		INFO="Change of file permission"
  		FILES_LIST=["/etc/sysctl.conf"]
  		STIG_ID_LIST=["LNX00520"]
		str = 'Changing file permissions of ' + ", ".join(FILES_LIST) + ' files to 0600'
		write_to_Check_Tracing(str,0)
  		Change_File_Permissions(FILES_LIST, STIG_ID_LIST,"0600", "-rw-------" ,INFO)

		INFO="Change of dir permission"
  		DIR_LIST=["/root/","/etc/cron.daily/","/etc/cron.weekly/","/etc/cron.hourly/","/etc/cron.monthly/"]
		str = 'Changing directory permissions of ' + ", ".join(FILES_LIST) + ' to 0700'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=["GEN000920","GEN003080-2","GEN00380-2","GEN00380-2","GEN00380-2",]
  		Change_Dir_Permissions(DIR_LIST, STIG_ID_LIST, "0700", "drwx------", INFO)

		DIR_LIST=["/usr/lib","/lib"]
  		STIG_ID_LIST=["GEN001300","GEN001300"]
		str = 'Changing directory permissions of ' + ", ".join(FILES_LIST) + ' to 0755'
		write_to_Check_Tracing(str,0)
  		Change_Dir_Permissions(DIR_LIST, STIG_ID_LIST, "0755", "drwxr-xr-x", INFO)


  		INFO="Change of file permission"
  		FILES_LIST=["/bin/traceroute"]
		str = 'Changing directory permissions of ' + ", ".join(FILES_LIST) + ' to 0700'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=["GEN004000"]
  		Change_File_Permissions(FILES_LIST, STIG_ID_LIST,"0700", "-rwx------", INFO)

  		INFO="Change of file permission"
  		FILES_LIST=["/etc/xinetd.conf"]
  		STIG_ID_LIST=["GEN006600"]
		str = 'Changing directory permissions of ' + ", ".join(FILES_LIST) + ' to 0440'
		write_to_Check_Tracing(str,0)
  		Change_File_Permissions(FILES_LIST, STIG_ID_LIST, "0440", "-r--r-----", INFO)
	
  		INFO="Change of file permission"
  		FILES_LIST=["/etc/gshadow"]
  		STIG_ID_LIST=["OL6-00-000038"]
		str = 'Changing directory permissions of ' + ", ".join(FILES_LIST) + ' to 0000'
		write_to_Check_Tracing(str,0)
  		Change_File_Permissions(FILES_LIST, STIG_ID_LIST, "0000", "-r--------", INFO)

  		INFO="Change of file permission"
  		FILES_LIST=["/etc/shadow"]
  		STIG_ID_LIST=["OL6-00-000035"]
		str = 'Changing directory permissions of ' + ", ".join(FILES_LIST) + ' to 0000'
		write_to_Check_Tracing(str,0)
  		Change_File_Permissions(FILES_LIST, STIG_ID_LIST, "0000", "-r--------", INFO)

		STIG_ID="GEN003740"
  		INFO="Permission change of all files whose permission were more permissive than octal 440 in directory '/etc/xinetd.d/' to octal 440"
  		str="Changing permission change of all files whose permission were more permissive than octal 440 in directory /etc/xinetd.d/ to octal 440"
		write_to_Check_Tracing(str,0)
  		Change_Permission_Of_Files_Exceeding_Given_Permission_In_Dir( "/etc/xinetd.d/","-440","440", STIG_ID,'*', INFO) 

  		STIG_ID="GEN005340"
  		INFO="Permission change of all MIB files whose permission were more permissive than octal 640 in directory '/' to octal 640"
  		str="Changing permission change of all MIB files whose permission were more permissive than octal 640 in directory / to octal 640"
		write_to_Check_Tracing(str,0)
  		Change_Permission_Of_Files_Exceeding_Given_Permission_In_Dir( "/", "-640", "640", STIG_ID, "*.mib", INFO) 

  		STIG_ID="GEN002480"
  		INFO="Permission change of all world writable files whose permission were octal 777 or 666 in directory '/opt/oracle/oak/pkgrepos' to octal 755 and 644 respectively"
  		str="Changing permission change of all world writable files whose permission were octal 777 or 666 in directory /opt/oracle/oak/pkgrepos to octal 755 and 644 respectively"
		write_to_Check_Tracing(str,0)
  		Change_Permission_Of_World_Writable_Files_In_Dir("/opt/oracle/oak/pkgrepos", "-002",STIG_ID, '*', INFO)

	  	STIG_ID="GEN001280"
  		INFO="Permission change of all manual pages whose permission were more permissive than octal 640 in directory '/usr/share/man/' to octal 640"
		write_to_Check_Tracing(INFO,0)
		dir_Name = '/usr/share/man'
  		Change_Permission_Of_Files_Exceeding_Given_Permission_In_Dir("/usr/share/man/","-640","640", STIG_ID,'*', INFO) 

		DIR_LIST=["/home/grid/.mozilla/extensions", "/home/grid/.mozilla/plugins", "/home/oracle/.mozilla/extensions", "/home/oracle/.mozilla/plugins"]
  		STIG_ID_LIST=["GEN001560", "GEN001560", "GEN001560", "GEN001560"]
		INFO='Remove Empty Directorys'
		str = 'Removing empty directories from the list : ' + ", ".join(FILES_LIST) 
		write_to_Check_Tracing(str,0)
  		Remove_Empty_Directory(DIR_LIST, STIG_ID_LIST, INFO)

		DIR_LIST=["/etc","/bin","/etc/bin","/usr/bin","/usr/lbin", "/sbin", "/usr/usb","/usr/sbin"]
  		STIG_ID_LIST=["GEN001200","GEN001200","GEN001200","GEN001200","GEN001200","GEN001200","GEN001200","GEN001200"]
		str = 'Changing directory permissions of ' + ", ".join(DIR_LIST) + ' to 0755'
		write_to_Check_Tracing(str,0)
  		Change_Dir_Permissions(DIR_LIST, STIG_ID_LIST, "0755", "drwxr-xr-x", INFO)

	# Restart any services if required due to change in conf file
  	Restart_Services()  
	print_Str = '\n' + '\n=====================================================================================================================\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)

	# Enhancement to show the status of fixing violations : 6-Aug-2014
	Log_Info ('True', '1111', 'Fix Violations completed', "FIX-COMPLETE")

def Check_First_Occurance_Pattern_Is_Commented(grep_str, file_Name):

	global	pattern_Commented
	pattern_Commented = 0
	grep_Cmd = 'egrep -m1 ' + grep_str + ' ' + file_Name
	Str = 'Executing the command : ' + grep_Cmd + ': to check if the first occurance of the pattern ' + grep_str + ' is commented'
	write_to_Check_Tracing(Str,0)
	q=subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE)
	Code = q.communicate()[0].startswith('#')
	if Code:
		pattern_Commented = 1
	return pattern_Commented
 
def Delete_Old_STIG_Log_Files():

	
	global Log_Dir
	subprocess.call(['tput', 'setaf', '4'])
	del_Files = raw_input('\n\tDo you want to delete old STIG log files (yes/no)[no] : ')
	if del_Files == 'yes' or del_Files == 'Yes' or del_Files == 'YES':
		days_prior = raw_input('\n\tHow many days old files you wish to delete [0 .. n] : ')
		print
		delete_tracing_commands_prior_Files(Log_Dir, days_prior)
		
	subprocess.call(['tput', 'sgr0'])
	sys.stdout.flush()

def Check_STIG_Violations(argv):
	
	global pattern_Present
	global ol6_Flag
	global Log_Dir
	global AUDIT_RULE_SET
	subprocess.call(['tput', 'setaf', '4'])

	print '\n\tINFO: Checking STIG Violations ........\n\n'
	subprocess.call(['tput', 'sgr0'])

	print_Str = '\n' + '\n=========================Executing the command : stig.py check <options> ==========================================\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	print_Str = '\n' + '\nLOGGING OF STIG CHECK STATUS AND TRACING OF COMMANDS EXECUTED TO CHECK THE STIG VULNERABILITIES : '+ Date_Str + '\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	print_Str = '\n' + '\n=====================================================================================================================\n\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)

	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	UName = 'uname -n'
	q=subprocess.Popen(UName, shell=True, stdout=subprocess.PIPE)
	uname_Code = (q.communicate())[0]
	print_Str = Date_Str + '  : Checking for STIG Violations on the system ' + uname_Code
        Cmd = 'printf ' +  '"'+print_Str+'"'  + ' | ' + 'tee -a ' + " >> " + STIG_Log_File 
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	Code = r.communicate()[0]
	if Code < 0:
		#oda_perror.ODA_Print_Error(50005)
		print 'Update to STIG Log file could not be made...'
	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	print_Str = '\n'+Date_Str + '  : Below details can also be found in the file '+'\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File 
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

  	# Set font to normal
	subprocess.call(['tput', 'sgr0'])
	Set_Grub_Conf_File_Name()
	# Sets the OL6 flag to TRUE
	Check_OL6()
	#sys.exit(0)

	check_All = ''
	num_Args = len(argv)
	if (num_Args == 2):
		check_All = 'all'
	if (num_Args == 3):
		if (argv[2] == 'all'):
			check_All = 'all'

	# GRUB Password Check (-grub option passed as an argument with -check)
	if ((check_All == 'all') or (argv[2] == 'grub')):

		INFO="Password for grub not enabled"
  		STIG_ID="LNX00140"
		file_Name=GRUB_CONF
  		Check_Pattern_Presence_In_File( '^[[:space:]]*password --md5',file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

	# CONF Check (-conf option will check all the configuration parameters in system files)
	if ((check_All == 'all') or (argv[2] == 'conf')):

  		INFO="The IPv6 protocol is not disabled"
 		STIG_ID="OL6-00-000098"
		file_Name='/etc/modprobe.d/*'
  		Check_Pattern_Presence_In_File( "options.*ipv6.*disable=1", file_Name) 
		if not pattern_Present:
			Flag_Str = "False"
  			Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")

		STIG_ID="OL6-00-000230"
		file_Name = '/etc/ssh/sshd_config'
		Get_Parameter_Value("^[[:space:]]*ClientAliveInterval[[:space:]]+", file_Name, "2") 
		if PARAM_VALUE  < 900:
			Info = "The timeout interval for SSH idle session is not set correctly"
			Log_Info("True", STIG_ID, Info, 'FAILED')

		STIG_ID="OL6-00-000231"
		file_Name = '/etc/ssh/sshd_config'
		Get_Parameter_Value("^[[:space:]]*ClientAliveCountMax[[:space:]]+", file_Name, "2") 
		if PARAM_VALUE  != 0:
			Info = "The timeout count for SSH idle session is not set correctly"
			Log_Info("True", STIG_ID, Info, 'FAILED')
		
		Info='The SSH daemon is allowing user environment settings'
		STIG_ID="OL6-00-000241"
		file_Name = '/etc/ssh/sshd_config'
  		Check_Pattern_Presence_In_File( "^[[:space:]]*PermitUserEnvironment.*no", file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
			Log_Info("True", STIG_ID, Info, 'FAILED')

		INFO="System is permitting interactive boot"
		STIG_ID="OL6-00-000070"
		file_Name='/etc/sysconfig/init'
  		Check_Pattern_Presence_In_File( '^[[:space:]]*PROMPT=no',file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="The Screen rpm is not installed on the system"
  		STIG_ID="OL6-00-000071"
  		Check_For_Installed_RPM("screen")
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="xinetd service is not disabled"
		STIG_ID="OL6-00-000203"
		if (os.path.exists('/etc/init.d/xinetd') == True):
			Out_Check1 = subprocess.Popen("chkconfig xinetd --list", shell=True, stdout=subprocess.PIPE)
			Out1 = Out_Check1.communicate()[0].find('on')
			if Out1 > 1:
				Flag_Str = 'False'
 				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="atd service is not disabled"
		STIG_ID="OL6-00-000262"
		Out_Check1 = subprocess.Popen("chkconfig atd --list", shell=True, stdout=subprocess.PIPE)
		Out1 = Out_Check1.communicate()[0].find('on')
		Out_Check2 = subprocess.Popen("service atd status", shell=True, stdout=subprocess.PIPE)
		Out2 = Out_Check2.communicate()[0].find('running')
		if Out1 > 0 or Out2 > 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="ntpdate service is not disabled"
		STIG_ID="OL6-00-000265"
		Out_Check1 = subprocess.Popen("chkconfig ntpdate --list", shell=True, stdout=subprocess.PIPE)
		Out1 = Out_Check1.communicate()[0].find('on')
		Out_Check2 = subprocess.Popen("service ntpdate status", shell=True, stdout=subprocess.PIPE)
		Out2 = Out_Check2.communicate()[0].find('running')
		if Out1 > 0 or Out2 > 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System not configured for SMB client using smbclient"
		STIG_ID="OL6-00-000272"
		file_Name='/etc/samba/smb.conf'
  		Check_Pattern_Presence_In_File( '^[[:space:]]*client.*signing.*=.*mandatory',file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="postfix service is not enabled"
		STIG_ID="OL6-00-000287"
		Out_Check2 = subprocess.Popen("service postfix status", shell=True, stdout=subprocess.PIPE)
		time.sleep(2)
		Out2 = Out_Check2.communicate()[0].find('running')
		if Out1 >= 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="Process core dumps are not disabled"
		STIG_ID="OL6-00-000308"
		file_Name='/etc/security/limits.conf'
  		Check_Pattern_Presence_In_File( '^[[:space:]]*.*hard.*core.*0',file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="Account inactivity is set to appropriate value"
		STIG_ID="OL6-00-000334-5"
		file_Name='/etc/default/useradd'
  		Check_Pattern_Presence_In_File( '^[[:space:]]*INACTIVE=35',file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
	
		# The STIGs 342, 343, 344 are commented as disabe SSH on second node, will create issues 
		# with create database	
		'''
		INFO="The umask for bashrc shell is not set to appropriate value"
		STIG_ID="OL6-00-000342"
		Out_Check1 = subprocess.Popen("grep 'umask.*077' /etc/bashrc", shell=True, stdout=subprocess.PIPE)
		Out2 = Out_Check1.communicate()[0]
		if Out2 == '':
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="The umask for csh shell is not set to appropriate value"
		STIG_ID="OL6-00-000343"
		Out_Check1 = subprocess.Popen("grep 'umask.*077' /etc/csh.cshrc", shell=True, stdout=subprocess.PIPE)
		Out2 = Out_Check1.communicate()[0]
		if Out2 == '':
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="The umask for /etc/profile is not set to appropriate value"
		STIG_ID="OL6-00-000344"
		Out_Check1 = subprocess.Popen("grep 'umask.*077' /etc/profile", shell=True, stdout=subprocess.PIPE)
		Out2 = Out_Check1.communicate()[0]
		if Out2 == '':
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
		'''

		# The STIGs 357/372 are commented in 12.1.2.7 as they are causing issues in creating database/dbstorage
		''' Begin Comment
		INFO="Excessive login failures beyond 15 minute interval is not disabled"
		STIG_ID="OL6-00-000357"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Presence_In_File ("pam_faillock.so", file_Name)
		if not  pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
		else:
			file_Name='/etc/pam.d/password-auth'
  			Check_Pattern_Presence_In_File ("pam_faillock.so", file_Name)
			if not  pattern_Present:
				Flag_Str = 'False'
 				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="OS is not configured to log unsuccessful logon/access"
		STIG_ID="OL6-00-000372"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Presence_In_File( 'pam_lastlog.so',file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
		End Comment'''
		# End Comment

		INFO="The /etc/security/opasswd file does not exist"
		STIG_ID="GEN000800"
		write_to_Check_Tracing('Checking if /etc/security/opasswd file exists or not',0)
		if (os.path.exists('/etc/security/opasswd')==False):
 			Log_Info('False', STIG_ID, INFO, "FAILED")
	
		INFO="The system-auth-ac are not included in pam.d files"
		cmd = 'grep -c system-auth-ac /etc/pam.d/* | wc -l'
		str = 'Executing the command : ' + 'grep -c system-auth-ac /etc/pam.d/* | wc -l' +  ' : to check whether system-auth-ac entries are included in pam.d file'
		write_to_Check_Tracing(str, 0)
		out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
		out_output = out.communicate()[0].strip('\n')
		if (out_output is ''):
			Log_Info('False',STIG_ID, INFO, "FAILED")
		'''
		Flag=0
		Src = '/etc/pam.d/system-auth'
		dst = 'system-auth-ac'
		INFO="Global settings defined in system-auth must be applied in the pam.d definition files"
		STIG_ID="GEN000600-2"
		if (os.path.exists('/etc/pam.d/system-auth')==True):
			path = os.path.islink(Src)
			if (path != False):
				Flag=1
		else:
			Flag=1
		if (Flag == 1):
			Log_Info('False',STIG_ID, INFO, "FAILED")
		'''	
	
		INFO="maxlogins parameter is not set to desired value"
  		STIG_ID="GEN000450"
		file_Name="/etc/security/limits.conf"
		search_Cmd = 'egrep -v ^# /etc/security/limits.conf | egrep -e "*  hard  maxlogins  10"'
		str = 'Executing the command : ' + search_Cmd + ' : to check the maxlogin parameter is set to the desired value'
		write_to_Check_Tracing(str, 0)
		p_search = subprocess.Popen(search_Cmd, shell=True, stdout=subprocess.PIPE)
		code = p_search.communicate()[0]
		if code == '':
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
		
		#Note : For files, pass the list as /etc/ntp.conf
		#       For directory, pass the list as /etc/
		if (os.path.exists('/etc/ntp.conf')==True):
			FILES_LIST = ['/etc/ntp.conf', '/usr/sbin/sshd']
			INFO_LIST=[' time synchronization ', ' network service daemon ']
			STIG_ID_LIST = ['GEN000253','GEN001190'] 
		else:
			FILES_LIST = ['/usr/sbin/sshd']
			INFO_LIST=[' network service daemon ']
			STIG_ID_LIST = ['GEN001190'] 
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'Check')

		STIG_ID_LIST = ['GEN001210','GEN001210','GEN001210','GEN001210','GEN001210','GEN001210','GEN001210'] 
		FILES_LIST = ['/etc/','/bin/','/usr/bin/', '/usr/lbin/','/usr/usb/', '/sbin/','/usr/sbin/']
		INFO_LIST = ['/etc/','/bin/','/usr/bin/', '/usr/lbin/','/usr/usb/', '/sbin/','/usr/sbin/']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'check')

		STIG_ID_LIST = ['GEN001270','GEN001290','GEN001290','GEN001290','GEN001310','GEN001310'] 
		FILES_LIST = ['/var/log/','/usr/share/man/','/usr/share/info/', '/usr/share/infopage/','/usr/lib/','/lib/']
		INFO_LIST = ['/var/log/','/usr/share/man/','/usr/share/info/', '/usr/share/infopage/','/usr/lib/','/lib/']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'check')

		STIG_ID_LIST = ['GEN001361','GEN001365','GEN001369','GEN001374','GEN001390','GEN001394'] 
		FILES_LIST = ['/var/yp/','/etc/resolv.conf','/etc/hosts', '/etc/nsswitch.conf','/etc/passwd','/etc/group']
		INFO_LIST = ['/var/yp/','/etc/resolv.conf','/etc/hosts', '/etc/nsswitch.conf','/etc/passwd','/etc/group']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'check')

		STIG_ID_LIST = ['GEN001430','GEN001590','GEN001590','GEN001810','GEN002230'] 
		FILES_LIST = ['/etc/shadow','/etc/rc*','/etc/init.d','/etc/skel','/etc/shells']
		INFO_LIST = ['/etc/shadow','/etc/rc*','/etc/init.d','/etc/skel','/etc/shells']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'check')

		STIG_ID_LIST = ['GEN001730','GEN001730','GEN001730','GEN001730','GEN001730']
		FILES_LIST = ['/etc/bashrc','/etc/chs.cshrc','/etc/csh.login','/etc/csh.logout','/etc/environment']
		INFO_LIST = ['/etc/bashrc','/etc/chs.cshrc','/etc/csh.login','/etc/csh.logout','/etc/environment']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'check')

		STIG_ID_LIST = ['GEN001730','GEN001730','GEN001730','GEN001730']
		FILES_LIST = ['/etc/ksh.kshrc','/etc/profile','/etc/suid_profile','/etc/profile.d/*']
		INFO_LIST = ['/etc/ksh.kshrc','/etc/profile','/etc/suid_profile','/etc/profile.d/*']
		Manage_ACL(FILES_LIST, STIG_ID_LIST, INFO_LIST, 'check')

		#sys.exit(0)
		#INFO="The time synchronization file has an extended ACL"
		#STIG_ID="GEN000253"
		#file_Name='/etc/ntp.conf'
		#if (os.path.exists('/etc/ntp.conf')==True):
		#	Check_ACL_exist(file_Name)
		#	if exists_flag  == True:
		#	Flag_Str = 'False'
 		#	Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		#INFO="The network service daemon sshd have an extended ACL"
		#STIG_ID="GEN001190"
		#file_Name='/usr/sbin/sshd'
		#Check_ACL_exist(file_Name)
		#if exists_flag  == True:
		#	Flag_Str = 'False'
 		#	Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		'''
		INFO="Linux Security Module SELINUX not configured to limit the privileges of system services"
		STIG_ID="GEN000000-LNX00800"
		cmd = 'cat /etc/sysconfig/selinux  | grep -v "^#" | egrep -q "SELINUX=enforcing"'
		str = 'Executing the command : ' + cmd
		write_to_Check_Tracing(str,0)
		out=subprocess.call(cmd, shell=True)
		if out != 0: 
			Flag_Str='False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="Linux Security Module SELINUXTYPE not configured to limit the privileges of system services"
		STIG_ID="GEN000000-LNX00800"
		cmd = 'cat /etc/sysconfig/selinux  | grep -v "^#" | egrep -q "SELINUXTYPE=targeted"'
		str = 'Executing the command : ' + cmd
		write_to_Check_Tracing(str,0)
		out1=subprocess.call(cmd, shell=True)
		if out1 != 0:
			cmd = 'cat /etc/sysconfig/selinux  | grep -v "^#" | egrep -q "SELINUXTYPE=strict"'
			out2=subprocess.call(cmd, shell=True)
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			if out2 != 0: 
				Flag_Str='False'
 				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
		'''	
		INFO="The successful login is not logged"
		STIG_ID="GEN000440"
		str = 'Checking if successful login is logged or not'
		write_to_Check_Tracing(str,0)
		if (os.path.exists('/var/log/wtmp')==False):
 			Log_Info('False', STIG_ID, INFO, "FAILED")

		INFO="The unsuccessful login is not logged"
		str = 'Checking if unsuccessful login is logged or not'
		write_to_Check_Tracing(str,0)
		if (os.path.exists('/var/log/btmp')==False):
 			Log_Info('False', STIG_ID, INFO, "FAILED")

	  	INFO="sendmail decode command is not commented in /etc/aliases"
  		STIG_ID="GEN004640"
		file_Name='/etc/aliases'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*decode:[[:space:]]*root", file_Name)
		if  pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
  	
		INFO="'uucp' service is active"
  		STIG_ID="LNX00320"
		file_Name='/etc/passwd'
  		Check_Pattern_Presence_In_File( "^[[:space:]]*uucp:.*uucp", file_Name)
		if pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="Ctrl-Alt-Del key combination is not disabled"
  		STIG_ID="LNX00580"
		file_Name='/etc/inittab'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*ca::ctrlaltdel:/usr/bin/logger*-p*security*info*CTRL-ALT-DEL*key*is*pressed*", file_Name) 
		if pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")	
		
  		INFO="The minimum password length is not set to fourteen characters"
  		STIG_ID="GEN000580"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*password.*pam_cracklib.so.*minlen=14.*", file_Name) 
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")	

  		INFO="The maxrepeat characters in a password is not set to 3 characters"
  		STIG_ID="LNX00680"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*password.*pam_cracklib.so.*maxrepeat=3.*", file_Name) 
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")	

  		INFO="The difok parameter is not set to 8 characters"
  		STIG_ID="OL6-00-000060"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*password.*pam_cracklib.so.*difok=8.*", file_Name) 
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")	

		if ol6_Flag == 'FALSE':   # This condition holds good for LNX00060, 70, 80, 90, 100 STIG IDs
			file_Name='/etc/syslog.conf'
		else:
			file_Name = '/etc/rsyslog.conf'
  		INFO="auth,user entry not available for syslog messages in " + file_Name + "  file "
  		STIG_ID="LNX000060"
  		Check_Pattern_Presence_In_File( "^[[:space:]]*auth.*user.*/var/log/messages", file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
  	
		INFO="kern log entry not available for syslog messages in " + file_Name +  " file "
  		STIG_ID="LNX000070"
  		Check_Pattern_Presence_In_File( "^[[:space:]]*kern.*/var/log/kern.log", file_Name)
		if  not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
  
		INFO="daemon log entry not available for syslog messages in " + file_Name + " file "
  		STIG_ID="LNX000080"
  		Check_Pattern_Presence_In_File( "^[[:space:]]*daemon.*/var/log/daemon.log", file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

	  	INFO="syslog log entry not available for syslog messages in " + file_Name +  " file "
  		STIG_ID="LNX000090"
  		Check_Pattern_Presence_In_File( "^[[:space:]]*syslog.*/var/log/syslog", file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

	  	INFO="unused log entry not available for syslog messages in " + file_Name + " file "
  		STIG_ID="LNX000100"
  		Check_Pattern_Presence_In_File( "^[[:space:]]*lpr.*local[1-9].*/var/log/unused.log", file_Name)
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="RealVNC rpm is installed on system"
  		STIG_ID="2006-T-0013"
		if ol6_Flag == 'FALSE':
  			Check_For_Installed_RPM("vnc-server")
			if pattern_Present:
				Flag_Str = 'False'
 				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
		else:
  			Check_For_Installed_RPM("tigervnc-server")
			if pattern_Present:
				Flag_Str = 'False'
 				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="rsh-server rpm is installed on system"
  		STIG_ID="GEN003825"
  		Check_For_Installed_RPM("rsh-server")
		if pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="The AIDE rpm is not installed on the system"
  		STIG_ID="OL6-00-000016"
  		Check_For_Installed_RPM("aide")
		if not pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="The xinetd rpm is installed on the system"
  		STIG_ID="OL6-00-000204"
  		Check_For_Installed_RPM("xinetd")
		if pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="Support for usb device found in kernel"
  		STIG_ID="LNX00040"
		file_Name=GRUB_CONF
  		Check_Pattern_Absence_In_File( "^[[:space:]]*kernel.*nousb.*", file_Name)
		if not pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="FAIL_DELAY is not set to desired value"
		STIG_ID="GEN000480"
		file_Name='/etc/login.defs'
  		Check_Pattern_Absence_In_File ("[[:space:]]*FAIL_DELAY[[:space:]]*4", file_Name) 
		if not pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="Login delay is not enabled in /etc/pam.d/system-auth"
  		STIG_ID="GEN000480"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Absence_In_File( "[[:space:]]*auth.*optional.*pam_faildelay.so.*delay=5000000", file_Name) 
		if not pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="Maximum age for a password change is more than 60 days"
		STIG_ID="GEN000700"
		file_Name='/etc/login.defs'
		Get_Parameter_Value("^[[:space:]]*PASS_MAX_DAYS[[:space:]]+", file_Name, "2") 
		if PARAM_VALUE > 60:
			Log_Info("True", STIG_ID, INFO,'FAILED')

		INFO="Password can be changed more than once in 24 hours"
  		STIG_ID="GEN000540"
 		Get_Parameter_Value( "^[[:space:]]*PASS_MIN_DAYS[[:space:]]+", file_Name, "2")
		if PARAM_VALUE == 0:
     			Log_Info("True", STIG_ID,INFO,"FAILED") 

		INFO="Password length is less than 15 characters"
  		STIG_ID="OL6-00-000050"
  		Get_Parameter_Value ("^[[:space:]]*PASS_MIN_LEN[[:space:]]+", file_Name, "2") 
		if PARAM_VALUE < 15:
			Log_Info("True", STIG_ID, INFO, "FAILED")

		# Disabled as it causes databse creation failure after the STIG sctrips are executed
		'''
		INFO="Direct login as root is enabled from ssh"
  		STIG_ID="GEN001120"
		file_Name='/etc/ssh/sshd_config'
  		Check_Pattern_Absence_In_File( "^[[:space:]]*PermitRootLogin[[:space:]]*no", file_Name)
		if not pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
		'''

  		if ol6_Flag == 'FALSE':	
			INFO="ekshell supported by the pam.rhost"
  			STIG_ID="GEN002100"
			file_Name='/etc/pam.d/ekshell'
  			Check_Pattern_Presence_In_File ("^[[:space:]]*auth.*pam_rhosts_auth.so" , file_Name)
			if pattern_Present:
				Flag_Str = 'False'
 				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

 		INFO="Access to cron is not through cron.allow and cron.deny"
  		STIG_ID="GEN002960"
		str = 'Checking if cron.allow and cron.deny files exists or not'
		if (os.path.exists('/etc/cron.allow') == False) or (os.path.exists('/etc/cron.deny') == False):
     			Log_Info("True", STIG_ID, INFO, "FAILED")

		STIG_ID="OL6-00-000080"
		file_Name = '/etc/sysctl.conf'
		Get_Parameter_Value("^[[:space:]]*net.ipv4.conf.default.send_redirects[[:space:]]+", file_Name, "3") 
		if PARAM_VALUE  != 0:
			Info = "Network parameter net.ipv4.conf.default.send_redirects is not set correctly"
			Log_Info("True", STIG_ID, Info, 'FAILED')

		STIG_ID="OL6-00-000081"
		file_Name = '/etc/sysctl.conf'
		Get_Parameter_Value("^[[:space:]]*net.ipv4.conf.all.send_redirects[[:space:]]+", file_Name, "3") 
		if PARAM_VALUE  != 0:
			Info = "Network parameter net.ipv4.conf.all.send_redirects is not set correctly"
			Log_Info("True", STIG_ID, Info, 'FAILED')

		STIG_ID="OL6-00-000083"
		file_Name = '/etc/sysctl.conf'
		Get_Parameter_Value("^[[:space:]]*net.ipv4.conf.all.accept_source_route[[:space:]]+", file_Name, "3") 
		if PARAM_VALUE  != 0:
			Info = "Network parameter net.ipv4.conf.all.accept_source_route is not set correctly"
			Log_Info("True", STIG_ID, Info, 'FAILED')

		STIG_ID="OL6-00-000086"
		file_Name = '/etc/sysctl.conf'
		Get_Parameter_Value("^[[:space:]]*net.ipv4.conf.all.secure_redirects[[:space:]]+", file_Name, "3") 
		if PARAM_VALUE  != 0:
			Info = "Network parameter net.ipv4.conf.all.secure_redirects is not set correctly"
			Log_Info("True", STIG_ID, Info, 'FAILED')

		STIG_ID="OL6-00-000088"
		file_Name = '/etc/sysctl.conf'
		#delete_line = 'sed -i "/net.ipv4.conf.all.log_martians=.*/d" ' + file_Name
                #print delete_line
                #p = subprocess.Popen(delete_line, shell=True, stdout=subprocess.PIPE)
                #code = p.communicate()[0]
                #if code == '':
		Get_Parameter_Value("^[[:space:]]*net.ipv4.conf.all.log_martians[[:space:]]+", file_Name, "3") 
		if PARAM_VALUE  != 1:
			Info = "Network parameter net.ipv4.conf.all.log_martians is not set correctly"
			Comment_Line_Matching_Pattern("^[[:space:]]*net.ipv4.conf.all.log_martians=.*",file_Name, STIG_ID, "")
			Log_Info("True", STIG_ID, Info, 'FAILED')

		STIG_ID="OL6-00-000092"
		file_Name = '/etc/sysctl.conf'
		Get_Parameter_Value("^[[:space:]]*net.ipv4.icmp_echo_ignore_broadcasts[[:space:]]+", file_Name, "3") 
		if PARAM_VALUE  != 1:
			Info = "Network parameter net.ipv4.icmp_echo_ignore_broadcasts is not set correctly"
			Log_Info("True", STIG_ID, Info, 'FAILED')

		STIG_ID="OL6-00-000093"
		file_Name = '/etc/sysctl.conf'
		Get_Parameter_Value("^[[:space:]]*net.ipv4.icmp_ignore_bogus_error_responses[[:space:]]+", file_Name, "3") 
		if PARAM_VALUE  != 1:
			Info = "Network parameter net.ipv4.icmp_ignore_bogus_error_responses is not set correctly"
			Log_Info("True", STIG_ID, Info, 'FAILED')

		#STIG_ID="OL6-00-000096"
		#file_Name = '/etc/sysctl.conf'
		#Get_Parameter_Value("^[[:space:]]*net.ipv4.conf.all.rp_filter[[:space:]]+", file_Name, "3") 
		#if PARAM_VALUE  != 1:
		#	Info = "Network parameter net.ipv4.conf.all.rp_filter is not set correctly"
		#	Log_Info("True", STIG_ID, Info, 'FAILED')

		STIG_ID="GEN003600"
		Get_Sysctl_Parameter_Value('net.ipv4.tcp_max_syn_backlog')
		if PARAM_VALUE  == 0:
			Info = "Network parameter net.ipv4.tcp_max_syn_backlog is not set"
			Log_Info("True", STIG_ID, Info, 'FAILED')
		else:
    			if PARAM_VALUE < 1280:
      				Info = "Network parameter net.ipv4.tcp_max_syn_backlog are not proper value"
      				Log_Info("True", STIG_ID, Info, 'FAILED')

 	 	INFO="tcpdump rpm is installed on system"
  		STIG_ID="GEN003865"
  		Check_For_Installed_RPM("tcpdump")
		if pattern_Present:
			Flag_Str = "False"
	  		Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="sendmail help command is enabled"
  		STIG_ID="GEN004540"
		file_Name='/etc/mail/sendmail.cf'
		write_to_Check_Tracing('Checking if /etc/mail/sendmail.cf file exists or not',0)
		if(os.path.exists(file_Name)==True):
  			Check_Pattern_Presence_In_File ("^[[:space:]]*O.*HelpFile=/etc/mail/helpfile.*", file_Name)
			if pattern_Present:
				Flag_Str = "False"
  				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		time.sleep(3)

  		INFO="sendmail version is not hidden."
 		STIG_ID="GEN004560"
		file_Name='/etc/mail/sendmail.cf'
		if (os.path.exists('/etc/mail/sendmail.cf')==True):
  			Check_Pattern_Presence_In_File( "^[[:space:]]*O.*SmtpGreetingMessage=.*Sendmail.*", file_Name) 
			if pattern_Present:
				Flag_Str = "False"
  				Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="The USB device is not disabled"
 		STIG_ID="OL6-00-000503"
		file_Name='/etc/modprobe.d/*'
  		Check_Pattern_Presence_In_File( "install.*usb-storage.*/bin/true", file_Name) 
		if not pattern_Present:
			Flag_Str = "False"
  			Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="The DCCP protocol is not disabled"
 		STIG_ID="OL6-00-000124"
		file_Name='/etc/modprobe.d/*'
  		Check_Pattern_Presence_In_File( "install.*dccp.*/bin/true", file_Name) 
		if not pattern_Present:
			Flag_Str = "False"
  			Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="The SCTP protocol is not disabled"
 		STIG_ID="OL6-00-000125"
		file_Name='/etc/modprobe.d/*'
  		Check_Pattern_Presence_In_File( "install.*sctp.*/bin/true", file_Name) 
		if not pattern_Present:
			Flag_Str = "False"
  			Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="The TIPC protocol is not disabled"
 		STIG_ID="OL6-00-000127"
		file_Name='/etc/modprobe.d/*'
  		Check_Pattern_Presence_In_File( "install.*tipc.*/bin/true", file_Name) 
		if not pattern_Present:
			Flag_Str = "False"
  			Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")


 	 	INFO="sendmail package is installed on the system"
  		STIG_ID="OL6-00-000288"
  		Check_For_Installed_RPM("sendmail")
		if pattern_Present:
			Flag_Str = "False"
	  		Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")

	# ACCESS Check (-access option will check the owners/groups of system files)
	if ((check_All == 'all') or (argv[2] == 'access')):

		INFO='The /etc/securetty file owner is not root'
		STIG_ID='GEN000000-LNX00640'
		write_to_Check_Tracing('Checking if /etc/securetty file exists or not',0)
		if (os.path.exists('/etc/securetty')==True):
			cmd = "ls -l /etc/securetty | awk '{print $3}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/security/access.conf file owner is not root'
		STIG_ID='GEN000000-LNX00400'
		write_to_Check_Tracing('Checking if /etc/security/access.conf file exists or not',0)
		if (os.path.exists('/etc/security/access.conf')==True):
			cmd = "ls -l /etc/security/access.conf | awk '{print $3}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/sysctl.conf file owner is not root'
		STIG_ID='GEN000000-LNX00480'
		write_to_Check_Tracing('Checking if /etc/sysctl.conf file exists or not',0)
		if (os.path.exists('/etc/sysctl.conf')==True):
			cmd = "ls -l /etc/sysctl.conf | awk '{print $3}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/sysctl.conf group is not owned by root'
		STIG_ID='GEN000000-LNX00500'
		if (os.path.exists('/etc/sysctl.conf')==True):
			cmd = "ls -l /etc/sysctl.conf | awk '{print $4}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/resolv.conf group is not owned by root'
		STIG_ID='GEN001362'
		write_to_Check_Tracing('Checking if /etc/resolve.conf file exists or not',0)
		if (os.path.exists('/etc/resolv.conf')==True):
			cmd = "ls -l /etc/resolv.conf | awk '{print $4}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/gshadow file is not owned by root'
		STIG_ID='OL6-00-000036'
		write_to_Check_Tracing('Checking if /etc/gshadow file exists or not',0)
		if (os.path.exists('/etc/gshadow')==True):
			cmd = "ls -l /etc/gshadow | awk '{print $4}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/gshadow owner is not root'
		STIG_ID='OL6-00-000037'
		if (os.path.exists('/etc/gshadow')==True):
			cmd = "ls -l /etc/gshadow | awk '{print $3}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/shadow file is not owned by root'
		STIG_ID='OL6-00-000033'
		write_to_Check_Tracing('Checking if /etc/shadow file exists or not',0)
		if (os.path.exists('/etc/shadow')==True):
			cmd = "ls -l /etc/shadow | awk '{print $4}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/shadow owner is not root'
		STIG_ID='OL6-00-000033'
		if (os.path.exists('/etc/shadow')==True):
			cmd = "ls -l /etc/shadow | awk '{print $3}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/securetty group is not owned by root'
		STIG_ID='GEN000000-LNX00620'
		if (os.path.exists('/etc/securetty')==True):
			cmd = "ls -l /etc/securetty | awk '{print $4}' | egrep -q  root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")

		INFO='The /etc/security/access.conf group is not owned by root'
		STIG_ID='GEN000000-LNX00420'
		if (os.path.exists('/etc/security/access.conf')==True):
			cmd = "ls -l /etc/security/access.conf | awk '{print $4}' | egrep -q  root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")
	
		INFO="Not Configured a supplemental group for users permitted to switch to the root"
		STIG_ID="GEN000850"
		file_Name='/etc/pam.d/su'
		write_to_Check_Tracing('Checking if /etc/pam.d/su file exists or not',0)
		if (os.path.exists(file_Name)==False):
			Log_Info('False', STIG_ID, "The /etc/pam.d/su file not configured, please contact System Administrtor", "FAILED")
		else:
        		Check_Pattern_Presence_In_File( "^[[:space:]]*auth.*[[:space:]]*required.*[[:space:]]*pam_wheel.so", file_Name)
        		if pattern_Present == 0:
                		Flag_Str = 'False'
                		Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="The remember password parameter is not set to 5 in PAM configuration file"
  		STIG_ID="GEN000800"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Absence_In_File("[[:space:]]*password.*sufficient.*pam_unix.so.*remember=5*", file_Name) 
		if not pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO='The /etc/ntp.conf file owner is not root'
		STIG_ID='GEN000250'
		write_to_Check_Tracing('Checking if /etc/ntp.conf file exists or not',0)
		if (os.path.exists('/etc/ntp.conf')==True):
			cmd = "ls -l /etc/ntp.conf | awk '{print $3}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")
		#else:
                # 	Log_Info('True', STIG_ID, 'Check if user is root : /etc/ntp.conf file not configured', "FAILED")

		INFO='The /etc/ntp.conf file group owner is not root'
		STIG_ID='GEN000251'
		write_to_Check_Tracing('Checking if /etc/ntp.conf file exists or not',0)
		if (os.path.exists('/etc/ntp.conf')==True):
			cmd = "ls -l /etc/ntp.conf | awk '{print $3}' | egrep -q root"
			str = 'Executing the command : ' + cmd
			write_to_Check_Tracing(str,0)
			u = os.system(cmd)
			if u != 0:
				Log_Info('False',STIG_ID, INFO, "FAILED")
		#else:
                # 	Log_Info('True', STIG_ID, 'Check for group owner : /etc/ntp.conf file not configured', "FAILED")

		INFO='The root login to virtual consoles are allowed'
		STIG_ID='OL6-00-000027'
		write_to_Check_Tracing('Checking for root login acces to virtual consoles',0)
		file_Name='/etc/securetty'
  		Check_Pattern_Presence_In_File( "^vc/[0-9]", file_Name) 
		if pattern_Present:
			Flag_Str = "False"
  			Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")

		INFO='The root login to serial consoles are allowed'
		STIG_ID='OL6-00-000028'
		write_to_Check_Tracing('Checking for root login acces to serial consoles',0)
		file_Name='/etc/securetty'
  		Check_Pattern_Presence_In_File( "^ttyS[0-9]", file_Name) 
		if pattern_Present:
			Flag_Str = "False"
  			Log_Info (Flag_Str, STIG_ID, INFO, "FAILED")


	# ACCOUNT Check (-account option will check different accounts defined/used in the system)
	if ((check_All == 'all') or (argv[2] == 'account')):

		file_Name = '/etc/passwd'	
		INFO="Duplicate accounts found on the system"
		STIG_ID="GEN000300"
		Check_Duplicate_Accounts(file_Name,'cat /etc/passwd | grep -v "^#" | cut -d: -f1 | uniq -d | wc -l')
		if exists_flag == True:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="Duplicate UIDs found on the system"
		STIG_ID="GEN000320"
		Check_Duplicate_Accounts(file_Name,'cat /etc/passwd | grep -v "^#" | cut -d: -f3 | uniq -d | wc -l')
		if exists_flag == True:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="Multiple root UIDs found on the system"
		STIG_ID="GEN000880"
		Check_Duplicate_Accounts(file_Name,'cat /etc/passwd | grep -v "^#" | cut -d: -f3 | grep 0 | uniq -d | wc -l')
		if exists_flag == True:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="The root user home directory set to /"
		STIG_ID="GEN000900"
		write_to_Check_Tracing('Checking if the root user home directory is set to /',0)
		file_Name='/etc/passwd'
		fp = open(file_Name,'r')
		for line in fp.readlines():
			if line.startswith('#'):
				continue
			else:
				temp_line =  line.strip('\n')
				string_check = line.split(':')
				if (string_check[0] == 'root' and string_check[5] == '/'):
					Flag_Str = 'False'
 					Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
		fp.close()

		INFO="The GIDs are not cross referenced in /etc/passwd and /etc/shadow files, contact System Administrators to correct security vulnerabilities"
		STIG_ID="GEN000380"
		str = 'pwck -r | grep [delete line][no matching][invalid user name] | wc -l'
		write_to_Check_Tracing(str,0)
		Check_PWCK('pwck -r | grep "[delete line][no matching][invalid user name]" |  wc -l')
		if exists_flag==True:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
        
		INFO="The system accounts are not allowed to configure with 'nullok' option"
        	STIG_ID="GEN000560"
       		file_Name='/etc/pam.d/system-auth'
        	Check_Pattern_Presence_In_File( "^[[:space:]]*auth.*[[:space:]]*nullok", file_Name)
        	if pattern_Present:
                	Flag_Str = 'False'
               		Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="Privilege account 'shutdown' is present"
  		STIG_ID="LNX00320"
		file_Name='/etc/passwd'
  		Check_Pattern_Presence_In_File( "^[[:space:]]*shutdown:.*shutdown", file_Name)
		if pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="Privilege account 'reboot' is present"
  		STIG_ID="GEN000000LNX00320"
		file_Name='/etc/passwd'
  		Check_Pattern_Presence_In_File( "^[[:space:]]*reboot:.*reboot", file_Name)
		if pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
  	
		INFO="Privilege account 'halt' is present"
  		STIG_ID="LNX00320"
		file_Name='/etc/passwd'
  		Check_Pattern_Presence_In_File( "^[[:space:]]*halt:.*halt", file_Name) 
		if pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="Ctrl-Alt-Del combination to shutdown system is enabled"
  		STIG_ID="LNX00580"
		file_Name='/etc/inittab'
  		Check_Pattern_Presence_In_File ("^[[:space:]]*ca::ctrlaltdel:/sbin/shutdown", file_Name) 
		if pattern_Present:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")	
  	
		INFO="Console access is permitted to non-root users"
  		STIG_ID="LNX0010"
		file_Name='/etc/security/access.conf'
  		Check_Pattern_Absence_In_File( "^[[:space:]]*-:ALL.*EXCEPT.*root:*LOCAL", file_Name)
		if not pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  		INFO="Access restrictions to be checked"
  		STIG_ID="LNX0020"
		file_Name='/etc/pam.d/login'
  		Check_Pattern_Absence_In_File( "^[[:space:]]*account.*required.*pam_access.so", file_Name)
		if not pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

 		INFO="Single user mode boot is enabled without a password"
  		STIG_ID="GEN000020"
		file_Name='/etc/inittab'
  		Check_Pattern_Absence_In_File( "^[[:space:]]*:S.*sulogin" , file_Name)
		if pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		STIG_ID_LIST = ['GEN000340', 'GEN000340', 'GEN000360']
		NON_PRIVILEGE_ACCOUNT = ['oprofile', 'gopher', 'avahi-autoipd']
		file_Name='/etc/passwd'
  		Find_UID_Of_Account_Name(NON_PRIVILEGE_ACCOUNT, STIG_ID_LIST, file_Name) 

  		INFO="pam_tally not used to lock account after 3 consecutive failed logins"
  		STIG_ID="GEN000460"
		file_Name='/etc/pam.d/system-auth'
  		Check_Pattern_Absence_In_File ("[[:space:]]+deny=[1-9]+[[:space:]]+unlock_time.*" , file_Name)
		if not pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		PASSWD_STRENGHT = ["lcredit", "ucredit", "dcredit", "ocredit"]
		INFO_LIST = ["lower case", "upper case", "numeric", "special"]
		STIG_ID_LIST = ["GEN000600", "GEN000600", "GEN000620", "GEN000640"]
		file_Name='/etc/pam.d/system-auth'
		Check_For_Multiple_Value_Absence_In_File(PASSWD_STRENGHT,STIG_ID_LIST,INFO_LIST, file_Name)

  		STIG_ID="LNX00340"
		Acc_Info = ['ftp' ,'games', 'news' ,'operator', 'gopher']
		str = 'Checking for accounts not needed in the system'
		write_to_Check_Tracing(str,0)
		Check_Not_Needed_Account_Info(Acc_Info, 'LNX00340')

	# FS Check (-fs option will check different file system related checks in the system)
	if (( check_All == 'all') or (argv[2] == 'fs')):
	
		cat_Cmd = '/usr/sbin/dmidecode ' + ' | grep -q domU'
		check = os.system(cat_Cmd)
		if check != 0:
		  	INFO="nodev option to non-root local partitions not available for /opt"
  			STIG_ID="GEN0000030"
			file_Name='/etc/fstab'
  			Check_Pattern_Presence_In_File( "^[[:space:]]*/dev.*/VolGroupSys.*/LogVolOpt.*opt.*ext3.*defaults.*nodev.*1.*2", file_Name)
			if not pattern_Present:
				Flag_Str = 'False'
 				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

  			INFO="nodev option to non-root local partitions not available /u01"
  			STIG_ID="GEN0000040"
  			Check_Pattern_Presence_In_File( "^[[:space:]]*/dev.*/VolGroupSys.*/LogVolU01.*u01.*ext3.*defaults.*nodev.*1.*2", file_Name)
			if  not pattern_Present:
				Flag_Str = 'False'
 				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")
	
  			INFO="nodev,nosuid,noexec option to non-root local partitions not available for tmpfs"
  			STIG_ID="GEN0000050"
  			Check_Pattern_Presence_In_File( "^[[:space:]]*tmpfs.*/dev.*/shm.*tmpfs.*defaults.*nodev.*nosuid.*noexec.*0.*0", file_Name)
			if not pattern_Present:
				Flag_Str = 'False'
 				Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

	# AUDIT Check (-audit option will audit different files related checks in the system)
	if ((check_All == 'all') or (argv[2] == 'audit')):
	
		INFO="Auditing is not enabled at boot"
  		STIG_ID="GEN000000-LNX00720"
		file_Name=GRUB_CONF
  		Check_Pattern_Absence_In_File( "^[[:space:]]*kernel.*audit=1.*", file_Name)
		if not pattern_Absent:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")


		INFO="System is not configured to execute adjtimex system call"
  		STIG_ID="OL6-00-000165"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w adjtimex /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to execute clock_settime system call"
  		STIG_ID="OL6-00-000171"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w clock_settime /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is configured to execute localtime call"
  		STIG_ID="OL6-00-000173"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w /etc/localtime /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit automatic account creation"
  		STIG_ID="OL6-00-000174(5,6,7)"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit MAC for SELinux"
  		STIG_ID="OL6-00-000183"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w /etc/selinux /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for chmod permissions"
  		STIG_ID="OL6-00-000184"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w chmod /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for chown permissions"
  		STIG_ID="OL6-00-000185"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w chown /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for fchmod permissions"
  		STIG_ID="OL6-00-000186"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w fchmod /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for fchmodat permissions"
  		STIG_ID="OL6-00-000187"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w fchmodat /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for fchown permissions"
  		STIG_ID="OL6-00-000188"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w fchown /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for fchownat permissions"
  		STIG_ID="OL6-00-000189"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w fchownat /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for fremovexattr permissions"
  		STIG_ID="OL6-00-000190"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w fremovexattr /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for fsetxattr permissions"
  		STIG_ID="OL6-00-000191"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w fsetxattr /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for lchown permissions"
  		STIG_ID="OL6-00-000192"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w lchown /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for lremovexattr permissions"
  		STIG_ID="OL6-00-000193"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w lremovexattr /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for lsetxattr permissions"
  		STIG_ID="OL6-00-000194"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w lsetxattr /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for removexattr permissions"
  		STIG_ID="OL6-00-000195"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w removexattr /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit DAC for setxattr permissions"
  		STIG_ID="OL6-00-000196"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w setxattr /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit successful file system mount "
  		STIG_ID="OL6-00-000199"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w mount /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		STIG_ID = 'OL6-00-000200'
		INFO = 'System is not configured to audit user deletions' 
		file_Name='/etc/audit/audit.rules'
		ACTION_LIST=['rmdir','unlink','unlinkat','rename','renameat']
		count = 1
		for count, actions in enumerate(ACTION_LIST): 
			Check_User_Deletions(actions, STIG_ID, INFO)

		INFO="System is not configured to audit changes to /etc/sudoers file"
  		STIG_ID="OL6-00-000201"
		file_Name='/etc/audit/audit.rules'
		Execute_AUDIT_Command("sudo grep -w /etc/sudoers /etc/audit/audit.rules")
		if AUDIT_RULE_SET == 0:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

		INFO="System is not configured to audit module management"
  		STIG_ID="OL6-00-000202"
		file_Name='/etc/audit/audit.rules'
		success_count = 0
		Execute_AUDIT_Command("sudo egrep -e '(-w | -F path=)/sbin/modprobe' /etc/audit/audit.rules")
		if AUDIT_RULE_SET != 0:
			success_count = 1
			Execute_AUDIT_Command("sudo egrep -e '(-w | -F path=)/sbin/insmod' /etc/audit/audit.rules")
			if AUDIT_RULE_SET != 0:
				success_count = 2 
				Execute_AUDIT_Command("sudo egrep -e '(-w | -F path=)/sbin/rmmod' /etc/audit/audit.rules")
				if AUDIT_RULE_SET != 0:
					success_count = 3 
					Execute_AUDIT_Command("sudo grep -w init_module /etc/audit/audit.rules")
					if AUDIT_RULE_SET != 0:
						success_count = 4 
						Execute_AUDIT_Command("sudo grep -w delete_module /etc/audit/audit.rules")
						if AUDIT_RULE_SET != 0:
							success_count = 5 

		if success_count != 5:
			Flag_Str = 'False'
 			Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

	# PERM Check (-perm option will check the file / directory permissions of different files/dir within in the system)
	if ((check_All == 'all') or (argv[2] == 'perm')):

		STIG_ID_LIST = ['GEN001580','GEN001580'] 
		FILES_LIST = ['/etc/init.d/init.oak', '/opt/oracle/oak/install/init.oak']
		str = 'Checking file permissions of ' + ", ".join(FILES_LIST) + ' files for 0744'
		write_to_Check_Tracing(str,0)
		Check_File_Permissions(FILES_LIST, STIG_ID_LIST, '-rwxr--r--', '0744')

		STIG_ID_LIST = ['GEN001364', 'GEN001368'] 
		FILES_LIST = ['/etcresolv.conf','/etc/hosts']
		str = 'Checking file permissions of ' + ", ".join(FILES_LIST) + ' files for 0644'
		write_to_Check_Tracing(str,0)
		Check_File_Permissions(FILES_LIST, STIG_ID_LIST, '-rw-r--r--', '0644')

		FILES_LIST=['/etc/security/access.conf', '/etc/crontab','/etc/cron.deny', '/etc/cron.allow', '/etc/snmp/snmpd.conf','/etc/securetty','/boot/grub/grub.conf'] 
		str = 'Checking file permissions of ' + ", ".join(FILES_LIST) + ' files for 0600'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=['LNX00520', 'LNX00440' ,'GEN003080','GEN003200', 'GEN005320', 'GEN000000-LNX00660','OL6-00-000067']
  		Check_File_Permissions (FILES_LIST, STIG_ID_LIST, '-rw-------', '0600')
	
			
		if ol6_Flag == 'FALSE':
			if (os.path.exists('/etc/ntp.conf')==True):
  				FILES_LIST=["/etc/syslog.conf", "/etc/ntp.conf"]
  				STIG_ID_LIST=["GEN005390", "GEN000252"]
			else:
  				FILES_LIST=["/etc/syslog.conf"]
  				STIG_ID_LIST=["GEN005390"]
		else:
			if (os.path.exists('/etc/ntp.conf')==True):
  				FILES_LIST=["/etc/rsyslog.conf", "/etc/ntp.conf"]
  				STIG_ID_LIST=["GEN005390", "GEN000252"]
			else:
  				FILES_LIST=["/etc/rsyslog.conf"]
  				STIG_ID_LIST=["GEN005390"]
		str = 'Checking file permissions of ' + ", ".join(FILES_LIST) + ' files for 0640'
		write_to_Check_Tracing(str,0)
  		Check_File_Permissions( FILES_LIST, STIG_ID_LIST, '-rw-r-----', '0640')
	
  		FILES_LIST=["/etc/sysctl.conf"]
		str = 'Checking file permissions of ' + ", ".join(FILES_LIST) + ' files for 0600'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=["LNX00520"]
  		Check_File_Permissions( FILES_LIST, STIG_ID_LIST, '-rw-------', '0600')

		STIG_ID_LIST = ['GEN000920', 'GEN003080-2', 'GEN003080-2', 'GEN003080-2', 'GEN003080-2'] 
		DIR_LIST = ['/root/', '/etc/cron.daily/', '/etc/cron.hourly/', '/cron/cron.monthly/','/cron/cron.weekly/']
		str = 'Checking directory permissions of ' + ", ".join(DIR_LIST) + ' for 0700'
		write_to_Check_Tracing(str,0)
		Check_Dir_Permissions(DIR_LIST, STIG_ID_LIST, 'drwx------', '0700')

		STIG_ID_LIST = ['GEN001300','GEN001300'] 
		DIR_LIST = ['/usr/lib','/lib']
		str = 'Checking directory permissions of ' + ", ".join(DIR_LIST) + ' for 0755'
		write_to_Check_Tracing(str,0)
		Check_Dir_Permissions(DIR_LIST, STIG_ID_LIST, 'drwxr-xr-x', '0755')

  		FILES_LIST=["/bin/traceroute"]
		str = 'Checking file permissions of ' + ", ".join(FILES_LIST) + ' files for 0700'
		write_to_Check_Tracing(str,0)
 		STIG_ID_LIST=["GEN004000"]
  		Check_File_Permissions(FILES_LIST, STIG_ID_LIST, "-rwx------", "0700") 

  		FILES_LIST=["/etc/xinetd.conf"]
		str = 'Checking file permissions of ' + ", ".join(FILES_LIST) + ' files for 0440'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=["GEN006600"]
  		Check_File_Permissions (FILES_LIST, STIG_ID_LIST, "-r--r-----", "0440")

  		FILES_LIST=["/etc/gshadow"]
		str = 'Checking file permissions of ' + ", ".join(FILES_LIST) + ' files for 0000'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=["OL6-00-000038"]
  		Check_File_Permissions (FILES_LIST, STIG_ID_LIST, "-r--------", "0000")

  		FILES_LIST=["/etc/shadow"]
		str = 'Checking file permissions of ' + ", ".join(FILES_LIST) + ' files for 0000'
		write_to_Check_Tracing(str,0)
  		STIG_ID_LIST=["OL6-00-000035"]
  		Check_File_Permissions (FILES_LIST, STIG_ID_LIST, "-r--------", "0000")

  		STIG_ID="GEN003740"
  		INFO="files in directory '/etc/xinetd.d/' have permission which are more permissive than octal 440"
		dir_Name='/etc/xinetd.d/'
  		List_Of_File_Exceeding_Give_Permission_In_Dir( dir_Name,"-440", STIG_ID, "*" ,INFO)

  		STIG_ID="GEN005340"
  		INFO="MIB files in directory '/' have permission which are more permissive than octal 640"
		dir_Name='/'
  		#List_Of_File_Exceeding_Give_Permission_In_Dir( dir_Name ,"-640", '0640', STIG_ID, "*.mib", INFO)
  		List_Of_File_Exceeding_Give_Permission_In_Dir( dir_Name ,"-640",  STIG_ID, "*.mib", INFO)

  		STIG_ID="GEN002480"
  		INFO="files in directory '/opt/oracle/oak/pkgrepos' have world writable permission of octal 777 or 666"
  		Number_Of_World_Writable_Files_In_Dir("/opt/oracle/oak/pkgrepos", "-002",STIG_ID, "*", INFO)


  		STIG_ID="GEN001280"
  		INFO="manual pages in directory '/usr/share/man/' have permission which are more permissive than octal 640"
		dir_Name='/usr/share/man'
  		#List_Of_File_Exceeding_Give_Permission_In_Dir( dir_Name,"-640", '0640', STIG_ID, "*", INFO)
  		List_Of_File_Exceeding_Give_Permission_In_Dir( dir_Name ,"-640",  STIG_ID, "*", INFO)

		DIR_LIST=["/home/grid/.mozilla/extensions", "/home/grid/.mozilla/plugins","/home/oracle/.mozilla/extensions", "/home/oracle/.mozilla/plugins"]
  		STIG_ID_LIST=["GEN001560", "GEN001560", "GEN001560", "GEN001560"]
  		Check_Dir_Permissions( DIR_LIST, STIG_ID_LIST, "drwxr-x---", "0750")

		DIR_LIST=["/etc","/bin","/etc/bin","/usr/bin","/usr/lbin", "/sbin", "/usr/usb","/usr/sbin"]
  		STIG_ID_LIST=["GEN001200","GEN001200","GEN001200","GEN001200","GEN001200","GEN001200","GEN001200","GEN001200"]
  		Check_Dir_Permissions( DIR_LIST, STIG_ID_LIST, "drwxr-x---", "0755")

	Log_Info ('True', '1111', 'Check Violations completed', "CHECK-COMPLETE")
	print_Str = '\n' + '\n=====================================================================================================================\n\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)

# This function changes the permissions of all files having permission more than given

def Change_Permission_Of_Files_Exceeding_Given_Permission_In_Dir(dir_Name, orig_Perm, new_Perm, STIG_ID, match_Pattern, Info):
	#print 'givn perm exceeding'

	NO_OF_FILES = 0
	NO_FILES = 0
	find_Cmd = "find " + dir_Name + " -path '/proc' -prune -o -name " +"'"+ match_Pattern +"'"+  " -type f  -perm " + orig_Perm + " \! -perm " + new_Perm + " -print | wc -l"
	#find_Cmd = 'find ' + dir_Name + ' -type f ! -perm ' + new_Perm
	p = subprocess.Popen(find_Cmd, shell=True, stdout=subprocess.PIPE)
	code = p.communicate()[0]
	#print type(code)
	NO_OF_FILES = int(code)
	#print NO_OF_FILES

	if NO_OF_FILES == 0: 
		Log_Info("True", STIG_ID, Info, 'ALREADY DONE')
	else:
		find_Cmd1 = "find " + dir_Name + ' -path "/proc" -prune -o -name ' + "'"+match_Pattern+"'" + " -type f -perm " + orig_Perm + "  -print | xargs chmod " + new_Perm
		if os.system(find_Cmd1) == 0:
			Log_Info("True", STIG_ID, Info, 'SUCCESSFUL')
		else:
			Log_Info("False", STIG_ID, Info, 'FAILED')
		
# This function will change the permissions

def Change_Permission_Of_World_Writable_Files_In_Dir(dir_Name, oct_perm, STIG_ID, search_Str, INFO):


	NO_OF_FILES = 0

	find_Cmd = "find " + dir_Name + " -path '/proc' -prune -o -name " + "'"+ search_Str+"'" + " -type f -perm " + oct_perm  + " -print | wc -l"
	#print find_Cmd
	p = subprocess.Popen(find_Cmd, shell=True, stdout=subprocess.PIPE)
	code = p.communicate()[0]
	NO_OF_FILES = int(code)
	
	#print NO_OF_FILES
	#print type(NO_OF_FILES)

	if NO_OF_FILES == 0:
		Log_Info("True", STIG_ID, INFO, 'ALREADY DONE')
	else:
		find_Cmd1 = "find " + dir_Name + " -path '/proc' -prune -o -name " + "'"+ search_Str+"'" + " -type f -perm " + oct_perm + "  -print | xargs chmod go-w"
		#print find_Cmd1
		if os.system(find_Cmd1) == 0:
			Log_Info("True", STIG_ID, INFO, 'SUCCESSFUL')
		else:
			Log_Info("False", STIG_ID, INFO, 'FAILED')
		

# This function gets the number of world writable files in the directory specified ----> TO DO  check with Radheshyam

def Number_Of_World_Writable_Files_In_Dir(dir_Name, oct_perm, STIG_ID, new_Str, Info):

	NO_OF_FILES = 0

	find_Cmd = "find " + dir_Name + " -path '/proc' -prune -o -name " + "'"+ new_Str+"'" + " -type f -perm " + oct_perm  + " -print | wc -l"
	str = 'Executing the command : ' + find_Cmd
	write_to_Check_Tracing(str,0)
	p = subprocess.Popen(find_Cmd, shell=True, stdout=subprocess.PIPE)
	code = p.communicate()[0]
	NO_OF_FILES = int(code)
	
	#print 'check : number of world writable files in dir' 
	#print 'No of world writable files in dir  is %d ' % NO_OF_FILES
	#print type(NO_OF_FILES)
	if NO_OF_FILES > 0:
		Log_Info("True", STIG_ID, Info, 'FAILED')


# This function lists the files exceeding given permission in directory  ----> TO DO  check with Radheshyam

def List_Of_File_Exceeding_Give_Permission_In_Dir(dir_Name, orig_Str, STIG_ID, search_Str, Info):

	NO_OF_FILES = 0

	echo_cmd = 'echo ' + orig_Str + " | sed 's/-//'"
	p = subprocess.Popen(echo_cmd, shell=True, stdout=subprocess.PIPE)
	code = p.communicate()[0]
	PERM_WITHOUT_NEGATIVE_SIGN = int(code)

	find_Cmd = "find " + dir_Name + " -path '/proc' -prune -o -name " + "'" + search_Str + "'"+ " -type f -perm " + orig_Str + " \! -perm " + str(PERM_WITHOUT_NEGATIVE_SIGN) + ' -print | wc -l'
	str_find = 'Executing the command : ' + find_Cmd
	write_to_Check_Tracing(str_find,0)
	p = subprocess.Popen(find_Cmd, shell=True, stdout=subprocess.PIPE)
	code = p.communicate()[0]
	NO_OF_FILES = int(code)
	#print 'check : number offiles exceeding perm in  wdir' 
	#print 'No of files exceedding the given perm is %d ' % NO_OF_FILES	
	if NO_OF_FILES > 0:
		Log_Info("True", STIG_ID, Info, 'FAILED')

# Sets the file name for tracing and logging of Check commands executed
def Set_Tracing_Commands_File(argv):

	global STIG_Log_File

	try:
		fptr = open(STIG_Log_File, 'a')
	except IOError:
    		print "\tI/O error opening STIG Tracing File"
	except:
		print "\tUnexpected error:", sys.exc_info()[0]
    		raise
	
	return STIG_Log_File

def delete_tracing_commands_prior_Files(path, days_prior):

	check_Cmd = 'find ' + path + ' -maxdepth 1 -type f -mtime ' + days_prior + ' | wc -l'
	p = subprocess.Popen(check_Cmd, shell=True, stdout=subprocess.PIPE)
	code = p.communicate()[0].strip('\n')
	NO_OF_FILES = int(code)
	if NO_OF_FILES > 0:	
		cmd = 'find ' + path + ' -maxdepth 1 -type f -mtime ' + days_prior + ' -exec rm {} \;'
		#print cmd
		u = os.system(cmd)
		if u >= 0:
			print '\tDeleted ' + code + ' file(s) of ' + days_prior + ' days old files from ' + path + ' directory\n'
	else:
		print '\tThere are NO log files in the path specified for deletion\n'


# Function to set the STIG Log file and create if not exist

def Set_STIG_Log_File_Name(argv):

	#import datetime
	global STIG_Log_File
	global Log_Dir
	#datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
	STIG_Log_File = Log_Dir+'stig.log'

	'''
	str= datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	if (argv == 'check'):

		STIG_Log_File = Log_Dir+'check-'+str+'.log'
		#print '\tINFO: The STIG Log File Name is : ',
		#print STIG_Log_File
		return STIG_Log_File

	if (argv == 'fix'):

		#print '\tINFO: The STIG Log File Name is : ',
		STIG_Log_File = Log_Dir+'fix-'+str+'.log'
		return STIG_Log_File
		#print STIG_Log_File
	'''

# Function complete

# Function to Check the previous runs. We have to use -force option
# along with -fix to fix STIG Violations


def Check_Prev_Runs(arg1, arg2):
	
	global Log_Dir
        Num_Of_Files = 0
        if ((arg1 == 'fix') and (arg2 != 'force')):
                print '\tINFO: To get the number of fix files in the log dir for the previous runs'

		No_Of_Files = len(fnmatch.filter(os.listdir(Log_Dir), "fix*.log"))	
		#No_Of_Files = len(fnmatch.filter(os.listdir(yy), "fix*.log"))	
		print '\tINFO: Number of fix log files in the STIG Log directory are %d ' % No_Of_Files

		if Num_Of_Files > 0:
			subprocess.call(['tput', 'setaf', '4'])
			print '\tINFO: You have already ran the script on the system, fix log files exists'
			print '\tINFO: You have to run the script with force option to rerun'
			subprocess.call(['tput', 'sgr0'])
			Stig_Usage()

# This function is used to update the information to the STIG Log File

def Log_Info(Flag_Str, STIG_ID, Info, Status):

	global STIG_Log_File
	global check_num_violations
	global num_violations_fixed

	try:
		fptr = open(STIG_Log_File, 'a')
	except IOError:
		#oda_perror.ODA_Print_Error(50006)
    		print "\tI/O error opening STIG Log File"

	except:
		#oda_perror.ODA_Print_Error(50006)
		print "\tUnexpected error:", sys.exc_info()[0]
    		raise

	date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

	if (Status == 'FAILED'):
		# Failure messages are printed/updated in Red colour text
		date_Str = date_Str +'  : ' +'[STIG ID : '+ str(STIG_ID) +']' + ': [CHECK] : ' + Info + ' [ '+str(STIG_ID)+' ] '
		Error_Str = Info
		check_num_violations = check_num_violations + 1
	else:
		if (Status == 'SUCCESSFUL' or Status == 'ALREADY DONE'):
			date_Str = date_Str +'  : ' +'[STIG ID : '+ str(STIG_ID) +']' + ': [FIXED] : ' + Info + ' [ '+str(STIG_ID)+' ] '+' ' + Status 
			
	if Status == 'FAILED':

		class color_Code:
			RED = '\033[91m'
			END = '\033[0m'
		fptr.write(date_Str + '\n\n')	
		print color_Code.RED + date_Str + '\n' + color_Code.END	
		#date_Str = '"'+color_Code.RED + date_Str + '\n\n' + color_Code.END+'"'	
		Error_Str = '"'+Error_Str+'"'
		#oda_perror.ODA_Print_Error(50007, Error_Str)
		#oda_perror.ODA_Print_Error(60009, Error_Str, Error_Str)

	elif Status == 'SUCCESSFUL':
		class color_Code:
			GREEN = '\033[92m'
			END = '\033[0m'
		fptr.write(date_Str + '\n\n')	
		print color_Code.GREEN + date_Str + '\n' + color_Code.END	
		num_violations_fixed = num_violations_fixed + 1
	# Enhancement to show status of violations : 6-Aug-2014
	elif Status == 'FIX-COMPLETE':
		if num_violations_fixed == 0:
			class color_Code:
				GREEN = '\033[92m'
				END = '\033[0m'
			fptr.write(date_Str + '\n\n')	
			print color_Code.GREEN + Info + ' : All STIG violations are fixed' + '\n' + color_Code.END	
		else:
			class color_Code:
				GREEN = '\033[92m'
				END = '\033[0m'
			fptr.write(Info + '\n\n')	
			#print color_Code.GREEN + Info + ' : Fixed ' + str(num_violations_fixed) + ' STIG violoations' + '\n\n' + color_Code.END	
			print color_Code.GREEN + Info + ' : Fixed  STIG violations' + '\n' + color_Code.END	
	# Enhancement to show status of violations : 6-Aug-2014
	elif Status == 'CHECK-COMPLETE':
		if check_num_violations == 0:
			class color_Code:
				GREEN = '\033[92m'
				END = '\033[0m'
			fptr.write(date_Str + '\n\n')	
			print color_Code.GREEN + Info + ' : There are no STIG violations' + '\n' + color_Code.END	
		else:
			class color_Code:
				RED = '\033[91m'
				END = '\033[0m'
			fptr.write(Info + '\n\n')	
			#print color_Code.RED + Info + ' : There are ' + str(check_num_violations) + ' violoations' + '\n\n' + color_Code.END	
			print color_Code.RED + Info + ' : STIG violations found ' + '\n' + color_Code.END	
	else:
		fptr.write(date_Str + '\n\n')
	
	fptr.close()



# This function checks for unnecessary accounts present in /etc/passwd file
# If such accounts are found  in /etc/password file, then update the STIG Log File with the information

def Check_Not_Needed_Account_Info(account_Array, STIG_ID):

	#print '\tINFO: Inside Check_Not_Needed account info'
	for acc in account_Array:
		#if subprocess.call(['grep', acc, '/etc/passwd']) == 0:
		#cmd = 'egrep -q  ' + acc + ' ' + '/etc/passwd'
		cmd = 'egrep -q  ' + '"^[[:space:]]*' + acc + ':*" ' + '/etc/passwd'
		u = os.system(cmd)
		if u == 0:
			Info = 'The unnecessary account ' + acc + ' found on the system'
			Log_Info("False", STIG_ID, Info, 'FAILED') 		

# This function checks the non_privilege accounts in /etc/passwd file and updates STIG Log File

def Find_UID_Of_Account_Name(non_Priv_Account, STIG_LIST, path_File):
	
	import pwd
	count=0	
	write_to_Check_Tracing('Checking for non privileged accounts in the system', 0)
	for count, acc in enumerate(non_Priv_Account):
		try:
			user_Info = pwd.getpwnam(acc)
			#print user_Info
			x = user_Info.pw_uid
			if x != 0:
				if x < 499:
					Info = "The Non-Privileged account " + acc + " found on the system"
					Log_Info("False", STIG_LIST[count], Info, 'FAILED') 		
		except KeyError:
			#print 'Account %s not found ' % acc
			continue
		count = count+1

# This function checks the files permissions for the list provided

def Check_File_Permissions(file_List, STIG_List, perm_String, oct_String):
	import stat
	count = 0
	for count, file_Name in enumerate(file_List):
		if os.path.exists(file_Name) == True:
			cmd = 'ls -l ' + file_Name + ' | ' + " awk '{print $1}'"		
			#print 'the command formed is : %s ' % cmd 
			#cmd_Out = subprocess.call(['ls -l ', file_Name , ' | ', "awk '{print $1}'"])
			p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
			#Code = (p.communicate())[0].find(perm_String)
			Code = (p.communicate())[0]
			#print Code
			if Code != 0:
				int_Cmd = stat.S_IMODE(os.stat(file_Name).st_mode)
				int_Cmd = oct(int_Cmd)
				#print oct_String 
				#print int_Cmd
				#print type(int_Cmd)
				#print type(oct_String) 
				if (int_Cmd == '0' and oct_String == '0000'):
					int_Cmd = oct_String
				if (int_Cmd == oct_String):
					Info = "The Permissions of file %s is permissive " % file_Name 
					#Log_Info("True", STIG_List[count], Info, 'None') 		
					#print 'permissions are ok....'
				else:
					#print 'the oct strings are not the same'
					Info = "The Permissions of file %s is more permissive than %s :" %(file_Name, oct_String) 
					Log_Info("True", STIG_List[count] ,Info, 'FAILED') 		
		'''
		else:
			Info = 'The file ' + file_Name + ' does not exist'
			Log_Info("True", STIG_List[count], Info, 'None') 		
			#print 'Check File Permission : The file does not exist'
		'''


#This function returns the sysctl value for the given parameter passe

def Get_Sysctl_Parameter_Value(param):

        global PARAM_VALUE
        p_Value = '/sbin/sysctl -e -n '+ param
	str = 'Executing the command : ' + p_Value
	write_to_Check_Tracing(str,0)
        #print 'the command formed is : %s ' % p_Value
        p = subprocess.Popen(p_Value, shell=True, stdout=subprocess.PIPE)
        Code = (p.communicate())[0]
        PARAM_VALUE = int(Code)
        #print 'The param value within the fn is %d' % PARAM_VALUE
        return PARAM_VALUE

# This function is used to get the parameters from the /etc/login.defs file

def Get_Parameter_Value( param, file_Name, index): 
	global PARAM_VALUE
	#print 'Inside Get_Parameter Value'
	if os.path.isfile(file_Name):
		grep_Cmd = 'egrep -e ' + param + ' ' + file_Name + ' | ' + " awk '{print $"+index+"}'"		
		write_to_Check_Tracing('Executing the command : ' + grep_Cmd,0)
		#print grep_Cmd	
		p = subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE)
		Code = (p.communicate())[0]
		if Code == '':
			PARAM_VALUE = 99999
			return PARAM_VALUE
		#print Code	
		#print type(Code)
		PARAM_VALUE = int(Code)
		#print type(PARAM_VALUE)
		#print PARAM_VALUE
		return PARAM_VALUE

# This function checks the permissions for the directory list provided
def Check_Dir_Permissions(dir_List, STIG_List, perm_String, oct_String):
	import stat
	count=0
	for count, dir_Name in enumerate(dir_List):
		#print "the dir Name is %s -----> " % dir_Name
		if os.path.exists(dir_Name) == True:
			cmd = 'ls -ld ' + dir_Name + ' | ' + " awk '{print $1}'"		
			p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
			Code = (p.communicate())[0]
			#Code = (p.communicate())[0].find(perm_String)
			if Code >= 0:
				int_Cmd = stat.S_IMODE(os.stat(dir_Name).st_mode)
				int_Cmd = oct(int_Cmd)
				#print int_Cmd
				if int_Cmd != oct_String:
					#print 'the permissions are not same'
					Info = "INFO: The Permissions of directory %s is more permissive and is other than octal %s :" %(dir_Name, oct_String) 
					Log_Info("False", STIG_List[count], Info, 'FAILED') 		
			else:
				Info = 'The directory ' + dir_Name + ' does not exist'
		else:
			Info = 'The directory ' + dir_Name + ' does not exist'

# This function checks for multiple values absent in the the file ---------> TO DO Check with Radheshyam

def Check_For_Multiple_Value_Absence_In_File(PWD_STRENGH, STIG_LIST, INFO, file_Name):


	count = 0
	#print	'Multiple values absent in the File'
	for count, acc  in enumerate(PWD_STRENGH):
		#print 'the password strenght is %s :' % acc
		#grep_Cmd = 'egrep -e ' + '"[[:space:]]+$'+acc+'=-1'+'[[:space:]]*" ' + file_Name
		grep_Cmd = 'egrep -q -e ' + '+$'+acc+'=-1 ' + file_Name
		str = 'Executing the command : ' + grep_Cmd
		write_to_Check_Tracing(str,0)
		p =  subprocess.call(grep_Cmd, shell=True)
		if not p:
			#print 'Account found ' + INFO[count]+'['+str(count)+']'
			#print STIG_LIST[count]
			Info = 'Force of at least one ' + INFO[count] + ' character is set for the password'
			#Log_Info("False", STIG_LIST[count], Info, 'None') 		
		else:
			#print 'Account not found ' + INFO[count] + ' ' + STIG_LIST[count]
			Info = 'Force of at least one ' + INFO[count] + ' character is not set for the password'
			#print STIG_LIST[count]		
			Log_Info("True", STIG_LIST[count], Info, 'FAILED') 		

# This function checks for the absence of a given string in a file passed as argument

def Check_For_Pattern_Absence_In_File(search_Pattern, file_Name):

	grep_Cmd = 'egrep -q -e ' + "[[:space:]]+$"+acc+'=-1'+'[[:space:]]* ' + file_Name
	#print grep_Cmd
	if subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE) == 0:
		print 'Account found ' + INFO[count]+'['+str(count)+']'
		#Log_Info("True", STIG_LIST[count], INFO[count], 'None') 		
	else:
		#print 'Account not found ' + INFO[count] + ' ' + STIG_LIST[count]
		Info = 'Force of at least one ' + INFO[count] + ' character is not set for the password'
		Log_Info("True", STIG_LIST[count], Info, 'FAILED') 		
	

# This function is used to delete the account
def Delete_Account(acc_List, STIG_LIST, file_Name, INFO):
	
	count = 0
	#print	'Deleting the account'
	for count, acc  in enumerate(acc_List):
		#print  acc	
		grep_Cmd = 'grep -q "^[[:space:]]*'+acc+':x:*"'+ ' '+ file_Name
		Str = 'Executing the command : ' + grep_Cmd
		write_to_Check_Tracing(Str,0)
		#print grep_Cmd
		p = os.system(grep_Cmd)
		if p == 0:
			del_Cmd = 'userdel ' + acc + ' >> /dev/null 2>&1'
			u = os.system(del_Cmd)
			#print u
			if u == 0:
				write_to_Check_Tracing('\tdelete of account successful', 0)
				#print acc
				Info = INFO + ' ' + acc + ' successful'
				#print Info
				#acc_Info = STIG_LIST[count] 
				Log_Info('True', STIG_LIST[count],  Info, 'SUCCESSFUL')
			else:
				#print 'delete of account failed'
				Info = INFO + ' ' + acc
				#print Info
				#acc_Info = STIG_LIST[count] 
				Log_Info('True', STIG_LIST[count],  Info,  'FAILED')
		else:
			#print 'delete of account already done'
			Info = INFO + ' ' + acc
			#acc_Info = STIG_LIST[count]
			Log_Info('True', STIG_LIST[count], Info, 'ALREADY DONE')
		count = count + 1

def write_to_Check_Tracing(command_str, data_type):

	global Log_Dir
	global STIG_Log_File
	global check_command_Count

	d = os.path.dirname(Log_Dir)
	if not os.path.exists(d):
		os.makedirs(d)

	if os.path.exists(STIG_Log_File) == False:
                os.system('touch ' + STIG_Log_File)
                os.system('chown root:root ' + STIG_Log_File)
                os.system('chmod 600 ' + STIG_Log_File)
	
	check_command_Count = check_command_Count + 1	

	if os.path.exists(STIG_Log_File) == False:
                fp = open(STIG_Log_File,'w')
        else:
                fp = open(STIG_Log_File,'a')
	if data_type == 0 :	
        	#cmd = 'printf ' +  '"\n'+ str(check_command_Count) + ". " + command_str+'\n"'  + ' >> ' + STIG_Log_File
		#subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        	string_to_write = '\n'+ str(check_command_Count) + ". " + command_str+'\n' 
		fp.write(string_to_write + '\n')
	fp.close()

# This function sets the path grub.conf file based on whether it is VM or not

def Set_Grub_Conf_File_Name():
	
	global is_VM
	global GRUB_CONF
	GRUB_CONF = "/boot/grub/menu.lst"
	if is_VM:
		#check if /boot/grub/grub.conf exists or not
		if not os.path.isfile(GRUB_CONF):
			GRUB_CONF = '/boot/grub/grub.conf'
			strI = 'The path ' + GRUB_CONF + ' checked for its existence, Setting the grub conf file path : It is VM environment'
			write_to_Check_Tracing(strI, 0)
			#print 'is VM environment'
		else:
			GRUB_CONF = '/boot/grub/menu.lst'
			sys.exit(0)
	else:
		strI = 'The path ' + GRUB_CONF + ' checked for its existence, Setting the grub conf file path : It is BM environment'
		write_to_Check_Tracing(strI, 0)
	#print GRUB_CONF
	return GRUB_CONF

# This function check for absence of a given pattern in a file

def Check_Pattern_Absence_In_File( grep_Cmd, file_Name):

	global pattern_Absent
	grep_Cmd = 'egrep -q -e ' + '"'+ grep_Cmd +'"' + ' ' + file_Name
	write_to_Check_Tracing('Executing the command : ' + grep_Cmd,0)
	u = os.system(grep_Cmd)
	if u==0:
		#print 'Pattern is absent' 
		pattern_Absent=1
	else:
		#print 'Pattern is present '
		pattern_Absent=0
	return pattern_Absent

# This function check for presence of a given pattern in a file

def Check_Pattern_Presence_In_File( Str, file_Name):

	global pattern_Present	
	grep_Cmd = "grep -vr '^#' " + file_Name + ' |  grep -e ' + '"' + Str + '"'
	#print grep_Cmd
	p = subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE) 
	write_to_Check_Tracing('Executing the command : ' + grep_Cmd,0)
	code = p.communicate()[0]
	#print code
	if code == '':
		#print 'Pattern not found  -0 ' 
		pattern_Present=0
	else:
		#print 'Pattern  found - 1'
		pattern_Present=1
	return pattern_Present 

def Check_For_Installed_RPM(rpm_Name):

	global pattern_Present
	rpm_Cmd = 'rpm -qa ' + rpm_Name 
	#print rpm_Cmd
	p = subprocess.Popen(rpm_Cmd, shell=True, stdout=subprocess.PIPE) 
	rpm_Name = p.communicate()[0]
	if rpm_Name == '':
		pattern_Present = 0
		#print 'Pattern not found - value %d ' % pattern_Present
	else:
		#print 'Pattern found - value %d ' % pattern_Present
		pattern_Present=1

	return pattern_Present 

def Install_RPM(rpm_Name, STIG_ID, Info):

	#print 'Inside Install RPM'
	rpm_Cmd = 'rpm -q ' + rpm_Name 
	Str = 'Executing the command : '+ rpm_Cmd + ' : To check if the rpm is installed or not' 
	write_to_Check_Tracing(Str,0)
	temp_rpm_Name = rpm_Name
	p = subprocess.Popen(rpm_Cmd, shell=True, stdout=subprocess.PIPE) 
	rpm_Name = p.communicate()[0].find('not')
	if rpm_Name >= 0:
		#print 'in else'
		yum_cmd = 'yum  --disablerepo=* --enablerepo=ol6_latest install ' + temp_rpm_Name + ' -y --nogpgcheck 2&>1  ' 
		p = subprocess.Popen(yum_cmd, shell=True, stdout=subprocess.PIPE) 
		rpm_Name2 = p.communicate()[0]
		#print rpm_Name2
		#print type(rpm_Name2)
		if rpm_Name2 == 0:
			write_to_Check_Tracing('The rpm is successfully installed', 0)
			#print 'The rpm is successfully installed'
			Log_Info('True', STIG_ID, Info, 'SUCCESSFUL')
	else:
		Log_Info('True', STIG_ID, Info, 'ALREADY DONE')

def UN_Install_Package(rpm_Name, STIG_ID, Info):

	rpm_Cmd = 'rpm -qa ' + rpm_Name 
	Str = 'Executing the command : '+ rpm_Cmd + ' : To check if the package is installed or not' 
	write_to_Check_Tracing(Str,0)
	temp_rpm_Name = rpm_Name
	p = subprocess.Popen(rpm_Cmd, shell=True, stdout=subprocess.PIPE) 
	rpm_Name = p.communicate()[0]
	time.sleep(2)
	if rpm_Name == '' :
		write_to_Check_Tracing('The package checked is already uninstalled', 0)
		#print 'the rpm is already uninstalled' + rpm_Name
		Log_Info('True', STIG_ID, Info, 'ALREADY DONE')
	else:
		rpm_Cmd = 'yum remove ' + temp_rpm_Name + ' -y' 
		p = subprocess.Popen(rpm_Cmd, shell=True, stdout=subprocess.PIPE) 
		rpm_Name = p.communicate()[0]
		time.sleep(2)
		if rpm_Name > 0:
			write_to_Check_Tracing('The package is successfully uninstalled', 0)
			#print 'the rpm is uninstalled' + rpm_Name
			Log_Info('True', STIG_ID, Info, 'SUCCESSFUL')
		else:
			Log_Info('True', STIG_ID, Info, 'FAILED')
			
		return True 

def UN_Install_RPM(rpm_Name, STIG_ID, Info):

	rpm_Cmd = 'rpm -qa ' + rpm_Name 
	Str = 'Executing the command : '+ rpm_Cmd + ' : To check if the rpm is installed or not' 
	write_to_Check_Tracing(Str,0)
	temp_rpm_Name = rpm_Name
	p = subprocess.Popen(rpm_Cmd, shell=True, stdout=subprocess.PIPE) 
	rpm_Name = p.communicate()[0]
	#print rpm_Name
	if rpm_Name == '' :
		write_to_Check_Tracing('The rpm checked is already uninstalled', 0)
		#print 'the rpm is already uninstalled' + rpm_Name
		Log_Info('True', STIG_ID, Info, 'ALREADY DONE')
	else:
		rpm_Cmd = 'rpm -ev ' + temp_rpm_Name 
		p = subprocess.Popen(rpm_Cmd, shell=True, stdout=subprocess.PIPE) 
		rpm_Name = p.communicate()[0]
		if rpm_Name > 0:
			write_to_Check_Tracing('The rpm is successfully uninstalled', 0)
			#print 'the rpm is uninstalled' + rpm_Name
			Log_Info('True', STIG_ID, Info, 'SUCCESSFUL')
		else:
			Log_Info('True', STIG_ID, Info, 'FAILED')
			
		return True 


def Rollback_Original_System_Files():


	Set_Grub_Conf_File_Name()
	global GRUB_CONF
	global ol6_Flag
	global is_VM
	global STIG_Log_File	
	#print GRUB_CONF
	Check_OL6()

	write_to_Check_Tracing('Rollback system configuration files which are preserved before STIG Fixes are executed', 0)
        cmd = 'cp /opt/oracle/oak/stig/aliases.original ' + '/etc/aliases'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/inittab.original ' + '/etc/inittab'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/passwd.original ' + '/etc/passwd'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/login.defs.original ' + '/etc/login.defs'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

	if is_VM:
        	cmd = 'cp /opt/oracle/oak/stig/menu.lst.original ' + '/boot/grub/menu.lst' 
	else:
        	cmd = 'cp /opt/oracle/oak/stig/grub.conf.original ' + '/boot/grub/grub.conf' 
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
        cmd = 'cp /opt/oracle/oak/stig/system-auth.original ' + '/etc/pam.d/system-auth'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ",Info , "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/sysctl.conf.original ' + '/etc/sysctl.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/sshd_config.original ' + '/etc/ssh/sshd_config'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        #cmd = 'cp /opt/oracle/oak/stig/init.oak.original ' + '/opt/oracle/oak/install/init.oak'
        #if not Execute_Command(cmd):
	#	Info = 'The command : ' + cmd + ' not successful'
	#	Log_Info("False", " - ", Info, "FAILED")
	#else:
	#	write_to_Check_Tracing(cmd, 0)
	if ol6_Flag == 'FALSE':
        	cmd = 'cp /opt/oracle/oak/stig/ekshell.original ' + '/etc/pam.d/ekshell'
        	if not Execute_Command(cmd):
			Info = 'The command : ' + cmd + ' not successful'
			Log_Info("False", " - ", Info, "FAILED")
		else:
			write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/access.conf.original ' + '/etc/security/access.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/login.original ' + '/etc/pam.d/login'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/fstab.original ' + '/etc/fstab'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
	if ol6_Flag == 'FALSE':
        	cmd = 'cp /opt/oracle/oak/stig/syslog.conf.original ' + '/etc/syslog.conf'
	else:
        	cmd = 'cp /opt/oracle/oak/stig/rsyslog.conf.original ' + '/etc/rsyslog.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/smb.conf.original ' + '/etc/samba/smb.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/audit.rules.original ' + '/etc/audit/audit.rules'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

        cmd = 'cp /opt/oracle/oak/stig/modprobe.conf.original ' + '/etc/modprobe.d/modprobe.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/init.original ' + '/etc/sysconfig/init'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/limits.conf.original ' + '/etc/security/limits.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/useradd.original ' + '/etc/default/useradd'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/stig/su.original ' + '/etc/pam.d/su'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

	print '\n\tRollback of System files to ODA Imaged state prior to STIG script exeution completed\n'

def Backup_Original_System_Files():

	temp_path = '/opt/oracle/oak/stig/'
	global Log_Dir		
	global STIG_Log_File	
	Set_Grub_Conf_File_Name()
	global GRUB_CONF
	global is_VM
	global ol6_Flag
	#print GRUB_CONF
	Check_OL6()

	write_to_Check_Tracing('Creating backup for each of the system configuration files which are likely to be mdofied', 0)
        cmd = 'cp /etc/aliases ' +  temp_path + 'aliases.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/inittab ' + temp_path + 'inittab.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/passwd ' + temp_path + 'passwd.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/login.defs ' + temp_path + 'login.defs.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
	if is_VM:
        	cmd = 'cp ' + GRUB_CONF +' ' + temp_path+'menu.lst.original'
	else:
        	cmd = 'cp ' + GRUB_CONF +' ' + temp_path+'grub.conf.original'

        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
        cmd = 'cp /etc/pam.d/system-auth ' + temp_path + 'system-auth.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ",Info , "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/sysctl.conf ' + temp_path + 'sysctl.conf.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/ssh/sshd_config ' + temp_path + 'sshd_config.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        #cmd = 'cp /opt/oracle/oak/install/init.oak ' + temp_path + 'init.oak.original'
        #if not Execute_Command(cmd):
	#	Info = 'The command : ' + cmd + ' not successful'
	#	Log_Info("False", " - ", Info, "FAILED")
	#else:
	#	write_to_Check_Tracing(cmd, 0)
	if ol6_Flag == 'FALSE':
        	cmd = 'cp /etc/pam.d/ekshell ' + temp_path + 'ekshell.original'
        	if not Execute_Command(cmd):
			Info = 'The command : ' + cmd + ' not successful'
			Log_Info("False", " - ", Info, "FAILED")
		else:
			write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/security/access.conf ' + temp_path + 'access.conf.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/pam.d/login ' + temp_path + 'login.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/fstab ' + temp_path + 'fstab.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
	if ol6_Flag == 'FALSE':
        	cmd = 'cp /etc/syslog.conf ' + temp_path + 'syslog.conf.original'
	else:
        	cmd = 'cp /etc/rsyslog.conf ' + temp_path + 'rsyslog.conf.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/samba/smb.conf ' + temp_path + 'smb.conf.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/audit/audit.rules ' + temp_path + 'audit.rules.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

        cmd = 'cp /etc/modprobe.d/modprobe.conf ' + temp_path + 'modprobe.conf.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/sysconfig/init ' + temp_path + 'init.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/security/limits.conf ' + temp_path + 'limits.conf.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/default/useradd ' + temp_path + 'useradd.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/pam.d/su ' + temp_path + 'su.original'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

	print '\tBackup of system files completed.\n'

# This command executes the OS System commands passed
def Restore_Previous_State():
        temp_path = ''
	global Log_Dir
	global STIG_Log_File	
	global is_VM
	Set_Grub_Conf_File_Name()
	global GRUB_CONF
	global ol6_Flag
	#print GRUB_CONF
	Check_OL6()

	write_to_Check_Tracing('Restoring each of the system configuration files which modified due to previous stig fix, Only the last change is preserved', 0)
        cmd = 'cp /etc/aliases.backup_stig ' +  temp_path + '/etc/aliases'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/inittab.backup_stig ' + temp_path + '/etc/inittab'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/passwd.backup_stig ' + temp_path + '/etc/passwd'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/login.defs.backup_stig ' + temp_path + '/etc/login.defs'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

        cmd = 'cp ' + GRUB_CONF +'.backup_stig ' + GRUB_CONF
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
        cmd = 'cp /etc/pam.d/system-auth.backup_stig ' + temp_path + '/etc/pam.d/system-auth'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ",Info , "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/sysctl.conf.backup_stig ' + temp_path + '/etc/sysctl.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/ssh/sshd_config.backup_stig ' + temp_path + '/etc/ssh/sshd_config'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/install/init.oak.backup_stig ' + temp_path + '/opt/oracle/oak/install/init.oak'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
	if ol6_Flag == 'FALSE':
        	cmd = 'cp /etc/pam.d/ekshell.backup_stig ' + temp_path + '/etc/pam.d/ekshell'
        	if not Execute_Command(cmd):
			Info = 'The command : ' + cmd + ' not successful'
			Log_Info("False", " - ", Info, "FAILED")
		else:
			write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/security/access.conf.backup_stig ' + temp_path + '/etc/security/access.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/pam.d/login.backup_stig ' + temp_path + '/etc/pam.d/login'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/fstab.backup_stig ' + temp_path + '/etc/fstab'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
	if ol6_Flag == 'FALSE':
        	cmd = 'cp /etc/syslog.conf.backup_stig ' + temp_path + '/etc/syslog.conf'
	else:
        	cmd = 'cp /etc/rsyslog.conf.backup_stig ' + temp_path + '/etc/rsyslog.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/audit/audit.rules.backup_stig ' + temp_path + '/etc/audit/audit.rules'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

        cmd = 'cp /etc/modprobe.d/modprobe.conf.backup_stig ' + temp_path + '/etc/modprobe.d/modprobe.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/sysconfig/init.backup_stig ' + temp_path + '/etc/sysconfig/init'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/security/limits.conf.backup_stig ' + temp_path + '/etc/security/limits.conf'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/default/useradd.backup_stig ' + temp_path + '/etc/default/useradd'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/pam.d/su.backup_stig ' + temp_path + '/etc/pam.d/su'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

# This command executes the OS System commands passed



def Take_Conf_File_Backup():
        temp_path = ''
	global Log_Dir
	global STIG_Log_File	
	global is_VM
	Set_Grub_Conf_File_Name()
	global GRUB_CONF
	global ol6_Flag
	#print GRUB_CONF
	Check_OL6()

	write_to_Check_Tracing('Creating backup for each of the system configuration files which are getting modified, Only the last change is preserved', 0)
        cmd = 'cp /etc/aliases ' +  temp_path + '/etc/aliases.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/inittab ' + temp_path + '/etc/inittab.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/passwd ' + temp_path + '/etc/passwd.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/login.defs ' + temp_path + '/etc/login.defs.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp ' + GRUB_CONF +' ' + GRUB_CONF+'.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
        cmd = 'cp /etc/pam.d/system-auth ' + temp_path + '/etc/pam.d/system-auth.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ",Info , "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/sysctl.conf ' + temp_path + '/etc/sysctl.conf.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/ssh/sshd_config ' + temp_path + '/etc/ssh/sshd_config.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /opt/oracle/oak/install/init.oak ' + temp_path + '/opt/oracle/oak/install/init.oak.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
	if ol6_Flag == 'FALSE':
        	cmd = 'cp /etc/pam.d/ekshell ' + temp_path + '/etc/pam.d/ekshell.backup_stig'
        	if not Execute_Command(cmd):
			Info = 'The command : ' + cmd + ' not successful'
			Log_Info("False", " - ", Info, "FAILED")
		else:
			write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/security/access.conf ' + temp_path + '/etc/security/access.conf.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/pam.d/login ' + temp_path + '/etc/pam.d/login.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/fstab ' + temp_path + '/etc/fstab.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
	if ol6_Flag == 'FALSE':
        	cmd = 'cp /etc/syslog.conf ' + temp_path + '/etc/syslog.conf.backup_stig'
	else:
        	cmd = 'cp /etc/rsyslog.conf ' + temp_path + '/etc/rsyslog.conf.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/audit/audit.rules ' + temp_path + '/etc/audit/audit.rules.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

        cmd = 'cp /etc/modprobe.d/modprobe.conf ' + temp_path + '/etc/modprobe.d/modprobe.conf.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/sysconfig/init ' + temp_path + '/etc/sysconfig/init.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/security/limits.conf ' + temp_path + '/etc/security/limits.conf.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/default/useradd ' + temp_path + '/etc/default/useradd.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)
        cmd = 'cp /etc/pam.d/su ' + temp_path + '/etc/pam.d/su.backup_stig'
        if not Execute_Command(cmd):
		Info = 'The command : ' + cmd + ' not successful'
		Log_Info("False", " - ", Info, "FAILED")
	else:
		write_to_Check_Tracing(cmd, 0)

# This command executes the OS System commands passed
def Execute_Command(cmd):
        if os.system(cmd) == 0:
                #print 'copy successfull'
		return True
        else:
                #print 'copy not succesful'
		return	False

# This function is used to comment the lines matching the string passed as first argument to this function'
def Comment_Line_Matching_Pattern(search_Str, file_Name, STIG_ID, Info):

	global RESTART_SENDMAIL
	global RESTART_INITTAB
 	grep_Cmd = 'grep -e ' + '"'+ search_Str +'"' + " " + file_Name
 	#grep_Cmd = 'egrep -v "^#" ' + file_Name + ' | ' + 'egrep -e ' + '"'+ search_Str +'"' + " " + file_Name
	#print grep_Cmd
	str_fix = 'Executing the command : ' + grep_Cmd + ' \n\t: to check if the line is commented or not'
	write_to_Check_Tracing(str_fix, 0)
	p = subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE) 
	Code = (p.communicate())[0]
	#u = os.system(grep_Cmd)
	#print Code
	if Code.startswith('#'):
		return
	#print type(Code)
	if Code == "":
        	Log_Info ('True', STIG_ID, Info, "ALREADY DONE")
		#print 'STRING already taken care - commenting is not needed'
	else:
		sed_Cmd = 'sed -i ' + "'"+"s/"+search_Str+"/#&/"+"'"+ ' ' + file_Name
		#print sed_Cmd
		p = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE)
		if p:
			#print 'SED 1 : comment line matching pattern sed succesful'
			str_fix = '\tCommenting the line using the command  : ' +  grep_Cmd 
			write_to_Check_Tracing(str_fix, 0)
			if Info != "":
        			Log_Info ('True', STIG_ID, Info, "SUCCESSFUL")
			if file_Name == '/etc/inittab':
				#print 'setting the global flag for inittab'
				REEXAMINE_INITTAB = 1
			if file_Name == '/etc/mail/sendmail.cf':
				#print 'setting the global flag for sendmail'
				RESTART_SENDMAIL = 1
      		else:
			#print 'sed failed'
			if Info != "":
        			Log_Info ('True', STIG_ID, Info, "FAILED")
	return RESTART_SENDMAIL

# This function is used to delete the lines matching the string passed as first argument to this function'
def Delete_Line_Matching_Pattern(search_Str, file_Name, STIG_ID, Info):

 	grep_Cmd = 'egrep -q -e ' + search_Str + " " + file_Name
	Str = 'Checking if ' + search_Str + ' is found in ' + file_Name + ' \n\t Executing : ' + grep_Cmd
	write_to_Check_Tracing(Str,0)
	p = os.system(grep_Cmd)
	if p == 0:
		sed_Cmd = 'sed -i ' + "'/"+search_Str+"/d'" + ' ' + file_Name
		#print sed_Cmd
		p = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE)
		if p:
			#print STIG_ID + " : " + Info
			Str = 'Deleting the line matching the pattern ' + search_Str + ' \n\tExecuting : ' + sed_Cmd
			write_to_Check_Tracing(Str,0)
        		Log_Info ('True', STIG_ID, Info, "SUCCESSFUL")
      		else:
			#print 'sed failed delete line'
        		Log_Info ('True', STIG_ID, Info, "FAILED")
	else:
		Str = 'The pattern ' + search_Str + ' is already deleted from ' + file_Name
		write_to_Check_Tracing(Str,0)
        	Log_Info ('True', STIG_ID, Info, "ALREADY DONE")
		#print 'STRING NOT Found - comment line not found delete line'
	
# This function is used to modify the parameters in /etc/login.defs file

def Modify_Parameter_In_File(search_Str, search_Method, modify_Value, file_Name, STIG_ID, Info):

	global RESTART_SSHD	
	grep_Cmd = 'egrep -e ' + "'" + search_Str + search_Method + "'" + " " +file_Name
 	Str = 'Checking if ' + search_Str + ' is enabled in file ' + file_Name
	write_to_Check_Tracing(Str,0)	
        #egrep -e "^[[:space:]]*PASS_MAX_DAYS[[:space:]]+60" login.defs
        is_Modified = subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE)
	str_Value = is_Modified.communicate()[0]
	sub_Value = str_Value.strip(search_Method)
	Value = sub_Value.strip()
        if Value == modify_Value: 
                #print 'Modify parameter already done'
		Str = 'The ' + modify_Value + ' is already specified in ' + file_Name
		write_to_Check_Tracing(Str,0)
		Log_Info('True', STIG_ID, Info, "ALREADY DONE")
        else:
                #print  'Modify parameter has to be done'
              	#grep_Cmd = 'egrep -q -e ' + '"'+search_Str+'"'+search_Method + " " + file_Name
		grep_Cmd = 'egrep -e ' + "'" + search_Str + search_Method + "'" + " " +file_Name
                q =  subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE)
		Code = q.communicate()[0].find(search_Method)
		sub_Value = str_Value.strip(search_Method)
		Value = sub_Value.strip()
		#print 'The code is %s ' % Code
		#print 'The value is %s ' % Value	
		if Code < 0 or Value < 0: 
                        print_Cmd = 'printf  "\n#  %s\n%s %s \n" ' + '"'+Info+'"' + ' ' + search_Method + ' ' + modify_Value + ' ' +  ">> " + " " + file_Name
                        r = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE) 
                        if r:
                                #print 'print to file successful'
				Str = 'Modified the /etc/login.defs file to reflect new parameter for ' + search_Str
				write_to_Check_Tracing(Str,0)
                                Log_Info ('True', STIG_ID, Info, "SUCCESSFUL")
                                if file_Name == '/etc/ssh/sshd_config':
                                        RESTART_SSHD = 1
                        else:
                                #print 'print to file failed '
                                Log_Info ('True', STIG_ID, Info, "FAILED")
                else:
			#print modify_Value
                        sed_Cmd = 'sed -i ' + "'s/"+search_Str+search_Method+".*/"+search_Method+ "  "+modify_Value+"/'" + ' ' + file_Name
			#print sed_Cmd
                        #sed -i 's/^[[:space:]]*PASS_MAX_DAYS.*/PASS_MAX_DAYS  60/' login.defs          print sed_Cmd
                        sp = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE)
                        if sp:
                                #print STIG_ID + " : " + Info
                                Log_Info ('True', STIG_ID, Info, "SUCCESSFUL")
                                if file_Name == '/etc/ssh/sshd_config':
                                        RESTART_SSHD = 1
                        else:
                                #print 'sed 4 failed modify value'
                                Log_Info ('True', STIG_ID, Info, "FAILED")
	return RESTART_SSHD

# This function is to modify sysctl conf parameter to new value

def Modify_Sysctl_Conf_Parameter_To_New_Value(parameter, min_Value, new_Value, file_Name, STIG_ID, Info):
	
	global PARAM_VALUE
	Get_Sysctl_Parameter_Value(parameter)

	if PARAM_VALUE >= int(min_Value):
		string_match= "^[[:space:]]*"+parameter
		grep_Cmd = 'egrep -q ' + string_match + ' ' + file_Name
		check_Present = os.system(grep_Cmd)
		if check_Present == 0:
			Flag_Str = 'False'
			Info = 'The sysctl parameter ' + parameter + ' is already set'
			write_to_Check_Tracing(Info, 0)
			Log_Info('False', STIG_ID, Info, "ALREADY DONE")
			#print 'sysctl update is already done'
		else:
			#print 'update to file is done'
			equals = " = "
			Hash = "#"
			#Info_Mod = "# " + Info
			#print Info_Mod
			print_Cmd = 'printf  "\n%s %s" ' + '"#"'+ '"'+Info+'"'  + " >>  " + file_Name
			#print print_Cmd
                        subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE) 
			print_Cmd = 'printf  "\n%s %s %s\n" ' +  parameter + equals + new_Value +  " >> "  + file_Name
			#print print_Cmd
                        subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE) 
			write_to_Check_Tracing('New Sysctl parameter is written to the file successfully',0)
			Log_Info('False', STIG_ID, Info, "SUCCESSFUL")
	else:
			equals = " = "
			if PARAM_VALUE == 0:
                        	print_Cmd = 'printf  "\n#  %s\n%s  %s \n" '  + '"' + Info + '"' + ' ' + parameter + '= ' + new_Value + ' ' +  ">> " + " " + file_Name
                        	subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE) 
        			p_Value = '/sbin/sysctl -q -p' 
       	 			p = subprocess.Popen(p_Value, shell=True, stdout=subprocess.PIPE)
        			Code = (p.communicate())[0]
        			if Code < 0:
					print 'The sysctl command execution failed'
			else:
				if PARAM_VALUE < 1280:
        				p_Value = '/sbin/sysctl -q '+ parameter+'='+new_Value 
       	 				p = subprocess.Popen(p_Value, shell=True, stdout=subprocess.PIPE)
        				Code = (p.communicate())[0]
        				if Code < 0:
						print 'The sysctlq is not set to 2048'
					#grep_Cmd = 'egrep -q -e ' + parameter + ' ' + file_Name
					grep_Cmd = 'egrep -q -e ' + "'^[[:space:]]*" + parameter + "'" + " " +file_Name
       	 				q = subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE)
					tcp_str = q.communicate()[0].find(parameter)
        				if tcp_str < 0: 
						equals = "="
						Info_Mod = "# " + Info
						#print Info_Mod
						print_Cmd = 'printf  "\n# %s\n" ' + Info_Mod + " >>  " + file_Name
                        			subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE) 
						print_Cmd = 'printf  "\n%s%s%s\n" ' +  parameter + equals + new_Value +  " >> "  + file_Name
                        			r = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE) 
                       				if r:
                                			#print ' 2  print to file successful'
							write_to_Check_Tracing('New Sysctl parameter is written to the file successfully',0)
                                			Log_Info ("True", STIG_ID, Info, "SUCCESSFUL")
                        			else:
                               				#print 'print to file failed '
                                			Log_Info ("True",STIG_ID, Info, "FAILED")
					else:
                        			sed_Cmd = 'sed -i ' + "'s/"+parameter+".*/"+parameter+ " =  "+new_Value+"/'" + ' ' + file_Name
						#print sed_Cmd
						#sed_Cmd = 'sed -i ' + "'s/[[:digit:]]*/"+new_Value+"/' " + file_Name
                        			s = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE) 
                       				if s:
                                			#print 'sed to file successful'
							write_to_Check_Tracing('Old Sysctl parameter is replaced by new value and is written to the file successfully',0)
                                			Log_Info ("True", STIG_ID, Info, "SUCCESSFUL")
                        			else:
                               				#print 'sedto file failed '
                                			Log_Info ("True", STIG_ID, Info, "FAILED")

def Insert_New_Line_Location(search_Str, parameter_Str, new_String, file_Name, STIG_ID, INFO, location):
 	p_grep_Cmd = 'egrep -e ' + "'" + search_Str + "' "  + file_Name
	#print p_grep_Cmd
	str_fix = 'Executing the command : ' + p_grep_Cmd + ' : to check if line exists'
	write_to_Check_Tracing(str_fix, 0)
	p_Cmd = subprocess.Popen(p_grep_Cmd, shell=True, stdout=subprocess.PIPE) 
	Code = (p_Cmd.communicate())[0].find(new_String)	
	#print Code
	if Code >= 0:
                Log_Info ('False',STIG_ID, INFO, "ALREADY DONE")
	else:
		if location == 0:
			temp = file_Name+'_temp'
			sed_Cmd = 'sed "`grep -n -m1 ' + parameter_Str + ' ' + file_Name + " | cut -c1` i \\" + new_String +'"'  +  ' ' + file_Name + ' > ' + temp
			#print sed_Cmd
			print_check = os.system(sed_Cmd)
			if print_check == 0:
				str_fix = 'Inserting the ' + new_String + ' in ' + file_Name + ' using : ' + sed_Cmd 
				write_to_Check_Tracing(str_fix, 0)
				#print 'login file update successful'
                       		Log_Info ('True',STIG_ID, INFO, "SUCCESSFUL")
				Copy_cmd = 'cp ' + temp + ' ' + file_Name
				os.system(Copy_cmd)
				Remove_cmd = 'rm ' + temp
				os.system(Remove_cmd)
			else:
				#print 'ERROR : The login file not modified '	
				Log_Info('True', STIG_ID, INFO, "FAILED")


def Insert_Before_Or_After_the_Match(search_Str, new_String, file_Name, STIG_ID, INFO, Flag):
	global G_Count
	if Flag == 0:
		#print 'pattern not found in the file, so add it'
        	sed_Cmd = 'sed -i ' + "'s/" + search_Str+ "/" + new_String + "\\n&/' " + file_Name
		#print sed_Cmd
		str = 'Inserting ' + new_String  + ' in ' + file_Name + ' : Executing the command : ' + sed_Cmd
		write_to_Check_Tracing(str,0)
               	s = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE) 
       		if s:
			G_Count = G_Count + 1
	else:
       		sed_Cmd = 'sed -i ' + "'s/" + search_Str+ "/&\\n" + new_String + "/' " + file_Name
		str = 'Inserting ' + new_String  + ' in ' + file_Name + ' : Executing the command : ' + sed_Cmd
		write_to_Check_Tracing(str,0)
               	s = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE) 
       		if s:
			G_Count = G_Count + 1
	#print G_Count
	return G_Count

# This function is used to insert the string specified in the file if the pattern is found

def Insert_New_Line_In_File(search_Str, new_String, file_Name, STIG_ID, INFO):

 	p_grep_Cmd = 'egrep -e ' + "'" + search_Str + "' "  + file_Name
	str_fix = 'Executing the command : ' + p_grep_Cmd + ' : to check if line exists'
	write_to_Check_Tracing(str_fix, 0)
	#print p_grep_Cmd
	p_Cmd = subprocess.Popen(p_grep_Cmd, shell=True, stdout=subprocess.PIPE) 
	Code = (p_Cmd.communicate())[0].find(new_String)	
	#print Code
	if Code >= 0:
                Log_Info ('False',STIG_ID, INFO, "ALREADY DONE")
		#print 'pattern found in the file, do not insert'
	else:
		print_Cmd = 'printf  "\n# %s \n" ' +  '"'+INFO+'"' +   " >>  "  + file_Name
               	r = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE) 
               	if not r:
                	#print 'print to file failed '
                       	Log_Info ('True', STIG_ID, INFO, "FAILED")
		#print new_String
		print_Cmd = 'printf  "%s \n" ' + '"'+ new_String +'"'+   " >>  "  + file_Name
		#print print_Cmd
               	s = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE) 
               	if s:
			str_fix = 'Inserting the ' +new_String+ ' in ' + file_Name + 'using : ' + p_grep_Cmd 
			write_to_Check_Tracing(str_fix, 0)
               		#print ' yy2  print to file successful'
			if INFO != "":
                       		Log_Info ('True', STIG_ID, INFO, "SUCCESSFUL")
                else:
                	#print 'pprint to file failed '
			if INFO != "":
                       		Log_Info ('True',STIG_ID, INFO, "FAILED")


def Insert_Pattern_At_End_Of_Line(search_Str, new_Str, file_Name, STIG_ID, INFO):
	
	grep_Str = "'" + search_Str + new_Str + '.*' + "'"
	grep_Cmd = 'egrep -e ' + grep_Str + ' ' + file_Name
	#print grep_Cmd
	str = 'Checking if ' + search_Str + ' found in ' + file_Name + ' : Executing the command : ' + grep_Cmd
	write_to_Check_Tracing(str,0)
	p_Cmd = subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE) 
	Code = p_Cmd.communicate()[0].find(new_Str)
	if Code < 0:
		#print 'pattern not found in the file, so add it'
             	sed_Cmd = 'sed -i ' + "'/" + search_Str+ "/s/$/ " + new_Str + "/g' " + file_Name
		#print sed_Cmd
		str = 'Inserting ' + new_Str  + ' in ' + file_Name + ' : Executing the command : ' + sed_Cmd
		write_to_Check_Tracing(str,0)
                s = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE) 
                if s:
                	#print 'sed to file successful'
                        Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
                else:
                        #print 'sed to file failed '
                        Log_Info ("True", STIG_ID, INFO, "FAILED")
	else:
                #print 'sed to file already done'
		str = 'Found ' + search_Str + 'in ' + file_Name
		write_to_Check_Tracing(str, 0)
		Log_Info("True", STIG_ID, INFO, "ALREADY DONE")

# This is function will change the permissions of the files list provided with the permissions suggested

def Change_File_Permissions( file_List, STIG_List, oct_String, perm_String, INFO):

	count = 0
	import stat
	for count, file_Name in enumerate(file_List):
		if os.path.exists(file_Name) == True:
			#print 'The file ' + file_Name + ' exist'
			FILE_PERM = ' '
			cmd = 'ls -l ' + file_Name + ' | ' + " awk '{print $1}'"		
			#cmd_Out = subprocess.call(['ls -l ', file_Name , ' | ', "awk '{print $1}'"])
			p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
			#Code = (p.communicate())[0].find(perm_String)
			Code = (p.communicate())[0]
			if Code != perm_String:
				int_Cmd = stat.S_IMODE(os.stat(file_Name).st_mode)
				int_Cmd = oct(int_Cmd)
				if (int_Cmd == '0' and oct_String == '0000'):
					int_Cmd = oct_String
				if int_Cmd != oct_String:
					Chmod = 'chmod ' + oct_String + ' ' + file_Name	
					q = subprocess.Popen(Chmod, shell=True, stdout=subprocess.PIPE)
					if q:
						Log_Info("True", STIG_List[count], INFO, 'SUCCESSFUL') 		
						#print 'permissions are changed'
					else:
						#print 'permissions are  not changed for %s', file_Name
						#	print 'the oct strings are not the same'
						Log_Info("True", STIG_List[count], INFO, 'FAILED') 		
				else:
					#print 'permissions are  already done'
					Log_Info("True", STIG_List[count], INFO, 'ALREADY DONE') 		

# This function will remove the empty directories mentioned in the list

def Remove_Empty_Directory( Dir_List, STIG_List, INFO):

	count = 0
	import stat
	for count, dir_Name in enumerate(Dir_List):
		if os.path.exists(dir_Name) == True:
			#print 'The file ' + file_Name + ' exist'
			cmd = 'rmdir ' + dir_Name 		
			#print cmd 
			p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
			if p:
				#print 'remove dir scuusss'
				Log_Info("True", STIG_List[count], INFO, 'SUCCESSFUL') 		
			else:
				#print 'remove dir fialed not changed'
				#	print 'the oct strings are not the same'
				Log_Info("True", STIG_List[count], INFO, 'FAILED') 		
		else:
			#print 'Remove dir are  already done'
			Log_Info("True", STIG_List[count], INFO, 'ALREADY DONE') 		
			

# This is function will change the permissions of the files list provided with the permissions suggested

def Change_Dir_Permissions(Dir_List, STIG_List, oct_String, perm_String, INFO):

	count = 0
	import stat
	for count, dir_Name in enumerate(Dir_List):
		if os.path.exists(dir_Name) == True:
			cmd = 'ls -ld ' + dir_Name + ' | ' + " awk '{print $1}'"		
			p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
			Code = (p.communicate())[0]
			if Code != perm_String:
				STIG_Info = STIG_List[count]
				int_Cmd = stat.S_IMODE(os.stat(dir_Name).st_mode)
				int_Cmd = oct(int_Cmd)
				if int_Cmd != oct_String:
					Chmod = 'chmod ' + oct_String + ' ' + dir_Name	
					q = subprocess.Popen(Chmod, shell=True, stdout=subprocess.PIPE)
					if q:
						Log_Info("True", STIG_Info, INFO, 'SUCCESSFUL') 		
					else:
						Log_Info("True", STIG_Info, INFO, 'FAILED') 		
				else:
					Log_Info("True", STIG_Info, INFO, 'ALREADY DONE') 		

# This function will replace a string in a file

def Replace_Pattern_In_File(search_Str, new_Str, file_Name, STIG_ID, INFO):

	grep_Cmd = 'egrep -q -e ' + "'" + search_Str + "'" + " " +file_Name
	Str = 'Executing the command : ' + grep_Cmd + ' : to check if the desired pattern present'
	write_to_Check_Tracing(Str, 0)
	p = os.system(grep_Cmd)
	if p == 0:
             	sed_Cmd = 'sed -i ' + "'s/" + search_Str+ "/" + new_Str +"/' " + file_Name
		#print sed_Cmd
                s = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE) 
                if s:
			Str = '\tCommand : ' + sed_Cmd  + ' executed successfully to replace with the new pattern'
			write_to_Check_Tracing(Str, 0)
                	#print 'replace pattern to file successful'
                        Log_Info ('True',STIG_ID, INFO, "SUCCESSFUL")
                else:
                        #print 'replace pattern sed to file failed '
                        Log_Info ('True', STIG_ID, INFO, "FAILED")
	else:
		if file_Name == '/etc/fstab':
             		sed_Cmd = 'sed -i ' + "'s/" + search_Str+ "/" + new_Str +"/' " + file_Name
			#print sed_Cmd
                	s = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE) 
                	if s:
				Str = '\tCommand : ' + sed_Cmd  + ' executed successfully to replace with the new pattern'
				write_to_Check_Tracing(Str, 0)
                		#print 'replace pattern to file successful'
                        	Log_Info ('True',STIG_ID, INFO, "SUCCESSFUL")
		else:
			#print 'replace pattern are  already done'
			Log_Info('False', STIG_ID, INFO, 'ALREADY DONE') 		


def Setup_Access_To_Cron_Job(STIG_ID, INFO):

	Success = 1
	check_2 = 0
	Setup_Cron_files = 1
	#if os.path.exists('/etc/cron.allow') == True:
	write_to_Check_Tracing('Setting up access to cron jobs with approriate files and ownership',0)
	if os.path.exists('/etc/cron.allow') == True:
		if os.path.exists('/etc/cron.deny') == True:
			check_2 = 1
	if check_2 == 1:
		if os.system("egrep -q root /etc/cron.allow") == 0:
			if os.system("egrep -q ALL /etc/cron.deny") == 0:
				Log_Info("True", STIG_ID, INFO, 'ALREADY DONE') 		
				Setup_Cron_files = 0
	if Setup_Cron_files == 1:
		if os.path.exists('/etc/cron.allow') != True:
			#print 'allow file does not exist'
			if os.system("touch /etc/cron.allow") == 0:
				allow_Ptr = open('/etc/cron.allow','a')
				allow_Ptr.write('root'+'\n')
				allow_Ptr.write('grid'+'\n')
				allow_Ptr.write('oracle'+'\n')
				allow_Ptr.close()
				#print 'root echoed to allow file'
				Success = 0
		else:
			if os.system('egrep -q root /etc/cron.allow') != 0:
				allow_Ptr = open('/etc/cron.allow','a')
				allow_Ptr.write('root'+'\n')
				allow_Ptr.close()
				#print 'update  to cron allow is done'
				
		if os.path.exists('/etc/cron.deny') != True:
			#print 'deny file does not exist'
			if os.system('touch /etc/cron.deny') == 0:
				allow_Ptr = open('/etc/cron.deny','a')
				allow_Ptr.write('ALL'+'\n')
				allow_Ptr.close()
				#print 'ALL echoed in deny file'
				Success = 0
		else:
			if os.system('egrep -q ALL /etc/cron.deny') != 0:
				allow_Ptr = open('/etc/cron.deny','a')
				allow_Ptr.write('ALL'+'\n')
				allow_Ptr.close()
				#print 'update  to cron deny is success'
				Success = 0

		if os.system('chmod 600 /etc/cron.allow') == 0:
			if os.system('chmod 600 /etc/cron.deny') == 0:
				if Success == 0:
					Log_Info("True", STIG_ID, INFO, 'SUCCESSFUL') 		
				else:
					Log_Info("True", STIG_ID, INFO, 'FAILED') 		
										
def Enable_Grub_Password(file_Name, STIG_ID, INFO):

	import getpass

	Status = 0
	Password = ""
	global pattern_Present
	global Log_Dir

	# Check if the password is already enabled.
	password_file = Log_Dir + 'grub_password'	
	
	Check_Pattern_Presence_In_File('^[[:space:]]*password --md5', file_Name) 
	#print 'The pattern Present is %d --->' % pattern_Present
	if pattern_Present:
		Log_Info('False', STIG_ID, INFO, "ALREADY DONE")
		#print 'The grub password is already enabled'
	else:
		#print 'The grub password is not enabled'
		# Set font as Green and reset
		subprocess.call(['tput', 'setaf', '2'])
		subprocess.call(['echo', 'Enabling the grub password using grub-md5-crypt'])
		subprocess.call(['echo', 'Please enter the password for grub'])
		subprocess.call(['tput', 'sgr0'])

		tmp_str1 = getpass.getpass('Enter Password : ')
		sys.stdout.flush()
		sys.stdin.flush()
		if tmp_str1:
   			tmp_str2 = getpass.getpass("Enter password again : ")
			sys.stdout.flush()
			sys.stdin.flush()
		else:
   			print "The Grub password cannot be an empty string. Exiting...STIG scripts"
			sys.exit(0)

		if(tmp_str1 != tmp_str2):
   			print "Password entered are not same, Exiting...STIG check scripts"
			sys.exit(0)

		# Open a temp for password grub file 
		fo = open(password_file, "w+")
		fo.write(tmp_str1);
		# Write doesn't newline at the end, so do it explicitly
		fo.write("\n");
		fo.write(tmp_str2);
		fo.write("\n");

		#print 'Close the temp password file' 
		fo.close()
		# Use shell command to do the magic of reading and writing to file
		grub_Cmd = 'echo $(cat ' + password_file + ' | /sbin/grub-md5-crypt 2> /dev/null) >> ' + password_file 
		os.system(grub_Cmd)

		grep_Cmd = 'grep ' + '"Sorry, passwords do not match" ' + password_file	
		r = subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE)
		if not r:
			print 'passwords do not match'
			Status = 1
		else:
			print '\nPasswords match : Proceeding...\n'

		grep_Cmd = 'grep ' + '"Empty password is not permitted" ' + password_file	
		t = subprocess.Popen(grep_Cmd, shell=True, stdout=subprocess.PIPE)
		if not t:
			print 'passwords do not match'
			Status = 1
		#print 'passwords match'
		file = open(password_file,'r')
		str3 ="Password:"
		splitString=''
		for line in file:
    			count = line.find(str3)
			if count >= 0:
       				splitString = line.split()

		if splitString[3] is '':
			print 'The grub password generation was not successful'
			#sys.exit(0)
			Status = 1
		if os.path.exists(file_Name) == True:
			fptr_grub_file = open(file_Name, "a")
		else:
			print 'The file %s does not exist. Exiting from fixing STIG violations' % file_Name
			sys.exit(0)
       		#Above will have encrypted password for using in grub.conf
		if Status == 1:
			print 'Failed to generate password, so log messages and return'
			Log_Info('False',STIG_ID, INFO, "FAILED")
			if os.path.exists(password_file) == True:
				rm_Cmd = 'rm -f ' + password_file 
				p = subprocess.Popen(rm_Cmd, shell=True, stdout=subprocess.PIPE)
				if p:
					print 'Failed to generate password file, %s file removed ' % password_file 
			return 

		else:
			splitString[3] = str(splitString[3])
			sed_Cmd = 'sed -i ' + "'/^[[:space:]]*default=/ipassword --md5 " + splitString[3] + "' " + file_Name
			p = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE)
			if  p:
				#print 'grub password update successful'
                       		Log_Info ('True',STIG_ID, INFO, "SUCCESSFUL")
			else:
				#print 'ERROR : The grub password not modified '	
				Log_Info('True', STIG_ID, INFO, "FAILED")
	
	if os.path.exists(password_file) == True:
		rm_Cmd = 'rm -f ' + password_file 
		p = subprocess.Popen(rm_Cmd, shell=True, stdout=subprocess.PIPE)
		if not p:
			print 'The grub password file was not removed'

# spinning cursor

def spinning_Cursor():
	while True:
		for cursor in '|/-\\':
			yield cursor
			
# This function is used to restart the services

def Restart_Services():

	global RESTART_SSHD
	global RESTART_SENDMAIL
	global REEXAMINE_INITTAB
	import time
	import sys

	if RESTART_SSHD == 1:
		write_to_Check_Tracing('Executing : /sbin/service sshd restart', 0)
		if os.system('/sbin/service sshd restart') != 0:
			INFO = "Disable direct login as root from ssh may not work"
			STIG_ID = "GEN001120"
			Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
			print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' : FAILED TO RESTART SSHD SERVICE' 
                        print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"' 
			q = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
			if not q:
				print '\nrestart_services: Update to SSHD file was not successful'
				write_to_Check_Tracing('\trestart_services: Update to SSHD file was not successful',0)
			else:
				write_to_Check_Tracing('\trestart_services: Update to SSHD file was successful',0)
	if RESTART_SENDMAIL == 1:			
		write_to_Check_Tracing('Executing : /sbin/service sendmail restart', 0)
		if os.system('/sbin/service sendmail restart') != 0: 
			INFO = "Disable of sendmail version may not work"
			STIG_ID = "GEN0004560"
			Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
			print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' : FAILED TO RESTART SENDMAIL SERVICE' 
                        print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"'
			q = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
			if not q:
				print '\nrestart_services: Update to sendmail file was not successful'
				write_to_Check_Tracing('\trestart_services: Update to sendmail file was not successful',0)
			else:
				write_to_Check_Tracing('\trestart_services: Update to sendmail file was successful',0)

	if RESTART_OAKD == 1:			
		write_to_Check_Tracing('Executing : /etc/init.d/init.oak shutdown', 0)
		#if subprocess.call(['/etc/init.d/init.oak', 'shutdown']) == 0: 
		if os.system('/etc/init.d/init.oak shutdown') == 0: # 
			print '\noak shutdown successful'
			write_to_Check_Tracing('\toak shutdown successful',0)
		else:
			print '\noak shutdown was not successful'
			write_to_Check_Tracing('\toak shutdown was not successful',0)

		print '\noak will be starting soon ....please wait.....'
		#time.sleep(300)

		spinner = spinning_Cursor()
		for _ in range(350):
			sys.stdout.write(spinner.next())
			sys.stdout.flush()
			time.sleep(0.1)
			sys.stdout.write('\b')
		sys.stdout.write('\n')

		#if subprocess.call(['/etc/init.d/init.oak', 'start'] )== 0:  
		write_to_Check_Tracing('Executing : oak start begin',0)
		if os.system('/etc/init.d/init.oak start')== 0:  # 
			print '\noak start begin successful'
			write_to_Check_Tracing('\toak start begin was successful',0)
		else:
			print '\noak start begin unsuccessful'
			write_to_Check_Tracing('\toak start begin was successful',0)

	if REEXAMINE_INITTAB == 1:
		write_to_Check_Tracing('Executing : init Q',0)
		if os.system('init Q')  != 0:	
			INFO = 'Changes made to file /etc/inittab may not work'
			STIG_ID = 'LNX00580 GEN000020'
			Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
			print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' : init process failed to reexamine "/etc/inittab" file' 
                        print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"' 
			q = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
			if not q:
				print '\nUpdate to inittab file was not successful'
				write_to_Check_Tracing('\tUpdate to inittab file was not successful',0)
		else:
			INFO = 'Changes made to file /etc/inittab may not work'
			STIG_ID = 'LNX00580 GEN000020'
			Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
			print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' : init process successfully reexamined "/etc/inittab" file' 
                        print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"' 
			q = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
			if not q:
				print 'Update to inittab file was not successful'
				write_to_Check_Tracing('\tUpdate to inittab file was not successful',0)
	#print 'Restart 8.5 Done'

# This function checks for three unsuccessful attempts, after which it will lock		
def Lock_Account_After_Three_Fail_Attempts(file_Name, STIG_ID, INFO):
	
	global ol6_Flag
	L1 = "auth.*required.*pam_env.so"
	if ol6_Flag == 'FALSE':
		L2 = "auth		required	pam_tally.so onerr=fail deny=3 unlock_time=300"
	else:
		L2 = "auth		required	pam_tally2.so onerr=fail deny=3 unlock_time=604800"

	grep_Cmd = 'egrep -q "^auth.*required.*pam_tally.*unlock_time=.*" ' + file_Name
	Str = 'Executing the command : ' + grep_Cmd
	write_to_Check_Tracing(Str,0)
	u = os.system(grep_Cmd)
	if u != 0:
		sed_Cmd = 'sed -i '+ "'/^[[:space:]]*"+L1+".*/s/$/\\n"+L2+"/' " + file_Name
		#print sed_Cmd
		p = os.system(sed_Cmd)
		if p == 0:
			#print 'system-auth update succesful'
			write_to_Check_Tracing('\tsystem-auth update succesful',0)
        		Log_Info ("True", STIG_ID, INFO, "SUCCESSFUL")
      		else:
			#print 'system-auth update failed'
        		Log_Info ("True", STIG_ID, INFO, "FAILED")
	else:
		#print 'system-auth update already done'
       		Log_Info("False", STIG_ID, INFO, "ALREADY DONE")


# This function is used to enable ssh root login

def Enable_SSH_Root_Login(argv):

	global	STIG_SCRIPT_VERSION
	global  Log_Dir
	global  STIG_Log_File
	global  ol6_Flag

	subprocess.call(['tput', 'setaf', '4'])
	#print '\n\tINFO: Running STIG Script Version %s : ' % STIG_SCRIPT_VERSION
	#print
	print '\n\tINFO: Enabling the SSH root login ........\n'
	print
	subprocess.call(['tput', 'sgr0'])
	global RESTART_SSHD
	global pattern_Absent
	global Host_Name

	print_Str = '\n' + '\n=========================Executing the command : stig.py enable  ===================================================\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	print_Str = '\n' + '\nLOGGING OF STIG ENABLE SSH STATUS AND TRACING OF COMMANDS EXECUTED TO ENABLE SSH ROOT LOGIN : '+ Date_Str + '\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	print_Str = '\n' + '\n=====================================================================================================================\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)


	INFO="Direct ssh login as root is Enabled"
	STIG_ID="GEN001120"
	Check_Pattern_Absence_In_File("^[[:space:]]*PermitRootLogin[[:space:]]*no", "/etc/ssh/sshd_config")
	#Check_Pattern_Absence_In_File("^[[:space:]]*PermitRootLogin[[:space:]]*no", "sshd_config")
	if not pattern_Absent:
		Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
		print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' on system '
                print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"'  + " >> " + Host_Name
		#print print_Cmd
		q = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
		if not q:
			print '\nEnable - print to file %s not successful' % Host_Name
	else:
        	sed_Cmd = 'sed -i ' + "'s/^[[:space:]]*PermitRootLogin.*no/PermitRootLogin yes/' " +  "/etc/ssh/sshd_config"
		#print sed_Cmd
		q = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE)
		if q:
			#print 'Setting restart sshd to 1'
         		RESTART_SSHD=1
			Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
			print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' on system '
               		print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"'  + " >> " + Host_Name
			#print print_Cmd
			subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)

	if RESTART_SSHD == 1:
		#print 'Enable restart sshd'
		Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
		print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' Restarting sshd services on sysstm ' 
               	print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"'  + " >> " + Host_Name
		#print print_Cmd
		subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
		Restart_Services()

	print_Str = '\n' + '\n=====================================================================================================================\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)

# This function is used to disable ssh root login

def Disable_SSH_Root_Login(argv):

	global STIG_SCRIPT_VERSION
	global RESTART_SSHD
	global pattern_Present
	global Host_Name
	global Log_Dir
	global STIG_Log_File
	global ol6_Flag

	subprocess.call(['tput', 'setaf', '4'])
	#print '\n\tINFO: Running STIG Script Version %s : ' % STIG_SCRIPT_VERSION
	#print
	print "\n\tINFO: Disabling the SSH root login ........\n"
	print
	subprocess.call(['tput', 'sgr0'])

	print_Str = '\n' + '\n=========================Executing the command : stig.py disable ===================================================\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
	print_Str = '\n' + '\nLOGGING OF STIG DISABLE SSH STATUS AND TRACING OF COMMANDS EXECUTED TO DISABLE SSH ROOT LOGIN : '+ Date_Str + '\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	print_Str = '\n' + '\n=====================================================================================================================\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)

	INFO="Direct ssh login as root is disabled"
	STIG_ID="GEN001120"
	Check_Pattern_Presence_In_File("^[[:space:]]*PermitRootLogin[[:space:]]*no", "/etc/ssh/sshd_config")
	#Check_Pattern_Presence_In_File("^[[:space:]]*PermitRootLogin[[:space:]]*no", "sshd_config")
	if pattern_Present:
		Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
		print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' on system '
                print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"'  + " >> " + Host_Name
		#print print_Cmd
		q = subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
		if not q:
			print '\nprint to file %s not successful' % Host_Name
		RESTART_SSHD=1
	else:
		#print '1...'
		Check_Pattern_Presence_In_File("^[[:space:]]*PermitRootLogin[[:space:]]*yes", "/etc/ssh/sshd_config")
		#Check_Pattern_Presence_In_File("^[[:space:]]*PermitRootLogin[[:space:]]*yes", "sshd_config")
		if pattern_Present:
         		#sed_Cmd = 'sed -i ' + "'s/^[[:space:]]*PermitRootLogin.*yes/PermitRootLogin no/' " +  "/etc/ssh/sshd_config"
         		sed_Cmd = 'sed -i ' + "'s/^[[:space:]]*PermitRootLogin.*yes/PermitRootLogin no/' " +  "/etc/ssh/sshd_config"
			#print sed_Cmd
			q = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE)
			if q:
         			RESTART_SSHD=1
				Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
				print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' on system '
               			print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"'  + " >> " + Host_Name
				subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
				#print '1 - sed  to file is succesful'
			else:
				Check_Pattern_Presence_In_File("^[[:space:]]*PermitRootLogin.*", "/etc/ssh/sshd_config")
				#Check_Pattern_Presence_In_File("^[[:space:]]*PermitRootLogin.*", "sshd_config")
				if pattern_Present:
					#print '2 - sed to file not successful'
					#sed_Cmd='sed -i ' +"'/^#[[:space:]]*PermitRootLogin.*/s/$/\nPermitRootLogin no/' " + '/etc/ssh/sshd_config'
					sed_Cmd='sed -i ' +"'/^#[[:space:]]*PermitRootLogin.*/s/$/\nPermitRootLogin no/' " + '/etc/ssh/sshd_config'
					rq = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE)
					if rq:
         					RESTART_SSHD=1
						Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
						print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' on system '
               					print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"'  + " >> " + Host_Name
						subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
					else:
						#print_Cmd = 'printf "\n%s" ' + "PermitRootLogin no " + ">>" + " " + '/etc/ssh/sshd_config'
						print_Cmd = 'printf "\n%s" ' + "PermitRootLogin no " + ">>" + " " + '/etc/ssh/sshd_config'
						subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
						RESTART_SSHD=1
						subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
						Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
						print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' on system ' 
               					print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"'  + " >> " + Host_Name
						subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
		else:
  			Insert_New_Line_In_File("^[[:space:]]*PermitRootLogin.*","PermitRootLogin no","/etc/ssh/sshd_config", STIG_ID,INFO)
			RESTART_SSHD=1
			
	if RESTART_SSHD == 1:
		Date_Str = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
		print_Str = Date_Str + ' : [STIG_ID : ' + STIG_ID + '] : ' + INFO + ' Restarting sshd services on sysstm ' 
               	print_Cmd = 'printf "%s\n" ' + '"'+ print_Str +'"'  + " >> " + Host_Name
		subprocess.Popen(print_Cmd, shell=True, stdout=subprocess.PIPE)
		Restart_Services()
			
	print_Str = '\n' + '\n=====================================================================================================================\n\n' 
        Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + STIG_Log_File
	r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)
	
# This is function is used to enable delay in  system-auth file
def Enable_Delay_In_Seconds(file_Name, STIG_ID, INFO):

	L1 = "auth.*required.*pam_env.so"
	L2 = "auth		optional	pam_faildelay.so delay=5000000"
	#Check_Pattern_Absence_In_File('[[:space:]]+pam_faildelay.*delay=5000000.*', file_Name) 
	grep_Cmd = 'egrep -q ' + '[[:space:]]+pam_faildelay.*delay=5000000.*' + ' ' + file_Name 
	str = 'Checking if delay is enabled in system-auth file, executing the command : ' + grep_Cmd
	write_to_Check_Tracing(str,0)
	u = os.system(grep_Cmd)	
	if u != 0:
		sed_Cmd = 'sed -i ' + "'/^[[:space:]]*"+ L1+".*/s/$/\\n"+L2+"/'" + " " + file_Name
		#print sed_Cmd
		t = os.system(sed_Cmd)
		#t = subprocess.Popen(sed_Cmd, shell=True, stdout=subprocess.PIPE)
		if t == 0:
			str = 'Enabling delay in system-auth file, executing : ' + sed_Cmd
			write_to_Check_Tracing(str,0)
			Log_Info("True", STIG_ID, INFO, "SUCCESSFUL")
		else:
			#print 'faield'	
			Log_Info("False", STIG_ID, INFO, "FAILED")
	else:
		str = 'The delay in already enabled in system-auth file '
		write_to_Check_Tracing(str,0)
		Log_Info("False", STIG_ID, INFO, "ALREADY DONE")

		
	
########################################################################################
## If the user is NOT root, the STIG script will not be executed

p = subprocess.Popen(['id'], stdout=subprocess.PIPE)
#ret_Code = (p.communicate()[0]).find('mrvachar') 
ret_Code = (p.communicate()[0]).find('root') 

if ret_Code < 0:
	print '\tINFO: You have not logged in as root user, cannot execute STIG scripts. Exiting....'
	sys.exit(0)

# Set the STIG script version
Set_STIG_Script_Version()

# Check whether you are in Dom0 or Dom1
# IF you are in Dom0, you cannot execute the script

Check_If_VM_Dom0()

def Check_Duplicate_Accounts(file_Name, cmd):

	global exists_flag
	exists_flag=False
	str = 'Executing the command : ' + cmd
	write_to_Check_Tracing(str,0)
	out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	out1 = out.communicate()[0].strip('\n')
	if (out1 != '0'):
		exists_flag = True
		return exists_flag

def Fix_Duplicate_Accounts(file_Name, cmd):

	global exists_flag
	exists_flag=False
	str = 'Executing the command : ' + cmd
	write_to_Check_Tracing(str,0)
	out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	out1 = out.communicate()[0].strip('\n')
	if (out1 != ''):
		exists_flag = True
		#print exists_flag
		return exists_flag


def Manage_ACL(file_List, stig_List, info_List, Action):

	#print 'inside manage ACL func'
	import stat
	count = 0
	global exists_flag	
	exists_flag=False
	for count, file_Name in enumerate(file_List):
		#print 'inside for'
		#print file_Name
		if os.path.exists(file_Name) == True:
			cmd = 'ls -l ' + file_Name
			out = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
			str = out.communicate()[0]
			#print str
			str1 = str.strip('\n')
			str2 = str1.split(' ')[0]
			#print str2
			substr = '+'
			if substr in str2:
				if Action == "check":
					#print 'in check'
					INFO="The " + info_List[count] + "has been found"
 					Log_Info("False", stig_List[count], INFO, "FAILED")
				else:
					substr = 'd'
					if substr in str2:
						acl_cmd = 'setfacl --remove-all ' + file_Name + '*'
					else:
						acl_cmd = 'setfacl --remove-all ' + file_Name 
					out = os.system(acl_cmd)
					if out == 0:
						INFO="The ACL for" + info_List[count] + " is removed"
                        			Log_Info('True', stig_List[count], INFO, "SUCCESSFUL")
	
			else:
	
				INFO="The ACL for" + info_List[count] + " has already been removed"
				#print 'already removed '
 				Log_Info("True", stig_List[count], INFO, "ALREADY DONE")
			exists_flag = False
		else:
			INFO="The ACL for" + info_List[count] + " cannot be removed, file does not exist"
			write_to_Check_Tracing(INFO,0)

def Check_ACL_exist(file_Name):

	global exists_flag	
	exists_flag=False
	cmd = 'ls -l ' + file_Name
	out = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
	str = out.communicate()[0]
	str1 = str.strip('\n')
	str2 = str1.split(' ')[0]
	substr = '+'
	if substr in str2:
		exists_flag = True	
		str = 'The ' + file_Name + ' has an extended ACL list'
		write_to_Check_Tracing(str, 0)
		return exists_flag

def Check_OEL_Support():

	if((os.path.exists('/etc/oracle-release') == False) and (os.path.exists('/etc/enterprise-release') == False)):
		class color_Code:
			RED = '\033[91m'
			END = '\033[0m'
		Str = '\n\tERROR: ODA is running on an unsupported Linux. Exiting STIG Verification ....'
		print color_Code.RED + Str + '\n' + color_Code.END
		sys.exit(0)

def Check_PWCK(cmd):

	global exists_flag	
	exists_flag=False
	out = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
	str = out.communicate()[0]
	if str > 0: 
		exists_flag = True	

def Check_User_Deletions(actions, STIG_ID, INFO):
	global AUDIT_RULE_SET
	Execute_AUDIT_Command("sudo grep -w " +  actions  + " /etc/audit/audit.rules")
	if AUDIT_RULE_SET == 0:
		Flag_Str = 'False'
		INFO = INFO + ' using ' + actions
 		Log_Info(Flag_Str, STIG_ID, INFO, "FAILED")

def Execute_AUDIT_Command(cmd):

	global AUDIT_RULE_SET
	AUDIT_RULE_SET=1
	out = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
	code = out.communicate()[0]
	if code == '':
		AUDIT_RULE_SET = 0
	return AUDIT_RULE_SET

def Check_OL6():
	global ol6_Flag
	find_Str = 'el6uek'
	cmd = 'uname -r'
	out = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
	code = out.communicate()[0].find(find_Str)
	if code > 0:
		ol6_Flag = 'TRUE'
	else:
		ol6_Flag = 'FALSE'
	return ol6_Flag
	#str1 = 'Executing the command : ' + cmd + ' : to check if the system has OL5 or OL6'
	#write_to_Check_Tracing(str1, 0)

#BEGIN : TO check whether valid arguments are passed with STIG or not
#python stig.py <arg1> <arg2>
def main(argv):

 	global ol6_Flag	
	Get_Host_Name()	
	global Log_Dir
	global STIG_Log_File	

	Check_OEL_Support()
	i = len(argv)
	if ((i == 1)  or (i > 4)):
		class color_Code:
			RED = '\033[91m'
			END = '\033[0m'
		print color_Code.RED + '\n\tINFO: Incorrect parameters passed with STIG scripts, exiting...\n' + color_Code.END
		Stig_Usage()
		sys.exit(0)

	Create_STIG_Log_Dir(argv[1])
	Set_STIG_Log_File_Name(argv[1])
	ol6_Flag = Check_OL6()
	if ol6_Flag <= 0:
		print '\tThe ODA system is not OL6. Exiting...\n'
		sys.exit(0)

	if os.path.exists('/opt/oracle/oak/') == True:
		Stig_exec_check = '/opt/oracle/oak/stig/' + 'stig_check'
		if os.path.exists(Stig_exec_check) == False:
			Str = 'mkdir /opt/oracle/oak/stig/'
			r = subprocess.Popen(Str, shell=True, stdout=subprocess.PIPE)
			Str_echo = 'echo "" > /opt/oracle/oak/stig/stig_check'
			rr = subprocess.Popen(Str_echo, shell=True, stdout=subprocess.PIPE)
			os.system('touch /opt/oracle/oak/stig/stig_check')
			os.system('chown root:root /opt/oracle/oak/stig/stig_check')
			os.system('chmod 600 /opt/oracle/oak/stig/stig_check')
			print_Str = 'stig original_backup 1'
			stig_check_file = '/opt/oracle/oak/stig/stig_check'
        		Cmd = 'printf ' +  '"'+print_Str+'"'  + " >> " + stig_check_file
			r = subprocess.Popen(Cmd, shell=True, stdout=subprocess.PIPE)

			print '\n\tPreserving System Files state to roll them back if needed'
			print '\tPlease wait...'
			Backup_Original_System_Files()

	if ((argv[1] == 'fix') and (argv[2] == 'rollback')):
		print '\n'
		print '\tGetting all system image state system files to its original Imaged state'
		print '\tPlease wait...Verifying...\n'
		if os.path.exists('/opt/oracle/oak/stig/stig_check') == True:
			# STIG fix has already been executed once at least
			# if argv[2] is rollback, then call rollback
			stig_fix_Check = 'cat /opt/oracle/oak/stig/stig_check | ' + "awk '{print $3}'"
			q = subprocess.Popen(stig_fix_Check, shell=True, stdout=subprocess.PIPE)
			check_val = q.communicate()[0].strip('\n')
			#print check_val 
			i_check_val = int(check_val)
			if i_check_val == 1:
				Rollback_Original_System_Files()
				print '\n\tRolled back all original system files\n'
				#Check if system needs to be rebooted
			else:
				print '\tSTIG scripts not executed to fix security vulnerabilities'
				print '\tRollback of system files are not required'
				print '\tExiting...\n'
			sys.exit(0)

	if ((argv[1] == 'fix') and (argv[2] == 'restore_prev')):
		print '\n'
		print '\tRestoring all previous system files state '
		print '\tPlease wait...Verifying...\n'

		if os.path.exists('/etc/passwd.backup_stig') == True:
			# STIG fix has already been executed once at least
			# if argv[2] is rollback, then call rollback
			Restore_Previous_State()
			print '\n\tRestored previous state system files\n'
			#Check if system needs to be rebooted
		else:
			print '\tSTIG scripts not executed to fix security vulnerabilities'
			print '\tRestore of system files are not required'
			print '\tExiting...\n'
		sys.exit(0)


	if  i == 2:
		if ((argv[1] != 'enable') and (argv[1] != 'disable') and (argv[1] != '-help') and (argv[1] != 'check') and (argv[1] != '-version') and (argv[1] != '-v') and (argv[1] != 'v') and (argv[1] != '-h') and (argv[1] != '-?') and (argv[1] != 'fix') and (argv[1] != '-V') and (argv[1] != 'V') and (argv[1] != '-Version') and (argv[1] != 'deletelog')): 
			subprocess.call(['clear', '\n'])
			class color_Code:
				RED = '\033[91m'
				END = '\033[0m'
			Str = '\n\tINFO:	The parameter ' + argv[1] + ' is not valid'
			print color_Code.RED + Str + '\n' + color_Code.END
			Invalid_Arguments(argv)
		else:
			#print '\tINFO: The parameter %s is valid '% argv[1]
			#sys.exit(0)
			if (argv[1] == 'fix'):
				#Display_STIG_Script_Msg(argv)
				Invalid_Arguments(argv)
				Stig_Usage()
				#Fix_STIG_Violations(argv)
				sys.exit(0)

			elif (argv[1] == 'check'):
				#Display_STIG_Script_Msg(argv)
				Invalid_Arguments(argv)
				Stig_Usage()
				sys.exit(0)

			elif (argv[1] == 'enable'):
				Display_STIG_Script_Msg(argv)
				Enable_SSH_Root_Login(argv)
				sys.exit(0)

			elif (argv[1] == 'disable'):
				Display_STIG_Script_Msg(argv)
				Disable_SSH_Root_Login(argv)
				sys.exit(0)

			elif (argv[1] == 'deletelog'):
				Delete_Old_STIG_Log_Files()	
				sys.exit(0)

			elif (argv[1] == '-version' or argv[1] == '-v' or argv[1] == '-V' or argv[1] == '-Version' or argv[1] == 'V' or argv[1] == 'v'):
				Display_STIG_Script_Version()
				#Stig_Usage()
				sys.exit(0)
			else:
				Stig_Usage()
				sys.exit(0)

	elif  i == 3:
		# To prompt the user to use -force option, even if there are previous runs
		#if ((argv[1] == '-fix') and ((argv[2] != '-force') and (argv[2] != '-h') and (argv[2] != '-help') and (argv[2] != '-all') and (argv[2] != '-perm'))):
		if ((argv[1] == 'fix') and ((argv[2] != 'force') and (argv[2] != '-h') and (argv[2] != '-help') and (argv[2] != '-?') and (argv[2] != '?') and (argv[2] != '-H') and  (argv[2] != 'all') and (argv[2] != 'perm') and (argv[2] != 'conf') and (argv[2] != 'account') and (argv[2] != 'fs') and (argv[2] != 'grub') and (argv[2] != 'audit') and (argv[2] != 'access') and (argv[2] != 'rollback') and (argv[2] != 'restore_prev'))):
			class color_Code:
				RED = '\033[91m'
				END = '\033[0m'
			Str = '\n\tINFO:	The parameters ' + argv[1] + ' and ' + argv[2]  + ' are not valid'
			print color_Code.RED + Str + '\n\n' + color_Code.END
			if (argv[2] == 'force'):
				Check_Prev_Runs(argv[1], argv[2])
			Invalid_Arguments(argv)
			Stig_Usage()
			sys.exit(0)
	
		if (argv[1] == '-help')  or (argv[1] == '-?') or (argv[1] == '-h'): 
			Stig_Usage()

		if (argv[1] != 'fix') and (argv[2] == 'force'):
			class color_Code:
				RED = '\033[91m'
				END = '\033[0m'
			Str = '\n\tINFO:	The parameters ' + argv[1] + ' and ' + argv[2]  + ' are not valid'
			print color_Code.RED + Str + '\n\n' + color_Code.END
			Invalid_Arguments(argv)
			sys.exit(0)
		if ((argv[1] == 'fix') and ((argv[2] != 'force') and (argv[2] != '-h') and (argv[2] != '-help') and (argv[2] != '-?') and (argv[2] != '?') and (argv[2] != '-H') and  (argv[2] != 'all') and (argv[2] != 'perm') and (argv[2] != 'conf') and (argv[2] != 'account') and (argv[2] != 'fs') and (argv[2] != 'grub') and (argv[2] != 'audit') and (argv[2] != 'access') and (argv[2] != 'rollback') and (argv[2] != 'restore_prev'))):
			Invalid_Arguments(argv)
			Stig_Fix_Usage()
			sys.exit(0)
		elif ((argv[1] == 'check') and ((argv[2] != '-h') and (argv[2] != '-help') and (argv[2] != '-?') and (argv[2] != '?') and (argv[2] != '-H') and  (argv[2] != 'all') and (argv[2] != 'perm') and (argv[2] != 'conf') and (argv[2] != 'account') and (argv[2] != 'fs') and (argv[2] != 'grub') and (argv[2] != 'audit') and (argv[2] != 'access'))):
			Invalid_Arguments(argv)
			Stig_Check_Usage()
			sys.exit(0)
		elif (argv[1] == 'fix') and (argv[2] == 'force'):
			Display_STIG_Script_Msg(argv)

			Take_Conf_File_Backup()
			Fix_STIG_Violations(argv)
			sys.exit(0)
		#elif (argv[1] == '-fix') and ((argv[2] == '-perm') or (argv[2] == '-all')):
		elif ((argv[1] == 'fix') and ((argv[2] == 'force') or (argv[2] == 'perm') or (argv[2] == 'all') or (argv[2] == 'conf') or (argv[2] == 'access') or (argv[2] == 'grub') or (argv[2] == 'account') or (argv[2] == 'fs') or (argv[2] == 'audit') and (argv[2] != 'rollback') and (argv[2] != 'restore_prev'))):
			Display_STIG_Script_Msg(argv)
			Take_Conf_File_Backup()
			Fix_STIG_Violations(argv)
			sys.exit(0)
		elif ((argv[1] == 'check') and ((argv[2] == 'perm') or (argv[2] == 'all') or (argv[2] == 'conf') or (argv[2] == 'access') or (argv[2] == 'grub') or (argv[2] == 'account') or (argv[2] == 'fs') or (argv[2] == 'audit'))):
			Display_STIG_Script_Msg(argv)
			Check_STIG_Violations(argv)
			sys.exit(0)
		elif ((argv[1] == 'fix') and ((argv[2] == '-h') or (argv[2] == '-help') or (argv[2] == '?') or (argv[2] == '-?'))):
		 	Stig_Fix_Usage()	
			sys.exit(0)
		elif ((argv[1] == 'check') and ((argv[2] == '-h') or (argv[2] == '-help') or (argv[2] == '?') or (argv[2] == '-?'))):
		 	Stig_Check_Usage()	
			sys.exit(0)
		else:
			class color_Code:
				RED = '\033[91m'
				END = '\033[0m'
			Str = '\n\tINFO:	The parameters ' + argv[1] + ' and ' + argv[2]  + ' are not valid'
			print color_Code.RED + Str + '\n\n' + color_Code.END
			#Invalid_Arguments(argv)
			Stig_Usage()
			sys.exit(0)

if __name__ == '__main__':
	main(sys.argv)

