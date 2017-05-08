import os
import sys
import json
import dropbox
import hashlib
import time
import fileinput
import shutil
import datetime

from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxltieclient import TieClient
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib

TOKEN = ""

MAXFILESIZE = 1024 * 1024 * 10

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file("dxl.conf")

def md5hex(filepath):
    return hashlib.md5(open(filepath, 'rb').read()).hexdigest()

def sha1hex(filepath):
    return hashlib.sha1(open(filepath, 'rb').read()).hexdigest()

DBFile = "fileDB.txt"
template = "misc/template.html"
reportcake = "report.html"

REPORT_NAME = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + ".log"

def checkDB(DBFile):
	if os.path.exists(DBFile):
		print "### Database exists"
		return 0
        else:
		print "### Database initialization"
		with open(DBFile, "wb") as buffer_file:
            		buffer_file.write("DropboxHash \t md5 \t sha1 \t name\n")
            	return 1

def isFileInList(DropboxHash, DBFile):
	if DropboxHash in open(DBFile).read():
		return 1
	else:
		return 0

def getFileInList(DropboxHash, DBFile):
	if (isFileInList(DropboxHash, DBFile)):
		with open(DBFile) as f:
    			for line in f:
        			if DropboxHash in line:
             				return line
	else:
		return 0
		
def addFileInList(DropboxHash,md5, sha1, name, DBFile):
	if not (isFileInList(DropboxHash, DBFile)):		
		with open(DBFile, "a") as buffer_file:
                	buffer_file.write(DropboxHash + " " + md5 + " " + sha1 + " " + name + "\n")
                return 1


def addLogReport(Log, REPORT_NAME):		
	with open(REPORT_NAME, "a") as buffer_file:
        	buffer_file.write(Log + "\n")
        return 1

def sortReport(REPORT_NAME):
	with open(REPORT_NAME, "r+") as f:
	    lines = f.readlines()
	    lines.sort()        
	    f.seek(0)
	    f.writelines(lines)


def templateUpdate(file,searchExp,replaceExp):
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp,replaceExp)
        sys.stdout.write(line)


reputations = {"99": "Known trusted", "85": "Most likely trusted", "70": "Might be trusted", "50": "Unknown", "30": "Might be malicious", "15": "Most likely malicious", "1": "Known malicious", "0": "Not Set"}

scores = {"99": 0, "85": 0, "70": 0, "50": 0, "30": 0, "15": 0, "1": 0, "0": 0}

folders = ['']

start = time.time()

checkDB(DBFile)

print "### Max file size scan:" + str(MAXFILESIZE / (1024*1024)) + " MB"

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()
    print "### DXL connected"

    # Create the McAfee Threat Intelligence Exchange (TIE) client
    tie_client = TieClient(client)

    # Create the Dropbox instance
    try:
    	box = dropbox.Dropbox(TOKEN)
    	print "### Dropbox connected"
    except:
	print "Dropbox connection problem. Check the TOKEN variable or your internet connection"
	exit(1)

    print "### Getting content from Dropbox\n"
    for folder in folders:
	    # Get the content of the "Software" folder

	    content = box.files_list_folder(folder)

	    for file in content.entries:

		try:
			if ( file.size < MAXFILESIZE ):
				#check if Dropbox servers are providing the content_hash

				try:
					#content_hash = box.files_get_metadata(path=str(file.path_display)).content_hash
					content_hash = file.id + file.rev
				except:
					print "hash not provided from dropbox"
					content_hash = '-'

				# check if the hash has been already calculated in the past
				if not isFileInList(content_hash, DBFile):
					print "Downloading and calculating the HASH..."

					# Download the file
					box.files_download_to_file(str(file.name),path=str(file.path_display))
					# Calc md5 and sha1
					md5item = md5hex(str(file.name))
					sha1item= sha1hex(str(file.name))

					if content_hash != '-':
						addFileInList(content_hash, md5item, sha1item, str(file.name), DBFile)

					# Delete the file
					os.remove(str(file.name))
				
				else:
					print "File already cached! Updating reputation."
					fileDescription = getFileInList(content_hash, DBFile)
					md5item = fileDescription.split(' ')[1]
					sha1item = fileDescription.split(' ')[2]
					
				#
				# Perform the file reputation query
				#
				reputations_dict = \
				    tie_client.get_file_reputation({
					HashType.MD5: md5item,
					HashType.SHA1: sha1item
				    })

				# Display the Global Threat Intelligence (GTI) trust level for the file
				if FileProvider.GTI in reputations_dict:
				    gti_rep = reputations_dict[FileProvider.GTI]
				    scores[str(gti_rep[ReputationProp.TRUST_LEVEL])] += 1
				    print "[GTI: " + reputations[str(gti_rep[ReputationProp.TRUST_LEVEL])] + "] " + file.path_display + "\n"
				    addLogReport("[GTI: " + reputations[str(gti_rep[ReputationProp.TRUST_LEVEL])] + "] " + file.path_display, REPORT_NAME)
				    

		except:
			folders.append(str(file.path_display))

end = time.time()

print "\n[" + str(sum(scores.values())) + "] Total file scanned in " + str(int(end-start)) + " seconds\n"
sortReport(REPORT_NAME)
print "Check the log file " + REPORT_NAME + " for details"
shutil.copy(template,reportcake)
templateUpdate(reportcake, "report-title","GTI report")

for rep,score in scores.items():
	templateUpdate(reportcake, "['" + reputations[rep] + "',0],","['" + reputations[rep] + "',     " + str(score) + "],")
	if score > 0:
		print "[" + str(score) + "] " + reputations[rep]





