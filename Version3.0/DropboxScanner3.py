TOKEN = ""
MAXFILESIZE = 1024 * 1024 * 10
TITLE="Dropbox TIE Scanner v 1.0"
DESCRIPTION="Threat Intelligence Exchange Dropbox Scanner"
AUTHOR="Author: Filippo Sitzia"
DBFile = "fileDB.txt"
reputations = {"99": "Known trusted", "85": "Most likely trusted", "70": "Might be trusted", "50": "Unknown", "30": "Might be malicious", "15": "Most likely malicious", "1": "Known malicious", "0": "Not Set"}

from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxltieclient import TieClient
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, CertProvider, CertEnterpriseAttrib

from Tkinter import *
import time
import os
import sys
import json
import dropbox
import hashlib
import time
import fileinput
import shutil
import datetime

REPORT_NAME = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + ".log"

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file("dxl.conf")

def md5hex(filepath):
    return hashlib.md5(open(filepath, 'rb').read()).hexdigest()

def sha1hex(filepath):
    return hashlib.sha1(open(filepath, 'rb').read()).hexdigest()

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

def quit():
	global root
	root.quit()

def stamp(ROW,buffer, background=None):
	global root
	Label(frame, text="                                                              ").grid(row=ROW, column=0)
	root.update()
	#Label(frame, text=buffer, bg=background, justify=LEFT, font=("Helvetica", 8)).grid(row=ROW, column=0, sticky=W)
	Label(frame, text=buffer, bg=background, justify=LEFT).grid(row=ROW, column=0, sticky=W)
	root.update()

def intro(title,descr,author):
	global root
	Label(frame, text=title, font=("Times", 22),fg="#6f5858").grid(row=10, column=0)
	Label(frame, text=descr, font=("Times", 12),fg="#6f5858").grid(row=12, column=0)
	Label(frame, text=author, font=("Times", 10),fg="#6f5858").grid(row=14, column=0)
	root.update()

def clean():
	global root
	for widget in frame.winfo_children():
		widget.destroy()
	root.update()

def report():
	global REPORT_NAME
	 # create child window
	win = Toplevel()
	win.title("Report")
	win.geometry("550x400+300+260")
	message = REPORT_NAME
	Label(win, text=message).pack()
	text = Text(win)
	try:
		with open(REPORT_NAME, 'r') as myfile:
    			data=myfile.read()
	except:
		data = " "

	text.insert(INSERT, data)
	text.pack()
	Button(win, text='OK', command=win.destroy).pack()

def json_report():
	data={}
	with open('data.json', 'w') as outfile,open(REPORT_NAME,"r") as f:
	    for line in f:
	       sp=line.split('\t')
	       data.setdefault("data",[]).append({"A": sp[0],"B": sp[1],"C": sp[2]})
	    json.dump(data, outfile)


def settings():
	global REPORT_NAME

	 # create child window
	win = Toplevel()
	win.title("Settings")
	win.geometry("150x50+300+260")
	Label(win, text="Work in progress...").pack()
	Button(win, text='OK', command=win.destroy).pack()



def scan():
	global root
	global REPORT_NAME
	folders = ['']

	start = time.time()
	scores = {"99": 0, "85": 0, "70": 0, "50": 0, "30": 0, "15": 0, "1": 0, "0": 0}
	REPORT_NAME = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + ".log"
	clean()
	ROW = 0
	# Create the client
	with DxlClient(config) as client:

	    # Connect to the fabric
	    client.connect()
	    print "### DXL connected"
	    stamp(ROW,"DXL connected")

	    # Create the McAfee Threat Intelligence Exchange (TIE) client
	    tie_client = TieClient(client)

	    # Create the Dropbox instance
	    try:
	    	box = dropbox.Dropbox(TOKEN)
	    	print "### Dropbox connected"

		stamp(ROW+1,"Dropbox connected")

	    except:
		print "Dropbox connection problem. Check the TOKEN variable or your internet connection"
		exit(1)
	    stamp(ROW+2,"Max file size scan:" + str(MAXFILESIZE / (1024*1024)) + " MB")
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

					stamp(ROW+4, str(file.path_display))

					# check if the hash has been already calculated in the past
					if not isFileInList(content_hash, DBFile):
						print "Downloading and calculating the HASH..."

						stamp(ROW+6, "Downloading and calculating the HASH...")

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
						print "File already cached! Updating reputation"

						stamp(ROW+6, "File already cached! Updating reputation")

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

					GTI=""
					ENT=""
					# Display the Global Threat Intelligence (GTI) trust level for the file
					if FileProvider.GTI in reputations_dict:
					    gti_rep = reputations_dict[FileProvider.GTI]
					    scores[str(gti_rep[ReputationProp.TRUST_LEVEL])] += 1

					    GTI=reputations[str(gti_rep[ReputationProp.TRUST_LEVEL])]
					    print "[GTI: " + reputations[str(gti_rep[ReputationProp.TRUST_LEVEL])] + "] " + file.path_display + "\n"

					    color = None

					    if gti_rep[ReputationProp.TRUST_LEVEL] < 50 and gti_rep[ReputationProp.TRUST_LEVEL] > 0:
						color = "Red"
					    if gti_rep[ReputationProp.TRUST_LEVEL] > 50:
						color = "Green"

					    stamp(ROW+8,"[GTI: " + reputations[str(gti_rep[ReputationProp.TRUST_LEVEL])] + "]",color)



					 # Display the Enterprise reputation information
					if FileProvider.ENTERPRISE in reputations_dict:
					    ent_rep = reputations_dict[FileProvider.ENTERPRISE]
					    ENT=reputations[str(ent_rep[ReputationProp.TRUST_LEVEL])]
					    color = None
					    if ent_rep[ReputationProp.TRUST_LEVEL] < 50 and ent_rep[ReputationProp.TRUST_LEVEL] > 0:
						color = "Red"
					    if ent_rep[ReputationProp.TRUST_LEVEL] > 50:
						color = "Green"

					    stamp(ROW+9,"[ENT: " + reputations[str(ent_rep[ReputationProp.TRUST_LEVEL])] + "]",color)


					#addLogReport("[GTI: " + reputations[str(gti_rep[ReputationProp.TRUST_LEVEL])] + "] " + file.path_display, REPORT_NAME)
					addLogReport("[GTI: " + GTI + "] " + "\t[ENT: " + ENT + "]\t " + file.path_display, REPORT_NAME)


					#print json.dumps(reputations_dict,sort_keys=True, indent=4, separators=(',', ': '))


			except:
				folders.append(str(file.path_display))

	end = time.time()

	print "\n[" + str(sum(scores.values())) + "] Total file scanned in " + str(int(end-start)) + " seconds\n"
	clean()
	ROW=1
	stamp(ROW,"[" + str(sum(scores.values())) + "] Total file scanned in " + str(int(end-start)) + " seconds")
	sortReport(REPORT_NAME)
	print "Check the log file " + REPORT_NAME + " for details"
	ROW=3
	for rep,score in scores.items():
		if score > 0:
			print "[" + str(score) + "] " + reputations[rep]
			ROW+=1
			stamp(ROW, "[" + str(score) + "] " + reputations[rep])

checkDB(DBFile)

print "### Max file size scan:" + str(MAXFILESIZE / (1024*1024)) + " MB"

root = Tk()

root.geometry("340x150+300+50")
frame = Frame(root)
frame.grid()
root.title(TITLE)
intro(TITLE, DESCRIPTION, AUTHOR)

menubar = Menu(root)
root.config(menu=menubar)

firstMenu = Menu(menubar)
firstMenu.add_command(label="Scan", command=scan)
firstMenu.add_command(label="Report", command=report)
firstMenu.add_command(label="Exit", command=quit)
menubar.add_cascade(label="Menu", menu=firstMenu)

SecondMenu = Menu(menubar)
SecondMenu.add_command(label="Edit...", command=settings)
menubar.add_cascade(label="Settings", menu=SecondMenu)

root.mainloop()

os.remove(REPORT_NAME)
