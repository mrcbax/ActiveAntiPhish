#!/usr/bin/python

import subprocess
from subprocess import call
import os
import zipfile
import fnmatch
import sys

#move into sha folders
files = [f for f in os.listdir(".") if os.path.isfile(f)]
for f in files:
	proc = subprocess.Popen(["sha256sum", f], stdout=subprocess.PIPE)
	tmp = proc.stdout.read()
	tmp = str(tmp).split(" ")[0]
	tmp = tmp.split("\'")[1]
	#make the folder
	call(["mkdir", tmp])
	#encrypt the original	
	call(["gpg", "--batch", "--passphrase", sys.argv[1], "-c", f])
	#move original
	call(["mv", f, "./" + tmp + "/"])
	#move encrypted
	call(["mv", f + ".gpg", "./" + tmp + "/"])

#Unzip all
rootPath = r"./"
pattern = '*.zip'
for root, dirs, files in os.walk(rootPath):
    for filename in fnmatch.filter(files, pattern):
        print(os.path.join(root, filename))
        zipfile.ZipFile(os.path.join(root, filename)).extractall(os.path.join(root, os.path.splitext(filename)[0]))