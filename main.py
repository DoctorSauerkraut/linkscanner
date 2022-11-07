#!/bin/python3

# Author : DrSauerkraut

VT_KEY = ""

import requests
import hashlib
import urllib
import magic
import virustotal_python
import os 
import mimetypes
import sys
import datetime

from colorama import Fore, Back, Style

if __name__ == "__main__" :
    openfile = sys.argv[1].strip()
    
    x = datetime.datetime.now()
    report_file = "analysis_"+str(x.year)+"_"+str(x.month)+"_"+str(x.day)+".txt"
    output_file = open(report_file, "w")

    print("Output file:\t"+report_file)

    link_file = open(openfile, "r")

    results = ("-"*72) + "\n"
    vt_score = 0
    i = 0

    ln = 0
    progress = 0
    with open(openfile, 'r') as fp:
        for l in fp:
            ln = ln + 1
    print("Total URLs:\t"+str(ln))

    for line in link_file:
        progress = int((i / ln)*10000)  
        sys.stdout.write("\rProgress:\t"+str(progress/100)+" %")
        type_check = False
        http_code = 0
        file_data = ""
        file_name = line.split("/")[-1].strip()
        file_type = "None"

        # DL the file
        try :
            req = urllib.request.urlopen(line)
            http_code = req.getcode()
            
            file_data = req.read()
        except urllib.error.HTTPError as e:
            http_code = e.code

        if(http_code==200):
            # Hash computation
            md5_returned = hashlib.md5(file_data).hexdigest()
            sha1_returned = hashlib.sha1(file_data).hexdigest()
            sha256_returned = hashlib.sha256(file_data).hexdigest()
            
            # VT check
            with virustotal_python.Virustotal(
                API_KEY=VT_KEY,
                PROXIES={"http": "", "https": ""},
                TIMEOUT=5.0,
            ) as vtotal:
                try:
                    resp = vtotal.request(f"files/{md5_returned}")
                    vt_score=resp.data["attributes"]["last_analysis_stats"]
                except virustotal_python.VirustotalError as err:
                    if("NotFoundError" in str(err)):
                        vt_score = "No report"

            # Extract extension
            split_tup = (os.path.splitext(line)[1]).strip()
            file_ext = magic.from_buffer(file_data, mime=True)
            type_check = (str(split_tup) == str(mimetypes.guess_extension(file_ext)))
            
            # Type check
            file_type = magic.from_buffer(file_data)

            # Magic number check
            magic_number = file_data[0:8].hex()
            
            if not os.path.exists("output/"):
                # if the demo_folder directory is not present 
                # then create it.
                os.makedirs("output/")
            f = open("output/"+file_name, "wb")
            f.write(file_data)
            i = i + 1

        # Format output
        results = results + ("General Info\n")
        results = results + ("-"*13) + " \n"

        results = results + ("URL:\t\t"+str(line.strip())+"\n")
        results = results + ("File type:\t"+str(file_type)+"\n")
        results = results + ("MD5:\t\t"+str(md5_returned)+"\n")
        results = results + ("SHA256:\t\t"+str(sha1_returned)+"\n")
        results = results + ("SHA1:\t\t"+str(magic_number)+"\n")
        

        results = results + ("\nScan results\n")
        results = results + ("-"*13) + " \n"
        
        if(type_check):
            color = Fore.GREEN
        else:
            color = Fore.RED

        results = results + ("Extension/Type check:\t"+color+str(type_check)+Style.RESET_ALL+"\n")

        if(vt_score == "No report"):
            color = Fore.GREEN
        else:
            color = Fore.RED

        results = results + ("VT Score:\t\t"+color+str(vt_score)+Style.RESET_ALL+"\n")
        
        if(http_code == 200):
            color = Fore.GREEN
        else:
            color = Fore.RED

        results = results + ("HTTP Code:\t\t"+color+str(http_code)+Style.RESET_ALL+"\n")


        results = results + ("-"*72) + " \n"
        results = results + ("-"*72) + " \n"

    # Print report
    output_file.write(results)
