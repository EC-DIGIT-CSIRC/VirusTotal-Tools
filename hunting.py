#
# Retrieve results of VT Hunting feature
#
# Author: David DURVAUX
# Copyright: EC DIGIT CSIRC - December 2015
#
# TODO:
#    - Improve/review proxy support
#
# Version 0.1 
#
import urllib
import urllib2
import json
import os
import argparse
import csv
import sys

# Variables and settings
vtapi = None
vturl = "https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=%s"
vtdwl = "https://www.virustotal.com/intelligence/download/?hash=%s&apikey=%s"
vtthresh = 3
directory = "./out"

# Proxy settings
proxy_uri = None
proxy_usr = None
proxy_pwd = None

# Output information
jsonres = "./vt-result.json"
outfile = sys.stdout

def getHuntingResult():
    # Some funcky thinks
    # Create an OpenerDirector with support for Basic HTTP Authentication...
    if(proxy_uri is not None):
        proxy = None
        if(proxy_usr is not None and proxy_pwd is not None):
            proxy = urllib2.ProxyHandler({'https' : 'http://%s:%s@%s' % (proxy_usr, proxy_pwd, proxy_uri)})
        else:
            proxy = urllib2.ProxyHandler({'https' : 'http://%s' % (proxy_uri)})
        opener = urllib2.build_opener(proxy)
        urllib2.install_opener(opener)

    try:
        result = []

        # retrieve JSON object from Virus Total
        jsonfd = urllib2.urlopen(vturl % (vtapi))
        jsonstr = jsonfd.read()

        print("DEBUG: %s" % (jsonstr)) #DEBUG

        try:
            # parse JSON
            jsonvt = json.loads(jsonstr)
            for notification in jsonvt["notifications"]:
            	positive = notification["positives"]
            	yararule = notification["subject"]
            	sha1 = notification["sha1"]
            	fseen = notification["first_seen"]
            	lseen = notification["last_seen"]
            	objtype = notification["type"]

                if(int(positive) >= vtthresh):
                    # add result to list of results
            	    result.append([positive, yararule, sha1, fseen, lseen, objtype])

                    if(directory is not None):
                        try:
                    		# retrieve sample
                    		# The following way to retrieve is commented due to issue
                    		# with proxy
                    		# urllib.urlretrieve(vtdwl % (sha1, vtapi), "%s/%s" % (directory, sha1))
                    		vtfile = urllib2.urlopen(vtdwl % (sha1, vtapi), "%s/%s")
                    		output = open("%s/%s" % (directory, sha1),'wb')
                    		output.write(vtfile.read())
                    		output.close()
                        except:
                            print "ERROR: Impossible to retrieve sample %s from VirusTotal :'(" % sha1    

            # Save JSON to file
            if(jsonres is not None):    
                fd = open(jsonres, "w")
                fd.write(jsonstr)
                fd.close()
        except:
            print "ERROR: Invalid result retrieved from VirusTotal (JSON Parsing Error) :'("    

        # Return result
        return result
    except:
        print "ERROR: Failed to retrieve Hunting result from VirusTotal :'("
        return None

def outputResults(results, outfile=sys.stdout):
    LDwriter = csv.writer(outfile)
    LDwriter.writerow(["# of detection", "YARA rule", "SHA1", "Binary type", "First seen", "Last seen"])
    for row in results:
        LDwriter.writerow(row)

def main():
    """
        Calling the script and options handling
    """

    # Argument definition
    parser = argparse.ArgumentParser(description='Retrieve results of VirusTotal Hunting.')
    
    # VirusTotal options
    parser.add_argument('-api', '--api', help='VirusTotal API key')
    parser.add_argument('-thres', '--threshold', help='Number of required infection to keep result (default 3)')

    # Proxy Settings
    parser.add_argument('-puri', '--proxy_uri', help='Proxy URI')
    parser.add_argument('-pusr', '--proxy_user', help='Proxy User')
    parser.add_argument('-ppwd', '--proxy_password', help='Proxy User')

    # Output options
    parser.add_argument('-json', '--json', help='JSON file to use to store full Hunting raw result (by default not done)')
    parser.add_argument('-out', '--output', help='File to store result (by default stdout')
    parser.add_argument('-samples', '--samples_directory', help='Directory where to wrote all matching samples (by default not done)')

    # Parse command line
    args = parser.parse_args()

    # Check if an output directory is set
    global directory
    if args.samples_directory:
        directory = os.path.dirname(args.samples_directory)

    # If directory doesn't exists yet, create it
    if directory is not None:
        if not os.path.exists(directory):
                os.makedirs(directory)

    # Parse Proxy Options
    global proxy_uri
    global proxy_usr
    global proxy_pwd
    if args.proxy_uri:
        proxy_uri = args.proxy_uri

        if args.proxy_user:
            proxy_usr = args.proxy_user

        if args.proxy_password:
            proxy_pwd = args.proxy_user

    # JSON OUTPUT
    global jsonres
    if args.json:
        jsonres = args.json

    # Control output instead of stdout
    global outfile
    if args.output:
        outfile = args.outfile
    else:
        outfile = sys.stdout

    # API KEY
    global vtapi
    if args.api:
        vtapi = args.api

    # Threshold control
    global vtthresh
    if args.threshold:
        vtthresh = args.threshold

    # Check if minimum set of parameters is available
    if(vtapi is None):
        print("ERROR: you need to specify at least an API key.  Use -h to get the manual.")
        return

    # Do all the magic now :)
    results = getHuntingResult()
    outputResults(results, outfile)

# Call the main function of this script and trigger all the magic \o/
if __name__ == "__main__":
    main()
# That's all folk ;)