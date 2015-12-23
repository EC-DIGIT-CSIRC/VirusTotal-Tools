# VirusTotal-Tools

## Hunting

The script aims at retrieving Hunting result from VirusTotal.  After you upload your set of YARA rules (see demo in demo folder), you can retrieve all the results by at least defining your API key to the script.

```
usage: hunting.py [-h] [-api API] [-thres THRESHOLD] [-cleanup]
                  [-puri PROXY_URI] [-pusr PROXY_USER] [-ppwd PROXY_PASSWORD]
                  [-json JSON] [-out OUTPUT] [-samples SAMPLES_DIRECTORY]

Retrieve results of VirusTotal Hunting.

optional arguments:
  -h, --help            show this help message and exit
  -api API, --api API   VirusTotal API key
  -thres THRESHOLD, --threshold THRESHOLD
                        Number of required infection to keep result (default
                        3)
  -cleanup, --cleanup   Cleanup notifications of retreived files from
                        VirusTotal
  -puri PROXY_URI, --proxy_uri PROXY_URI
                        Proxy URI
  -pusr PROXY_USER, --proxy_user PROXY_USER
                        Proxy User
  -ppwd PROXY_PASSWORD, --proxy_password PROXY_PASSWORD
                        Proxy User
  -json JSON, --json JSON
                        JSON file to use to store full Hunting raw result (by
                        default not done)
  -out OUTPUT, --output OUTPUT
                        File to store result (by default stdout
  -samples SAMPLES_DIRECTORY, --samples_directory SAMPLES_DIRECTORY
                        Directory where to wrote all matching samples (by
                        default not done)
```
