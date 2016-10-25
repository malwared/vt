import simplejson
import urllib
import urllib2
import time
with open('hash_list') as f:
        lines = f.readlines()
        for e in lines:
                url = "https://www.virustotal.com/vtapi/v2/file/report"
                parameters = {"resource": e.rstrip(),
                                  "apikey": "key"}
                data = urllib.urlencode(parameters)
                req = urllib2.Request(url, data)
                response = urllib2.urlopen(req)
                json = response.read()
                print json
                time.sleep(15)
