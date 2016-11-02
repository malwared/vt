import json
import urllib
import urllib2
import time
with open('file.txt') as f:
        lines = f.readlines()
        for e in lines:
                url = "https://www.virustotal.com/vtapi/v2/url/report"
                parameters = {'resource': e.rstrip(), 'apikey': '#APIKEY'}
                data = urllib.urlencode(parameters)
                req = urllib2.Request(url, data)
                response = urllib2.urlopen(req)
                json13 = response.read()
                dat = json.loads(json13)
                if(dat['response_code'] == 1):
                        if(dat['positives'] == 0):
                                print "Good: %s " % e.rstrip()
                                f = open('good_list','a')
                                f.write(e.rstrip())
                                f.write("\n")
                                f.close()
                        else:
                                print "bad: %s " % e.rstrip()
                                f = open('bad_list','a')
                                f.write(e.rstrip())
                                f.write("\n")
                                f.close()
                else:
                        print "No VT scan for: %s" % e.rstrip()
                        f = open('404_list','a')
                        f.write(e.rstrip())
                        f.write("\n")
                        f.close()
                time.sleep(15)
