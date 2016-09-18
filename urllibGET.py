import urllib2

body = urllib2.urlopen("http://xperblueray.com")

print body.read()


