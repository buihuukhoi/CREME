import requests
import sys

domainname = sys.argv[1]

r = requests.get('http://{}/index.html'.format(domainname))
r = requests.get('http://{}/about.html'.format(domainname))
r = requests.get('http://{}/courses.html'.format(domainname))
r = requests.get('http://{}/pricing.html'.format(domainname))
r = requests.get('http://{}/gallery.html'.format(domainname))
r = requests.get('http://{}/blog.html'.format(domainname))
r = requests.get('http://{}/blog_details.html'.format(domainname))
r = requests.get('http://{}/elements.html'.format(domainname))
r = requests.get('http://{}/contact.html'.format(domainname))
