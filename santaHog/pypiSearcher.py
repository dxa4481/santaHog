import urllib
import tarfile
import re
import os
import requests
import tempfile
from scan_archives import get_secrets_from_targz
from bs4 import BeautifulSoup
from truffleHogRegexes.regexChecks import regexes
from tarfile import ReadError

def get_packages_from_term(term):
    params = {':action': 'search', 
       'term': term, 
       'submit': 'search'}
    encodedParams = urllib.urlencode(params)
    url = ('https://pypi.python.org/pypi?{}').format(encodedParams)
    text = requests.get(url).text
    soup = BeautifulSoup(text, 'html.parser')
    soupTable = soup.findAll('table', {'class': 'list'})[0]
    package = []
    for url in soupTable.find_all('a'):
        package.append(url['href'].split('/')[2])

    return package


def get_recent_secrets(package):
    response = requests.get(('https://pypi.python.org/pypi/{}/').format(package))
    soup = BeautifulSoup(response.text, 'html.parser')
    try:
        url = soup.find_all('a', {'class': 'button green'})[0]['href']
    except IndexError:
        return []

    get_secrets_from_targz(url, package)


def scan_package(package, custom_regexes=regexes, scan_entropy=False, scan_regexes=True):
    results = {}
    response = requests.get(('https://pypi.org/simple/{}/').format(package))
    soup = BeautifulSoup(response.text, 'html.parser')
    try:
        a_tags = soup.find_all('a', href=True)
    except:
        raise 'Error connecting to pypi'

    for a_tag in a_tags:
        url = a_tag['href']
        version = a_tag.string
        current_version_results = get_secrets_from_targz(url, package, custom_regexes=regexes, scan_entropy=scan_entropy, scan_regexes=scan_regexes)
        if current_version_results:
            results[version] = current_version_results

    return results
