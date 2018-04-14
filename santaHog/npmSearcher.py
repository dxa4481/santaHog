import tempfile
import os
import requests
import re
import tarfile
import json
from uuid import uuid4
from scan_archives import get_secrets_from_targz
from truffleHogRegexes.regexChecks import regexes

def get_npm_package_urls(package):
    url = 'https://registry.npmjs.org/{}'
    versions = []
    jsonMetadata = requests.get(url.format(package)).json()
    for version in jsonMetadata['versions']:
        versions.append(jsonMetadata['versions'][version]['dist']['tarball'])

    return versions


def scan_package(package_name, custom_regexes=regexes, scan_entropy=False, scan_regexes=True):
    tarballs = get_npm_package_urls(package_name.strip())
    results = {}
    for tarball in tarballs:
        version_name = tarball.split('/')[-1]
        package_results = get_secrets_from_targz(tarball, package_name, custom_regexes=custom_regexes, scan_entropy=scan_entropy, scan_regexes=scan_regexes)
        if package_results:
            results[version_name] = package_results

    return results


def scan_by_maintainer(maintainer):
    packages = []
    maintainer_uri = 'https://www.npmjs.com/-/search?text=maintainer%3A{}&from=0&size=1000'
    data = requests.get(maintainer_uri.format(maintainer)).json()
    for dataObject in data['objects']:
        packages.append(dataObject['package']['name'])

    for package in packages:
        print scan_package(package.strip())
