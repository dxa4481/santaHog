import tempfile
import requests
import os
import tarfile
import math
from truffleHogRegexes.regexChecks import regexes
from tarfile import ReadError
from requests.exceptions import MissingSchema

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


def get_secrets_from_targz(uri, package, custom_regexes=regexes, scan_entropy=False, scan_regexes=True):
    project_path = tempfile.mkdtemp()
    targzPath = os.path.join(project_path, package)
    try:
        response = requests.get(uri, stream=True)
    except MissingSchema:
        return []
    response.raise_for_status()
    with open(targzPath, 'wb') as handle:
        for block in response.iter_content(1024):
            handle.write(block)
    try:
        tar = tarfile.open(targzPath)
    except ReadError:
        return []
    file_results = {}
    for member in tar.getmembers():
        try:
            f = tar.extractfile(member)
        except KeyError:
            continue
        if f == None:
            continue
        content = f.read()
        if scan_entropy:
            strings_found = []
            for word in content.split():
                base64_strings = get_strings_of_set(word, BASE64_CHARS)
                hex_strings = get_strings_of_set(word, HEX_CHARS)
                for string in base64_strings:
                    b64Entropy = shannon_entropy(string, BASE64_CHARS)
                    if b64Entropy > 4.5:
                        strings_found.append(string)
                for string in hex_strings:
                    hexEntropy = shannon_entropy(string, HEX_CHARS)
                    if hexEntropy > 3:
                        strings_found.append(string)
            if strings_found:
                if member.name in file_results:
                    file_results[member.name] += strings_found
                else:
                    file_results[member.name] = strings_found
        if scan_regexes:
            for regex in custom_regexes:
                found_strings = custom_regexes[regex].findall(content.decode('utf-8', errors='replace'))
                if found_strings:
                    if member.name in file_results:
                        file_results[member.name] += found_strings
                    else:
                        file_results[member.name] = found_strings
    tar.close()
    return file_results



def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings
