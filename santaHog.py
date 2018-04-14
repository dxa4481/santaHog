import npmSearcher
import pypiSearcher
import argparse
from truffleHogRegexes.regexChecks import regexes


def scan_package(package, scan_npm=False, scan_pypi=False, entropy=False, regexes=True, custom_regexes=regexes):
    if scan_npm:
        npmSearcher.scan_package(package, custom_regexes=regexes, scan_entropy=entropy, custom_regexes=regexes)
    if scan_pypi:
        pypiSearcher.scan_package(package, custom_regexes=regexes, scan_entropy=entropy, custom_regexes=regexes)

def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of packages.')
    parser.add_argument('package', type=str, help='The package name for secret searching')
    parser.add_argument("--regex", dest="regex", action="store_true", help="Enable high signal regex checks")
    parser.add_argument("--npm", dest="npm", action="store_true", help="This is an npm package")
    parser.add_argument("--pypi", dest="pypi", action="store_true", help="This is a pypi package")
    parser.add_argument("--rules", dest="rules", help="Ignore default regexes and source from json list file")
    parser.add_argument("--entropy", dest="entropy", action="store_true", help="Enable entropy checks")
    parser.set_defaults(regex=True)
    parser.set_defaults(entropy=False)
    parser.set_defaults(npm=False)
    parser.set_defaults(pypi=False)
    parser.set_defaults(rules={})

    args = parser.parse_args()
    rules = {}
    if args.rules:
        try:
            with open(args.rules, "r") as ruleFile:
                rules = json.loads(ruleFile.read())
                for rule in rules:
                    rules[rule] = re.compile(rules[rule])
        except (IOError, ValueError) as e:
            raise("Error reading rules file")
        for regex in dict(regexes):
            del regexes[regex]
        for regex in rules:
            regexes[regex] = rules[regex]
    scan_package(args.package, args.npm, args.pypi, args.entropy, args.regex, custom_regexes=regexes)

if __name__ == "__main__":
    main()
