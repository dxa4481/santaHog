# Santa Hog
Searches through npm and pypi packages for secrets, digging deep into commit package history. This is effective at finding secrets accidentally pushed.


```
santaHog left-pad --npm
```

or

```
santaHog left-pad --npm --entropy
```

## Install
```
pip install santaHog
```

## How it works
This module will go through the entire history of the package, and check eacand check for secrets. This is both by regex and by entropy. For entropy checks, santahog will evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.

## Help

```
santahog --help
usage: santahog [-h] [--regex] [--npm] [--pypi] [--rules RULES] [--entropy]
                package

Find secrets hidden in the depths of packages.

positional arguments:
  package        The package name for secret searching

optional arguments:
  -h, --help     show this help message and exit
  --regex        Enable high signal regex checks
  --npm          This is an npm package
  --pypi         This is a pypi package
  --rules RULES  Ignore default regexes and source from json list file
  --entropy      Enable entropy checks
```

