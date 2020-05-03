#!/usr/bin/env python

#
# Altered original author's code to have no console trace of passwords
#

import hashlib
import sys

try:
    import requests
except ModuleNotFoundError:
    print("###  pip install requests  ###")
    raise

# Let's hide entered string

import getpass

try: 
    pwd = getpass.getpass(prompt='Password: ', stream=None) 
except Exception as error: 
    print('ERROR', error)

# Show only 2 first characters of entered string for convenience
# in any type of output

maskedpwd = pwd[0:2]+("." * int(pwd.count('') - 2))

def lookup_pwned_api(pwd):
    """Returns hash and number of times password was seen in pwned database.

    Returns:
        A (sha1, count) tuple where sha1 is SHA-1 hash of pwd and count is number
        of times the password was seen in the pwned database.  count equal zero
        indicates that password has not been found.

    Raises:
        RuntimeError: if there was an error trying to fetch data from pwned
            database.
        UnicodeError: if there was an error UTF_encoding the password.
    """
    sha1pwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    head, tail = sha1pwd[:5], sha1pwd[5:]
    url = 'https://api.pwnedpasswords.com/range/' + head
    res = requests.get(url)
    if not res.ok:
        raise RuntimeError('Error fetching "{}": {}'.format(
            url, res.status_code))
    hashes = (line.split(':') for line in res.text.splitlines())
    count = next((int(count) for t, count in hashes if t == tail), 0)
    return sha1pwd, count


def main(args):
    ec = 0
    try:
        sha1pwd, count = lookup_pwned_api(pwd)
    except UnicodeError:
        errormsg = sys.exc_info()[1]
        print("\nString {0} could not be checked: {1}".format(maskedpwd, errormsg))
        ec = 1

    if count:
        foundmsg = "\nString {0} was found with {1} occurrences (hash: {2})"
        print(foundmsg.format(maskedpwd, count, sha1pwd))
        ec = 1
    else:
        print("\nString {0} was not found".format(maskedpwd))
    return ec


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
