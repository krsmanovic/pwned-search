# pwned-search
Pwned Password API lookup

- Required libraries:

* requests: `pip install requests`

Usage:

* `python pwned.py` – reads passwords from standard input;

Using Docker:
* `docker build -t pwned .` Builds docker image
* `docker run --rm pwned [password]` Runs the pwned command pre-installed in a docker container

## If you find one of your own passwords, change it asap!
