# PRSS
Simple script that fetches RSS feeds periodically and (after making a disk cache) sends updated feeds via Gmail.


# Usage
```sh
$ prss -h
```
```text
It needs a file that contains RSS-feed links in each line and fetches RSS feeds periodically and (after making a disk cache) sends updated feeds via Gmail.

Required environment variables:
PRSS_URL_FILE
PRSS_SENDER
PRSS_PASSWORD
PRSS_RECEIVER

for example:
PRSS_URL_FILE=/a/file/containing/my/rss-feed/links
PRSS_SENDER=my.gamil.username@gmail.com
PRSS_PASSWORD=my-gm4il-p4ssw0rd
PRSS_RECEIVER=receiver-gmail-username@gmail.com

Optional environment variables with default values:
CACHE_FILE=prss.cache
CACHE_MAX_SIZE=1000
SLEEP_RANGE_START=60
SLEEP_RANGE_STOP=120

Undefined environment variables:
PRSS_NO_COLORIZE
PRSS_NO_SYSLOG
PRSS_PRINT_RSS_ENTRY
PRSS_PRINT_MAIL_CONTENT

Note that you can put environment variables in a file named prss.env or .env too.

Version: 21.6.13
Author: pouriya.jahanbakhsh@gmail.com
```

# Download & Install
You should have Python3.6^ installed.
```sh
$ pip3 install feedparser
...
$ curl -sSf https://raw.githubusercontent.com/pouriya/prss/21.6.13/prss.py > prss && \
  chmod a+x prss                                                                  && \
  sudo mv prss /usr/local/bin/prss                                                && \
  prss -v
21.6.13
```
Note that for sender account you should allow accessing it via less secure apps [here](https://myaccount.google.com/lesssecureapps).
