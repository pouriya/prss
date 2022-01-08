# PRSS
Simple script that fetches RSS feeds periodically and (after making a disk cache) sends updated feeds to Gotify server.  


# Usage
```sh
$ prss -h
```
```text
It needs a file that contains RSS-feed links in each line and fetches RSS feeds periodically and (after making a disk cache) sends updated feeds to Gotify.

Required environment variables:
PRSS_URL_FILE
PRSS_GOTIFY_HOSTNAME
PRSS_GOTIFY_PORT
PRSS_GOTIFY_APPLICATION_TOKEN
PRSS_GOTIFY_TLS

for example:
PRSS_URL_FILE=/a/file/containing/my/rss-feed/links
PRSS_GOTIFY_HOSTNAME=notifications.example.tld
PRSS_GOTIFY_PORT=443
PRSS_GOTIFY_TLS=1
PRSS_GOTIFY_APPLICATION_TOKEN=MyS3cr3tT0k3n

Optional environment variables with default values:
PRSS_CACHE_FILE=prss.cache
PRSS_CACHE_MAX_SIZE=1000
PRSS_SLEEP_RANGE_START=60
PRSS_SLEEP_RANGE_STOP=120

Undefined environment variables:
PRSS_NO_COLORIZE
PRSS_SYSLOG
PRSS_PRINT_RSS_ENTRY

Note that you can put environment variables in a file named prss.env or .env too.

Version: 22.01.08
Author: pouriya.jahanbakhsh@gmail.com
```

# Download & Install
You should have Python3.6^ installed.
```sh
$ pip3 install feedparser
...
$ curl -sSf https://raw.githubusercontent.com/pouriya/prss/22.01.08/prss.py > prss && \
  chmod a+x prss                                                                  && \
  sudo mv prss /usr/local/bin/prss                                                && \
  prss -v
22.01.08
```
