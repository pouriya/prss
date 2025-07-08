#! /usr/bin/env python3
import os
import re
import syslog

from time import sleep
from random import randrange
from datetime import datetime
from os import rename, remove, environ
from os.path import isfile
from syslog import LOG_ERR, LOG_INFO, LOG_WARNING
from json import dumps as json_encode
from json import loads as json_decode
import http.client as http_client
import urllib.parse as url_parser


__version__ = '25.07.07'
__author__ = 'pouriya.jahanbakhsh@gmail.com'

colorize = True if environ.get('PRSS_NO_COLORIZE') is None else False
red = '\033[1;31m' if colorize else ''
white = '\033[1;37m' if colorize else ''
gray = '\033[1;30m' if colorize else ''
yellow = '\033[1;33m' if colorize else ''
green = '\033[1;32m' if colorize else ''
reset = '\033[0m' if colorize else ''
COLORS = {'red': red, 'white': white, 'gray': gray, 'yellow': yellow, 'green': green, 'reset': reset}

SYSLOG = True if environ.get('PRSS_SYSLOG') is not None else False
PRINT_RSS_ENTRY = False if environ.get('PRSS_PRINT_RSS_ENTRY') is None else True
DEFAULT_HTTP_CONNECT_TIMEOUT = 15


def datetime_string():
    return datetime.now().strftime('%y/%d/%m-%H:%M:%S')


def log(level_name, level_color, text, args, forward_to_syslog=True):
    level = ('{' + level_color + '}{:^7}{reset}').format(level_name, **COLORS)
    print('[{}] [{}] '.format(datetime_string(), level) + text.format(*args, **COLORS))
    if SYSLOG and forward_to_syslog:
        colors = {item[0]: '' for item in COLORS.items()}
        syslog_level = LOG_INFO
        if level_name == 'ERROR':
            syslog_level = LOG_ERR
        elif level_name == 'WARNING':
            syslog_level = LOG_WARNING
        try:
            syslog.syslog(syslog_level, text.format(*args, **colors))
        except Exception as error:
            log('ERROR', 'gray', '{gray}could not use syslog: {}{reset}', [error], False)


def log_info(text, args):
    log('INFO', 'white', text, args)


def log_error(text, args):
    log('ERROR', 'red', text, args)


def log_warning(text, args):
    log('WARNING', 'yellow', text, args)


try:
    import feedparser
except ImportError:
    log_error("could not import 'feedparser', install it via pip (pip3 install feedparser)", [])
    exit(1)


def hide_url_path(url):
    prefix = ''
    if url.startswith('http://'):
        prefix = 'http://'
        url = url[7:]
    elif url.startswith('https://'):
        prefix = 'https://'
        url = url[8:]
    url_parts = url.split('/')
    if len(url_parts) > 1:
        return prefix + url_parts[0] + '/' + '/'.join([len(x) * '*' for x in url_parts[1:]])
    return url


def fetch_rss(url):
    entries = []
    log_info('attempt to fetch RSS from {white}{!r}{reset}', [hide_url_path(url)])
    try:
        fp = feedparser.parse(url)
    except Exception as error:
        log_error('could not read RSS feed from URL {!r}: {}', [hide_url_path(url), error])
        return entries
    try:
        if fp['status'] == 200:
            if 'bozo_exception' in fp.keys():
                raise ValueError(fp['bozo_exception'])
            for entry in fp['entries']:
                PRINT_RSS_ENTRY and print('\nRSS ENTRY: {}\n'.format(entry))
                title = entry['title']
                link = entry['links'][0]['href']
                summery = ''
                if 'summary' in entry.keys():
                    summery = remove_html_tags(entry['summary'])
                image = None
                for link_item in entry['links'][1:]:
                    if 'type' in link_item.keys():
                        if link_item['type'].startswith('image'):
                            image = link_item['href']
                            break
                if image and summery.find(image) != -1:
                    image = None
                # Remove duplicates:
                for entry2 in entries:
                    _, link2, _, _ = entry2
                    if link == link2:
                        log_warning('found duplicate for URL {yellow}{!r}{reset}', [hide_url_path(url)])
                        entries.remove(entry2)
                        break
                entries.append((title, link, summery, image))
        else:
            log_error('unhandled status code {} from URL {!r}', [fp['status'], hide_url_path(url)])
    except Exception as error:
        log_error('could not found known elements in RSS response from URL {!r}: {}', [hide_url_path(url), error])
    if entries:
        log_info('fetched {green}{}{reset} RSS feeds from {white}{!r}{reset}', [len(entries), hide_url_path(url)])
    return entries


def remove_html_tags(text):
    while True:
        tag_start_position, tag_stop_position = text.find('<'), text.find('>')
        # print(text, tag_start_position, tag_stop_position)
        if tag_start_position == -1 or tag_stop_position == -1 or tag_stop_position < tag_start_position:
            return text
        text = text.replace(text[tag_start_position:tag_stop_position+1], '')


def get_domain_from_url(url):
    url = url.replace('https://', '').replace('http://', '')
    url_parts = url.split('/', 1)
    address = url_parts[0]
    address_parts = address.split(':', 1)
    domain = address_parts[0]
    domain_parts = domain.split('.')
    name = domain_parts[-2] if len(domain_parts) > 1 else domain
    return name.upper()


class PrintError(Exception):
    pass


def read_urls_from_file(filename):
    urls = []
    # Regex copied from:
    # https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not
    url_check_regex = re.compile(
        r'^(?:http|ftp)s?://'                                            # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.'
        r'?|[A-Z0-9-]{2,}\.?)|'                                          # domain...
        r'localhost|'                                                    # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'                           # ...or ip
        r'(?::\d+)?'                                                     # optional port
        r'(?:/?|[/?]\S+)$',
        re.IGNORECASE
    )

    log_info('attempt to read URL(s) from {white}{!r}{reset}', [filename])
    try:
        fd = open(filename)
    except Exception as error:
        raise PrintError('could not open URL file {!r}: {}'.format(filename, error))

    line_number = 1
    links = []
    for line in fd:
        line = line.strip()
        if not line or line[0] == '#':
            line_number += 1
            continue
        parts = line.split(' ', 1)
        name = parts[1] if len(parts) == 2 else ''
        name = name.strip()
        link = parts[0]
        if re.match(url_check_regex, link) is not None:
            if link not in links:
                urls.append((name, link))
                links.append(link)
            else:
                log_warning(
                    'found duplicate URL {yellow}{!r}{reset} in {yellow}{!r}{reset} at line {yellow}{}{reset}, dropped',
                    [line, filename, line_number]
                )
        else:
            log_error(
                'found badly formatted URL {yellow}{!r}{reset} in {yellow}{!r}{reset} at line {yellow}{}{reset}',
                [line, filename, line_number]
            )
        line_number += 1

    length = len(urls)
    if length == 0:
        log_warning('could not found any URL in {yellow}{!r}{reset}', [filename])
    else:
        log_info('found {green}{}{reset} URL(s) in {white}{!r}{reset}', [length, filename])
    return urls


class Cache:

    def __init__(self, filename, max_size):
        self.filename = filename
        self.max_size = max_size
        not self.ensure_file() and log_info('cache file {green}{!r}{reset} already exists', [self.filename])

    def ensure_file(self):
        if not isfile(self.filename):
            try:
                fd = open(self.filename, 'w')
                fd.close()
            except Exception as error:
                raise PrintError('could not create cache file {!r}: {}'.format(self.filename, error))
            log_info('created cache file {green}{!r}{reset}', [self.filename])
            return True
        return False

    def append_entries(self, entries):
        fd = open(self.filename, 'a')
        fd.write('\n'.join(entries))
        fd.close()

    def maybe_remove_old_entries(self):
        current_size = self.size()
        if current_size <= self.max_size:
            return 0
        diff = current_size - (self.max_size + 1)
        log_info(
            'attempt to remove {green}{}{reset} cache entries from cache file {white}{!r}{reset} with {} entries',
            [diff, self.filename, current_size]
        )
        tmp_filename = self.filename + '.tmp'
        rename(self.filename, tmp_filename)
        fd = open(self.filename, 'w')
        entry_number = 1
        for url in open(tmp_filename):
            if entry_number > diff:
                fd.write(url)
            entry_number += 1
        fd.close()
        remove(tmp_filename)
        log_info('removed {green}{}{reset} entries from cache file {white}{!r}{reset}', [diff, self.filename])
        return diff

    def find_newly_added_entries(self, entries):
        for entry in open(self.filename):
            entry = entry.replace('\n', '')
            if entry in entries:
                entries.remove(entry)
        return entries

    def size(self):
        size = 0
        for _ in open(self.filename):
            size += 1
        return size

    def update(self, entries):
        self.ensure_file()
        newly_added_entries = self.find_newly_added_entries(entries)
        self.append_entries(newly_added_entries)
        self.maybe_remove_old_entries()
        return newly_added_entries


class PRSS:

    def __init__(
            self,
            url_filename,
            cache_filename,
            max_cache_size,
            sleep_range
    ):
        self.url_filename = url_filename
        self.cache = Cache(cache_filename, max_cache_size)
        self.sleep_range = sleep_range

    def run(self):
        while True:
            self.pre_read_urls()
            urls = read_urls_from_file(self.url_filename)
            urls = self.post_read_urls(urls)
            feeds = []
            urls = self.pre_fetch_urls(urls)
            for name, url in urls:
                if self.pre_fetch_url(name, url):
                    url_feeds = fetch_rss(url)
                    (name, url_feeds) = self.post_fetch_url(name, url_feeds)
                    for url_feed in url_feeds:
                        feeds.append((name, url_feed))
            log_info('fetched {green}{}{reset} feeds from {white}{}{reset} URL(s)', [len(feeds), len(urls)])
            feeds = self.post_fetch_urls(feeds)
            self.pre_update_cache()
            newly_added_links = self.cache.update(
                [x[1] for _, x in feeds]
            )
            newly_added = []
            for feed in feeds:
                if feed[1][1] in newly_added_links:
                    newly_added.append(feed)
            log_info('detected {green}{}{reset} newly fetched URL(s)', [len(newly_added)])
            self.post_update_cache(newly_added)
            sleep_time = randrange(self.sleep_range[0], self.sleep_range[1])
            sleep_time = self.pre_sleep(sleep_time)
            if sleep_time > 0:
                log_info('sleeping for {green}{}{reset}m', [sleep_time])
                sleep(sleep_time * 60)
                self.post_sleep(sleep_time)

    def pre_read_urls(self):
        pass

    def post_read_urls(self, urls):
        return urls

    def pre_fetch_urls(self, urls):
        return urls

    def pre_fetch_url(self, name, url):
        return True

    def post_fetch_url(self, name, url_feeds):
        return name, url_feeds

    def post_fetch_urls(self, feeds):
        return feeds

    def pre_update_cache(self):
        pass

    def post_update_cache(self, newly_added):
        pass

    def pre_sleep(self, sleep_time):
        return sleep_time

    def post_sleep(self, sleep_time):
        pass


def make_http_connection(host, port, tls, tls_skip_verify, timeout):
    default_port = 443 if tls else 80
    port = port if port is not None else default_port
    timeout = timeout if timeout is not None else DEFAULT_HTTP_CONNECT_TIMEOUT
    try:
        if tls:
            if tls_skip_verify:
                import ssl
                insecure_context = ssl.create_default_context()
                insecure_context.check_hostname = False
                insecure_context.verify_mode = ssl.CERT_NONE
                http_connection = http_client.HTTPSConnection(host, port=port, timeout=timeout, context=insecure_context)
            else:
                http_connection = http_client.HTTPSConnection(host, port=port, timeout=timeout)
        else:
            http_connection = http_client.HTTPConnection(host, port=port, timeout=timeout)
    except Exception as connect_error:
        log_error(
            'could not connect to {yellow}{}:{}{reset}{red}:{reset} {white}{}{reset}',
            [host, port, connect_error]
        )
        return False
    return http_connection


def read_and_decode_http_response(http_connection, host, port, http_path, body, log_text):
    try:
        http_response = http_connection.getresponse()
    except Exception as request_error:
        log_error(
            'could not get response from {yellow}{}:{}/{}{reset}{red} with body{reset} {yellow}{}{reset}{red}:{reset} {'
            'white}{}{reset}',
            [host, port, http_path, body, request_error]
        )
        return False
    try:
        response = http_response.read()
    except Exception as response_error:
        log_error(
            'could not read response from {yellow}{}:{}/{}{reset}{red} with body{reset} {yellow}{}{reset}{red}:{reset} '
            '{white}{}{reset}',
            [host, port, http_path, body, response_error]
        )
        return False
    if not response:
        return None
    try:
        response = json_decode(response)
    except Exception as decode_error:
        log_error(
            'could not decode response {yellow}{!r}{reset}{red} from {reset}{yellow}{}:{}/{}{reset}{red} with body{rese'
            't} {yellow}{}{reset}{red}:{reset} {white}{}{reset}',
            [response, host, port, http_path, body, decode_error]
        )
        return False
    if 'errorDescription' in response.keys():
        reason = response['errorDescription']
        log_error(
            'could {} {yellow}{}:{}/{}{reset}{red} with body{reset} {yellow}{}{reset}{red}:{reset} {white}{}{reset}',
            [log_text, host, port, http_path, body, reason]
        )
        return False
    return response


def send_notification(
        host,
        message,
        application_token,
        priority=None,
        title=None,
        tls=True,
        tls_skip_verify=False,
        extras=None,
        port=None,
        timeout=None
):
    http_connection = make_http_connection(host, port, tls, tls_skip_verify, timeout)
    if http_connection is False:
        return False
    http_path = '/message?' + url_parser.urlencode({'token': application_token})
    log_http_path = '/message?token=' + \
                    application_token[0] + ((len(application_token) - 2) * '*') + application_token[-1]
    http_headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    priority = priority if priority is not None else 0
    body = {'message': message, 'priority': priority}
    if title:
        body['title'] = title
    if extras:
        body['extras'] = extras
    body_json = json_encode(body, sort_keys=True)
    try:
        http_connection.request('POST', http_path, body_json, http_headers)
    except Exception as request_error:
        log_error(
            'could not send request to {yellow}{}:{}/{}{reset}{red} with body{reset} {yellow}{}{reset}{red}:{reset} {wh'
            'ite}{}{reset}',
            [host, port, log_http_path, body_json, request_error]
        )
        return False
    response = read_and_decode_http_response(
        http_connection,
        host,
        port,
        log_http_path,
        body_json,
        'send notification to'
    )
    if type(response) is dict:
        log_info(
            'sent notification to {yellow}{}:{}{reset}{red} with body{reset} {yellow}{}{reset}',
            [host, port, body_json]
        )
        return response['id']
    return response


if __name__ == '__main__':
    from sys import argv as cmd_args

    PRSS_ENV_FILE = 'prss.env'
    PRSS_CACHE_FILE = 'prss.cache'
    if 'help' in cmd_args or '-h' in cmd_args or '--help' in cmd_args:
        print(
            'It needs a file that contains RSS-feed links in each line and fetches RSS feeds periodically and (after ma'
            'king a disk cache) sends updated feeds to Gotify.'
        )
        print()
        print('Required environment variables:')
        print('PRSS_URL_FILE')
        print('PRSS_GOTIFY_HOSTNAME')
        print('PRSS_GOTIFY_PORT')
        print('PRSS_GOTIFY_APPLICATION_TOKEN')
        print('PRSS_GOTIFY_TLS')
        print()
        print('for example:')
        print('PRSS_URL_FILE=/a/file/containing/my/rss-feed/links')
        print('PRSS_GOTIFY_HOSTNAME=notifications.example.tld')
        print('PRSS_GOTIFY_PORT=443')
        print('PRSS_GOTIFY_TLS=1')
        print('PRSS_GOTIFY_APPLICATION_TOKEN=MyS3cr3tT0k3n')
        print()
        print('Optional environment variables with default values:')
        print('PRSS_CACHE_FILE={}'.format(PRSS_CACHE_FILE))
        print('PRSS_CACHE_MAX_SIZE=1000')
        print('PRSS_SLEEP_RANGE_START=60')
        print('PRSS_SLEEP_RANGE_STOP=120')
        print()
        print('Undefined environment variables:')
        print('PRSS_GOTIFY_TLS_SKIP_VERIFY')
        print('PRSS_NO_COLORIZE')
        print('PRSS_SYSLOG')
        print('PRSS_PRINT_RSS_ENTRY')
        print()
        print('Note that you can put environment variables in a file named {} or .env too.'.format(PRSS_ENV_FILE))
        print()
        print('Version: {}'.format(__version__))
        print('Author: {}'.format(__author__))
        exit(0)
    if 'version' in cmd_args or '-v' in cmd_args or '--version' in cmd_args:
        print(__version__)
        exit(0)

    class Main(PRSS):

        def __init__(
                self,
                url_filename,
                cache_filename,
                max_cache_size,
                sleep_range,
                hostname,
                port,
                application_token,
                tls,
                tls_skip_verify
        ):
            super().__init__(
                url_filename,
                cache_filename,
                max_cache_size,
                sleep_range
            )
            self.hostname = hostname
            self.port = port
            self.application_token = application_token
            self.tls = tls
            self.tls_skip_verify = tls_skip_verify

        def post_update_cache(self, feeds):
            self.send_feeds_to_gotify(feeds)
            return feeds

        def send_feeds_to_gotify(self, feeds):
            fa = []
            en = []
            for name, url_feeds in feeds:
                title, _, _, _ = url_feeds
                is_fa = False
                for char in title:
                    if ord(char) == 1575 or ord(char) == 1605:  # Alef & Mim
                        is_fa = True
                        break
                if is_fa:
                    fa.append((name, url_feeds))
                else:
                    en.append((name, url_feeds))
            fa != [] and self.send_mail(fa, 'Farsi')
            en != [] and self.send_mail(en, 'English')

        def send_mail(self, feeds, lang):
            notification_count = 0
            for name, url_feeds in feeds:
                title, url, summary, image = url_feeds
                if not name:
                    name = get_domain_from_url(url)
                extras = {
                    'client::notification': {'click': {'url': url}},
                    # 'android::action': {'onReceive': {'intentUrl': url}},
                    'client::display': {'contentType': 'text/markdown'}
                }
                send_notification(
                    self.hostname,
                    summary + '\n - [**LINK**]({})'.format(url),
                    self.application_token,
                    title=name + '\n ' + title,
                    tls=self.tls,
                    tls_skip_verify=self.tls_skip_verify,
                    port=self.port,
                    extras=extras
                )
                notification_count += 1
            log_info(
                '{green}{}{reset} {white}{}{reset} content(s) have been sent to Gotify at {white}{!r}{reset}',
                [notification_count, lang, self.hostname]
            )
            return True

    env_file = '.env' if isfile('.env') else None
    env_file = PRSS_ENV_FILE if isfile(PRSS_ENV_FILE) else env_file
    if env_file:
        keys = []
        for line in open(env_file):
            parts = line.strip().split('=', 1)
            key = parts[0]
            if key.startswith('#'):  # It's commented
                continue
            value = "1"
            if len(parts) > 1:
                value = parts[1]
            os.environ[key] = value
            keys.append(key)
        [log_info('loaded {white}{}{reset} from env file {white}{!r}{reset}', [key, env_file]) for key in keys]

    env_keys = [
        ('PRSS_' + x, y)
        for x, y in [
            ('URL_FILE', None),
            ('CACHE_FILE', PRSS_CACHE_FILE),
            ('CACHE_MAX_SIZE', '1000'),
            ('SLEEP_RANGE_START', '60'),
            ('SLEEP_RANGE_STOP', '120'),
            ('GOTIFY_HOSTNAME', None),
            ('GOTIFY_APPLICATION_TOKEN', None),
            ('GOTIFY_PORT', '443'),
            ('GOTIFY_TLS', '1'),
            ('GOTIFY_TLS_SKIP_VERIFY', '0'),
        ]
    ]
    cfg = {}
    for key, default_value in env_keys:
        value = environ.get(key)
        if not value:
            if not default_value:
                log_error('required environment variable {yellow}{!r}{reset} is not set', [key])
                exit(1)
            value = default_value
        key = key.replace('PRSS_', '')
        cfg[key] = value
    cfg['GOTIFY_TLS'] = True if cfg['GOTIFY_TLS'] == '1' else False
    cfg['GOTIFY_TLS_SKIP_VERIFY'] = True if cfg['GOTIFY_TLS_SKIP_VERIFY'] == '1' else False
    try:
        Main(
            cfg['URL_FILE'],
            cfg['CACHE_FILE'],
            int(cfg['CACHE_MAX_SIZE']),
            (int(cfg['SLEEP_RANGE_START']), int(cfg['SLEEP_RANGE_STOP'])),
            cfg['GOTIFY_HOSTNAME'],
            int(cfg['GOTIFY_PORT']),
            cfg['GOTIFY_APPLICATION_TOKEN'],
            cfg['GOTIFY_TLS'],
            cfg['GOTIFY_TLS_SKIP_VERIFY']
        ).run()
    except KeyboardInterrupt:
        print()
    except PrintError as reason:
        log_error(str(reason), [])
        exit(1)
