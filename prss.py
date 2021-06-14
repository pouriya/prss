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


__version__ = '21.6.13'
__author__ = 'pouriya.jahanbakhsh@gmail.com'

colorize = True if environ.get('PRSS_NO_COLORIZE') is None else False
red = '\033[1;31m' if colorize else ''
white = '\033[1;37m' if colorize else ''
gray = '\033[1;30m' if colorize else ''
yellow = '\033[1;33m' if colorize else ''
green = '\033[1;32m' if colorize else ''
reset = '\033[0m' if colorize else ''
COLORS = {'red': red, 'white': white, 'gray': gray, 'yellow': yellow, 'green': green, 'reset': reset}

SYSLOG = True if environ.get('PRSS_NO_SYSLOG') is None else False
PRINT_RSS_ENTRY = False if environ.get('PRSS_PRINT_RSS_ENTRY') is None else True


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
                    summery = entry['summary']
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


def get_domain_from_url(url):
    url = url.replace('https://', '').replace('http://', '')
    url_parts = url.split('/', 1)
    address = url_parts[0]
    address_parts = address.split(':', 1)
    domain = address_parts[0]
    domain_parts = domain.split('.')
    name = domain_parts[-2] if len(domain_parts) > 1 else domain
    return '[' + name.upper() + ']'


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
        name = parts[1] + ' ' if len(parts) == 2 else ''
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


if __name__ == '__main__':
    from sys import argv as cmd_args

    PRSS_ENV_FILE = 'prss.env'
    PRSS_CACHE_FILE = 'prss.cache'
    if 'help' in cmd_args or '-h' in cmd_args or '--help' in cmd_args:
        print(
            'It needs a file that contains RSS-feed links in each line and fetches RSS feeds periodically and (after ma'
            'king a disk cache) sends updated feeds via Gmail.'
        )
        print()
        print('Required environment variables:')
        print('PRSS_URL_FILE')
        print('PRSS_SENDER')
        print('PRSS_PASSWORD')
        print('PRSS_RECEIVER')
        print()
        print('for example:')
        print('PRSS_URL_FILE=/a/file/containing/my/rss-feed/links')
        print('PRSS_SENDER=my.gamil.username@gmail.com')
        print('PRSS_PASSWORD=my-gm4il-p4ssw0rd')
        print('PRSS_RECEIVER=receiver-gmail-username@gmail.com')
        print()
        print('Optional environment variables with default values:')
        print('CACHE_FILE={}'.format(PRSS_CACHE_FILE))
        print('CACHE_MAX_SIZE=1000')
        print('SLEEP_RANGE_START=60')
        print('SLEEP_RANGE_STOP=120')
        print()
        print('Undefined environment variables:')
        print('PRSS_NO_COLORIZE')
        print('PRSS_NO_SYSLOG')
        print('PRSS_PRINT_RSS_ENTRY')
        print('PRSS_PRINT_MAIL_CONTENT')
        print()
        print('Note that you can put environment variables in a file named {} or .env too.'.format(PRSS_ENV_FILE))
        print()
        print('Version: {}'.format(__version__))
        print('Author: {}'.format(__author__))
        exit(0)
    if 'version' in cmd_args or '-v' in cmd_args or '--version' in cmd_args:
        print(__version__)
        exit(0)

    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    class Main(PRSS):

        def __init__(
                self,
                url_filename,
                cache_filename,
                max_cache_size,
                sleep_range,
                from_mail,
                password,
                to_mail
        ):
            super().__init__(
                url_filename,
                cache_filename,
                max_cache_size,
                sleep_range
            )
            self.from_mail = from_mail
            self.to_mail = to_mail
            self.password = password
            self.print_mail_content = False if environ.get('PRSS_PRINT_MAIL_CONTENT') is None else True

        def post_update_cache(self, feeds):
            self.send_feeds_to_mail(feeds)
            return feeds

        def send_feeds_to_mail(self, feeds):
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
            fa != [] and self.send_mail(fa, True)
            en != [] and self.send_mail(en)

        def send_mail(self, feeds, fa=False):
            alignment = 'right' if fa else 'left'
            language_code = 'fa' if fa else 'en'
            language = 'farsi' if fa else 'english'
            mail_content = ''
            content_count = 0
            for name, url_feeds in feeds:
                title, url, summary, image = url_feeds
                if not name:
                    name = get_domain_from_url(url)
                mail_content += '<h3 style="text-align:{};">{}</h3>\n <p style="text-align:{};">\n'.format(
                    alignment,
                    name,
                    alignment
                )

                mail_content += '  <a href="{}"><b>{}</b></a>\n'.format(url, title)
                # height: auto;
                # max-width: 100%;
                # width: 100%;
                image_content = '' if not image else '<br/><img src="{}" alt="{}" style="width:100%;height:auto;max-wi'\
                    'dth:100%"/>'.format(image, title)
                mail_content += '  ' + image_content + '\n'
                if summary:
                    mail_content += '  <br/>{}<br/><br/>\n'.format(summary)
                mail_content += ' </p>\n'
                content_count += 1
            sender_address = self.from_mail
            sender_pass = self.password
            receiver_address = self.to_mail
            message = MIMEMultipart()
            message.add_header('Content-Type', 'text/html; charset=UTF-8')
            message['From'] = sender_address
            message['To'] = receiver_address
            message['Subject'] = '{} - {} - ({:0>4})'.format(datetime_string(), language_code, content_count)
            message.attach(MIMEText(mail_content, 'html'))
            self.print_mail_content and print('{}\nMAIL CONTENT:\n{}\n{}'.format('-' * 80, mail_content, '-' * 80))
            try:
                session = smtplib.SMTP('smtp.gmail.com', 587)  # use gmail with port
                session.starttls()  # enable security
                session.login(sender_address, sender_pass)  # login with mail_id and password
                session.sendmail(sender_address, receiver_address, message.as_string())
                session.quit()
            except Exception as error:
                log_error('could not send mail: {}', [error])
                return False
            log_info(
                '{green}{}{reset} {white}{}{reset} content(s) have been sent to {white}{!r}{reset}',
                [content_count, language, sender_address]
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
            ('SENDER', None),
            ('PASSWORD', None),
            ('RECEIVER', None)
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
    try:
        Main(
            cfg['URL_FILE'],
            cfg['CACHE_FILE'],
            int(cfg['CACHE_MAX_SIZE']),
            (int(cfg['SLEEP_RANGE_START']), int(cfg['SLEEP_RANGE_STOP'])),
            cfg['SENDER'],
            cfg['PASSWORD'],
            cfg['RECEIVER']
        ).run()
    except KeyboardInterrupt:
        print()
    except PrintError as reason:
        log_error(str(reason), [])
        exit(1)
