#!/usr/bin/env python2

'''Finds hundreds of HTTP proxies by scraping a number of different lists of proxies then tests them all in parallel to check for malicious behavior.'''

from gevent import monkey
monkey.patch_all()
import difflib
import hashlib
import requests
import ast
import gevent
import sys, re,
from BeautifulSoup import BeautifulSoup

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class find_http_proxy():
    ''' Will only gather L1 (elite anonymity) proxies
    which should not give out your IP or advertise
    that you are using a proxy at all '''

    def __init__(self):
        self.proxy_list = []
        self.headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36'}
        self.errors = []
        self.print_counter = 0
        self.externalip = self.external_ip()

    def external_ip(self):
        req = requests.get('http://myip.dnsdynamic.org/', headers=self.headers)
        ip = req.text
        return ip

    def run(self):
        ''' Gets raw high anonymity (L1) proxy data then calls make_proxy_list()
        Currently parses data from gatherproxy.com and letushide.com '''

        print '[*] Your accurate external IP: %s' % self.externalip

        letushide_list = self.letushide_req()
        print '[*] letushide.com: %s proxies' % str(len(letushide_list))

         # Has a login now :(
        gatherproxy_list = self.gatherproxy_req()
        print '[*] gatherproxy.com: %s proxies' % str(len(gatherproxy_list))

        checkerproxy_list = self.checkerproxy_req()
        print '[*] checkerproxy.net: %s proxies' % str(len(checkerproxy_list))

        self.proxy_list.append(letushide_list)
        self.proxy_list.append(gatherproxy_list)
        self.proxy_list.append(checkerproxy_list)

        # Flatten list of lists (1 master list containing 1 list of ips per proxy website)
        self.proxy_list = [ips for proxy_site in self.proxy_list for ips in proxy_site]
        self.proxy_list = list(set(self.proxy_list)) # Remove duplicates

        print '[*] %d unique high anonymity proxies found' % len(self.proxy_list)
        self.proxy_checker()

    def checkerproxy_req(self):
        ''' Make the request to checkerproxy and create a master list from that site '''
        cp_ips = []
        try:
            url = 'http://checkerproxy.net/all_proxy'
            r = requests.get(url, headers=self.headers)
            html = r.text
        except Exception:
            print '[!] Failed to get reply from %s' % url
            checkerproxy_list = []
            return checkerproxy_list

        checkerproxy_list = self.parse_checkerproxy(html)
        return checkerproxy_list

    def parse_checkerproxy(self, html):
        ''' Only get elite proxies from checkerproxy '''
        ips = []
        soup = BeautifulSoup(html)
        for tr in soup.findAll('tr'):
            if len(tr) == 19:
                ip_found = False
                elite = False
                ip_port = None
                tds = tr.findAll('td')
                for td in tds:
                    if ':' in td.text:
                        ip_found = True
                        ip_port_re = re.match('(\d{1,3}\.){3}\d{1,3}:\d{1,5}', td.text)
                        if ip_port_re:
                            ip_port = ip_port_re.group()
                        if not ip_port:
                            ip_found = False
                    if ip_found == True:
                        ips.append(str(ip_port))
                        break
        return ips

    def letushide_req(self):
        ''' Make the request to the proxy site and create a master list from that site '''
        letushide_ips = []
        for i in xrange(1,20): # can search maximum of 20 pages
            try:
                url = 'http://letushide.com/filter/http,hap,all/%s/list_of_free_HTTP_High_Anonymity_proxy_servers' % str(i)
                r = requests.get(url, headers=self.headers)
                html = r.text
                ips = self.parse_letushide(html)

                # Check html for a link to the next page
                if '/filter/http,hap,all/%s/list_of_free_HTTP_High_Anonymity_proxy_servers' % str(i+1) in html:
                    pass
                else:
                    letushide_ips.append(ips)
                    break
                letushide_ips.append(ips)
            except:
                print '[!] Failed get reply from %s' % url
                break

        # Flatten list of lists (1 list containing 1 list of ips for each page)
        letushide_list = [item for sublist in letushide_ips for item in sublist]
        return letushide_list

    def parse_letushide(self, html):
        ''' Parse out list of IP:port strings from the html '''
        # \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}  -  matches IP addresses
        # </a></td><td>  -  is in between the IP and the port
        # .*?<  -  match all text (.) for as many characters as possible (*) but don't be greedy (?) and stop at the next greater than (<)
        raw_ips = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}</a></td><td>.*?<', html)
        ips = []
        for ip in raw_ips:
            ip = ip.replace('</a></td><td>', ':')
            ip = ip.strip('<')
            ips.append(ip)
        return ips

    def gatherproxy_req(self):
        url = 'http://gatherproxy.com/proxylist/anonymity/?t=Elite'
        try:
            r = requests.get(url, headers = self.headers)
            lines = r.text.splitlines()
        except:
            print '[!] Failed get reply from %s' % url
            gatherproxy_list = []
            return gatherproxy_list

        gatherproxy_list = self.parse_gp(lines)
        return gatherproxy_list

    def parse_gp(self, lines):
        ''' Parse the raw scraped data '''
        gatherproxy_list = []
        for l in lines:
            if 'proxy_ip' in l.lower():
                l = l.replace('gp.insertPrx(', '')
                l = l.replace(');', '')
                l = l.replace('null', 'None')
                l = l.strip()
                l = ast.literal_eval(l)

                proxy = '%s:%s' % (l["PROXY_IP"], l["PROXY_PORT"])
                gatherproxy_list.append(proxy)
                #ctry = l["PROXY_COUNTRY"]
        return gatherproxy_list

    def proxy_checker(self):
        ''' Concurrency stuff here '''
        jobs = [gevent.spawn(self.proxy_checker_req, proxy) for proxy in self.proxy_list]
        try:
            gevent.joinall(jobs)
        except KeyboardInterrupt:
            sys.exit('[-] Ctrl-C caught, exiting')

    def proxy_checker_req(self, proxy):
        ''' See how long each proxy takes to open each URL '''

        # A lot of proxy checker sites give a different final octet for some reason
        #proxy_split = proxyip.split('.')
        #first_3_octets = '.'.join(proxy_split[:3])+'.'

        results = []
        urls = ['http://danmcinerney.org/ip.php', 'http://myip.dnsdynamic.org', 'https://www.astrill.com/what-is-my-ip-address.php', 'http://danmcinerney.org/headers.php']
        for url in urls:
            try:
                url = self.url_shortener(url)
                results.append(("Passed: elite proxy", proxy, url))

            except Exception as e:
                time_or_error = self.error_handler(str(e))
                url = self.url_shortener(url)
                results.append((time_or_error, proxy, url))

        self.printerMalicious(results)

    def printerMalicious(self, results):
        differ = difflib.Differ()
        for result in results:
            proxy = result[1]
            try:
                html = requests.get("http://www.daviddworken.com/", proxies = {'http':'http://'+proxy}, headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.69 Safari/537.36'})
                htmlNormal = requests.get("http://www.daviddworken.com/")
                htmlHash = hashlib.sha1(html.content).digest()
                htmlNormalHash = hashlib.sha1(htmlNormal.content).digest()
                if(not(htmlHash == htmlNormalHash)):
                    htmlNormalL = htmlNormal.content.splitlines()
                    htmlL = html.content.splitlines()
                    diff = differ.compare(htmlNormalL, htmlL)
                    print(bcolors.WARNING + "[-] Malicious proxy found at " + proxy + bcolors.ENDC)
                    diffOut =  '\n'.join(diff)
                    print(diffOut)
            except:
                pass

    def get_country_code(self, proxyip):
        ''' Get the 3 letter country code of the proxy using geoiptool.com
        Would use the geoip library, but it requires a local DB and what
        is the point of that hassle other than marginal speed improvement '''
        cc_line_found = False
        cc = 'N/A'

        try:
            r = requests.get('http://www.geoiptool.com/en/?IP=%s' % proxyip, headers=self.headers)
            html = r.text
            html_lines = html.splitlines()
            for l in html_lines:
                if cc_line_found == True:
                    cc = l.split('(', 1)[1].split(')', 1)[0]
                    break
                if 'country code:' in l.lower():
                    cc_line_found = True
        except:
            pass
        return cc

    def error_handler(self, e):
        if 'Cannot connect' in e:
            time_or_error = 'Err: Cannot connect to proxy'
        elif 'timed out' in e.lower():
            time_or_error = 'Err: Timed out'
        elif 'retries exceeded' in e:
            time_or_error = 'Err: Max retries exceeded'
        elif 'Connection reset by peer' in e:
            time_or_error = 'Err: Connection reset by peer'
        elif 'readline() takes exactly 1 argument (2 given)' in e:
            time_or_error = 'Err: SSL error'
        else:
            time_or_error = 'Err: ' + e
        return time_or_error

    def url_shortener(self, url):
        if 'ip.php' in url:
            url = 'danmcinerney.org'
        elif 'headers.php' in url:
            url = 'Header check'
        elif 'dnsdynamic' in url:
            url = 'dnsdynamic.org'
        elif 'astrill' in url:
            url = 'https://astrill.com'
        return url

    def passed_all_tests(self, results):
        for r in results:
            time_or_error= r[0]
            if 'Err:' in time_or_error:
                return False
        return True


P = find_http_proxy()
P.run()
