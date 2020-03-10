import os
import re
import json
import pyfofa
import warnings
import requests
import dns.resolver
from tld import get_fld
from difflib import SequenceMatcher
from urllib.parse import urljoin, quote, urlparse
warnings.filterwarnings("ignore")

fofa_email = '' or os.environ.get('FOFA_EMAIL')
fofa_key = '' or os.environ.get('FOFA_KEY')
assert all([fofa_email, fofa_key]) == True, '[FATAL] Plsease set FOFA_EMAIL and FOFA_KEY'
headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36"}
request_timeout = 10

def find_cname(domain):
    try:
        cname = dns.resolver.query(domain).canonical_name.to_text()
    except:
        ### fatal
        print('[DNS] {} can not find CNAME record'.format(domain))
        exit(1)
    return cname

def use_cdn(cname):
    try:
        fld = get_fld(cname.rstrip('.'), fix_protocol=True)
        answers = dns.resolver.query(fld, 'NS')
    except:
        ### debug
        print('[DNS] {} can not find NS record'.format(fld))
    else:
        cdn_nss = json.load(open('cdn-ns.json'))
        for answer in answers:
            for cdn_vendor, cdn_ns_list in cdn_nss.items():
                if get_fld(answer.to_text().rstrip('.'), fix_protocol=True) in cdn_ns_list:
                    ### debug
                    print('[CDN] Vendor: {}, NS: {}'.format(cdn_vendor, answer.to_text()))
                    return True
    return False

def get_a_record_answer(cname):
    try:
        answers = dns.resolver.query(cname, 'A')
    except:
        ### fatal
        print('[DNS] {} can not find A record'.format(cname))
        exit(1)
    a_record = [answer.to_text() for answer in answers]
    return a_record

def website_behind_cdn(url):
    _url = urlparse(url)
    if _url.port:
        host_name = _url.netloc.split(':')[0]
    else:
        host_name = _url.netloc
    cname = find_cname(host_name)
    cdn_cloudflare = use_cdn(cname)
    a_record_answer = get_a_record_answer(cname)
    return any([cdn_cloudflare]), a_record_answer

def website_alive_test(url):
    try:
        resp = requests.get(url, headers=headers, timeout=request_timeout, verify=False)
    except:
        ### fatal
        print("Website could't open.")
        exit(1)
    return resp

def website_behind_waf(url, origin_page):
    flag = False
    waf_vector = "AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"
    waf_url = urljoin(url, '?waf_test=666 {}'.format(waf_vector))
    try:
        resp = requests.get(waf_url, headers=headers, timeout=request_timeout, verify=False)
        ratio = SequenceMatcher(None, resp.text, origin_page).quick_ratio()
        flag = ratio < 0.5
    except:
        flag = True
    finally:
        if flag:
            ### debug
            print('[WAF] {}'.format(quote(waf_url, safe='/:')))
        return flag

def website_feature_extract(resp):
    title = get_website_title(resp.text)
    cert_info = get_website_cert(resp.request.url)
    return title, cert_info

def get_website_title(resp_text):
    match = re.search('<title>(.*?)</title>', resp_text, re.S|re.I)
    if match and len(match.groups()) == 1:
        title = match.group(1).strip()
        print('[TITLE] {}'.format(title[:80]))
    else:
        title = None
    return title

def get_website_cert(url):
    _url = urlparse(url)
    if _url.scheme == 'https':
        if _url.port:
            host_name = _url.netloc.split(':')[0]
        else:
            host_name = _url.netloc
        cert_info = host_name
        print('[CERT] {}'.format(cert_info))
    else:
        cert_info = None
    return cert_info

def search_fofa_with_same_feature(title, cert_host, domain_a_records):
    if title and cert_host:
        query = 'title="{title}" || cert="{cert}"'.format(title=title, cert=cert_host)
    elif title:
        query = 'title="{title}"'.format(title=title)
    elif cert_host:
        query = 'cert="{cert}"'.format(cert=cert_host)
    else:
        ### fatal
        print('[FATAL] can not find TITLE and CERT info.')
        exit(1)
    search = pyfofa.FofaAPI(fofa_email, fofa_key)
    result = search.get_data(query, 1, "host,ip,domain,protocol")
    size = result.get('size')
    ### 返回数量太大可能存在误报
    if size > 100:
        print('[FOFA] size: {}, check manualy, query: {}'.format(size, query))
        exit(0)
    clean_result = {}
    for host,ip,domain,protocol in result['results']:
        ### 存在domain的需要丢弃，我们要找可以通过ip进行访问的网站
        ### ip为域名解析后的ip，需要丢弃，通常waf、cdn配置后不存在该情况
        if domain or ip in domain_a_records:
            continue
        sites = clean_result.get(ip, set([]))
        if protocol:
            site = '{}://{}'.format(protocol, host)
        elif not host.startswith('http'):
            site = '{}://{}'.format('http', host)
        else:
            site = host
        sites.add(site)
        clean_result[ip] = sites
    ### info
    print('[FOFA] find {} ip has same site. Waiting for checking...'.format(len(clean_result.keys())))
    return clean_result

def page_check(ip_sites, title, host_name, origin_resp):
    same_sites = []
    headers['Host'] = host_name
    for ip, sites in ip_sites.items():
        for site in list(sites):
            try:
                resp = requests.get(site, headers=headers, timeout=request_timeout, verify=False)
            except Exception as e:
                ### debug
                print('[request-exception] {}, site: {}'.format(e, site))
                continue
            site_title = get_website_title(resp.text)
            ratio = SequenceMatcher(None, resp.text, origin_resp.text).quick_ratio()
            if site_title == title and ratio > 0.9:
                same_sites.append(site)
    return same_sites


def main(input_url, ignore_cdn_waf):
    # input_url = "https://hyvanpuoleiset.fi"       # cdn
    # input_url = "http://www.jjwater.com/?add=xs"        # waf
    _url = urlparse(input_url)
    url = '{}://{}/'.format(_url.scheme, _url.netloc)
    behind_cdn, a_record = website_behind_cdn(url)
    origin_resp = website_alive_test(url)
    behind_waf = website_behind_waf(url, origin_resp.text)
    # if ignore_cdn_waf == False and not any([behind_cdn, behind_waf]):
    if not (ignore_cdn_waf or any([behind_cdn, behind_waf])):
        ### info
        print('CDN and WAF not detected. Exit')
        exit(0)
    title, host_name = website_feature_extract(origin_resp)
    internet_same_sites = search_fofa_with_same_feature(title, host_name, a_record)
    same_sites = page_check(internet_same_sites, title, host_name, origin_resp)
    if same_sites:
        print('[SITES] behind CND or WAF(saas) as follow:\n{}'.format('\n'.join(same_sites)))
    else:
        print('[SITES] no site found.')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='veil-explore, find ip behind CDN or WAF(saas)')
    parser.add_argument("url", help="url for CDN or WAF site")
    parser.add_argument('--force', action='store_true', help="ignore CDN and WAF detect result to find site")
    args = parser.parse_args()
    main(input_url=args.url, ignore_cdn_waf=args.force)
