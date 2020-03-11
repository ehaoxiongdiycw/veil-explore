# veil-explore
veil-explore, find ip behind CDN or WAF(saas)

## ENV

```
$ python -V
Python 3.7.1
$ pip install -r requirements.txt
```

## USAGE

```
$ export FOFA_EMAIL="xxx@xx.com"
$ export FOFA_KEY="xxxxxxxxxxxxxxxx"
$ python veil-explore.py http://site_behind_cdn_or_waf/
$ python veil-explore.py -h
usage: veil-explore.py [-h] [--force] [--max-threads MAX_THREADS] url

veil-explore, find ip behind CDN or WAF(saas)

positional arguments:
  url                   url for CDN or WAF site

optional arguments:
  -h, --help            show this help message and exit
  --force               ignore CDN and WAF detect result to find site
  --max-threads MAX_THREADS
                        max threads for async http client, default: 10
```

## Supported WAF & CDN

- All saas WAF in theoretically.
- Cloudflare, Akamai, Amazon-Cloudfront, Microsoft-Azure and so on.

## Supported Cyberspace Search Engine

- FOFA

## Referer

- https://blog.christophetd.fr/bypassing-cloudflare-using-internet-wide-scan-data/
- https://dualuse.io/blog/curryfinger/
- https://github.com/christophetd/CloudFlair
- https://github.com/tbiehn/CURRYFINGER
