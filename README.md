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
```

## Supported CDN

- cloudflare

## Supported WAF

- all saas waf (theoretically)

## Supported Cyberspace Search Engine

- FOFA

## Referer

- https://blog.christophetd.fr/bypassing-cloudflare-using-internet-wide-scan-data/
- https://dualuse.io/blog/curryfinger/
- https://github.com/christophetd/CloudFlair
- https://github.com/tbiehn/CURRYFINGER
