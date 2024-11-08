# Domain-parser
Returns complete whois and domain info parser domain information
## Getting Started

Install using composer:
```bash
composer require qycorp/domain-parser
```

Qycorp Domains parser uses a public suffix PHP dataset auto-generated from the [publicsuffix.org](https://publicsuffix.org/). The dataset get periodically updates from us, but you can also manually update it by cloning this library and running the import script with the import command:

```bash
php ./data/import.php
```
> If you want to parse ordinary web urls then use `$host = parse_url($return, PHP_URL_HOST); $domain = new \Qycorp\DomainParser\Parser($host);` to get the domain object. 


## Library API

* **get()** - Return you full domain name.
* **getTLD()** - Return only the top-level-domain.
* **getSuffix()** - Return only the public suffix of your domain, for example: co.uk, ac.be, org.il, com, org.
* **getRegisterable()** - Return the registered or registrable domain, which is the public suffix plus one additional label.
* **getName()** - Returns only the registerable domain name. For example, blog.example.com will return 'example', and demo.co.uk will return 'demo'.
* **getSub()** - Returns the full sub domain path for you domain. For example, blog.example.com will return 'blog', and subdomain.demo.cn will return 'subdomain.demo'.
* **getWhoisServer()** - Returns whois server url info.
* **getWhoisInfo()** - Returns whois info.
* **isKnown()** - Returns true if public suffix is know and false otherwise.
* **isICANN()** - Returns true if the public suffix is found in the ICANN DOMAINS section of the public suffix list.
* **isPrivate()** - Returns true if the public suffix is found in the PRIVATE DOMAINS section of the public suffix list.
* **isTest()** - Returns true if the domain TLD is 'locahost' or 'test' and false otherwise.

## Support functions

* **iana_whois($domain,$is_server)** Return the original whois information of the domain name
* **iana_domain($domain)** Return the components of the domain name, including subdomain, name, top-level domain, original whois information, etc

## Copyright and license

The MIT License (MIT) [http://www.opensource.org/licenses/mit-license.php](http://www.opensource.org/licenses/mit-license.php)
