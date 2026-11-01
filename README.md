# vscan-domain-age-analyzer
Determines the age of a domain and associated domains, identifying potentially suspicious or newly registered domains often associated with phishing or malicious activities. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuardAI/vscan-domain-age-analyzer`

## Usage
`./vscan-domain-age-analyzer [params]`

Data source: by default, the age lookup scrapes the whois page of viewdns.info, a third party site, and parses the creation date out of its HTML. That default path sends the domain you name to viewdns.info. Use `-w` to look the creation date up through the whois library instead. With `-d`, A records come from address resolution, and MX and NS records come from MX and NS lookups through the resolver. Age lookups for returned MX and NS hosts run on the registered domain of each host, not on IP addresses.

## Parameters
- `-h`: Show help message and exit
- `-d`: Check associated domains via DNS records (A, MX, NS). May increase analysis time.
- `-w`: Retrieve WHOIS information. Requires whois package. May be slow.

## License
Copyright (c) ShadowGuardAI
