import argparse
import logging
import requests
from bs4 import BeautifulSoup
import datetime
import socket
import whois
import dns.resolver
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-domain-age-analyzer: Determines the age of a domain and associated domains.")
    parser.add_argument("domain", help="The domain to analyze (e.g., example.com)")
    parser.add_argument("-d", "--dns", action="store_true", help="Check associated domains via DNS records (A, MX, NS). May increase analysis time.")
    parser.add_argument("-w", "--whois", action="store_true", help="Retrieve WHOIS information. Requires whois package. May be slow.")

    return parser.parse_args()


def get_domain_age(domain, use_whois=False):
    """
    Retrieves the domain age using WHOIS lookup.

    Args:
        domain (str): The domain to analyze.
        use_whois (bool): Whether to use whois lookup.
    Returns:
        datetime.date: The creation date of the domain or None if an error occurred.
    """
    try:
        if use_whois:
             # Attempt WHOIS lookup using the whois library.
            try:
                w = whois.whois(domain)
                if w.creation_date:
                  if isinstance(w.creation_date, list):
                    # Registries that report several dates do not promise
                    # their order, so the earliest date is the creation
                    # date. Picking the first entry can take a renewal or
                    # transfer stamp and make an old domain look new.
                    candidates = []
                    for entry in w.creation_date:
                        if isinstance(entry, datetime.datetime):
                            candidates.append(entry.date())
                        elif isinstance(entry, datetime.date):
                            candidates.append(entry)
                    if not candidates:
                        logging.warning(f"Unexpected date type for {domain}: {type(w.creation_date)}")
                        return None
                    creation_date = min(candidates)
                  else:
                    creation_date = w.creation_date
                  
                  if isinstance(creation_date, datetime.datetime):
                    return creation_date.date()
                  elif isinstance(creation_date, datetime.date):
                    return creation_date
                  else:
                    logging.warning(f"Unexpected date type for {domain}: {type(creation_date)}")
                    return None
                else:
                    logging.warning(f"No creation date found for {domain} using whois.")
                    return None
            except whois.parser.PywhoisError as e:
                logging.error(f"WHOIS lookup failed for {domain}: {e}")
                return None
        else:
            #Attempt creation date retrieval using web scraping fallback (if WHOIS not explicitly requested)
            try:
                response = requests.get(f"https://viewdns.info/whois/?domain={domain}", timeout=10)  #Added timeout
                response.raise_for_status() # Raise HTTPError for bad responses (4XX or 5XX)
                soup = BeautifulSoup(response.content, 'html.parser')
                pre_tags = soup.find_all('pre') # Find all <pre> tags
                
                for pre_tag in pre_tags:
                  whois_data = pre_tag.text.strip() #Get text content of <pre> tag
                  if 'Creation Date:' in whois_data:
                    # Accept the common registry date shapes: ISO dates
                    # (2020-01-02, also the date part of an ISO datetime),
                    # Mon-DD-YYYY, and DD-Mon-YYYY.
                    for pattern, fmt in (
                        (r"Creation Date:\s*(\d{4}-\d{2}-\d{2})", "%Y-%m-%d"),
                        (r"Creation Date:\s*([A-Za-z]{3}-\d{2}-\d{4})", "%b-%d-%Y"),
                        (r"Creation Date:\s*(\d{2}-[A-Za-z]{3}-\d{4})", "%d-%b-%Y"),
                    ):
                        match = re.search(pattern, whois_data)
                        if match:
                            try:
                                return datetime.datetime.strptime(match.group(1), fmt).date()
                            except ValueError:
                                continue
            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching WHOIS data for {domain}: {e}")
                return None
            except Exception as e:
                logging.error(f"Error processing WHOIS data for {domain}: {e}")
                return None
    except Exception as e:
       logging.error(f"Unexpected error getting domain age for {domain}: {e}")
       return None

    return None


# Common two-level public suffixes. This is a short built-in list, not
# the full public suffix list, but it covers the suffixes most often
# seen on mail and nameserver hosts.
TWO_LEVEL_SUFFIXES = {
    "ac.uk", "co.uk", "gov.uk", "org.uk",
    "com.au", "net.au", "org.au", "co.nz",
    "com.br", "com.cn", "com.tw", "co.jp", "ne.jp", "co.kr",
    "co.in", "com.mx", "com.sg", "com.hk", "co.za",
}

def registered_domain(host):
    """Return the registered domain of a host name.

    That is the last two labels, or the last three when the last two
    form a known two-level public suffix such as co.uk, so the result
    is the operator's domain rather than the suffix itself.
    """
    host = host.rstrip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def get_associated_domains(domain):
    """
    Retrieves DNS records for a domain, grouped by record type.

    A records come from address resolution. MX and NS records come from
    real MX and NS lookups through the resolver.

    Args:
        domain (str): The domain to analyze.

    Returns:
        dict: Mapping of "A", "MX", and "NS" to lists of record values.
              A values are IP addresses; MX and NS values are host names.
    """
    records = {"A": [], "MX": [], "NS": []}
    try:
        # A records, from address resolution
        try:
            records["A"] = list(socket.gethostbyname_ex(domain)[2])
        except socket.gaierror:
            logging.warning(f"Could not resolve A records for {domain}")

        # MX records, from an MX lookup through the resolver
        try:
            answers = dns.resolver.resolve(domain, "MX")
            records["MX"] = sorted({answer.exchange.to_text().rstrip(".") for answer in answers})
        except Exception:
            logging.warning(f"Could not resolve MX records for {domain}")

        # NS records, from an NS lookup through the resolver
        try:
            answers = dns.resolver.resolve(domain, "NS")
            records["NS"] = sorted({answer.target.to_text().rstrip(".") for answer in answers})
        except Exception:
            logging.warning(f"Could not resolve NS records for {domain}")

    except Exception as e:
        logging.error(f"Error getting associated domains for {domain}: {e}")

    return records


def validate_domain(domain):
    """
    Validates the domain format.

    Args:
        domain (str): The domain to validate.

    Returns:
        bool: True if the domain is valid, False otherwise.
    """
    # Shape check against typos, not a statement that the domain
    # exists: at least two labels, no empty labels (so no leading,
    # trailing, or doubled dots), each label 1 to 63 letters, digits,
    # or hyphens and not starting or ending with a hyphen, and a top
    # level domain of at least two letters. Punycode labels (xn--)
    # pass; raw non-ASCII names do not.
    if not domain or len(domain) > 253:
        logging.error(f"Invalid domain format: {domain}")
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        logging.error(f"Invalid domain format: {domain}")
        return False
    for label in labels:
        if not re.match(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", label):
            logging.error(f"Invalid domain format: {domain}")
            return False
    if not re.match(r"^[A-Za-z]{2,}$", labels[-1]):
        logging.error(f"Invalid domain format: {domain}")
        return False
    return True


def main():
    """
    Main function to execute the domain age analysis.
    """
    args = setup_argparse()
    domain = args.domain

    if not validate_domain(domain):
        sys.exit(1)

    logging.info(f"Analyzing domain: {domain}")

    creation_date = get_domain_age(domain, args.whois)
    if creation_date:
        age = (datetime.date.today() - creation_date).days
        print(f"Domain: {domain} - Creation Date: {creation_date}, Age: {age} days")
    else:
        print(f"Could not determine age for domain: {domain}")

    if args.dns:
        age_cache = {}
        records = get_associated_domains(domain)
        if any(records.values()):
            print("\nAssociated Domains (DNS):")
            for record_type in ("A", "MX", "NS"):
                print(f"{record_type}:")
                for value in records[record_type]:
                    if record_type == "A":
                        # A values are IP addresses; age lookups run on domain names only.
                        print(f"  - {value}")
                    else:
                        reg_domain = registered_domain(value)
                        # Cache per registered domain: several MX or NS
                        # hosts usually share one, and its age is fetched
                        # only once per run.
                        if reg_domain not in age_cache:
                            age_cache[reg_domain] = get_domain_age(reg_domain, args.whois)
                        creation_date_assoc = age_cache[reg_domain]
                        if creation_date_assoc:
                          age_assoc = (datetime.date.today() - creation_date_assoc).days
                          print(f"  - {value} - Registered Domain: {reg_domain} - Creation Date: {creation_date_assoc}, Age: {age_assoc} days")
                        else:
                          print(f"  - {value} - Registered Domain: {reg_domain} - Could not determine age")
        else:
            print("No associated domains found.")


if __name__ == "__main__":
    main()