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
                    # First is not earliest. Registries that report several dates do not promise their order, so picking index zero can take a renewal or transfer stamp and make an old domain look newly registered, which is the exact mistake this tool exists to avoid.
                    creation_date = w.creation_date[0] # Use the first creation date if multiple are present
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
                    # My default path, when --whois is not passed, is this scrape of one website's page layout and one date shape. A registry whose record writes the date in ISO form, or a page that changes its markup, gives me nothing, and the failure reads exactly like a domain with no creation date.
                    match = re.search(r"Creation Date:\s*([A-Za-z]{3}-\d{2}-\d{4})", whois_data) #Updated Regex
                    if match:
                        date_str = match.group(1)
                        creation_date = datetime.datetime.strptime(date_str, "%b-%d-%Y").date()
                        return creation_date
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


def registered_domain(host):
    """Return the registered domain (last two labels) of a host name."""
    host = host.rstrip(".")
    parts = host.split(".")
    if len(parts) >= 2:
        # Last two labels is a shortcut that breaks on public suffixes: a host under co.uk reduces to co.uk itself, and the age I then look up belongs to the suffix registry, not to the operator's domain.
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
    # A simple regex for basic domain validation.  More complete validation might be needed.
    # This pattern also accepts names with leading dots, empty labels, and hyphens at the edges, while refusing single letter top level domains and internationalised names. It is a shape check against typos, not a statement that the domain exists.
    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
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
                        # There is no caching on this loop. Several MX or NS hosts usually share one registered domain, and I fetch its age again for each of them, which on the scraping path means repeated requests to the same page for the same answer.
                        creation_date_assoc = get_domain_age(reg_domain, args.whois)
                        if creation_date_assoc:
                          age_assoc = (datetime.date.today() - creation_date_assoc).days
                          print(f"  - {value} - Registered Domain: {reg_domain} - Creation Date: {creation_date_assoc}, Age: {age_assoc} days")
                        else:
                          print(f"  - {value} - Registered Domain: {reg_domain} - Could not determine age")
        else:
            print("No associated domains found.")


if __name__ == "__main__":
    main()