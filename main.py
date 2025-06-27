import argparse
import logging
import requests
from bs4 import BeautifulSoup
import datetime
import socket
import whois
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


def get_associated_domains(domain):
    """
    Retrieves associated domains by performing DNS lookups (A, MX, NS records).

    Args:
        domain (str): The domain to analyze.

    Returns:
        set: A set of associated domains.
    """
    associated_domains = set()
    try:
        # A records
        try:
            a_records = socket.gethostbyname_ex(domain)[2]
            for ip in a_records:
                try:
                    associated_domain = socket.getfqdn(ip)
                    associated_domains.add(associated_domain)
                except socket.herror:
                    pass  # Ignore if reverse DNS lookup fails
        except socket.gaierror:
            logging.warning(f"Could not resolve A records for {domain}")

        # MX records
        try:
            mx_records = socket.getaddrinfo(domain, 25)
            for mx in mx_records:
                associated_domains.add(mx[4][0])
        except socket.gaierror:
            logging.warning(f"Could not resolve MX records for {domain}")

        # NS records - requires a separate module or API call for proper resolution.
        # This example doesn't implement NS record retrieval for simplicity and due to
        # reliance on external dependencies or APIs.  A more complete implementation
        # would use dnspython or a similar library.

    except Exception as e:
        logging.error(f"Error getting associated domains for {domain}: {e}")

    return associated_domains


def validate_domain(domain):
    """
    Validates the domain format.

    Args:
        domain (str): The domain to validate.

    Returns:
        bool: True if the domain is valid, False otherwise.
    """
    # A simple regex for basic domain validation.  More robust validation might be needed.
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
        associated_domains = get_associated_domains(domain)
        if associated_domains:
            print("\nAssociated Domains (DNS):")
            for assoc_domain in associated_domains:
                creation_date_assoc = get_domain_age(assoc_domain, args.whois)
                if creation_date_assoc:
                  age_assoc = (datetime.date.today() - creation_date_assoc).days
                  print(f"  - {assoc_domain} - Creation Date: {creation_date_assoc}, Age: {age_assoc} days")
                else:
                  print(f"  - {assoc_domain} - Could not determine age")
        else:
            print("No associated domains found.")


if __name__ == "__main__":
    main()