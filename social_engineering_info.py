import whois

def get_social_engineering_info(domain):
    try:
        w = whois.whois(domain)
        return {
            'Domain Name': w.domain_name,
            'Registrar': w.registrar,
            'Whois Server': w.whois_server,
            'Referral URL': w.referral_url,
            'Updated Date': str(w.updated_date),
            'Creation Date': str(w.creation_date),
            'Expiration Date': str(w.expiration_date),
            'Name Servers': w.name_servers,
            'Status': w.status,
            'Emails': w.emails,
            'DNSSEC': w.dnssec,
            'Name': w.name,
            'Org': w.org,
            'Address': w.address,
            'City': w.city,
            'State': w.state,
            'Zipcode': w.zipcode,
            'Country': w.country
        }
    except Exception as e:
        print(f"Error gathering social engineering information: {e}")
        return {}
