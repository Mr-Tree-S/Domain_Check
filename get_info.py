import requests
from config import VT_API_KEY
# It can be adjusted to only obtain source data through the API.
# Filtering source data can be done in another lib


# Various types of domain check functions
def get_reputation(domain_to_scan):
    url = f'https://www.virustotal.com/api/v3/domains/{domain_to_scan}'
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    analysis_stats = data["data"]["attributes"]["last_analysis_stats"]
    if analysis_stats.get("malicious") is not None:
        malicious = analysis_stats["malicious"]
        total = sum(analysis_stats.values())
        reputation_stat = f'{malicious}/{total}'
        return reputation_stat
    return "N/A"


def get_mx(domain_to_scan):
    url = f'https://www.virustotal.com/api/v3/domains/{domain_to_scan}'
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    dns_records = data["data"]["attributes"]["last_dns_records"]
    for record in dns_records:
        if record.get("type") == "MX":
            mx_record = record["value"]
            return mx_record
    return "N/A"


def get_url(domain_to_scan):
    return "N/A"


# Accept the domain and the type to check
def get_domain_info(domain, mx, reputation, url, result_dict):
    domain_results = {}
    if reputation:
        result = get_reputation(domain)
        domain_results['reputation'] = result
    if mx:
        result = get_mx(domain)
        domain_results['mx'] = result
    if url:
        result = get_url(domain)
        domain_results['url'] = result
    result_dict[domain] = domain_results
