import requests
from config import VT_API_KEY, URLSCAN_API_KEY
# It can be adjusted to only obtain source data through the API.
# Filtering source data can be done in another lib


# Various types of domain check functions
def get_vt_reputation(domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
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


def get_vt_mx(domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
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


def get_urlscan(domain):
    url = f'https://urlscan.io/api/v1/search/?q={domain}'
    headers = {
        "accept": "application/json",
        # "API-Key": URLSCAN_API_KEY
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    total = data["total"]
    if total != 0:
        urlscan = data["results"][0]["page"]["url"]
        return urlscan
    return "N/A"

def get_guard_subdomailing(domain):
    url = f'https://guard.io/v3/subdomailing/domain?domain={domain}'
    headers = {
        "accept": "/*",
    }
    response = requests.get(url, headers=headers)
    guard_subdomailing = response.json()
    return guard_subdomailing


# Accept the domain and the type to check
def get_domain_info(domain, mx, reputation, urlscan, guard_subdomailing, result_dict):
    domain_results = {}
    if reputation:
        result = get_vt_reputation(domain)
        domain_results['reputation'] = result
    if mx:
        result = get_vt_mx(domain)
        domain_results['mx'] = result
    if urlscan:
        result = get_urlscan(domain)
        domain_results['urlscan'] = result
    if guard_subdomailing:
        result = get_guard_subdomailing(domain)
        domain_results['guard_subdomailing'] = result
    result_dict[domain] = domain_results
