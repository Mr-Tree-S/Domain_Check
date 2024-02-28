import requests


def get_url(domain_to_scan):
    url = f'https://guard.io/v3/subdomailing/domain?domain={domain_to_scan}'
    headers = {
        "accept": "/*",
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    print(data)

domain_to_scan = "msn.com"
get_url(domain_to_scan)

