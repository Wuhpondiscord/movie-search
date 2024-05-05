import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import time

def load_blacklist(filename):
    blacklist = set()
    try:
        with open(filename, 'r') as file:
            for line in file.readlines():
                domain = line.strip()
                blacklist.add(domain)
    except FileNotFoundError:
        print(f"Warning: {filename} not found. No domains will be blacklisted.")
    return blacklist

def is_blacklisted(domain, blacklist):
    for blacklisted_domain in blacklist:
        if domain == blacklisted_domain:
            return True
        if blacklisted_domain.startswith("*."):
            subdomain_to_check = blacklisted_domain[2:]  
            if subdomain_to_check in domain:
                return True
    return False

def virustotal_scan(url, api_key):
    params = {'apikey': api_key, 'url': url}
    try:
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        response.raise_for_status()
        response_json = response.json()
        if response_json['response_code'] == 1:
            print("URL successfully submitted for scanning.")
            return response_json['scan_id']
        else:
            print("Failed to submit URL for scanning. Error message:", response_json['verbose_msg'])
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning URL {url}: {e}")
        return None

def virustotal_report(scan_id, api_key):
    params = {'apikey': api_key, 'resource': scan_id}
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        response.raise_for_status()  
        response_json = response.json()
        if response_json['response_code'] == 1:
            print("Scan report retrieved successfully.")
            print("URL to the full report:", response_json['permalink'])
            print("Scan results:")
            for scanner, result in response_json['scans'].items():
                if result['detected']:
                    print(f"{scanner}: Detected - {result['result']}")
            return response_json
        else:
            print("Failed to retrieve scan report. Error message:", response_json['verbose_msg'])
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while getting report for scan ID {scan_id}: {e}")
        return None

def google_dork(movie_name, length, max_results=10, virustotal_api_key=None):
    dorks = {
        1: {
            "Trailer": f'"{movie_name}" -trailer',
        },
        2: {
            "File Types": {
                1: f'"{movie_name}" MKV',
                2: f'"{movie_name}" MOV',
                3: f'"{movie_name}" AVI',
                4: f'"{movie_name}" MP4'
            }
        },
        3: {
            "Resolution": {
                1: f'"{movie_name}" 720p',
                2: f'"{movie_name}" 1080p',
                3: f'"{movie_name}" 2160p',
                4: f'"{movie_name}" 4K',
                5: f'"{movie_name}" (720p OR 1080p OR 2160p OR 4K)'
            }
        },
        4: {
            "Aspect Ratio": {
                1: f'"{movie_name}" 4:3',
                2: f'"{movie_name}" standard definition',
                3: f'"{movie_name}" 16:9 HD',
                4: f'"{movie_name}" high definition'
            }
        }
    }

    blacklist = load_blacklist("blacklisted_domains.txt")

    print(f"\nWelcome to Movie Search for '{movie_name}'!")
    print("Search Options:")
    for key, value in dorks.items():
        print(f"{key}.")
        for sub_category, sub_value in value.items():
            if isinstance(sub_value, dict):
                print(f"  {sub_category}:")
                for sub_key, sub_dork in sub_value.items():
                    print(f"   {sub_key}. {sub_dork}")
            else:
                print(f"  {sub_category}: {sub_value}")
    print("5. Exit")

    while True:
        choice = input("Enter the number of your choice: ")
        if choice == '5':
            print("Exiting Movie Search. Goodbye!")
            return
        elif choice.isdigit() and int(choice) in dorks:
            sub_dorks = dorks[int(choice)]
            break
        else:
            print("Invalid choice. Please enter a number corresponding to the provided options.")

    while True:
        sub_choice = input("Choose a sub-category or enter 'any' to use any available option: ").lower()
        if sub_choice == 'any':
            sub_dork = next(iter(sub_dorks.values()))
            break
        elif sub_choice.isdigit() and int(sub_choice) in sub_dorks.get("Aspect Ratio", {}):
            sub_dork = sub_dorks["Aspect Ratio"][int(sub_choice)]
            break
        elif sub_choice.isdigit() and int(sub_choice) in sub_dorks.get("Resolution", {}):
            sub_dork = sub_dorks["Resolution"][int(sub_choice)]
            break
        elif sub_choice.isdigit() and int(sub_choice) in sub_dorks.get("File Types", {}):
            sub_dork = sub_dorks["File Types"][int(sub_choice)]
            break
        elif sub_choice in sub_dorks.get("Aspect Ratio", {}).values():
            sub_dork = sub_choice
            break
        elif sub_choice in sub_dorks.get("Resolution", {}).values():
            sub_dork = sub_choice
            break
        elif sub_choice in sub_dorks.get("File Types", {}).values():
            sub_dork = sub_choice
            break
        else:
            print("Invalid choice. Please enter a valid sub-category number or 'any'.")

    found_videos = []
    processed_urls = set()

    print(f"\nSearching for '{movie_name}'...")
    search_url = f"https://www.google.com/search?q={sub_dork}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
    }

    try:
        response = requests.get(search_url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        search_results = soup.find_all('a', href=True)
        print("Number of search results found:", len(search_results))  
        for result in search_results:
            url = result['href']
            if url.startswith('http') or url.startswith('www'):  
                domain = urlparse(url).netloc.split(':')[0] if urlparse(url).netloc else ""  
                if domain and is_blacklisted(domain, blacklist):  
                    continue
                processed_urls.add(url)
        found_videos = list(processed_urls)[:max_results]

        print("\nSearch results:")
        for index, url in enumerate(found_videos, start=1):
            print(f"{index}. {url}")
        if virustotal_api_key:
            for url in found_videos:
                scan_choice = input(f"Do you want to scan '{url}' with VirusTotal? (Y/N): ").strip().lower()
                if scan_choice == 'y':
                    scan_id = virustotal_scan(url, virustotal_api_key)
                    if scan_id:
                        print("Waiting for the report to come back...")
                        time.sleep(10)  
                        report = virustotal_report(scan_id, virustotal_api_key)
                        if report:
                            print("Scan report:")
                            print(json.dumps(report, indent=4))
                        else:
                            print("Failed to retrieve scan report.")
                    else:
                        print(f"Failed to scan '{url}' with VirusTotal.")
                elif scan_choice == 'n':
                    continue
                else:
                    print("Invalid choice. Please enter 'Y' or 'N'.")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while searching: {e}")

if __name__ == "__main__":
    movie_name = input("Enter the movie name: ")
    length = input("Enter the movie length in minutes: ")

    virustotal_api_key = input("Enter your VirusTotal API key (press Enter to skip VirusTotal scanning): ")

    max_results_input = input("Enter the maximum number of search results to consider (default is 10) or 'exit' to quit: ").lower()
    if max_results_input == 'exit':
        print("Exiting Movie Search. Goodbye!")
    elif max_results_input.isdigit():
        max_results = int(max_results_input)

        google_dork(movie_name, length, max_results, virustotal_api_key)
    elif not max_results_input:
        max_results = 50
        google_dork(movie_name, length, max_results, virustotal_api_key)
    else:
        print("Invalid input. Exiting Movie Search. Goodbye!")
