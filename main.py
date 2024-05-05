from flask import Flask, render_template, request, jsonify
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import requests
import time

app = Flask(__name__)

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
        if domain == blacklisted_domain or (blacklisted_domain.startswith("*.") and blacklisted_domain[2:] in domain):
            return True
    return False

def add_to_blacklist(domain, filename):
    with open(filename, 'a') as file:
        file.write(domain + '\n')

def virustotal_scan(url, api_key):
    params = {'apikey': api_key, 'url': url}
    try:
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        response.raise_for_status()
        response_json = response.json()
        if response_json.get('response_code') == 1:
            print("URL successfully submitted for scanning.")
            return response_json['scan_id']
        else:
            print("Failed to submit URL for scanning. Error message:", response_json.get('verbose_msg'))
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
        if response_json.get('response_code') == 1:
            print("Scan report retrieved successfully.")
            print("URL to the full report:", response_json.get('permalink'))
            print("Scan results:")
            positive_count = 0
            for scanner, result in response_json.get('scans', {}).items():
                if result.get('detected'):
                    positive_count += 1
                    print(f"{scanner}: Detected - {result.get('result')}")
            return response_json, positive_count
        else:
            print("Failed to retrieve scan report. Error message:", response_json.get('verbose_msg'))
            return None, 0
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while getting report for scan ID {scan_id}: {e}")
        return None, 0

def google_dork(movie_name, length, search_category, search_subcategory, max_results=10, virustotal_api_key=None):
    dorks = {
        "Trailer": f'"{movie_name}" -trailer',
        "File Types": {
            "MKV": f'"{movie_name}" MKV',
            "MOV": f'"{movie_name}" MOV',
            "AVI": f'"{movie_name}" AVI',
            "MP4": f'"{movie_name}" MP4'
        },
        "Resolution": {
            "720p": f'"{movie_name}" 720p',
            "1080p": f'"{movie_name}" 1080p',
            "2160p": f'"{movie_name}" 2160p',
            "4K": f'"{movie_name}" 4K',
            "Any": f'"{movie_name}" (720p OR 1080p OR 2160p OR 4K)'
        },
        "Aspect Ratio": {
            "4:3": f'"{movie_name}" 4:3',
            "standard definition": f'"{movie_name}" standard definition',
            "16:9 HD": f'"{movie_name}" 16:9 HD',
            "high definition": f'"{movie_name}" high definition'
        }
    }

    dork = dorks.get(search_category, {}).get(search_subcategory)
    if not dork:
        return [], 0

    print(f"Search query: {dork}")

    blacklist = load_blacklist("blacklisted_domains.txt")

    search_results = search(dork, max_results, blacklist)
    positive_count = 0
    for url in search_results:
        scan_id = virustotal_scan(url, virustotal_api_key)
        if scan_id:
            time.sleep(10)  
            _, count = virustotal_report(scan_id, virustotal_api_key)
            positive_count += count

    return search_results[:max_results], positive_count

def search(keyword, max_results, blacklist):
    found_videos = []
    processed_urls = set()

    print(f"\nSearching for '{keyword}'...")
    search_url = f"https://www.google.com/search?q={keyword}"
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
                if domain and not is_blacklisted(domain, blacklist):  
                    processed_urls.add(url)
        found_videos = list(processed_urls)[:max_results]

        print("Found videos:", found_videos)

        return found_videos

    except requests.exceptions.RequestException as e:
        print(f"Error occurred while searching: {e}")

    return found_videos

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        movie_name = request.form['movie_name']
        length = request.form['length']
        search_category = request.form['search_category']
        search_subcategory = request.form['search_subcategory']
        virustotal_api_key = request.form['virustotal_api_key']
        max_results = int(request.form['max_results'])

        results, positive_count = google_dork(movie_name, length, search_category, search_subcategory, max_results, virustotal_api_key)
        scan_results = []
        for url in results:
            scan_result = "Positive" if positive_count > 0 else "Negative"
            scan_results.append({'url': url, 'scan_result': scan_result})
        print("Scan Results:", scan_results)
        return jsonify(scan_results=scan_results, positive_count=positive_count)  

    contacts = load_contacts("contacts.json")
    return render_template('index.html', contacts=contacts)

def load_contacts(filename):
    try:
        with open(filename, 'r') as file:
            contacts = json.load(file)
        return contacts
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
        return []

@app.route('/add-to-blacklist', methods=['POST'])
def add_to_blacklist_endpoint():
    data = request.get_json()
    domain = data.get('domain')
    print("Received domain:", domain)  
    if domain:
        try:
            with open('blacklisted_domains.txt', 'a') as file:
                file.write(domain + '\n')
            return 'Domain added to blacklist successfully.', 200
        except Exception as e:
            print("Error writing to file:", e)  
            return 'Error writing to file.', 500
    else:
        return 'Invalid domain.', 400

if __name__ == '__main__':
    app.run(debug=True)
