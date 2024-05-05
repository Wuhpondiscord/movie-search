Google Dork Movie Search
This is a Flask web application for searching movie-related content using Google dorks. It provides a user interface to input movie details and search criteria, then retrieves relevant search results from Google. Additionally, it offers a feature to scan the retrieved URLs for potential security threats using the VirusTotal API.

Table of Contents
Features
Setup
Usage
Contributing
License
Features
Google Dork Search: Utilizes Google dorks to search for movie-related content.
Flexible Search Criteria: Allows users to specify search categories and subcategories.
VirusTotal Integration: Scans retrieved URLs for potential security threats using the VirusTotal API.
Blacklist Management: Provides functionality to add domains to a blacklist to exclude them from search results.
Setup
To run this application locally, follow these steps:

Clone the repository:
bash
Copy code
git clone https://github.com/your_username/your_repository.git
Install dependencies:
bash
Copy code
pip install -r requirements.txt
Set up configuration:
Ensure you have a valid config.json file with necessary configurations.
Update the virustotal_api_key field with your VirusTotal API key.
Usage
Run the application:
bash
Copy code
python app.py
Access the application:Open your web browser and navigate to http://localhost:5000 to access the application.
Search for movies:
Enter the movie name, length, search category, search subcategory, and maximum results.
Click on the "Search" button to retrieve search results.
View scan results:
Scan results will be displayed indicating whether the URLs contain potential security threats.
Manage blacklist:
To blacklist a domain, use the "Add to Blacklist" feature.
Contributing
Contributions are welcome! If you'd like to contribute to this project, please follow these steps:

Fork the repository.
Create a new branch (git checkout -b feature-name).
Make your changes.
Commit your changes (git commit -am 'Add new feature').
Push to the branch (git push origin feature-name).
Create a new Pull Request.
