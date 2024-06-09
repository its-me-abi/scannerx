import requests
from bs4 import BeautifulSoup

def detect_cms(url):
    cms_info = {}
    try:
        response = requests.get(url)
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')

        if 'wp-content' in html_content:
            cms_info['CMS'] = 'WordPress'
        elif 'Joomla' in html_content:
            cms_info['CMS'] = 'Joomla'
        elif 'sites/all' in html_content:
            cms_info['CMS'] = 'Drupal'

        return cms_info
    except Exception as e:
        print(f"Error detecting CMS: {e}")
        return cms_info
