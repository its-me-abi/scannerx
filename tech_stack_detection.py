import requests
from bs4 import BeautifulSoup

def detect_technology_stack(url):
    tech_stack = {}
    try:
        response = requests.get(url)
        headers = response.headers
        html_content = response.text

        if 'server' in headers:
            tech_stack['Server'] = headers['server']
        if 'x-powered-by' in headers:
            tech_stack['X-Powered-By'] = headers['x-powered-by']

        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if script.get('src'):
                if 'jquery' in script['src']:
                    tech_stack['JavaScript Library'] = 'jQuery'
                if 'angular' in script['src']:
                    tech_stack['JavaScript Framework'] = 'Angular'
                if 'react' in script['src']:
                    tech_stack['JavaScript Framework'] = 'React'

        return tech_stack
    except Exception as e:
        print(f"Error detecting technology stack: {e}")
        return tech_stack
