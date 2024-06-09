import requests

def detect_external_services(url):
    services = {}
    try:
        response = requests.get(url)
        html_content = response.text

        if 'www.google-analytics.com' in html_content:
            services['Analytics'] = 'Google Analytics'
        if 'cloudflare' in response.headers.get('server', '').lower():
            services['CDN'] = 'Cloudflare'

        return services
    except Exception as e:
        print(f"Error detecting external services: {e}")
        return services
