import time
from zapv2 import ZAPv2

# ANSI escape codes for text color
class colors:
    PINK = '\033[95m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    END = '\033[0m'

# Function for loading animation
def loading_animation():
    animation = ["\U0001f600", "\U0001F606", "\U0001F923","\U0001F621","\U0001F628"]
    for i in range(20):
        time.sleep(0.1)
        print(f"\rLoading {animation[i % len(animation)]}", end="", flush=True)

# OWASP ZAP API URL
ZAP_URL = 'https://localhost:8080/'

# Create ZAP instance
zap = ZAPv2(apikey='o1k4cmnl2tek93j16g304egksv', proxies={'http': ZAP_URL, 'https': ZAP_URL})

# Target URL to scan
TARGET_URL = 'https://certifiedhacker.com/'

# Start ZAP spider
print(colors.PINK + "Spidering target URL..." + colors.END)
zap.spider.scan(TARGET_URL)
while zap.spider.status() != '100':
    print(f"\rSpider progress: {zap.spider.status()}%", end="", flush=True)
    loading_animation()

print("\nSpidering completed!")

# Start ZAP active scan
print(colors.BLUE + "Starting active scan..." + colors.END)
zap.ascan.scan(TARGET_URL)
while zap.ascan.status() != '100':
    print(f"\rActive scan progress: {zap.ascan.status()}%", end="", flush=True)
    loading_animation()

print("\nActive scan completed!")

# Get alerts (vulnerabilities)
alerts = zap.core.alerts()
if alerts:
    print(colors.RED + "Vulnerabilities found:" + colors.END)
    for alert in alerts:
        print(f"Alert: {alert['alert']} | Risk: {alert['risk']} | Description: {alert['description']}")
else:
    print(colors.GREEN + "No vulnerabilities found." + colors.END)
