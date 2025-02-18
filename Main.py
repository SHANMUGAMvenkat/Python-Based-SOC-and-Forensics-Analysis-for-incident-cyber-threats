import os

# ANSI escape codes for text color
COLORS = {
    'HEADER': '\033[95m',
    'OKBLUE': '\033[94m',
    'OKGREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',  # End color
}

def show_options():
    print(COLORS['OKGREEN'] + "Enter option to analyze" + COLORS['ENDC'])

    print(COLORS['WARNING'] + " _________________________________________________________")
    print(COLORS['OKBLUE'] + "option 1" + COLORS['ENDC'] + " SYSTEM LOG ANALYSIS")
    print(COLORS['WARNING'] + "option 2" + COLORS['ENDC'] + " NETWORK MONITER")
    print(COLORS['HEADER'] + "option 3" + COLORS['ENDC'] + " NETWORK ANALYZE")
    print(COLORS['FAIL'] + "option 4" + COLORS['ENDC'] + " MALWARE ANALYSIS")
    print(COLORS['OKGREEN'] + "option 5" + COLORS['ENDC'] + " WEB APP SCANNING")
    print(COLORS['OKBLUE'] + "option 6" + COLORS['ENDC'] + " IDS/IPS SCAN")
    print(COLORS['WARNING'] + " _________________________________________________________")
    print(COLORS['HEADER'] + "option 0" + COLORS['ENDC'] + " EXIT")

def open_file(filename):
    try:
        os.system("python " + filename)
    except FileNotFoundError:
        print("File not found.")

if __name__ == "__main__":
    while True:
        show_options()
        option = input("Enter your choice (0-7): ")
        
        if option == '1':
            open_file("ExtractLogs.py")
        elif option == '2':
            open_file("Networkmoniter.py")
        elif option == '3':
            open_file("PcapAnalyze.py")
        elif option == '4':
            open_file("MAanalysis.py")
        elif option == '5':
            open_file("ZAP.py")
        elif option == '6':
            open_file("IDSIPS.py")
        elif option == '0':
            break
        else:
            print("Invalid option. Please enter a number between 0 and 6.")
