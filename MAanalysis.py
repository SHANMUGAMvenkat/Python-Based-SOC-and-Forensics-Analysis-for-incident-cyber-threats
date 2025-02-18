import os
import hashlib
import time
import pefile

def check_anti_vm(file_path):
    anti_vm_tricks = [
        b"Red Pill",
        b"VirtualPc trick",
        b"VMware trick",
        b"VMCheck.dll",
        b"VMCheck.dll for VirtualPC",
        b"Xen",
        b"Bochs & QEmu CPUID Trick",
        b"Torpig VMM Trick",
        b"Torpig (UPX) VMM Trick"
    ]
    with open(file_path, "rb") as f:
        data = f.read()
        for trick in anti_vm_tricks:
            if trick in data:
                return True
    return False

def check_peid_signatures(pe):
    # Since we don't have a PEiD signature database file, return an empty list
    return []

def calculate_hashes(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
        md5_hash = hashlib.md5(data).hexdigest()
        sha1_hash = hashlib.sha1(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()
    return md5_hash, sha1_hash, sha256_hash

def get_architecture(pe):
    if pe.FILE_HEADER.Machine == 0x14C:  # IMAGE_FILE_MACHINE_I386
        return "32-bit"
    elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
        return "64-bit"
    else:
        return "Unknown"

def analyze_exe(file_path):
    try:
        pe = pefile.PE(file_path)
        
        anti_vm_check = check_anti_vm(file_path)
        peid_signatures = check_peid_signatures(pe)
        md5_hash, sha1_hash, sha256_hash = calculate_hashes(file_path)
        architecture = get_architecture(pe)
        crc_hash = pe.OPTIONAL_HEADER.CheckSum
        timestamp = time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))

        print("Analysis Report for:", file_path)
        print("Anti-VM Check:", "Detected" if anti_vm_check else "Not Detected")
        print("PEiD Signatures:", peid_signatures if peid_signatures else "None")
        print("MD5 Hash:", md5_hash)
        print("SHA1 Hash:", sha1_hash)
        print("SHA256 Hash:", sha256_hash)
        print("CRC Hash:", hex(crc_hash))
        print("Architecture:", architecture)
        print("Timestamp:", timestamp)

        # Entry point and section overview
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print("\nEntry Point:", hex(entry_point))

        print("\nSection Overview:")
        for section in pe.sections:
            print("Name:", section.Name.decode().strip('\x00'))
            print("Virtual Address:", hex(section.VirtualAddress))
            print("Virtual Size:", hex(section.Misc_VirtualSize))
            print("Size of Raw Data:", hex(section.SizeOfRawData))
            print()

        # Calculate Malware Severity Level based on certain criteria
        malware_severity = 0
        if anti_vm_check:
            malware_severity += 20
        if peid_signatures:
            malware_severity += 30
        if architecture == "Unknown":
            malware_severity += 10

        print("\nMalware Severity Level:", malware_severity)
        if malware_severity > 50:
            print("This file is highly suspicious and may be malware.")
        elif malware_severity > 30:
            print("This file shows moderate indicators of being malware.")
        else:
            print("This file shows low indicators of being malware.")

    except Exception as e:
        print("Error analyzing the file:", e)

if __name__ == "__main__":
    file_path = input("Enter the path of the executable file to analyze: ")
    if os.path.exists(file_path) and os.path.isfile(file_path):
        analyze_exe(file_path)
    else:
        print("Invalid file path.")
