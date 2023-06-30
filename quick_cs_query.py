import pandas as pd
import re
import argparse
import os
import json
from urllib.parse import urlparse

OUTPUT_FILE = "cs_query.txt"
hash_list = list()
ipv4_list = list()
filename_list = list()
filepath_list = list()
domain_list = list()

# Remove neutralization ('[' and/or ']') of IOCs
def remove_neutralization(str):
    return str.replace('[', '').replace(']', '').strip()

# Validate IP. Subnets, ranges, and IPv6 are ignored.
def ip_cleanup(ip):
    if '/' in ip:
        return None
    if '-' in ip:
        return None
    if re.search(r'[a-zA-Z]+', ip):
        return None
    
    new_ip = remove_neutralization(ip)

    if re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", new_ip):
        return new_ip
    else:
        return None

# Extract IOCs from a json in STIX2 format
def extract_iocs_from_stix2_json(input_file):
    type_value_list = list()

    with open(input_file, "r") as read_file:
        data = json.load(read_file)
        for obj in data['objects']:
            if obj['type'] == 'indicator':
                ioc_type = obj['labels'][0].split("=")[1].replace("\"",'').replace("\\",'').strip()
                pattern = obj['pattern']
                type_value_list.append([ioc_type, pattern])

    for type_value in type_value_list:
        ioc_type=type_value[0]
        pattern=type_value[1]
        
        if "sha256" in ioc_type.lower():
            ioc_value = pattern.split('=')[1].strip().replace(']','').replace("'",'')

        elif "ip-dst" in ioc_type.lower():
            ioc_type = "ip"
            ioc_value = pattern.split('AND')[1].strip().replace(']','')
            ioc_value = ioc_value.split('=')[1].strip().replace("'",'')

        elif ioc_type.lower() in ("url", "hostname", "domain"):
            ioc_value = pattern.split('=')[1].strip().replace(']','').replace("'",'')

        else:
            continue        # other cases exist but are not handled yet

        validate_ioc(ioc_type,ioc_value)

# Extract IOCs from an excel file
def extract_iocs_from_excel(df):
    dict = df.to_dict()
    column_A=list(dict.keys())[0]
    column_B=list(dict.keys())[1]
    for key in dict[column_A]:
        ioc_type = dict[column_A][key]
        ioc_value = dict[column_B][key]
        validate_ioc(ioc_type, ioc_value)

# Validate accepted IOCs
def validate_ioc(ioc_type, ioc_value):
    if not isinstance(ioc_type, str) or not ioc_type:
        return
    if ioc_type.lower() in ("sha256", "file sha256"):
        if len(ioc_value.strip()) == 64:
            hash_list.append(ioc_value.strip())

    elif ioc_type.lower() in ("ip", "ipv4-addr", "ipv4"):
        new_ip = ip_cleanup(ioc_value)
        if new_ip:
            ipv4_list.append(new_ip)

    elif ioc_type.lower() in ("filename", "file name"):
        filename_list.append(ioc_value)

    elif ioc_type.lower() in ("directory", "filepath"):
        filepath = ioc_value.strip()
        filepath = filepath.replace('\\', '\\\\')
        filepath_list.append(filepath)

    elif ioc_type.lower() in ("domain", "dns", "domain-name", "hostname"):
        domain_list.append(remove_neutralization(ioc_value))

    elif ioc_type.lower() in ("url"):
        domain_from_url = urlparse(ioc_value).netloc
        domain_list.append(remove_neutralization(domain_from_url))


# (1) PARSE COMMAND LINE ARGUMENTS
parser = argparse.ArgumentParser()
parser.add_argument("-f", '--file', type=str, help="file.xlsx, file.csv or file.json (in STIX2 format)", required=False)
parser.add_argument("-o", '--output', type=str, help="outputfile.txt", required=False)

args = parser.parse_args()
input_file = args.file
output_file = args.output


# (2) OPEN FILE AND EXTRACT IOCS
print("[*] Processing... ")
if input_file:
    if input_file.endswith('.xlsx'):
        df = pd.read_excel(input_file, usecols='A, B')
        extract_iocs_from_excel(df)


    elif input_file.endswith('.csv'):
        read_file = pd.read_csv(input_file, sep=';')
        read_file.to_excel(input_file + '.xlsx', index=None, header=True)
        df = pd.read_excel(input_file + '.xlsx', usecols='A, B')
        os.remove(input_file + '.xlsx')
        extract_iocs_from_excel(df)

    elif input_file.endswith('.json'):
        extract_iocs_from_stix2_json(input_file)
        
else:
    df = pd.read_excel("Book1.xlsx", usecols='A, B')
    extract_iocs_from_excel(df)

    
# (3) CONSTRUCT CS SUBQUERIES
all_subqueries_list = list()

if ipv4_list:
    ipv4_query = "( "
    ipv4_query += "event_simpleName=NetworkConnectIP4 AND (\n"
    for ip in ipv4_list[:-1]:
        ipv4_query += "RemoteAddressIP4=" + ip
        ipv4_query += " OR \n"
    ipv4_query += "RemoteAddressIP4=" + ipv4_list[-1] + ") )"

    all_subqueries_list.append(ipv4_query)

if filename_list:
    filename_query = "( "
    for name in filename_list[:-1]:
        filename_query += "(FileName=\"*{}*\" OR ImageFileName=\"*{}*\" OR CommandLine=\"*{}*\" OR OriginalFilename=\"*{}*\")".format(name, name, name, name)
        filename_query += " OR \n"
    filename_query += "(FileName=\"*{}*\" OR ImageFileName=\"*{}*\" OR CommandLine=\"*{}*\" OR OriginalFilename=\"*{}*\")".format(filename_list[-1], filename_list[-1], filename_list[-1], filename_list[-1])
    filename_query += " )"

    all_subqueries_list.append(filename_query)

if filepath_list:
    filepath_query = "( event_platform=Win AND (\n"
    for path in filepath_list[:-1]:
        filepath_query += "(FilePath=\"*{}*\" OR ImageFileName=\"*{}*\")".format(path, path)
        filepath_query += " OR \n"
    filepath_query += "(FilePath=\"*{}*\" OR ImageFileName=\"*{}*\")".format(filepath_list[-1], filepath_list[-1])
    filepath_query += " ) )"
    
    all_subqueries_list.append(filepath_query)

if domain_list:
    domain_list = list(dict.fromkeys(domain_list))
    domain_query = "( "
    domain_query += "event_simpleName=*DnsRequest AND (\n"
    for domain in domain_list[:-1]:
        domain_query += "DomainName=*{}*".format(domain)
        domain_query += " OR \n"
    domain_query += "DomainName=*{}*".format(domain_list[-1]) + ") )"

    all_subqueries_list.append(domain_query)

if hash_list:
    hash_query = "( (event_simpleName=ImageHash* OR event_simpleName=*ProcessRollup*) AND (\n"
    for hash in hash_list[:-1]:
        hash_query += "SHA256HashData=" + hash
        hash_query += " OR \n"
    hash_query += "SHA256HashData=" + hash_list[-1] + ") )"

    all_subqueries_list.append(hash_query)


# (4) CONSTRUCT CS FINAL QUERY
full_query = ""
if all_subqueries_list:
    for subquery in all_subqueries_list[:-1]:
        full_query += subquery
        full_query += "\n OR \n"
    full_query += all_subqueries_list[-1]


# (5) OUTPUT THE RESULT
if not full_query:
    print("[*] No query was created. Exiting")
    exit()

if output_file:
    file = open(output_file, "w")
else:
    file = open(OUTPUT_FILE, "w")
file.write(full_query)
file.close()

if output_file:
    print("[*] Done. Check: " + output_file)
else:
    print("[*] Done. Check: " + OUTPUT_FILE)
