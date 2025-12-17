import pandas as pd
import re
import concurrent.futures
import os
import json
import yaml
import ipaddress
from io import StringIO
import requests

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/vnd.github.v3+json"
}

token = os.environ.get("GITHUB_TOKEN", "")
if token:
    HEADERS["Authorization"] = f"Bearer {token}"

# Mapping dictionary to unify different rule patterns into consistent keys.
MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix',
    'HOST-SUFFIX': 'domain_suffix',
    'host-suffix': 'domain_suffix',
    'DOMAIN': 'domain',
    'HOST': 'domain',
    'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword',
    'HOST-KEYWORD': 'domain_keyword',
    'host-keyword': 'domain_keyword',
    'IP-CIDR': 'ip_cidr',
    'ip-cidr': 'ip_cidr',
    'IP-CIDR6': 'ip_cidr',
    'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr',
    'GEOIP': 'geoip',
    'DST-PORT': 'port',
    'SRC-PORT': 'source_port',
    "URL-REGEX": "domain_regex",
    "DOMAIN-REGEX": "domain_regex"
}

def read_yaml_from_url(url):
    """
    Downloads a YAML file from a URL and returns the parsed YAML data.
    """
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    yaml_data = yaml.safe_load(response.text)
    return yaml_data

def read_list_from_url(url):
    """
    Downloads a .list file (or generic text/csv) from a URL and parses
    it into a DataFrame. Also handles special “AND” logical rules.
    """
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        return None

    csv_data = StringIO(response.text)
    df = pd.read_csv(
        csv_data,
        header=None,
        names=['pattern', 'address', 'other', 'other2', 'other3'],
        on_bad_lines='skip'
    )

    filtered_rows = []
    rules = []

    # Handle logical "AND" rules (ex: AND(DOMAIN,google.com)(IP-CIDR,1.2.3.4/24))
    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {
                "type": "logical",
                "mode": "and",
                "rules": []
            }
            # Convert row to a comma-separated string
            pattern = ",".join(row.values.astype(str))

            # Find all parenthetical blocks in the pattern
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                # Check if one of our MAP_DICT keys is in there
                for keyword in MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({
                                MAP_DICT[keyword]: value
                            })
            rules.append(rule)

    # Filter out rows containing "AND"
    for index, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules

def is_ipv4_or_ipv6(address):
    """
    Checks if a string is a valid IPv4 or IPv6 network (CIDR).
    Returns 'ipv4', 'ipv6', or None.
    """
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    """
    Given a link (.yaml, .txt, or .list), download and parse it into
    a DataFrame of rules. Also captures logical rules if present.
    """
    rules = []
    # Determine the file type based on extension
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            # If the loaded YAML is not a string, we expect a key 'payload'
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                # Fallback if the YAML data is actually just text
                lines = yaml_data.splitlines()
                line_content = lines[0] if lines else ''
                items = line_content.split()

            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            # Remove leading plus or dot
                            address = address.lstrip('+.')
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)

                # If there's still another comma, split again
                if ',' in address:
                    address = address.split(',', 1)[0]

                rows.append({
                    'pattern': pattern.strip(),
                    'address': address.strip(),
                    'other': None
                })
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        except:
            df, rules = read_list_from_url(link)
    else:
        df, rules = read_list_from_url(link)
    return df, rules

def sort_dict(obj):
    """
    Recursively sort the keys of dictionaries (and nested dicts/lists).
    Ensures a consistent ordering in the final JSON output.
    """
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_list_file(link, output_directory):
    """
    Main function to parse a single .list (or .yaml/.txt) file from a URL,
    generate a JSON structure, and optionally compile it to .srs.
    """
    try:
        # Parse in a thread (though we are only passing one link here)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(parse_and_convert_to_dataframe, [link]))
            # results is a list of (df, rules) tuples
            dfs = [df for df, rules in results]
            rules_list = [rules for df, rules in results]

            # Combine all dataframes
            df = pd.concat(dfs, ignore_index=True)

        # Remove lines with '#' in pattern and lines not in MAP_DICT
        df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        df = df.drop_duplicates().reset_index(drop=True)

        # Map the pattern to consistent keys (DOMAIN-SUFFIX -> domain_suffix, etc.)
        df['pattern'] = df['pattern'].replace(MAP_DICT)

        # Make sure output directory exists
        os.makedirs(output_directory, exist_ok=True)

        # Build the final JSON structure
        result_rules = {"version": 3, "rules": []}
        domain_entries = []
        domain_suffix_entries = []
        domain_keyword_entries = []
        domain_regex_entries = []
        ip_cidr_entries = []

        grouped_data = df.groupby('pattern')['address'].apply(list).to_dict()

        for pattern, addresses in grouped_data.items():
            if pattern == 'domain_suffix':
                domain_suffix_entries.extend([addr.strip() for addr in addresses])
            elif pattern == 'domain':
                domain_entries.extend([addr.strip() for addr in addresses])
            elif pattern == 'domain_keyword':
                domain_keyword_entries.extend([addr.strip() for addr in addresses])
            elif pattern == 'domain_regex':
                domain_regex_entries.extend([addr.strip() for addr in addresses])
            elif pattern == 'ip_cidr':
                ip_cidr_entries.extend([addr.strip() for addr in addresses])

        # Add entries in the right order
        if domain_entries:
            result_rules["rules"].insert(0, {'domain': list(set(domain_entries))})
        if domain_suffix_entries:
            result_rules["rules"].append({'domain_suffix': list(set(domain_suffix_entries))})
        if domain_keyword_entries:
            result_rules["rules"].append({'domain_keyword': list(set(domain_keyword_entries))})
        if domain_regex_entries:
            result_rules["rules"].append({'domain_regex': list(set(domain_regex_entries))})
        if ip_cidr_entries:
            result_rules["rules"].append({'ip_cidr': list(set(ip_cidr_entries))})

        # Sort and write the JSON
        file_basename = os.path.basename(link).split('.')[0]
        file_name = os.path.join(output_directory, f"{file_basename}.json")

        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)

        # Optionally compile to .srs with sing-box (requires sing-box to be installed)
        srs_path = file_name.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")

        return file_name
    except Exception as e:
        print(f'Error fetching link, skipped: {link} , reason: {str(e)}')
        return None

def get_list_files_from_github(owner, repo, path="rule/QuantumultX"):
    """
    Recursively fetch all *.list file links from a GitHub repository folder.
    """
    base_api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
    url = f"{base_api_url}/{path}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        print(f"Warning: Could not access {url} . HTTP {response.status_code}")
        return []

    contents = response.json()
    results = []

    for item in contents:
        if item["type"] == "dir":
            subdir_results = get_list_files_from_github(owner, repo, item["path"])
            results.extend(subdir_results)
        elif item["type"] == "file" and item["name"].endswith(".list"):
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{item['path']}"
            results.append(raw_url)

    return results

if __name__ == "__main__":
    owner = "proother"
    repo = "ios_rule_script"
    all_list_urls = get_list_files_from_github(owner, repo, path="rule/QuantumultX")
    
    print(f"Found {len(all_list_urls)} .list files in the repository.")

    output_dir = "./"
    result_file_names = []

    for link in all_list_urls:
        result_file_name = parse_list_file(link, output_directory=output_dir)
        if result_file_name:
            result_file_names.append(result_file_name)

    for file_name in result_file_names:
        print("Generated:", file_name)
