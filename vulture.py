#!/bin/python3
import requests
import click
import json
import sys
import os


global hunter_key, dehashed_cred_key, dehashed_key

# Place Keys here
hunter_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' # Hunter.io API Key
dehashed_cred_key = 'XXXXXXXXXXXXXXXXXXXXXXXXX' # Dehashed email
dehashed_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' # Dehashed API Key


@click.command()
@click.option('-D', '--domain', default=None, help='Specify the domain to enumerate credentials.')
# @click.option('-d/-no-d', default=False, help='Enumerate dehased API to enumerate for breached credentials.')
# @click.option('-g/-no-g', default=False, help='Enumerate Google for accessable documents.')
# @click.option('-l/-no-l', default=False, help='Enumerate LinkedIn to for employees of company.')
# @click.option('-p/-no-p', default=False, help='Create password list based on organization.')
@click.option('--raw/--no-raw', default=False, help="Print the raw JSON information from the API's.")

def main(domain, raw):
    if domain:
        print("Domain set: " + domain)
        domain_dehash(domain, raw)
    else:
        print('Error: No domain specified.')
        print('Usage: ./vulture.py [OPTIONS]')
        print("Try './vulture.py --help' for help.")
        sys.exit()

''' later additions
def main(domain, dehashed, pwned)
    if (dehashed and pwned):
        print('Error: Dehased and Pwned are excluse to eachother')
        print('Usage: vulture.py [OPTIONS]')
        print("Try 'vulture.py --help' for help.")
        sys.exit()
    elif (target and domain):
        print('Error: Target and Domain are exclusive to eachother.')
        print('Usage: vulture.py [OPTIONS]')
        print("Try 'vulture.py --help' for help.")
        sys.exit()
    elif (target and dehashed):
        print("Running dehashed against Target...")
        print("Target set: " + target)
        target_dehashed(target)
    elif (target and pwned):
        print("Running have i been pwned against Target...")
        print("Target set: " + target)
        target_pwned(target)
    elif (domain and dehashed):
        print("Running deahsed against Domain...")
        print("Domain set: " + domain)
        domain_dehashed(domain)
    elif (domain and pwned):
        print("Running have i been pwned against Domain...")
        print("Domain set: " + domain)
        domain_pwned(domain)
    elif (target == None and domain == None):
        print('Error: Either domain or target should be set so there is something to search.')
        print('Usage: vulture.py [OPTIONS]')
        print("Try 'vulture.py --help' for help.")
        sys.exit()
    elif (dehashed == None and pwned == None):
        print('Error: Either dehashed or pwned should be set so you can search with one.')
        print('Usage: vulture.py [OPTIONS]')
        print("Try 'vulture.py --help' for help.")
        sys.exit()
'''


#-------------------------------- File IO --------------------------------------#

#Saves files to domain directory and creates directory if needed.
def save_file_to_directory(directory_name, file_name, content):
        current_directory = os.path.dirname(os.path.abspath(__file__))
        dir_path = os.path.join(current_directory, directory_name)

        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path)
                print(f"Directory {directory_name} created.")
            except OSError as e:
                print(f"Failed to create directory {directory_name}: {e}")
                return
    
        file_path = os.path.join(dir_path, file_name)
        try:
            with open(file_path, 'w') as file:
                if "raw_json" in file_name:
                    file.write(content)
                elif "dehash" in file_name:
                    file.write(dehash_to_plaintext(content))
                elif "hunter" in file_name:
                    file.write(hunter_to_plaintext(content))
                else:
                    print(f"Filename {file_name} incorrect format.")
                file.close()
            print(f"File '{file_name}' saved successfully.")
        except IOError as e:
            print(f"Failed to save the file '{file_name}': {e}")



#------------------- String and JSON Manipulation Functions --------------------#

#Removes empty JSON values
def remove_empty_dehashed_values(json_data):
    response_dict = json.loads(json_data)
    entries = response_dict.get("entries", [])
    cleaned_entries = []
    
    for item in entries:
        cleaned_item = {key: value for key, value in item.items() if value is not None and value != ""}
        cleaned_entries.append(cleaned_item)

    response_dict["entries"] = cleaned_entries
    return json.dumps(response_dict)

# reformat to json, better viewing
def format_json_indents(json_data):
    data_dict = json.loads(json_data)
    formatted_results = json.dumps(data_dict, indent=4)
    return formatted_results

# This fixes the weird json string that hunter.io responds with and removes and rogue double quotes that would break the JSON formatting
def fix_hunter_json_string(json_data_str):
    result = ""
    previous_quote = False
    second_quote = False

    for char in json_data_str:
        if char == '"' or char == "'":
            if second_quote:
                previous_quote = True
            else:
                result += char
                second_quote = True
        elif previous_quote and second_quote and (char == ',' or char == '}' or char == ":" or char == "]"):
            result += '"'
            result += char
            previous_quote = False
            second_quote = False
        else:
            result += char
            previous_quote = False
    #fixed_json_data_str = json_data_str.replace("'", '"').replace(": True", ': "true"').replace(": False", ': "false"').replace(": None", ': ""') #This has a bug lol
    return result

#Converts Dehashed JSON data strings into a clean plaintext format.
def dehash_to_plaintext(dehash_data):
    data = json.loads(dehash_data)

    # Extract balance
    balance = data["balance"]

    # Extract entries
    entries = data["entries"]

    # Generate plain text
    plain_text = f"Balance: {balance}\n\nEntries:\n"

    for idx, entry in enumerate(entries, start=1):
        plain_text += f"{idx}. ID: {entry['id']}\n"
        plain_text += f"   Email: \"{entry['email']}\"\n" if entry['email'] else ""
        plain_text += f"   IP Address: \"{entry['ip_address']}\"\n" if entry['ip_address'] else ""
        plain_text += f"   Username: \"{entry['username']}\"\n" if entry['username'] else ""
        plain_text += f"   Password: \"{entry['password']}\"\n" if entry['password'] else ""
        plain_text += f"   Hashed Password: \"{entry['hashed_password']}\"\n" if entry['hashed_password'] else ""
        plain_text += f"   Name: \"{entry['name']}\"\n" if entry['name'] else ""
        plain_text += f"   VIN: \"{entry['vin']}\"\n" if entry['vin'] else ""
        plain_text += f"   Address: \"{entry['address']}\"\n" if entry['address'] else ""
        plain_text += f"   Phone: \"{entry['phone']}\"\n" if entry['phone'] else ""
        plain_text += f"   Database Name: \"{entry['database_name']}\"\n" if entry['database_name'] else ""
        plain_text += f"\n"
    return plain_text

#Convert Hunter JSON data strings into a clean plaintext format
def hunter_to_plaintext(json_data):
    data = json.loads(json_data)

    formatted_text = f"""
Company Information:
---------------------
Domain: {data['data']['domain']}
Disposable: {data['data']['disposable']}
Webmail: {data['data']['webmail']}
Accept All Emails: {data['data']['accept_all']}
Pattern: {data['data']['pattern']}
Organization: {data['data']['organization']}
Description: {data['data']['description']}
Twitter: {data['data']['twitter']}
Facebook: {data['data']['facebook']}
LinkedIn: {data['data']['linkedin']}
Instagram: {data['data']['instagram']}
YouTube: {data['data']['youtube']}

Technologies Used:
-------------------
"""
    formatted_text += "- " + "\n- ".join(data['data']['technologies'])
    formatted_text += f"""

Location:
----------
Country: {data['data']['country']}
State: {data['data']['state']}
City: {data['data']['city']}
Postal Code: {data['data']['postal_code']}
Street: {data['data']['street']}

Email Contacts:
----------------
"""
    for idx, email in enumerate(data['data']['emails'], 1):
        sources = "\n     - ".join([f"{source['domain']} (Extracted on {source['extracted_on']}, Still on Page)" for source in email["sources"]])
        formatted_text += f"{idx}. {email['first_name']} {email['last_name']}\n"
        formatted_text += f"   - Email: {email['value']}\n"
        formatted_text += f"   - Confidence: {email['confidence']}%\n"
        formatted_text += f"   - Sources:\n     - {sources}\n\n"
    return formatted_text



#--------------------------------- Domain Option -------------------------------#

# This will skip the domain enumeration with Hunter.io and only enumerate for credentials with the domain given
def domain_dehash(domain, raw):
    # This is being worked on
    global hunter_key, dehashed_cred_key, dehashed_key
       # Use the 'target' variable in your program logic
    
    # Hunter.io API
    def domain_information(company_domain):
        global hunter_key
        api_url = f"https://api.hunter.io/v2/domain-search?domain={company_domain}&api_key={hunter_key}"
        hunter_results = requests.get(api_url)
        hunter_data = hunter_results.json()
        
        # For debugging purposes
        #print(hunter_data)

        fixed_hunter_data = fix_hunter_json_string(json.dumps(hunter_data))

        # This doesnt need to be printed but should be sent to a file
        # print(format_json_indents(fixed_hunter_data))

        save_file_to_directory(domain, f"hunter.{company_domain}.txt", fixed_hunter_data)

        if raw == True:
            save_file_to_directory(domain, f"raw_json.hunter.{domain}.txt", json.dumps(hunter_data))
    
        return 
    
    # Dehashed API
    def dehashed_information(target_arg):
        global dehashed_cred_key, dehashed_key
        headers = {'Accept': 'application/json'}
        params = {
        'query': f'domain:{target_arg}',
        'size': 10000,  # Adjust the size as needed
        }
        dehashed_json = requests.get('https://api.dehashed.com/search',
            headers=headers,
            params=params,
            auth=(f'{dehashed_cred_key}', f'{dehashed_key}')).text

        # print(dehashed_json)

        if raw == True:
            save_file_to_directory(domain, f"raw_json.dehash.{domain}.txt", dehashed_json)
        
        return dehashed_json

    domain_information(domain)
    
    results = dehashed_information(domain)
    if results:
        # For debugging purposes
        # print(results)
    
        formatted_results = format_json_indents(results) 
        
        finished_results = remove_empty_dehashed_values(formatted_results)
    
        #print(format_json_indents(finished_results))

        save_file_to_directory(domain, f"dehash.{domain}.txt", results)
    
    else:
        print("No information found for the domain on dehashed.com.")
    
    return



if __name__ == '__main__':
    main()
