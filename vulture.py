#!/bin/python3
import requests
import click
import json
import sys
import os


global hunter_key, dehashed_cred_key, dehashed_key

# Place Keys here
hunter_key = '7b717fa472543170fd923a7c1d3a988ed3d33816' # Hunter.io API Key
dehashed_cred_key = 'ryanvoit@outlook.com' # Dehashed email
dehashed_key = 'uuibngiuc0kf9kcwgoc83jgj0ulsdprr' # Dehashed API Key


@click.command()
@click.option('-T', '--target', default=None, help='Specify your target to enumerate domain and credentials.')
@click.option('-D', '--domain', default=None, help='Specify the domain to enumerate credentials.')
# @click.option('--dehashed', default=None, help='Specify dehased API to enumerate for breached credentials.')
# @click.option('--pwned', default=None, help='Specify have i been pwned API to enumerate for breached accounts.')
# @click.option('--raw/--no-raw', default=False, help="Print the raw JSON information from the API's.")

def main(target, domain):
    if (target and domain):
        print('Error: Target and Domain are exclusive.')
        print('Usage: vulture.py [OPTIONS]')
        print("Try 'vulture.py --help' for help.")
        sys.exit()
    elif target:
        print("Target set: " + target)
        target_dehash(target)
    elif domain:
        print("Domain set: " + domain)
        domain_dehash(domain)
    else:
        print('Error: No target or domain specified.')
        print('Usage: Vulture.py [OPTIONS]')
        print("Try 'Vulture.py --help' for help.")
        sys.exit()


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
                if "dehash" in file_name:
                    file.write(content)
                elif "hunter" in file_name:
                    file.write("we are working on this. Sorry")
                    #file.write(content)
                else:
                    print(f"Filename {file_name} incorrect format.")
                file.close()
            print(f"File '{file_name}' saved successfully.")
        except IOError as e:
            print(f"Failed to save the file '{file_name}': {e}")


#-------------------------------- Target Option -------------------------------#

# Target 
# Starts with searching for a domain of the company specified with Hunter.io then will move into enumerating for credentials
def target_dehash(target):
    global hunter_key, dehashed_cred_key, dehashed_key
       # Use the 'target' variable in your program logic


    #------------- API Calls ------------#

    # Hunter.io API
    def fetch_company_domain(company_name):
        global hunter_key
        api_url = f"https://api.hunter.io/v2/domain-search?company={company_name}&api_key={hunter_key}"
        hunter_results = requests.get(api_url)
        hunter_data = hunter_results.json()
        
        print(hunter_data)

        domain = hunter_data['data']['domain']

        save_file_to_directory(company_name, f"hunter.{domain}.txt", hunter_data)
    
        return domain
    
    # Dehashed API
    def dehashed_information(target_arg):
        global dehashed_cred_key, dehashed_key
        headers = {'Accept': 'application/json'}
        params = (('query', f'domain:{target_arg}'),)
        
        dehashed_json = requests.get('https://api.dehashed.com/search',
            headers=headers,
            params=params,
            auth=(f'{dehashed_cred_key}', f'{dehashed_key}')).text

        
        return dehashed_json
    
    domain = fetch_company_domain(target)
    if domain:
        print("Domain: ", domain)
    
    else:
        print("No domain found for the company domain on Hunter.io.")
        sys.exit()
    
    results = dehashed_information(domain)
    if results:
        # For debugging purposes
        # print(results)
    
            # reformat to json, better viewing
        data_dict = json.loads(results)
        formatted_results = json.dumps(data_dict, indent=4)

        print(formatted_results)

        save_file_to_directory(target, f"dehash.{domain}.txt", formatted_results)
    
    
    else:
        print("No information found for the domain on dehashed.com.")
    
    return


#--------------------------------- Domain Option -------------------------------#

# This will skip the domain enumeration with Hunter.io and only enumerate for credentials with the domain given
def domain_dehash(domain):
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

        print(hunter_data)

        save_file_to_directory(domain, f"hunter.{company_domain}.txt", hunter_data)

        return 
    
    # Dehashed API
    def dehashed_information(target_arg):
        global dehashed_cred_key, dehashed_key
        headers = {'Accept': 'application/json'}
        params = (('query', f'domain:{target_arg}'),)
        
        dehashed_json = requests.get('https://api.dehashed.com/search',
            headers=headers,
            params=params,
            auth=(f'{dehashed_cred_key}', f'{dehashed_key}')).text

        #print(dehashed_json)
        
        return dehashed_json

    domain_information(domain)
    
    results = dehashed_information(domain)
    if results:
        # For debugging purposes
        # print(results)
        

        data_dict = json.loads(results)
        formatted_results = json.dumps(data_dict, indent=4)

        print(formatted_results)

        save_file_to_directory(domain, f"dehash.{domain}.txt", formatted_results)
    
    else:
        print("No information found for the domain on dehashed.com.")
    
    return



if __name__ == '__main__':
    main()
