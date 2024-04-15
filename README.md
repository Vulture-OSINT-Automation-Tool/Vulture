# Vulture
OSINT Automation Tool

Vulture is built to help automate the task of locating different Open-Source Intellegence information on the internet and displaying it back to the user. Our vision is to empower individuals, particularly pentesters, with a versatile and user-friendly platform that simplifies the collection, analysis, and utilization of open-source information. 

## Usage
Install requirements
```
pip install -r requirements.txt
```

Running the application
```
python3 vulture.py -D <domain> [OPTIONS]
```

## Modules
### Dehashed `-d`
This module is ran by adding the `-d` switch when being run. This will make a request to the Dehashed API which will return with data breaches associated with the target. This will include emails and passwords that have been leaked. 

This module requires an account with [Dehashed](dehashed.com). This account will need an active subscription and API uses to run. Input your API key and account email into the variables in the Vulture code. 

### Google Dorking `-g`
Google Dorking is enabled using the -g switch. This feature prompts users to select their preferred types of dorks, offering choices such as File Types, Login Pages, and Directory Enumeration. Once a selection is made, the program performs tailored Google Dorks based on the specified parameters. It sifts through the results and compiles all URLs that meet the user's criteria into a text file for subsequent use.

This is a brute-force style program that will eventually alert Google bot detection. If detection is alerted, you must wait for a lockout cooldown or change IP. 

### Whois `-w`
The whois module is ran by addint the `-w` switch. This module will gather information on the domain and its registration. This option will also ask if you are interested in querying the reputation of the domain which will check to see if theres known issues with the domain. It will then ask if you want to check how much domain registration history there is. 

This module requires you to install the requirements.txt and an account with [whoismxlapi](www.whoisxmlapi.com). Get your whois API key and imput it into the whois variable in Vulture at the top. 

### Hunter.io `-h`
The Hunter.io module will run with the `-h` option. It will make a request to the Hunter.io API to gather information including company information, email format, social medias, and potential technologies used. 

This module requires an account with [Hunter.io](hunter.io). Create an API key for your account and input it into the Hunter.io API key variable in Vulture. 

### PassForge.py
PassForage is a scipt that allows the user to create a list of words that could potentially be used to password spray and identify any weak credentials. 
