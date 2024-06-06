# Vulture
OSINT Automation Tool

Vulture is built to help automate the task of locating different Open-Source Intellegence information on the internet and displaying it back to the user. Our vision is to empower individuals, particularly pentesters, with a versatile and user-friendly platform that simplifies the collection, analysis, and utilization of open-source information. 

This tool focuses on gathering this information from a <ins>**passive perspective**</ins> not touching the targets technologies in the hope to remain stealthy and to not have the possibility of touching an out-of-scope technology in a penetration test. 

## Usage
### Install requirements
```
pip install -r requirements.txt
```

### Input API keys into `api_keys.py`

Links for API keys are mentioned below; you do not have to fill out the whole file, only the keys you plan on using. 

### Running the application
```
python3 vulture.py -D <domain> [OPTIONS]
```

## Modules
### Dehashed `-d`
This module is ran by adding the `-d` switch when being run. This will make a request to the Dehashed API which will return with data breaches associated with the target. This will include emails and passwords that have been leaked. 

This module requires an account with [Dehashed](https://dehashed.com). This account will need an active subscription and API uses to run. Input your API key and account email into the variables in `api_keys.py`. 

### Google Dorking `-g`
Google Dorking is enabled using the -g switch. This feature prompts users to select their preferred types of dorks, offering choices such as File Types, Login Pages, and Directory Enumeration. Once a selection is made, the program performs tailored Google Dorks based on the specified parameters. It sifts through the results and compiles all URLs that meet the user's criteria into a text file for subsequent use.

This is a brute-force style program that will eventually alert Google bot detection. If detection is alerted, you must wait for a lockout cooldown or change IP. 

We want to give credit to [Fast-Google-Dorks-Scan](https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan) for inspiration and aid in understanding how we could implement this tactic into our code.

### Whois `-w`
The whois module is ran by addint the `-w` switch. This module will gather information on the domain and its registration. This option will also ask if you are interested in querying the reputation of the domain which will check to see if theres known issues with the domain. It will then ask if you want to check how much domain registration history there is. 

This module requires you to install the requirements.txt and an account with [whoismxlapi](https://www.whoisxmlapi.com). Get your whois API key and imput it into the whois variable in `api_keys.py`. 

### Hunter.io `-h`
The Hunter.io module will run with the `-h` option. It will make a request to the Hunter.io API to gather information including company information, email format, social medias, and potential technologies used. 

This module requires an account with [Hunter.io](hunter.io). Create an API key for your account and input it into the Hunter.io API key variable in `api_keys.py`.


## Scripts
### PassForge.py
PassForage is a scipt that allows the user to create a list of words that could potentially be used to password spray and identify any weak credentials. 

### Credharvest.py
This script will take the input of the dehash result file from Vulture and grab the emails and passwords, remove duplicates, sort them, and display them in a format that is easy for the user to view credentials from the file. This will output to a file called `credentials.txt` for the user to view later when needed. 
