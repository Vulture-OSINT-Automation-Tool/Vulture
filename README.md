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

### Whois `-w`

### Hunter.io `-h`
The Hunter.io module will run with the `-h` option. It will make a request to the Hunter.io API to gather information including company information, email format, social medias, and potential technologies used. 

This module requires an account with [Hunter.io](hunter.io). Create an API key for your account and input it into the Hunter.io API key variable in Vulture. 

### PassForge.py
