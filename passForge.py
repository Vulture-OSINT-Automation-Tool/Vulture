import argparse
import datetime
import os
import re
import time

# Author Andre Richard aka 0ffDre
# PassForge the Automatic & Manuel Password Generator - under the Vulture OSINT Tool Belt

def forgeMonths(outputMonthsList):
    currentMonth = datetime.datetime.now().month
    months = [
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december"
    ]

    currentMonthName = months[currentMonth - 1]
    outputMonthsList.append(currentMonthName)

    for i in range(1, 6):
        currentMonthIndex = (currentMonth + i - 1) % 6
        outputMonthsList.append(months[currentMonthIndex])
    return outputMonthsList

def forgeSeasons(outputSeasonsList):
    seasons = {
        'winter': ['12', '1', '2'],
        'spring': ['3', '4', '5'],
        'summer': ['6', '7', '8'],
        'fall': ['9', '10', '11']
    }

    currentMonth = datetime.datetime.now().month

    for season, months in seasons.items():
        if str(currentMonth) in months:
            currentSeason = season
            break

    if currentSeason:
        seasonOrder = list(seasons.keys())
        currentSeasonIndex = seasonOrder.index(currentSeason)
        orderedSeasons = seasonOrder[currentSeasonIndex:] + seasonOrder[:currentSeasonIndex]
        outputSeasonsList.extend(orderedSeasons)

    return outputSeasonsList

def addCustomWordsToWordList(wordList):
    customWords = input("Enter custom words separated by spaces: ")
    words = customWords.lower().split()
    wordList.extend(words)
    print("Custom words have been added to the word list:")
    print(wordList)

def addCommonPasswords(passwordList):
    common = [
    "123456", "password", "12345", "123456789", "qwerty", "1234", "qwerty123", "1q2w3e", "111111", "12345678",
    "info", "DEFAULT", "1q2w3e4r5t", "Password", "1234567", "123", "infoinfo", "123123", "1234567890", "welcome",
    "abc123", "123321", "654321", "000000", "qwe123", "7777777", "test", "password1", "1q2w3e4r", "666666", 
    "Switzerland", "1111", "555555", "aaaaaa", "asdfgh", "qwertyuiop", "test123", "11111111", "222222", "1111111",
    "1qaz2wsx", "qazwsx", "SKIFFY", "11111", "123qwe", "Willkommen", "temppass", "112233", "121212", "777777"
]
    passwordList.extend(common)

def importHunterFile(inputList, hunterFile):
    currentYear = datetime.datetime.now().year
    # Hunter Information
    try:
        with open(hunterFile, 'r') as file:
            fileContent = file.read()

            # Extract domain using regex
            domain_match = re.search(r"Domain: ([^.]+)", fileContent)
            if domain_match:
                domain = domain_match.group(1).strip().lower()
                inputList.extend([domain])

            # Extract location using regex
            location_match = re.search(r"Location:[\s\S]*?Country: ([^\n]+)\nState: ([^\n]+)\nCity: ([^\n]+)", fileContent)
            if location_match:
                country = location_match.group(1).strip().lower()
                state = location_match.group(2).strip().lower()
                city = location_match.group(3).strip().lower()
                inputList.extend([
                    country, state, city    
                ])
    except FileNotFoundError:
        print("Hunter file not found.")

def generatePreMadePasswordList(inputList):
    currentYear = datetime.datetime.now().year

    # Seasons
    seasons = ["spring", "summer", "fall", "winter"]
    for season in seasons:
        inputList.extend([
            season, season.capitalize(),
            season + str(currentYear), season.capitalize() + str(currentYear),
            season + "!", season.capitalize() + "!",
            season + str(currentYear) + "!", season.capitalize() + str(currentYear) + "!"
        ])

    # Months
    months = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"]
    for month in months:
        inputList.extend([
            month, month.capitalize(),
            month + str(currentYear), month.capitalize() + str(currentYear),
            month + "!", month.capitalize() + "!",
            month + str(currentYear) + "!", month.capitalize() + str(currentYear) + "!"
        ])

def writeListToFile(outputList, filename):
    with open(filename, 'w') as file:
        for item in outputList:
            if isinstance(item, list):
                file.write(' '.join(item) + '\n')
            else:
                file.write(str(item) + '\n')        

def clearScreen():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')

def viewLists(wordList, passwordList):
    while True:
        clearScreen()
        print("    Vulture - List Options")
        print("-----------------------------------------")
        print("\nList Options:")
        print(" 1) List Wordlist")
        print(" 2) List Passwordlist")
        print(" 0) Return to main menu......")

        choice = input("\nEnter your choice to list the desired option: ")

        if choice == '1':
            print("\nWordlist:")
            for word in wordList:
                print(word)
            input("\nPress Enter to continue...")
        elif choice == '2':
            print("\nPasswordlist:")
            for password in passwordList:
                print(password)
            input("\nPress Enter to continue...")
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please try again.")
            input("\nPress Enter to continue...")

def addWordsToPasswordList(wordList, passwordList):
    unique_words = set(wordList) - set(passwordList)
    passwordList.extend(unique_words)
    print("Unique words have been added to the password list.")
    input("Press Enter to continue...")

def passForgePasswordMenu(wordList, passwordList):
    while True:
        clearScreen()
        print(" Vulture - PassForge Customization")
        print("-----------------------------------------")
        print("\nPassword Customization Options:")
        print("1) Add custom char to the start of each word")
        print("2) Add custom char to the end of each word")
        print("3) View lists")
        print("0) Return to main menu......")

        choice = input("\nEnter your choice to customize your password: ")

        if choice == '1':
            custom_char = input("Enter a single custom char to add to the start of each word: ")
            if custom_char:
                for word in wordList:
                    passwordList.append(custom_char + word)
                print("Custom char was added to the start of each word in the word list")
            else:
                print("No custom char provided. Nothing added.")
            input("Press Enter to continue...")
        elif choice == '2':
            custom_char = input("Enter a single custom char to add to the end of each word: ")
            if custom_char:
                for word in wordList:
                    passwordList.append(word + custom_char)
                print("Custom char was added to the end of each word in the word list")
            else:
                print("No custom char provided. Nothing added.")
            input("Press Enter to continue...")
        elif choice == '3':
            viewLists(wordList, passwordList)
        elif choice == '0':
            clearScreen()
            print("Returning to the Password Forge Menu.")
            break
        else:
            print("Invalid choice. Please try again.")  
            input("Press Enter to continue...")
    return passwordList

def saveLists(wordList, passwordList):
    
    # Take every word in wordlist and put 
    # them into passwordlist
    for word in wordList:
        passwordList.append(word)
    
    # Take passwordlist and add capitalized versions 
    # of every password in passwordlist
    for password in passwordList[:]:  # Iterate over a copy of the list
        passwordList.append(password.capitalize())

    print("Congrats: Would you like to save your new Forge Password list? (Y/n)")
    outputChoice = input().strip().lower()
    if outputChoice == 'y':
        customFilename = input("\nEnter a custom filename (or press Enter to use 'passForgeManuelList'): ").strip()
        if customFilename:
            filename = customFilename
            outputList = passwordList
            writeListToFile(outputList, filename)
            print(f"Lists have been saved to '{filename}'")
            print("Exiting PassForge.......")
        else:
            filename = 'passForgeManuelList'
            outputList = passwordList
            
            # add common passwords to outputlist
            addCommonPasswords(passwordList)

            # write outputlist to filename
            writeListToFile(outputList, filename)
            print(f"Lists have been saved to '{filename}'.")
            print("Exiting PassForge.......")
    else:
        print("Exiting PassForge.......")


def passForgeManualMenu():
    
    # Adds a check mark to show what user has already added to wordlist
    visited = {
        '1': False,
        '2': False,
        '4': False,
    }
    
    # Initialize lists
    wordList = []
    passwordList = []

    while True:
        clearScreen()
        print("    Vulture - PassForge Main Menu")
        print("-------------------------------------")
        print("\nGenerate Wordlist Options:")
        print(" 1) Use Current Seasons")
        print(" 2) Use Current Months")
        print(" 3) Add Custom Words")
        print(" 4) Import your Hunter.io Information")
        print(" 5) Passwords Generator (!, @, 2020, 2023!)")
        print(" 6) View Lists")
        print(" 0) EXIT......")

        choice = input("\nEnter your choice to customize your forging: ")

        if choice == '1':
            if not visited['1']:
                forgeSeasons(wordList)
                print("Words based on seasons have been added to the list.")
                visited['1'] = True
                input("Press Enter to continue...")
            else:
                print("Option 1 has already been selected. Please choose another option.")
                input("Press Enter to continue...")
        elif choice == '2':
            if not visited['2']:
                forgeMonths(wordList)
                print("Words based on months have been added to the list.")
                visited['2'] = True
                input("Press Enter to continue...")
            else:
                print("Option 2 has already been selected. Please choose another option.")
                input("Press Enter to continue...")
        elif choice == '3':
            addCustomWordsToWordList(wordList)
            input("Press Enter to continue...")
        elif choice == '4':
            if not visited['4']:
                # Ask user for the text file
                hunterFile = input("Please enter the name/path of the *hunter.io* file:")
                if hunterFile:
                    importHunterFile(wordList, hunterFile)
                    print("Your hunter information has been added to your word list.")
                    input("Press Enter to continue...")
                    visited['4'] = True
                else: 
                    print("You did not import a correct File to be analyzed.")
                    input("Press Enter to continue...")

            else:
                print("Option 4 has already been selected. Please choose another option.")
                input("Press Enter to continue...")
        elif choice == '5':
            if wordList:
                passwordList = passForgePasswordMenu(wordList, passwordList)
            else:
                print("Please add words to your word list before customizing your passwords.")
                input("Press Enter to continue...")
        elif choice == '6':
            viewLists(wordList, passwordList)    
        elif choice == '0':
            # Add orignal wordlist back into passwordlist
            if wordList and not passwordList: 
                print("Error: You only have values in your wordlist")
                print("Would you like to go back to the main menu? Y/n")
                outputChoice = input().strip().lower()
                if outputChoice == 'y':
                    mainMenu()
                else:
                    print("Exiting PassForge.......")
            elif wordList and passwordList:
                saveLists(wordList, passwordList)
            break
        else:
            print("Invalid choice. Please try again.")  
            input("Press Enter to continue...")

def passForgeAutomaticMode():
    clearScreen()
    print("      Welcome to Auto PassForge")
    print("  Your Automatic Password Generator")
    print("-------------------------------------")

    # Ask user for the text file
    hunterFile = input("Please enter the name/path of the *hunter.io* file:")
    
    # Initialize password list
    autoPasswordList = []
    
    # Add seasons and months
    generatePreMadePasswordList(autoPasswordList)

    # Import Hunter Information
    importHunterFile(autoPasswordList, hunterFile)
    
    # Add common passwords
    addCommonPasswords(autoPasswordList)   
        
    # Write password list to a file
    writeListToFile(autoPasswordList, f"{hunterFile}_PassForgeAutoList")
    print(f"Password list has been saved to {hunterFile}")
    input("Press Enter to Exit......")

def mainMenuGUI():
    while True:
        clearScreen()
        print("    Vulture - PassForge Main Menu")
        print("---------------------------------")
        print("\nChoose a Mode:")
        print(" 1) Automatic Mode")
        print(" 2) Manual Mode")
        print(" 0) EXIT......")

        choice = input("\nEnter your choice: ")

        if choice == '1':
            passForgeAutomaticMode()
        elif choice == '2':
            passForgeManualMenu()
        elif choice == '0':
            print("Exiting PassForge.......")
            break
        else:
            print("Invalid choice. Please Try Again.")  
            input("Press Enter to continue...")
        
def mainMenu():
    clearScreen()
    parser = argparse.ArgumentParser(description="Vulture - PassForge Help Menu", 
                                     usage=argparse.SUPPRESS, 
                                     )
    parser.add_argument("-a", "--automatic", action="store_true", help="Automatic Mode")
    parser.add_argument("-m", "--manual", action="store_true", help="Manual Mode")
    parser.add_argument("-ab", "--about", action="store_true", help="About")
    parser.add_argument("-v", "--vulture", action="store_true", help=argparse.SUPPRESS)
    
    args = parser.parse_args()

    if args.automatic:
        passForgeAutomaticMode()
    elif args.manual:
        passForgeManualMenu()
    elif args.about:
        print('''
------------------------------------------------------
|                                                    |
|  This is your Password Generator, with two         |
|  different modes to offer automation for password  |
|  spraying attacks.                                 |
|                                                    |
|  PassForge is tailored to pentesters,              |
|  leveraging OSINT data from Vulture.               |
|                                                    |
|  With two modes: Automatic [-a] and Manual [-v].   |
|                                                    |
------------------------------------------------------
''')
    elif args.vulture:
     displayArt()
    else:
        print("Invalid choice. Please try again.") 
        print("Please specify a domain: [-h], [-a], [-m]")
        print("python3 passForge.py [domain]") 
        print("[-h] = Help Page") 
        print("[-a] = Automatic Mode")
        print("[-m] = Manuel Mode")  


def displayArt():
    # Define the ASCII art images
    art1='''

 _     _         _                                         ______                     _______                         
| |   | |       | |   _                                   (_____ \                   (_______)                        
| |   | | _   _ | | _| |_  _   _   ____  _____    _____    _____) )_____   ___   ___  _____  ___    ____  ____  _____ 
| |   | || | | || |(_   _)| | | | / ___)| ___ |  (_____)  |  ____/(____ | /___) /___)|  ___)/ _ \  / ___)/ _  || ___ |
 \ \ / / | |_| || |  | |_ | |_| || |    | ____|           | |     / ___ ||___ ||___ || |   | |_| || |   ( (_| || ____|
  \___/  |____/  \_)  \__)|____/ |_|    |_____)           |_|     \_____|(___/ (___/ |_|    \___/ |_|    \___ ||_____)
                                                                                                        (_____|       
                                                                                                                                                     

                  @@@%=                                                         
                   *@@@@@@%*                                                    
                     @@@@@@@@@*                                                 
                      *@@@@@@@@@+                                 @@            
                        %@@@@@@@@@           @@                 @@@@            
                         =@@@@@@@@@+         @@     @        #@@@@@             
                        *@@@@@@@@@@@@        @@    @@      @@@@@@               
                      +@@@@@@@@@@@@@@@*      @@   @@     @@@@@@@                
                    %@@@@@@@@@@@@@@@@@@@=    @@   @@   #@@@@@@@@                
                  #@@@@@@@@@@@@ @@@@@@@@@%   @@  @@  +@@@@@@@@@@                 
                @@@@@@@@@@@@@    =@@@@@@@@@+   @@ @@@@@@@@@@@@@                 
             =@@@@@@@@@@@@+        #@@@@@@@#    @@@@@@@@@@@@@@@                 
           +@@@@@@@@@@@@%   @@@@     @@@@#   *@@@@@@@@@@@@@@@@@@                
         *@@@@@@@@@@@@=        @@@@@@ --   @@@@@@@@@@@@@@@@@@@@@@@              
       =@@@@@@@@@@@@=              @@@    @@@@@@@@@@@@@@@@@@@@@@@@@@@%-:-#+     
     #@@@@@@@@@@@@+                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%    
    @@@@@@@@@@@@         @@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#      
     =@@@@@@@@                     %@@@@@@@@@@@@@    %@@@@@@@@@@@@@@@@@         
       %@@@*                     *@@@@@@@@@@@%         :@@@@@@@@@@@@@           
        -*                     @@@@@@@@@@@@             @@@@@@@@@@@             
                             @@@@@@@@@@=                @@@@@@@@*               
                            #@@@@@@                     @@@@@@                  
                                                       @@@@@                    
                                                       #@%                      
                                                            '''
    art2='''

 _     _         _                                         ______                     _______                         
| |   | |       | |   _                                   (_____ \                   (_______)                        
| |   | | _   _ | | _| |_  _   _   ____  _____    _____    _____) )_____   ___   ___  _____  ___    ____  ____  _____ 
| |   | || | | || |(_   _)| | | | / ___)| ___ |  (_____)  |  ____/(____ | /___) /___)|  ___)/ _ \  / ___)/ _  || ___ |
 \ \ / / | |_| || |  | |_ | |_| || |    | ____|           | |     / ___ ||___ ||___ || |   | |_| || |   ( (_| || ____|
  \___/  |____/  \_)  \__)|____/ |_|    |_____)           |_|     \_____|(___/ (___/ |_|    \___/ |_|    \___ ||_____)
                                                                                                        (_____|       
                                                                                
              *+*++++=+==+======= =                              %@            
           +%@@@@@@@@@@@@@@@@@@@@@@@%                           %@@@            
       +#@@@@@@@@@@@@@@@@@@@@@@@@@@@%                        *@@@@#             
    #%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                      %@@@@%               
   ##*#*#*********@@@@@@@%**#*******+                    %@@@@@@                
                 *@@@@@@@#                            *@@@@@@@@*                
                 *@@@@@@@#                          +@@@@@@@@@@                 
                 *@@@@@@@#                        %@@@@@@@@@@@%                 
                 *@@@@@@@#                      %@@@@@@@@@@@@@@                 
                 *@@@@@@@#                   *@@@@@@@@@@@@@@@@@%                
                 *@@@@@@@*                 #@@@@@@@@@@@@@@@@@@@@@#              
                 #@@@@@@@*                @@@@@@@@@@@@@@@@@@@@@@@@@@@#===*+     
                 #@@@@@@@*              #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#    
                 #@@@@@@@#            %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*      
                 #@@@@@@@#         #@@@@@@@@@@@@#    #@@@@@@@@@@@@@@@@%         
                 #@@@@@@@#       *@@@@@@@@@@@#         =@@@@@@@@@@@@#           
                 %@@@@@@@#     %@@@@@@@@@@%             #@@@@@@@@@#             
                 #@@@@@@@*   %@@@@@@@@%                #@@@@@@@*               
                 *@@@@@@@*  #@@@@@@                    @@@@@%                  
                 #@@@@@@@*                             @@@@%                    
                 #*******+                             *@#                      
                                                                                
                                                               '''
    for _ in range(4):
        clearScreen()  # Clear the screen
        print(art1)    # Display word1
        time.sleep(1)   # Wait for 1 second
        clearScreen()  # Clear the screen
        print(art2)    # Display word2
        time.sleep(1)   # Wait for 1 second
        clearScreen()
# Call the menu function
mainMenu()