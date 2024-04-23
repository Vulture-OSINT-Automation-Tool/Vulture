import sys
import subprocess

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        sys.exit(1)

def sort_uniq(input_string):
    unique_lines = set(input_string.splitlines())
    sorted_unique_lines_arr = sorted(unique_lines)

    sorted_unique_lines = ""
    for result in sorted_unique_lines_arr:
        sorted_unique_lines = sorted_unique_lines + result + '\n'
    return sorted_unique_lines

def convert_format(results):
    formatted_results_arr = []
    current_email = None
    for line in results:
        if "Email:" in line:
            current_email = line.split("Email:")[1].strip()
        elif "Password:" in line and current_email:
            password = line.split("Password:")[1].strip()
            formatted_results_arr.append(f"{current_email}:{password}")
            current_email = None

    formatted_results = ""
    for result in formatted_results_arr:
        formatted_results = formatted_results + result + '\n'
    return formatted_results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <input_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    grep_command = f'grep "Password:" {input_file} -B 5 | grep -v "Hashed Password:" | grep -v "ID:" | grep -v "IP Address:" | grep -v "Database" | grep -v "Phone" | grep -v "Username" | grep -v "Address" | grep -v "Name" | grep -v "VIN" | grep "Password:" -B 1 | tr -d "-" | tr -d " "'

    try:
        output_lines = run_command(grep_command)
    except Exception as e:
        print(f"Error executing command: {e}")
        sys.exit(1)

    formatted_results = convert_format(output_lines)
    #print(formatted_results)

    uniq_results = sort_uniq(formatted_results)
    #print(uniq_results)
    
    with open("credentials.txt", "w") as file:
        for line in uniq_results.splitlines():
            email, password = line.strip('"').split('":"')
            file.write(f"Email: {email}\n")
            file.write(f"Password: {password}\n\n")
            print(f"Email: {email}")
            print(f"Password: {password}")
            print()
    
    print("Email-password pairs written to credentials.txt.")
