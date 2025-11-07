import json
import re

with open('ubuntu22_04_stig_list.json', 'r') as stigfile:
    whole_stig = json.load(stigfile)


stig_fingings = whole_stig["stig"]["findings"]

# print(stig_fingings["V-260469"])



# for findingID in stig_fingings:
#     print(f"ID: {findingID}")
#     print(f"Title: {stig_fingings[findingID]["title"]}")
#     print(f"Severity: {stig_fingings[findingID]["severity"]}")
#     checker = re.findall(r'^\s*\$ (.+)$', stig_fingings[findingID]["checktext"], re.MULTILINE)
#     print(f"Checker commands: {checker}")
#     print(stig_fingings[findingID]["fixtext"])
#     print("-" * 50)

#print(stig_fingings["V-260469"]["checktext"])
#print(type(stig_fingings["V-260469"]))

# Checker regex test

# print(re.findall(r'^\s*\$ (.+)$', stig_fingings["V-260470"]["checktext"], re.MULTILINE))


# for findingID in stig_fingings:
#     print(f"# {findingID} | {stig_fingings[findingID]["severity"]} | {stig_fingings[findingID]["title"]}")
#     print(f"echo '=== {findingID} | {stig_fingings[findingID]["severity"]} ==='")
#     checker = re.findall(r'^\s*\$ (.+)$', stig_fingings[findingID]["checktext"], re.MULTILINE)

#     for command in checker:
#         print(f"Running: {command}")
#         print(command)
#     print()

# with open('run_checks.sh', 'w') as output_file:
#     output_file.write('#!/bin/bash\n\n')

#     for findingID in stig_fingings:
#         output_file.write(f"# {findingID} | {stig_fingings[findingID]["severity"]} | {stig_fingings[findingID]["title"]}\n")
#         output_file.write(f"echo '=== {findingID} | {stig_fingings[findingID]["severity"]} ==='\n")
#         checker = re.findall(r'^\s*\$ (.+)$', stig_fingings[findingID]["checktext"], re.MULTILINE)

#         for command in checker:
#             output_file.write(f"echo 'Running: {command}'\n")
#             output_file.write(command + '\n')
#         output_file.write("\n")
    
def high_checks():
    with open('high_checks.sh', 'w') as output_file:
        output_file.write('#!/bin/bash\n\n')
        output_file.write('set +e\n\n')
        for findingID in stig_fingings:
            if stig_fingings[findingID]["severity"] == "high":
                output_file.write(f"# {findingID} | {stig_fingings[findingID]["severity"]} | {stig_fingings[findingID]["title"]}\n")
                output_file.write(f"echo '=== {findingID} | {stig_fingings[findingID]["severity"]} ==='\n")
                checker = re.findall(r'^\s*\$ (.+)$', stig_fingings[findingID]["checktext"], re.MULTILINE)

                for command in checker:
                    output_file.write(f"# 'Running: {command}'\n")
                    output_file.write(command + '\n')
                output_file.write("\n")

high_checks()


def medium_checks():
    with open('medium_checks.sh', 'w') as output_file:
        output_file.write('#!/bin/bash\n\n')
        output_file.write('set +e\n\n')
        
        for findingID in stig_fingings:
            if stig_fingings[findingID]["severity"] == "medium":
                output_file.write(f"# {findingID} | {stig_fingings[findingID]["severity"]} | {stig_fingings[findingID]["title"]}\n")
                output_file.write(f"echo '=== {findingID} | {stig_fingings[findingID]["severity"]} ==='\n")
                checker = re.findall(r'^\s*\$ (.+)$', stig_fingings[findingID]["checktext"], re.MULTILINE)

                for command in checker:
                    output_file.write(f"# 'Running: {command}'\n")
                    output_file.write(command + '\n')
                output_file.write("\n")

medium_checks()