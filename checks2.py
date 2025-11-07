import json
import re

with open('ubuntu22_04_stig_list.json', 'r') as stigfile:
    whole_stig = json.load(stigfile)

stig_fingings = whole_stig["stig"]["findings"]

with open('run_checks.sh', 'w') as output_file:
    output_file.write('#!/bin/bash\n\n')

    for findingID in stig_fingings:
        output_file.write(f"# {findingID} | {stig_fingings[findingID]["severity"]} | {stig_fingings[findingID]["title"]}\n")
        output_file.write(f"echo '=== {findingID} | {stig_fingings[findingID]["severity"]} ==='\n")
        checker = re.findall(r'^\s*\$ (.+)$', stig_fingings[findingID]["checktext"], re.MULTILINE)

        for command in checker:
            output_file.write(f"echo 'Running: {command}'\n")
            output_file.write(command + '\n')
        output_file.write("\n")