import json
import re

with open('ubuntu22_04_stig_list.json', 'r') as stigfile:
    whole_stig = json.load(stigfile)


stig_fingings = whole_stig["stig"]["findings"]



for findingID in stig_fingings:
    print(f"ID: {findingID}")
    print(f"Title: {stig_fingings[findingID]["title"]}")
    print(f"Severity: {stig_fingings[findingID]["severity"]}")
    print(stig_fingings[findingID]["fixtext"])
    print("-" * 50)