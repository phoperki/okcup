import json

with open('ubuntu22_04_stig_list.json', 'r') as stigfile:
    whole_stig = json.load(stigfile)


stig_fingings = whole_stig["stig"]["findings"]

# print(stig_fingings["V-260469"])



for findingID in stig_fingings:
    print(findingID)
    print(stig_fingings[findingID]["checktext"])
    print("-" * 50)

#print(stig_fingings["V-260469"]["checktext"])
#print(type(stig_fingings["V-260469"]))