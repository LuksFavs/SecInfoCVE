import requests
import json

numPerPage =2000 
pagina = 1
chave = "504d19f8-2d68-4c99-866f-5c0a28335e29"
params = {
        "resultsPerPage": 100,
        "startIndex": 0,
        "apiKey": "504d19f8-2d68-4c99-866f-5c0a28335e29",

        }
listaCves = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)

print(listaCves.status_code,listaCves.reason)

if listaCves.status_code == 200:
    with open('cve.json', 'w') as file:
        json.dump(listaCves.json, file)
        print(salvei)