import json
def retirarAsRegression():
    regressions = []
    noRegressions = []
    with open("nvdcve-1.1-modified.json\\nvdcve-1.1-modified.json", encoding="utf8") as file:
        data=json.load(file)
        ##print(data['CVE_Items'][0]['cve']['description']['description_data'][0]["value"])
        for i in range(len(data["CVE_Items"])):
            print()
            if 'regression' in data['CVE_Items'][i]['cve']['description']['description_data'][0]["value"]:
                regressions.append(data['CVE_Items'][i].copy())
            else:
                noRegressions.append(data['CVE_Items'][i].copy())
        print(len(regressions))

retirarAsRegression()
