import json

def retirarAsRegression():
    regressions = []
    noRegressions = []
    with open("data/nvdcve-1.1-modified.json", encoding="utf8") as file:
        data=json.load(file)
        for i in range(len(data["CVE_Items"])):
            if 'regression' in data['CVE_Items'][i]['cve']['description']['description_data'][0]["value"]:
                regressions.append(data['CVE_Items'][i].copy())
            else:
                noRegressions.append(data['CVE_Items'][i].copy())

    if len(regressions) != 0:
        with open("regression.json", "w") as file:
            json.dump(regressions,file)
                
if __name__ == "__main__":
    retirarAsRegression()
