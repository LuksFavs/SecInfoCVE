import requests
import json
url = "https://bugzilla.mozilla.org/rest/bug"
headers = {"Content-Type": "application/json"}
apikey="fWnUTCtzSermhD8DE6m4L8UROHcvpefTer8aj8QD"
params={
    "id":"aaa",
    "api_key":apikey
}
bugs={}
name="bug"

counter = 0
for i in open("./vulnerabilitesLevantament.txt"):
    params["id"] = i
    r = requests.get(url,params=params ) 
    bug = r.json()
    if r.status_code == 200:
        if len(bug["bugs"][0]["regressed_by"]) > 0:
            counter+=1
            print(counter)
            aux=name+str(counter)
            bugs[aux] = bug

print(bugs)
with open("withregby.txt", "w") as newfile:
    json.dump(bugs, newfile)

    #    bug = r.json()
    #    for i in bug["bugs"][0]:
    #        print(i, bug["bugs"][0][i])
    #        print()
    
    #else:
    #    print("Error: ", r.status_code)
    #    print(r.text)


