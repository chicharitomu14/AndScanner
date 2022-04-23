import json


def extractTestResult():
    result = dict()
    with open("2020-11-26_15-23-33_400684.log") as fp:
        data = fp.readlines()
    for line in data:
        line = line[line.find("CVE-") :].strip()
        parts = line.split(" ")
        print(parts)
        cve = parts[0][:-1]
        if parts[1] == "notAffected:":
            result[cve] = {"notAffected": True}
        else:
            isFixed = True if parts[-1] == "True" else False
            isVulnerable = True if parts[2] == "True" else False
            result[cve] = {"isFixed": isFixed, "isVulnerable": isVulnerable}
    with open("myresult.json", "w") as fp:
        json.dump(result, fp, indent=2, sort_keys=True)


def compareTestResult():
    with open("tests/groundtruth.json") as fp:
        groundtruth = json.load(fp)

    with open("myresult.json") as fp:
        myresult = json.load(fp)

    for cve, res in groundtruth.items():
        if cve == "CVE-2019-2099":
            continue
        if res != myresult[cve]:
            if "notAffected" in res:
                print(cve, res["notAffected"], myresult[cve]["notAffected"])
            else:
                print(
                    "{} (isvuln:{}, isfixed:{}) (isvuln:{}, isfixed:{})".format(
                        cve,
                        res["isVulnerable"],
                        res["isFixed"],
                        myresult[cve]["isVulnerable"],
                        myresult[cve]["isFixed"],
                    )
                )


# extractTestResult()
compareTestResult()