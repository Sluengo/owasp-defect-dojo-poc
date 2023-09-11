#### URLS/DOCS ####
# Application URL: http://10.40.147.149:8080/dashboard
# API Swagger URL: http://10.40.147.149:8080/api/v2/doc/
# Github-DefectDojo Example: https://defectdojo.github.io/django-DefectDojo/integrations/parsers/#github-vulnerability
# GraphyQL API: https://docs.github.com/en/graphql/reference/objects#repositoryvulnerabilityalert
# Curl Converter to Python: https://www.scrapingbee.com/curl-converter/python/

#### TO DO ####
# Consider looking into argparse to handle input validation and secure inputs 

## Example Calls
# & C:/Users/steven/AppData/Local/Programs/Python/Python39/python.exe c:/Users/steven/Documents//repos/ParentWorkflows/DefectDojo/graphql-api.py GithubTokenHere RepoName  appName commitHashHere buildIDHere Production "https://github.com/orgName/AppName" "DefectDojoAPIHeaderTokenhere"

#### LIBRARIES ####
import json
import sys
import os
from pathlib import Path
import requests
from datetime import date


####  VARIABLE DECLARATIONS ####

API_TEST_URL                =  "http://IP_HERE:8080/api/v2/tests/"

## DYANMIC INPUTS FROM PIPELINE
GH_TOKEN                    = sys.argv[1]
REPO_NAME                   = sys.argv[2]
ORG_NAME                    = sys.argv[3]
COMMIT_HASH                 = sys.argv[4]
BUILD_ID                    = sys.argv[5]
ENVIRONMENT                 = sys.argv[6]             
DEFECT_DOJO_TOKEN           = sys.argv[7]
SCAN_TYPE                   = sys.argv[8]
ENGAGEMENT_NAME             = sys.argv[9]
TEST_TITLE                  = sys.argv[10]

# Processing on Dyanmic Vars
REPO_NAME                   = REPO_NAME.split("/")[1] 
#JSON_FILE_NAME              = REPO_NAME + "_response.json"
PRODUCT_TYPE_PREFIX         = REPO_NAME.split("-")[0]

# Query against Github API for vulnerabilities 
QUERY = """
query getVulnerabilitiesByRepoAndOwner($name: String!, $owner: String!) {
  repository(name: $name, owner: $owner) {
    vulnerabilityAlerts(first: 100) {
      nodes {
        id
        createdAt
        securityVulnerability {
          severity
          package {
            name
            ecosystem
          }
          advisory {
            description
            summary
            identifiers {
              value
              type
            }
            references {
              url
            }
            cvss {
              vectorString
            }
          }
        }
        vulnerableManifestPath
      }
    }
  }
}
"""

#### FUNCTION DEFINITIONS ####

def CheckInputs (GH_TOKEN, REPO_NAME, ORG_NAME, COMMIT_HASH, BUILD_ID, ENVIRONMENT, DEFECT_DOJO_TOKEN, SCAN_TYPE, ENGAGEMENT_NAME, TEST_TITLE):
  arguments = locals()
  print(arguments)


def GetRepoVulnerabilities(GH_TOKEN, REPO_NAME, ORG_NAME, QUERY):
    headers = {"Authorization": "Bearer " + GH_TOKEN}

    request = requests.post(url='https://api.github.com/graphql',
                            json={
                            "operationName": "getVulnerabilitiesByRepoAndOwner",
                            'query': QUERY,
                            'variables': {
                                'name': REPO_NAME,
                                'owner': ORG_NAME
                            }
                            },
                            headers=headers)

    # Create JSON File
    JSON_FILE_NAME = REPO_NAME + "_response.json"
    result = request.json()
    json_object = json.dumps(result, indent=2) 

    # Open file in write mode and put the json_object response to it
    with open(JSON_FILE_NAME, "w") as outfile:
        outfile.write(json_object)

    current_working_dir = os.getcwd()
    path = rf"{current_working_dir}\{JSON_FILE_NAME}"

    # Return if file exists
    my_file = Path(path)
    if my_file.is_file(): 
        print ("File SUCCESSFULLY created") 
        return JSON_FILE_NAME
    else:
      print ("File FAILED to create. Exiting.") 
      sys.exit(1)  
  

def GetTest(TEST_TITLE, API_TEST_URL):

    headers = {'Authorization': DEFECT_DOJO_TOKEN}

    params = {
        'title': TEST_TITLE,
    }

    response = requests.get(API_TEST_URL, params=params, headers=headers)
    return response


def CheckScanType(SCAN_TYPE):
  # Check for type of scan
  if "Github" in SCAN_TYPE:
    # Using GraphQL API, make call to Github Repo and get latest vulnerabilities. Return if the file was successfully created.
   JSON_FILE_NAME = GetRepoVulnerabilities(GH_TOKEN, REPO_NAME, ORG_NAME, QUERY)
   return JSON_FILE_NAME
  
  elif "SARIF" in SCAN_TYPE:
    JSON_FILE_NAME = rf"C:\temp\DefectDojo\pcc_scan_results.sarif.json"
    return JSON_FILE_NAME
  
  else:
    print("An error has occured during scan check.")
    sys.exit(1)

# https://blog.jetbridge.com/multipart-encoded-python-requests/
def UploadScanResult(test_exists, JSON_FILE_NAME, DEFECT_DOJO_TOKEN, TEST_TITLE, REPO_NAME, PRODUCT_TYPE_PREFIX, ENGAGEMENT_NAME, SCAN_TYPE, ENVIRONMENT, BUILD_ID, COMMIT_HASH):
    
    # If condition here to switch scan_Url depending of its a new import or re-import

    if (test_exists == 0):
        print ("NEW TEST, INITIAL IMPORT STARTED!")
        scan_url  = 'http://10.40.147.149:8080/api/v2/import-scan/'
    else:
        print ("TEST(S) EXISTS, RE-IMPORT STARTED!")
        scan_url  = 'http://10.40.147.149:8080/api/v2/reimport-scan/'
    
    
    # Decide on PRODUCT TYPE. Expand this for other prefixes
    if PRODUCT_TYPE_PREFIX == "WS":
        product_type = "Software Engineering Team"
    
    # Get Today's date to append to upload
    today = date.today()
    # YYYY-mm-dd
    today_formated = today.strftime("%Y-%m-%d")

    headers = {'Authorization': DEFECT_DOJO_TOKEN}

    files = {
        'scan_date': (None, today_formated),
        'minimum_severity': (None, 'Low'),
        'active': (None, 'true'),
        'verified': (None, 'true'),
        'auto_create_context': (None, 'true'),
        'deduplication_on_engagement': (None, 'true'),
        'test_title': (None, TEST_TITLE),
        'scan_type': (None, SCAN_TYPE),
        'file': open(JSON_FILE_NAME, 'rb'),
        'product_name': (None, REPO_NAME),
        'product_type_name': (None, product_type),
        'engagement_name': (None, ENGAGEMENT_NAME),
        'close_old_findings': (None, 'false'),
        'close_old_findings_product_scope': (None, 'true'),
        'push_to_jira': (None, 'false'),
        'environment': (None, ENVIRONMENT),
        'build_id': (None, BUILD_ID),
        'commit_hash': (None, COMMIT_HASH),
        'create_finding_groups_for_all_findings': (None, 'true'),
    }

    response = requests.post(scan_url, headers=headers, files=files, verify=True) # set verify to False if ssl cert is self-signed
    return response

def main():

  # Validates/Checks Inputs 
  CheckInputs(GH_TOKEN, REPO_NAME, ORG_NAME, COMMIT_HASH, BUILD_ID, ENVIRONMENT, DEFECT_DOJO_TOKEN, SCAN_TYPE, ENGAGEMENT_NAME, TEST_TITLE)


  JSON_FILE_NAME = CheckScanType(SCAN_TYPE)
  
  #GetRepoVulnerabilities(GH_TOKEN, REPO_NAME, ORG_NAME, QUERY, JSON_FILE_NAME)


  # Get Tests and check for Test, "SCAN_TYPE" --> Github Vulnerability Scan using Title of Test. If it exists, Call ReImport Scan, otherwise Call Upload Scan
  test_exists = GetTest(TEST_TITLE, API_TEST_URL)
  # Converts response to raw json and returns a count of the number of tests for TEST_TITLE. 
  test_exists = test_exists.json()['count']

  # Upload vulnerabilities
  upload_response = UploadScanResult(test_exists, JSON_FILE_NAME, DEFECT_DOJO_TOKEN, TEST_TITLE, REPO_NAME, PRODUCT_TYPE_PREFIX, ENGAGEMENT_NAME, SCAN_TYPE, ENVIRONMENT, BUILD_ID, COMMIT_HASH)

  if upload_response.status_code >= 200 and upload_response.status_code < 400:
    print(upload_response.status_code)
    print(upload_response.reason)
    print("Successfully uploaded report!!")
    print(upload_response.content)
    sys.exit(0)
  else:
    print("File DID NOT upload!!")
    print("Status Code, Reason, and Content:")
    print(upload_response.status_code)
    print(upload_response.reason)
    print(upload_response.content)
    sys.exit(1)


if __name__ == "__main__":
    main()
