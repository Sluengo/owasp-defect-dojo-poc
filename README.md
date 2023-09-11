# owasp-defect-dojo

A proof of concept utilizing OWASP's [DefectDojo](https://owasp.org/www-project-defectdojo/), which is a vulnerability management platform that allows you to ingest a wide variety of vulnerability data.
I was looking for a way to ingest the vareity of scanning data we would receive from Dependabot, Primsa Cloud, etc into one place.

## STEPS
1. The defectdojo-child.yml workflow is placed in a repository that you want to onboard into Defect Dojo.
2. You pass a series of inputs specifically: SCAN TYPE, ENGAGEMENT TYPE, and TEST TILE. These control the type of scan that's being ingested into Defect Dojo.
3. Usually the graphql-api.py code, which is the script responsible for making the API calls into DefectDojo is kept seperately in a different repository. Hence the need to setup a submodule in your "Child workflow". So, you will need to set that up.
4. Whenever you push new code to the onboarded "Child" repository, it would make a call to the "Parent" - defectdojo-parent.yml workflow within the DefectDojo repository and run.
5. The graphql.api.py python file will ingest the arguments passed into the parent workflow from the child workflow and make the appropriate API calls. You will need to update some variables to fit your environmnt like 
API_TEST_URL.