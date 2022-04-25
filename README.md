# SnykDesk
CLI app that creates Zendesk tickets for Snyk issues based on flags passed in.

## Instructions/Requirements
1. Must have properly scoped Zendesk and Snyk API keys, CLI will prompt for these at run time. (Please see references for more info)
2. Populate required variables for Zendesk in `config.py`.
3. Install requirements `pip install -r requirements.txt`.

## Help
`python snykdesk.py --help`  

```
  _________              __    ________                 __    
 /   _____/ ____ ___.__.|  | __\______ \   ____   _____|  | __
 \_____  \ /    <   |  ||  |/ / |    |  \_/ __ \ /  ___/  |/ /
 /        \   |  \___  ||    <  |    `   \  ___/ \___ \|    < 
/_______  /___|  / ____||__|_ \/_______  /\___  >____  >__|_ \
        \/     \/\/          \/        \/     \/     \/     \/

Usage: snykdesk.py [OPTIONS]

Options:
  -o, --orgs TEXT                 One or many org id(s) to filter on can be
                                  passed in. For example -o
                                  6c9f83bd-e86a-eg56-ba2e-bees86sc965b -o
                                  fd2dsfsa-60b1-4236-b2ec-715c7cabds4gh. If no
                                  org id(s) are passed the default will be all
                                  orgs in Snyk account that the API key has
                                  access to.
  -p, --projects TEXT             One or many many project(s) to filter on can
                                  be passed in that belong to orgs. For
                                  example -p snyk/project1 -p snyk/project2.
                                  If no project names(s) are passed the
                                  default will be all projects that belong to
                                  the orgs. Note: if no orgs were passed in
                                  earlier and no projects are passed in all
                                  projects in Snyk account that the API key
                                  has access to will be included.
  -iss, --issues TEXT             One or more issue IDs to filter issues by.
                                  For example -iss SNYK-DEBIAN8-CURL-358682
                                  -iss SNYK-DEBIAN8-IMAGEMAGICK-401199.
                                  Default is an empty array, that will return
                                  results for all issue IDs.
  -s, --severity [critical|high|medium|low]
                                  One or many severities for issues can be
                                  chosen to filter on. For example -s Critical
                                  -s medium. If no severitie(s) are passed in
                                  the default is to return issues with all
                                  severity levels.  [default: critical, high,
                                  medium, low]
  -em, --exploit_maturity [mature|proof-of-concept|no-known-exploit|no-data]
                                  One or many exploit maturity for issues can
                                  be chosen to filter on. For example -em
                                  mature -em proof-of-concept.) If no exploit
                                  maturities are passed in the default is to
                                  return issues with all exploit maturity
                                  levels.  [default: mature, proof-of-concept,
                                  no-known-exploit, no-data]
  -t, --types [vuln|license|configuration]
                                  One or many type of issues can be chosen to
                                  filter on. For example -t vuln -t license.)
                                  If no types are passed in the default is to
                                  return issues with all types of issues.
                                  [default: vuln, license, configuration]
  -l, --languages [node|javascript|ruby|java|scala|python|golang|php|dotnet|swift-objective-c|elixir|docker|linux|dockerfile|terraform|kubernetes|helm|cloudformation]
                                  One or many type of languages can be chosen
                                  to filter on. For example -l node -l
                                  python.) If no languages are passed in the
                                  default is to return issues with all
                                  languages currently supported by Snyk.
                                  [default: node, javascript, ruby, java,
                                  scala, python, golang, php, dotnet, swift-
                                  objective-c, elixir, docker, linux,
                                  dockerfile, terraform, kubernetes, helm,
                                  cloudformation]
  -i, --identifier TEXT           A search term to filter issue name by, or an
                                  exact CVE or CWE. For example -i apache2
                                  Buffer Overflow  -i CVE-2021-44790.) If no
                                  identifier is passed in the default is to
                                  return issues without filetering by
                                  identifier.
  -ig, --ignored                  If set only include issues which are
                                  ignored. If not set, only include issues
                                  which are not ignored. Example -ig will
                                  return all of the issues that are ignored.
  -pa, --patched                  If set only include issues which are
                                  patched. If not set only includes issues
                                  which are not patched. Example -pa will
                                  return all of the issues that are patched.
  -f, --fixable                   If set only include issues which are
                                  fixable. If not set only includes issues
                                  which are not fixable. Example -f will
                                  return all of the issues that are fixable.
  -if, --is_fixed                 If set only include issues which are fixed.
                                  If not set only includes issues which are
                                  not fixed. Example -if will return all of
                                  the issues that are fixed.
  -iu, --is_upgradable            If set only include issues which are
                                  upgradable. If not set only includes issues
                                  which are not upgradable. Example -iu will
                                  return all of the issues that are
                                  upgradable.
  -ip, --is_patchable             If set only include issues which are
                                  patchable. If not set only includes issues
                                  which are not patchable. Example -if will
                                  return all of the issues that are patchable.
  -ipin, --is_pinnable            If set only include issues which are
                                  pinnable. If not set only includes issues
                                  which are not pinnable. Example -ipin will
                                  return all of the issues that are pinnable.
  -min, --min INTEGER             Min priority score, default is set to 1.
                                  [default: 1]
  -max, --max INTEGER             Max priority score, default is set to 1000.
                                  [default: 1000]
  -sak, --snyk_api_key TEXT       No need to pass will be asked for it during
                                  runtime as password prompt. API Key is
                                  required to get information, you may get
                                  this from admin to Snyk account.  [required]
  -zak, --zendesk_api_key TEXT    No need to pass will be asked for it during
                                  runtime as password prompt. API Key is
                                  required to create zendesk tickets, you may
                                  get this from admin to Zendesk account.
                                  [required]
  --help                          Show this message and exit.

```
## Notes
 - There's a lot of filters please make sure you know what you are looking for or choose defaults. The idea with filters is to have a one to one with all the filters Snyk provides through their API giving users plenty of options to drill down. 
 - Currently set to group tickets by package@version, this gives the convenience of creating one ticket for all severity level passed in CLI and issues for specific package@version. This may not be ideal workflow for all users, an availability to create a ticket for each issue will be coming in the near future. 

 ## References
 - https://snyk.docs.apiary.io/#reference/reporting-api/latest-issues
 - https://snyk.docs.apiary.io/#reference/projects/project-issue-paths/list-all-project-issue-paths
 - https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/
 - https://click.palletsprojects.com/en/8.1.x/options/#password-prompts

### Author: Walter Carbajal
### Version: 1.0
### Written in python 3