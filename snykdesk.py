import requests
import json
import click
from pyfiglet import Figlet
from config import BaseConfig as config


def get_orgs_info(snyk_api_key):
     
    res = requests.get('https://snyk.io/api/v1/orgs', headers={'Authorization': f'token {snyk_api_key}'})
    if res.status_code == 200:
        res_dict = json.loads(res.text)
        return [org['id'] for org in res_dict['orgs']]
        
            

@click.command()
@click.option('-o', '--orgs', multiple=True, required=False,
help='''One or many org id(s) to filter on can be passed in. For example -o 6c9f83bd-e86a-eg56-ba2e-bees86sc965b -o fd2dsfsa-60b1-4236-b2ec-715c7cabds4gh.
If no org id(s) are passed the default will be all orgs in Snyk account that the API key has access to.''')
@click.option('-p', '--projects', multiple=True, required=False,
help='''One or many many project(s) to filter on can be passed in that belong to orgs. For example -p snyk/project1 -p snyk/project2.
If no project names(s) are passed the default will be all projects that belong to the orgs. Note: if no orgs were passed in earlier and no projects are passed in all projects in Snyk account that the API key has access to will be included.''')
@click.option('-iss','--issues', multiple=True, default=[], show_default=True,
help='''One or more issue IDs to filter issues by. For example -iss SNYK-DEBIAN8-CURL-358682 -iss SNYK-DEBIAN8-IMAGEMAGICK-401199.
Default is an empty array, that will return results for all issue IDs.''')
@click.option('-s','--severity',multiple=True, type=click.Choice(['critical', 'high','medium','low'], case_sensitive=False),default= ['critical', 'high','medium','low'], show_default=True,
help='''One or many severities for issues can be chosen to filter on. For example -s Critical -s medium.
If no severitie(s) are passed in the default is to return issues with all severity levels.''')
@click.option('-em','--exploit_maturity',multiple=True, type=click.Choice(['mature','proof-of-concept','no-known-exploit','no-data'], case_sensitive=False),default= ['mature','proof-of-concept','no-known-exploit','no-data'], show_default=True,
help='''One or many exploit maturity for issues can be chosen to filter on. For example -em mature -em proof-of-concept.)
If no exploit maturities are passed in the default is to return issues with all exploit maturity levels.''')
@click.option('-t','--types',multiple=True, type=click.Choice(['vuln','license','configuration'], case_sensitive=False),default= ['vuln','license','configuration'], show_default=True,
help='''One or many type of issues can be chosen to filter on. For example -t vuln -t license.)
If no types are passed in the default is to return issues with all types of issues.''')
@click.option('-l','--languages',multiple=True, type=click.Choice(['node','javascript','ruby','java','scala','python','golang','php','dotnet','swift-objective-c','elixir','docker','linux','dockerfile','terraform','kubernetes','helm','cloudformation'], case_sensitive=False),default=['node','javascript','ruby','java','scala','python','golang','php','dotnet','swift-objective-c','elixir','docker','linux','dockerfile','terraform','kubernetes','helm','cloudformation'], show_default=True,
help='''One or many type of languages can be chosen to filter on. For example -l node -l python.)
If no languages are passed in the default is to return issues with all languages currently supported by Snyk.''')
@click.option('-i','--identifier', default='', show_default=True,
help='''A search term to filter issue name by, or an exact CVE or CWE. For example -i apache2 Buffer Overflow
 -i CVE-2021-44790.)
If no identifier is passed in the default is to return issues without filetering by identifier.''')
@click.option('-ig','--ignored', is_flag=True,
help='''If set only include issues which are ignored. If not set, only include issues which are not ignored.
Example -ig will return all of the issues that are ignored.''')
@click.option('-pa','--patched', is_flag=True,
help='''If set only include issues which are patched. If not set only includes issues which are not patched.
Example -pa will return all of the issues that are patched.''')
@click.option('-f','--fixable', is_flag=True,
help='''If set only include issues which are fixable. If not set only includes issues which are not fixable.
Example -f will return all of the issues that are fixable.''')
@click.option('-if','--is_fixed', is_flag=True,
help='''If set only include issues which are fixed. If not set only includes issues which are not fixed.
Example -if will return all of the issues that are fixed.''')
@click.option('-iu','--is_upgradable', is_flag=True,
help='''If set only include issues which are upgradable. If not set only includes issues which are not upgradable.
Example -iu will return all of the issues that are upgradable.''')
@click.option('-ip','--is_patchable', is_flag=True,
help='''If set only include issues which are patchable. If not set only includes issues which are not patchable.
Example -if will return all of the issues that are patchable.''')
@click.option('-ipin','--is_pinnable', is_flag=True,
help='''If set only include issues which are pinnable. If not set only includes issues which are not pinnable.
Example -ipin will return all of the issues that are pinnable.''')
@click.option('-min','--min', default=1, show_default=True,
help='''Min priority score, default is set to 1.''')
@click.option('-min','--min', default=1, show_default=True,
help='''Min priority score, default is set to 1.''')
@click.option('-max','--max', default=1000, show_default=True,
help='''Max priority score, default is set to 1000.''')
@click.option("-sak","--snyk_api_key", prompt=True, hide_input=True, required=True,
help="No need to pass will be asked for it during runtime as password prompt. API Key is required to get information, you may get this from admin to Snyk account.")
@click.option("-zak","--zendesk_api_key", prompt=True, hide_input=True, required=True,
help="No need to pass will be asked for it during runtime as password prompt. API Key is required to create zendesk tickets, you may get this from admin to Zendesk account.")

def run(orgs, projects, issues, severity, exploit_maturity, types, languages, identifier, ignored, patched, fixable, is_fixed, is_upgradable, is_patchable, is_pinnable, min, max, snyk_api_key, zendesk_api_key):


    if not orgs:
        orgs_info = get_orgs_info(snyk_api_key)
        orgs = orgs_info['orgs_id']
        

    body = {

        "filters": {
            "orgs": orgs,
            "severity": severity,
            "exploitMaturity": exploit_maturity,
            "types": types,
            "languages": languages,
            "issues": issues,
            "identifier": identifier,
            "ignored": ignored,
            "patched": patched,
            "fixable": fixable,
            "isFixed": is_fixed,
            "isUpgradable": is_upgradable,
            "isPatchable": is_patchable,
            "isPinnable": is_pinnable,
            "priorityScore": {
            "min": min,
            "max": max
            }
        
        }

        }

    if orgs and projects:
       body['filters'].update({'projects':projects})

    page = 1
    per_page = 1000
    issues = []
   
    while page == 1 or len(res_dict['results']) == per_page:
        API_URL = f'https://snyk.io/api/v1/reporting/issues/latest?page={page}&perPage={per_page}&sortBy=severity&order=desc'
        res = requests.post(API_URL, json=body, headers={'Authorization': f'token {snyk_api_key}'})
        if res.status_code == 200:
            res_dict = json.loads(res.text)
            issues += res_dict['results']
            page += 1

    issues_grouped ={}
    for issue in issues:
        if issue['issue']['semver']['vulnerable'] == ["*"]:
            continue
        group_identifier = f'{issue["issue"]["package"]}@{issue["issue"]["version"]}'
        

        detailed_path = issue['project']['name']
        for org in orgs:
            list_issue_path_url = f'https://snyk.io/api/v1/org/{org}/project/{issue["project"]["id"]}/issue/{issue["issue"]["id"]}/paths'
            res = requests.get(list_issue_path_url, headers={'Authorization': f'token {snyk_api_key}'})
            if res.status_code == 200:
                res_dict = json.loads(res.text)
                paths = res_dict['paths']
                for path in paths:
                    for item in path:
                        detailed_path += f' -> {item["name"]}{item["version"]}'
                break

        details= {
            'Title': issue['issue']['title'],
            'ID': issue['issue']['id'],
            'Severity': issue['issue']['severity'],
            'Package': group_identifier,
            'Package Manager': issue['issue']['packageManager'],
            'Vulnerable':issue['issue']['semver']['vulnerable'],
            'CVE': issue['issue']['identifiers']['CVE'],
            'CWE': issue['issue']['identifiers']['CWE'],
            'cvss Score': issue['issue']['cvssScore'],
            'Issue URL': issue['issue']['url'],
            'Language': issue['issue']['language'],
            'Project Name': issue['project']['name'],
            'Project URL': issue['project']['url'],
            'Project Source': issue['project']['source'],
            'Detailed Path': detailed_path
        }
        if group_identifier not in issues_grouped:
            issues_grouped[group_identifier] = [details]

        else:
            issues_grouped[group_identifier].append(details)
   
    zendesk_user = config.zendesk_user
    
    assignee_id = config.assignee_id
    ticket_form_id = config.ticket_form_id

    for item in issues_grouped:
        issue = issues_grouped[item]
        formatted_issue = create__ticket(issue, zendesk_api_key, zendesk_user, assignee_id, ticket_form_id)
        send_ticket(formatted_issue, zendesk_api_key, zendesk_user)

def create__ticket(issue, zendesk_api_key, zendesk_user, assignee_id, ticket_form_id):
    """Creates a tickets in Zendesk for Snyk Issues"""

    subject = f'{issue[0]["Severity"].capitalize()} {issue[0]["Project Name"]} - {issue[0]["Package"]}'
    is_duplicate = check_duplicates(subject, zendesk_user, zendesk_api_key)

    if is_duplicate:
            return None
    
    table = ''
    for item in issue:
             
       table += f'\nIssue: {item["Title"]}'
       table += f'\n**Severity: {item["Severity"].capitalize()}**' 
       table += f'\nVulnerable Package: {item["Package"]}'
       table += f'\n**Vulnerable version: {item["Vulnerable"][0]}**'
       table += f'\n**Detailed Path: {item["Detailed Path"]}**'
       table += f'\ncvss Score: {item["cvss Score"]}'
       table += f'\nCVE: {item["CVE"][0] if item["CVE"] else "None"}' 
       table += f'\nCWE: {item["CWE"][0] if item["CWE"] else "None"}'
       table += f'\nMore info : {item["Issue URL"]}'
       table += "\n\n--------------------------------------------------\n"


    payload = {
            "ticket": {
                "subject": subject,
                "comment": {
                    "body": "# Summary                                           \n"
                    + f'**Project Source: {issue[0]["Project Source"]} \nProject: {issue[0]["Project Name"]}'
                    + f'\nProject URL: {issue[0]["Project URL"]}'
                    + f'\nVulnerable Package: {issue[0]["Package"]} \nTotal issues: {len(issue)}'
                    + "**\n\n"
                    + "--------------------------------------------------\n"
                    + "# Issues                                            \n"
                    + table
                    
                },
                "assignee_id": assignee_id,
                "ticket_form_id": ticket_form_id,
                "tags": ["snyk_container"]
            }
        }
    return payload




def send_ticket(issue,zendesk_api_key,zendesk_user):
    payload = json.dumps(issue)
    headers = {"content-type": "application/json"}

    try:
        response = requests.post(
            f'{config.zendesk_base_url}/api/v2/tickets.json',
            data=payload,
            auth=(zendesk_user, zendesk_api_key),
            headers=headers,
        )
        response.raise_for_status()

    except requests.exceptions.HTTPError as errh:
        print(errh)
    except requests.exceptions.ConnectionError as errc:
        print(errc)
    except requests.exceptions.Timeout as errt:
        print(errt)
    except requests.exceptions.RequestException as err:
        print(err)

def check_duplicates(subject,zendesk_user,zendesk_api_key):
    """Guards against duplicate tickets by comparing the subject passed in against the
    subject of all the tickets requested by zendesk user."""

    url = f'{config.zendesk_base_url}/api/v2/users/373795365734/tickets/requested.json'
    is_duplicate = False

    response = requests.get(url, auth=(zendesk_user, zendesk_api_key))
    result = json.loads(response.content)
    tickets = result["tickets"]

    # every call to api can not exceed 100 tickets for more info see https://developer.zendesk.com/rest_api/docs/support/introduction#pagination
    while result["next_page"]:
        response = requests.get(
            result["next_page"], auth=(zendesk_user,zendesk_api_key)
        )
        result = json.loads(response.content)
        tickets += result["tickets"]

    # check if the subject passed in matches that of any ticket already in the system
    for ticket in tickets:
        if subject == ticket["raw_subject"]:
            is_duplicate = True
            break

    return is_duplicate

        
    


if __name__ == "__main__":
    custom_fig = Figlet(font="graffiti")
    print(custom_fig.renderText("SnykDesk"))

    run()
