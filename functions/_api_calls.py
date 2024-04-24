import json
import requests
from operator import itemgetter 

def top_n_agents(n, url, request_header):
    try:
        response = requests.get(url + "/agents?limit=20", headers=request_header, verify=False)
        if response.status_code == 200:
            agents = json.loads(response.text)["data"]["affected_items"]
            agent_vulnerabilities = []
            for agent in agents:
                try:
                    agent_id = agent['id']
                    agent_name = agent['name']
                    agent_os_name = agent['os']['name']
                    agent_status = agent['status']

                    vul_response = requests.get(url + f"/vulnerability/{agent_id}", headers=request_header, verify=False)
                    if vul_response.status_code == 200 and vul_response.json().get('data'):
                        vulnerabilities = json.loads(vul_response.text)["data"]["total_affected_items"]
                        agent_vulnerabilities.append({"id": agent_id, "vulnerabilities": vulnerabilities, "name": agent_name, "os_name": agent_os_name, "status": agent_status})
                except Exception as inner_e:
                    print(f"Error processing agent {agent_id}: {str(inner_e)}")
                   
            return sorted(agent_vulnerabilities, key=itemgetter("vulnerabilities"), reverse=True)[:n]
        else:
            # Aquí manejamos el caso de respuesta no exitosa (HTTP status != 200)
            return [{"name": "Failed to fetch data", "vulnerabilities": 0}]
    except Exception as e:
        print(f"Error: {str(e)}")
        return [{"agent": "Failed to fetch data due to an error", "vulnerabilities": 0}]

def vulnerabilities_by_keyword(keyword, url, request_header):
    try:
        response = requests.get(url + "/agents?limit=50", headers=request_header, verify=False)
        if response.status_code == 200: 
            agents = response.json()["data"]["affected_items"]
            result_vulnerabilities = []
            for agent in agents:
                agent_id = agent['id']
                agent_name = agent['name']

                vul_response = requests.get(url + f"/vulnerability/{agent_id}", headers=request_header, verify=False)
                if vul_response.status_code == 200 and vul_response.json().get('data'):
                        vulnerabilities = json.loads(vul_response.text)
                    
                        vulnerabilities = vul_response.json()["data"]["affected_items"]
                        for vulnerability in vulnerabilities:
                            if keyword.lower() in vulnerability['name'].lower():
                                print(vulnerability)
                                result_vulnerabilities.append({'agent_id': agent_id, 'agent_name':agent_name, 'vul_name':vulnerability['name'], 'cve':vulnerability['cve'], 'severity':vulnerability['severity'] })

            return result_vulnerabilities
    except Exception as e:
        print(f"Error: {str(e)}")
        return [{"agent": "Failed to fetch data due to an error", "vulnerabilities": 0}]