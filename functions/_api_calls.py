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
