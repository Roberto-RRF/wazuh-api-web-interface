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
    
def get_vulnerabilities_with_agents(url,request_header):
    result = {}
    response_agents = requests.get(url + "/agents?limit=20", headers=request_header, verify=False)
    agents = json.loads(response_agents.text)["data"]["affected_items"]
    for agent in agents:
        agent_id = agent["id"]
        agent_name = agent['name']
        response_vul = requests.get(url + f"/vulnerability/{agent_id}/summary/cve", headers=request_header, verify=False)
        if response_vul.status_code == 200 and response_vul.json().get('data'):
            vulnerabilities_cve = json.loads(response_vul.text)["data"]["cve"]
            for cve in vulnerabilities_cve.keys():
                if cve not in result:
                    result[cve] = []
                agent_info = {
                    'id': agent_id,
                    'name': agent_name,
                }
                result[cve].append(agent_info)
    return result

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
    
    
def vulnerabilities_overview(url, request_header):
    try:
        response = requests.get(url + "/agents", headers=request_header, verify=False)
        if response.status_code == 200: 
            agents = response.json()["data"]["affected_items"]
            critical = []
            high = []
            medium = []
            low = []
            total = 0
            for agent in agents:
                agent_id = agent['id']
                agent_name = agent['name']

                vul_response = requests.get(url + f"/vulnerability/{agent_id}", headers=request_header, verify=False)
                if vul_response.status_code == 200 and vul_response.json().get('data'):
                        vulnerabilities = json.loads(vul_response.text)
                    
                        vulnerabilities = vul_response.json()["data"]["affected_items"]
                        for vulnerability in vulnerabilities:
                            if vulnerability['severity'] == 'Critical':
                                critical.append({'agent_id': agent_id, 'agent_name':agent_name, 'vul_name':vulnerability['name'], 'cve':vulnerability['cve'], 'severity':vulnerability['severity'] })
                            if vulnerability['severity'] == 'High':
                                high.append({'agent_id': agent_id, 'agent_name':agent_name, 'vul_name':vulnerability['name'], 'cve':vulnerability['cve'], 'severity':vulnerability['severity'] })
                            if vulnerability['severity'] == 'Medium':
                                medium.append({'agent_id': agent_id, 'agent_name':agent_name, 'vul_name':vulnerability['name'], 'cve':vulnerability['cve'], 'severity':vulnerability['severity'] })
                            if vulnerability['severity'] == 'Low':  
                                low.append({'agent_id': agent_id, 'agent_name':agent_name, 'vul_name':vulnerability['name'], 'cve':vulnerability['cve'], 'severity':vulnerability['severity'] })   
                                                
            total = len(critical) + len(high) + len(medium) + len(low)
            return (total, critical, high, medium, low)
    except Exception as e:
        print(f"Error: {str(e)}")
        return [{"agent": "Failed to fetch data due to an error", "vulnerabilities": 0}]

def agent_by_name(agent_name, url, request_header):
    try:
        # Obtener las vulnerabilidades relacionadas con el nombre del agente
        vulnerabilities = vulnerabilities_by_name(agent_name, url, request_header)
        
        # Obtener el recuento de vulnerabilidades
        vulnerabilities_count = len(vulnerabilities)
        
        # Obtener el ID del agente
        agent_id = vulnerabilities[0].get('agent_id') if vulnerabilities else None
        
        # Obtener el nombre del agente
        agent_name = vulnerabilities[0].get('agent_name') if vulnerabilities else None
        
        # Retornar el resultado como una lista con un solo elemento que contiene la información del agente y el recuento de vulnerabilidades
        return [{"agent_id": agent_id, "agent_name": agent_name, "vulnerabilities_count": vulnerabilities_count}]
    except Exception as e:
        print(f"Error: {str(e)}")
        return [{"error": "Failed to fetch data due to an error"}]


def vulnerabilities_by_name(agent_name, url, request_header):
    try:
        response = requests.get(url + "/agents?limit=50", headers=request_header, verify=False)
        if response.status_code == 200: 
            agents = response.json()["data"]["affected_items"]
            result_vulnerabilities = []
            for agent in agents:
                if agent['name'] == agent_name:
                    agent_id = agent['id']
                    agent_name = agent['name']

                    vul_response = requests.get(url + f"/vulnerability/{agent_id}", headers=request_header, verify=False)
                    if vul_response.status_code == 200 and vul_response.json().get('data'):
                            vulnerabilities = vul_response.json()["data"]["affected_items"]
                            for vulnerability in vulnerabilities:
                                result_vulnerabilities.append({'agent_id': agent_id, 'agent_name':agent_name, 'vul_name':vulnerability['name'], 'cve':vulnerability['cve'], 'severity':vulnerability['severity'] })

            return result_vulnerabilities
    except Exception as e:
        print(f"Error: {str(e)}")
        return []

