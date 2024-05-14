from imaplib import _Authenticator
import json
from flask import redirect, request, url_for
import requests
from operator import itemgetter 
import csv
from functions import _authentication

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
        # Construir la URL para obtener detalles del agente por su nombre
        agent_details_endpoint = f"{url}/agents?search={agent_name}&limit=1"
        
        # Realizar la solicitud GET a la API de Wazuh para obtener los detalles del agente
        response = requests.get(agent_details_endpoint, headers=request_header, verify=False)
        
        if response.status_code == 200:
            # Obtener los detalles del agente de la respuesta JSON
            agent_details = response.json()["data"]["affected_items"][0]
            agent_id = agent_details.get('id')
            agent_name = agent_details.get('name')
            agent_status = agent_details.get('status')
            agent_OperatingSystem = agent_details.get('operating system')
            
            # Retornar el resultado como un diccionario con la información del agente
            return {"agent_id": agent_id, "agent_name": agent_name, "agent_status": agent_status, "agent_OperatingSystem": agent_OperatingSystem}
        else:
            # Si la solicitud no es exitosa, devolver un mensaje de error
            return {"error": f"Failed to fetch agent details. Status code: {response.status_code}"}
    except Exception as e:
        print(f"Error: {str(e)}")
        return {"error": "Failed to fetch data due to an error"}


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
    
def vulnerability_severity_by_os(url, request_header):
    os_vulnerability_data = {}
    response = requests.get(url + "/agents", headers=request_header, verify=False)
    if response.status_code == 200:
        agents = response.json()["data"]["affected_items"]
        for agent in agents:
            try:
              agent_id = agent['id']
              os_name = agent['os']['name']
              vul_response = requests.get(url + f"/vulnerability/{agent_id}", headers=request_header, verify=False)
              if vul_response.status_code == 200 and vul_response.json().get('data'):
                  vulnerabilities = vul_response.json()["data"]["affected_items"]
                  for vulnerability in vulnerabilities:
                      severity = vulnerability['severity']
                      if os_name not in os_vulnerability_data:
                          os_vulnerability_data[os_name] = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
                      os_vulnerability_data[os_name][severity] += 1
            except Exception as inner_e:
              print(f"Error processing agent {agent_id}: {str(inner_e)}")
    return os_vulnerability_data


def add_rule(ID, category, level, name, group, description):
    # Crear el objeto de regla con los datos proporcionados
    new_rule = {
        'ID': ID,
        'category': category,
        'level': level,
        'name': name,
        'group': group,
        'Description': description
    }

    added_rules = []
    
    # Agregar la nueva regla a la lista de reglas agregadas
    added_rules.append(new_rule)

    # Devolver la lista de reglas agregadas actualizada
    return added_rules

def add_decoder(rule_id, decoder_name, regex, type, description):
    # Crear el objeto del decoder con los datos proporcionados
    new_decoder = {
        'rule_id': rule_id,
        'decoder_name': decoder_name,
        'regex': regex,
        'type': type,
        'description': description
    }

    added_decoders = []

    # Agregar el nuevo decoder a la lista de decoders agregados
    added_decoders.append(new_decoder)

    # Devolver la lista de decoders agregados actualizada
    return added_decoders


def restart_agent(url, request_header, agent_id):
    try:
        # Construir la URL para obtener todas las reglas del servidor de Wazuh
        rules_endpoint = f"{url}/agents/{agent_id}/restart"

        # Realizar la solicitud GET a la API de Wazuh para obtener todas las reglas
        response = requests.put(rules_endpoint, headers=request_header, verify=False)

    except Exception as e:
        print(f"Error: {str(e)}")
        return {"error": "Failed to fetch data due to an error"}
    
def update_agent(url, request_header):
    try:
        # Construir la URL para obtener todas las reglas del servidor de Wazuh
        rules_endpoint = f"{url}/agents/upgrade"

        # Realizar la solicitud GET a la API de Wazuh para obtener todas las reglas
        response = requests.put(rules_endpoint, headers=request_header, verify=False)

    except Exception as e:
        print(f"Error: {str(e)}")
        return {"error": "Failed to fetch data due to an error"}
    
def read_csv():
    rules = []
    try:
        with open('rules.csv', mode='r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                rules.append(row)
    except UnicodeDecodeError as e:
        print(f"Error decoding file: {e}")
    return rules