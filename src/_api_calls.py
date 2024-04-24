import json
import requests
import urllib3
from base64 import b64encode
from operator import itemgetter 

# Desactivar las advertencias de https inseguro (para certificados SSL autofirmados)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuración de la conexión a la API
protocol = 'https'
host = '54.149.137.67'
port = 55000
user = 'wazuh'
password = 'ePdVeStfbVuujM2eGG5*WQ.1vNLvz675'
login_endpoint = 'security/user/authenticate'

# Proceso de registro con la información básica
login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
basic_auth = f"{user}:{password}".encode()
login_headers = {'Content-Type': 'application/json',
                 'Authorization': f'Basic {b64encode(basic_auth).decode()}'}

# Solicitud del token para hacer uso de la API
response = requests.post(login_url, headers=login_headers, verify=False)
if response.status_code == 200:
    token = json.loads(response.content.decode())['data']['token']
    requests_headers = {'Content-Type': 'application/json',
                        'Authorization': f'Bearer {token}'}
else:
    requests_headers = None
    exit()


def get_header():
    return requests_headers

def get_host() -> str:
    return host