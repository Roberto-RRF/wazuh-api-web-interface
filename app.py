from flask import Flask, render_template, request
import sys
import os
from werkzeug.utils import secure_filename
sys.path.append('functions')
from functions import _api_calls , _authentication, _logs_recommendations

app = Flask(__name__)

@app.route("/")
def home():

    return render_template(
        "team.html"
    )

@app.route('/analyze_logs', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('analyze_logs.html', message="No file part")
        file = request.files['file']
        if file.filename == '':
            return render_template('analyze_logs.html', message="No selected file")
        if file and _logs_recommendations.allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join("logs", filename)
            file.save(file_path)
            result = _logs_recommendations.process_file(file_path)
            if isinstance(result, str):
                return render_template('analyze_logs.html', message=f"Error: {result}")
            clusteres_data=_logs_recommendations.clusteres_data(result["clusters_keywords"], result["clusters_samples"])
            analysis = _logs_recommendations.openai_call(clusteres_data)
            return render_template(
                'analyze_logs.html',
                optimal_clusters=result["optimal_clusters"],
                elbow_plot_path=result["elbow_plot_path"],
                cluster_plot_path=result["cluster_plot_path"],
                analysis=analysis,
                clusteres_data=clusteres_data,
            )
        else:
            return render_template('analyze_logs.html', message="Invalid file type")
    return render_template('analyze_logs.html')


@app.route("/team")
def team():
    return render_template(
        "team.html"
    )

@app.route("/vulnerabilities_os")
def vulnerabilities_os():
    header = _authentication.get_header()
    url = _authentication.url
    os_vulnerability_data = _api_calls.vulnerability_severity_by_os(url, header)
    return render_template('vulnerabilities_os.html', data=os_vulnerability_data)

@app.route("/top_10")
def top_10():
    header = _authentication.get_header()
    top_10 = _api_calls.top_n_agents(10,_authentication.url,header)
    return render_template('top_10.html', top_10=top_10)

@app.route("/common", methods=['GET', 'POST'])
def common():
    header = _authentication.get_header()
    vulnerabilities = _api_calls.get_vulnerabilities_with_agents(_authentication.url,header)
    selected_cve = request.form.get('cve')
    if selected_cve:
        # Filtrar agentes basado en el CVE seleccionado
        filtered_agents = {selected_cve: vulnerabilities[selected_cve]}
    else:
        filtered_agents = vulnerabilities

    return render_template(
        'common.html',
        vulnerabilities=vulnerabilities,
        filtered_agents=filtered_agents,
        selected_cve=selected_cve
        )


# =============================================
#    --> search vulnerability by agent
# =============================================

@app.route("/agent", methods=['GET', 'POST'])
def agent():
    header = _authentication.get_header()
    
    # Inicializamos una lista para almacenar los resultados de la búsqueda
    search_results = []
    
    if request.method == 'POST':
        # Obtener el nombre del agente del formulario si se envió
        agent_name = request.form.get('agent')
        
        # Obtener los detalles del agente por su nombre
        if agent_name:
            agent_info = _api_calls.agent_by_name(agent_name, _authentication.url, header)
            
            # Verificar si se obtuvo la información del agente correctamente
            if 'error' not in agent_info:
                search_results.append(agent_info)
        else:
            search_results = []
    
    # Renderizar la plantilla HTML con la información obtenida
    return render_template(
        'agent.html',
        search_results=search_results
    )

# =============================================
#    --> search vulnerability by key word
# =============================================

@app.route("/key_word")
def key_word():
    return render_template('key_word.html')

@app.route('/key_word', methods=['POST'])
def render_something():
    key_word = request.form['value']

    # Perform search with key word
    header = _authentication.get_header()
    vulnerability_by_key_word = _api_calls.vulnerabilities_by_keyword(key_word,_authentication.url,header)
    return render_template('key_word.html', vulnerability_by_key_word=vulnerability_by_key_word)

# =============================================
#    --> vulnerabilidades
# =============================================

@app.route("/vulnerabilities")
def vulnerabilities():
    header = _authentication.get_header()
    total, critical, high, medium, low = _api_calls.vulnerabilities_overview(_authentication.url, header)
    data = {
        'l_critical': len(critical),
        'l_high': len(high),
        'l_medium': len(medium),
        'l_low': len(low),    
        'p_critical': round(len(critical)*100/total,2),
        'p_high': round(len(high)*100/total,2),
        'p_medium': round(len(medium)*100/total,2),
        'p_low': round(len(low)*100/total,2),       
        'critical':critical[:10],
        'high':high[:10],
        'medium':medium[:10],
        'low':low[:10]
    }
    return render_template('vulnerabilities.html', data=data)



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)