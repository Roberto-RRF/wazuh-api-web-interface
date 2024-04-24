from flask import Flask, render_template, request
import sys
sys.path.append('functions')
from functions import _api_calls , _authentication

app = Flask(__name__)

@app.route("/")
def home():
    return render_template(
        "index.html"
    )

@app.route("/top_10")
def top_10():
    header = _authentication.get_header()
    print(header)
    top_10 = _api_calls.top_n_agents(10,_authentication.url,header)
    return render_template('top_10.html', top_10=top_10)

@app.route("/common")
def common():
    return render_template(
        "common.html"
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