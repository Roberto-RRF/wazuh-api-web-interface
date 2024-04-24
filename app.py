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

@app.route("/key_word")
def key_word():


    return render_template('key_words.html')

@app.route('/key_word', methods=['POST'])
def render_something():
    key_word = request.form['value']

    # Perform search with key word
    header = _authentication.get_header()
    vulnerability_by_key_word = _api_calls.vulnerabilities_by_keyword(key_word,_authentication.url,header)
    return render_template('key_words.html', vulnerability_by_key_word=vulnerability_by_key_word)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)