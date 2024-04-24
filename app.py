from flask import Flask, render_template
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)