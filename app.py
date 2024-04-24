from flask import Flask, render_template
import sys
sys.path.append('src')
from . import _api_calls

app = Flask(__name__)

@app.route("/")
def home():
    return render_template(
        "index.html"
    )

@app.route("/top_10")
def top_10():
    countries = [
        ('United States', '65%'),
        ('UK', '15.7%'),
        ('Russia', '5.8%'),
        ('Spain', '2.1%'),
        ('India', '1.9%'),
        ('France', '1.5%')
    ]
    header=_api_calls.get_header()
    print(header)
    return render_template('top_10.html', countries=countries)

@app.route("/common")
def common():
    return render_template(
        "common.html"
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)