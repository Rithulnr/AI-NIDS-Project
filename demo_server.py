from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Demo Server Running"

@app.route("/data")
def data():
    return "data response"

if __name__ == "__main__":
    app.run(port=8000)