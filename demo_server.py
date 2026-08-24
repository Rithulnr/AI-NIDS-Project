from flask import Flask, request, Response
import requests
from neutralization import tarpitted_ips

app = Flask(__name__)

@app.before_request
def check_tarpit():
    ip = request.remote_addr
    if ip in tarpitted_ips or ip == "127.0.0.1": # for local testing, we might want to tarpit localhost if we simulate an attack from it, but let's just check the set.
        pass # Wait, if we test locally, the IP is always 127.0.0.1.
    
    if ip in tarpitted_ips:
        print(f"[DEMO_SERVER] IP {ip} is tarpitted. Proxying to AI Tarpit...")
        # Act as a reverse proxy to the tarpit server
        tarpit_url = f"http://127.0.0.1:5051/{request.full_path}"
        try:
            resp = requests.request(
                method=request.method,
                url=tarpit_url,
                headers={key: value for (key, value) in request.headers if key != 'Host'},
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False
            )
            
            headers = [(name, value) for (name, value) in resp.raw.headers.items()]
            response = Response(resp.content, resp.status_code, headers)
            return response
        except Exception as e:
            return f"Tarpit Offline: {e}", 500

@app.route("/")
def home():
    return "Demo Server Running"

@app.route("/data")
def data():
    return "data response"

if __name__ == "__main__":
    app.run(port=8000)