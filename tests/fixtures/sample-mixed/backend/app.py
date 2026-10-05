from flask import Flask
app = Flask(__name__)

@app.route("/api/hello")
def a():
    return "hello from python"
