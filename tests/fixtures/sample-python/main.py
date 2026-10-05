from fastapi import FastAPI
import uvicorn
import subprocess

app = FastAPI()

@app.get("/items/{x1}")
def handler2(x1: str):
    # Obfuscated / AI-generated function with meaningless identifiers
    tmp = f"SELECT * FROM items WHERE id = '{x1}'"
    return {"query": tmp}

def a(x):
    # Dangerous subprocess execution in generic function name
    return subprocess.run(x, shell=True)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
