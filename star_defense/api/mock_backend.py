# star_defense/api/mock_backend.py

from fastapi import FastAPI, Request, Header
import uvicorn
import logging

logger = logging.getLogger("uvicorn.error")

app = FastAPI()

@app.get("/status")
async def status():
    return {"message": "Backend: Status OK"}

@app.post("/login")
async def login(request: Request, x_stardefense_verified: str = Header(None)):
    # The backend can check this header to see if StarDefense vetted the request
    
    logger.info("/status API endpoint called")
    return {
        "message": "Backend: /login Successful",
        "status_code": 200,
        "verified_by_stardefense": x_stardefense_verified
    }


if __name__ == "__main__":
    uvicorn.run("star_defense.api.mock_backend:app", host="127.0.0.1", port=8080, reload=True)
