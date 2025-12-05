from fastapi import FastAPI, Request
import logging
import logging.config
import sys
import src.LogParser.logAnalizer as logAnalizer
import base64
import json


try:
    from uvicorn.config import LOGGING_CONFIG
    logging.config.dictConfig(LOGGING_CONFIG)
    logger = logging.getLogger("uvicorn.error")
except Exception:
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")



app = FastAPI()
logger.info("/backendApis Module Initiated")


@app.get("/status")
def get_status():
    logger.info("/status API endpoint called")
    return {
        "message": "/status API is running successfully",
        "status_code": 200
    }

@app.post("/login")
async def login(loginRequest: Request):
    logger.info("/login API endpoint called")

    logAnalizerInstance = logAnalizer.LogAnalizer(httpRequestData=loginRequest)
    loginPostData = await logAnalizerInstance.extractAllHTTPDetails()

    return {"message": "/login API is running successfully", "status_code": 200, "httpData": loginPostData}
    



# TODO: Future - Implement Authentication and Authorization for APIs
# TODO: Future - Implement detailed error handling and logging
# 
