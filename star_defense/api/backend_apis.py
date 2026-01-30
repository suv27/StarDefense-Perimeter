
import sys
import logging
import logging.config
# import star_defense.logparser.log_analizer as LogAnalizer
from star_defense.logparser.log_analizer import LogAnalizer
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from star_defense.waf.engine import WAFEngine



try:
    from uvicorn.config import LOGGING_CONFIG
    logging.config.dictConfig(LOGGING_CONFIG)
    logger = logging.getLogger("uvicorn.error")
except Exception:
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


app = FastAPI()
waf = WAFEngine()


@app.middleware("http")
async def waf_middleware(wafMiddlewareRequest: Request, call_next):    
    logAnalizerInstance = LogAnalizer(httpRequestData=wafMiddlewareRequest)
    request_payload = await logAnalizerInstance.extractAllHTTPPostData()
    waf_decision = waf.evaluate(request_payload)

    logger.info(f"/WAFEngine Decision: {waf_decision['action']}")

    if waf_decision["action"] == "BLOCK":
        return JSONResponse(
            status_code=403,
            content={
                "message": "Request blocked by WAF",
                "waf": waf_decision
            }
        )

    # Attach decision for downstream use (optional but powerful)
    wafMiddlewareRequest.state.waf = waf_decision

    return await call_next(wafMiddlewareRequest)

@app.get("/status")
async def get_status(statusRequest: Request):
    logger.info("/status API endpoint called")
    
    return {
        "message": "/status API is running successfully",
        "status_code": 200
    }

@app.post("/login")
async def login(request: Request):
    logger.info("/login API endpoint called")

    return {
        "status_code": 200,
        "message": "/login API is running successfully",
        "waf": request.state.waf
    }


# TODO: Future - Implement Authentication and Authorization for APIs
# TODO: Future - Implement detailed error handling and logging
# TODO: Design the WAF rule engine
# TODO: Implement FastAPI middleware
# TODO: Add attack classification
# TODO: Or shape this into a portfolio-ready README
