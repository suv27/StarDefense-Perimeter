import logging
import json
import os

logger = logging.getLogger("uvicorn.error")

class LogAnalizer:
    def __init__(self, httpRequestData):
        logger.info("/LogAnalizer Class Initiated")
        self.httpRequestData = httpRequestData
    
    async def extractAllHTTPDetails(self):
        logger.info("/extractAllHTTPDetails Method Initiated")

        payload = {
            "method": self.httpRequestData.method,
            "url": str(self.httpRequestData.url),
            "path": self.httpRequestData.url.path,
            "query_string": self.httpRequestData.scope.get("query_string", b"").decode("utf-8", "replace"),
            "query_params": dict(self.httpRequestData.query_params),
            "path_params": dict(self.httpRequestData.path_params),
            "cookies": dict(self.httpRequestData.cookies),
            "client": {"host": self.httpRequestData.client.host, "port": self.httpRequestData.client.port} if self.httpRequestData.client else None,
            "scope": {
                "server": self.httpRequestData.scope.get("server"),
                "scheme": self.httpRequestData.scope.get("scheme"),
                "http_version": self.httpRequestData.scope.get("http_version"),
            },
            "headers": dict(self.httpRequestData.headers),
            "connection": self.httpRequestData.scope.get("connection"),
            "content_type": self.httpRequestData.headers.get("content-type"),
            "content_length": self.httpRequestData.headers.get("content-length"),
            "transfer_encoding": self.httpRequestData.headers.get("transfer-encoding"),
            "content_encoding": self.httpRequestData.headers.get("content-encoding"),
            "authorization": self.httpRequestData.headers.get("authorization"),
            "user_agent": self.httpRequestData.headers.get("user-agent"),
            "accept": self.httpRequestData.headers.get("accept"),
            "host_header": self.httpRequestData.headers.get("host"),
            "origin": self.httpRequestData.headers.get("origin"),
            "referer": self.httpRequestData.headers.get("referer"),
            "x_forwarded_for": self.httpRequestData.headers.get("x-forwarded-for"),
            "x_forwarded_proto": self.httpRequestData.headers.get("x-forwarded-proto", None),
            "x_real_ip": self.httpRequestData.headers.get("x-real-ip"),
            "accept_encoding": self.httpRequestData.headers.get("accept-encoding"),
            "accept_language": self.httpRequestData.headers.get("accept-language"),
            "cache_control": self.httpRequestData.headers.get("cache-control"),
            "pragma": self.httpRequestData.headers.get("pragma"),
            "if_modified_since": self.httpRequestData.headers.get("if-modified-since"),
            "if_none_match": self.httpRequestData.headers.get("if-none-match"),
            "range": self.httpRequestData.headers.get("range"),
            "sec_ch_ua": self.httpRequestData.headers.get("sec-ch-ua"),
            "sec_ch_ua_mobile": self.httpRequestData.headers.get("sec-ch-ua-mobile"),
            "sec_ch_ua_platform": self.httpRequestData.headers.get("sec-ch-ua-platform"),
            "sec_fetch_site": self.httpRequestData.headers.get("sec-fetch-site"),
            "sec_fetch_mode": self.httpRequestData.headers.get("sec-fetch-mode"),
            "sec_fetch_dest": self.httpRequestData.headers.get("sec-fetch-dest"),
            "dnt": self.httpRequestData.headers.get("dnt"),
            "upgrade_insecure_requests": self.httpRequestData.headers.get("upgrade-insecure-requests"),
            "via": self.httpRequestData.headers.get("via"),
            "forwarded": self.httpRequestData.headers.get("forwarded"),
            "x_request_id": self.httpRequestData.headers.get("x-request-id"),
            "x_correlation_id": self.httpRequestData.headers.get("x_correlation_id"),
            "traceparent": self.httpRequestData.headers.get("traceparent"),
            "tracestate": self.httpRequestData.headers.get("tracestate"),
            "x_amzn_trace_id": self.httpRequestData.headers.get("x-amzn-trace-id"),
            "cf_connecting_ip": self.httpRequestData.headers.get("cf-connecting-ip"),
            "true_client_ip": self.httpRequestData.headers.get("true-client-ip"),
            "body_size": len(await self.httpRequestData.body()),
            "body": (json.loads((await self.httpRequestData.body()).decode("utf-8")))
        }

        # parsedPayload = self.parseTraffic(payload)
        self.logPayload(payload)
        return payload


    def parseTraffic(self, payload):
        # catch all the details of the HTTP Traffic
        # TODO: implement the logic to parse HTTP traffic extractAllHTTPDetails(self):
        pass
        

    def logPayload(self, parsedPayload):
        # log the payload details into a file in a correct format for future dashboard on the frontend UI

        try:
            filename = "http_events_log.txt"

            with open(filename, "a", encoding="utf-8") as log_file:
                json.dump(parsedPayload, log_file, ensure_ascii=False)
                log_file.write("\n")
        except Exception:
            logger.exception("Failed to write http event to log file")
        