#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
import ipaddress
from ipwhois import IPWhois
from datetime import datetime

app = FastAPI(title="WhoisScanService", version="1.0")

# ----- REQUEST MODEL -----
class WhoisRequest(BaseModel):
    target: str = Field(..., description="IPv4/IPv6 address to lookup")
    confirm: bool = Field(False, description="Must be true to authorize lookup")

# ----- ENDPOINTS -----
@app.post("/whois")
def whois_lookup(req: WhoisRequest):
    if not req.confirm:
        raise HTTPException(status_code=400, detail="You must set confirm=true to authorize whois lookup.")

    # validate IP
    try:
        ipaddress.ip_address(req.target)
    except Exception:
        raise HTTPException(status_code=400, detail="Target must be a valid IP address.")

    try:
        obj = IPWhois(req.target)
        result = obj.lookup_rdap(asn_methods=["whois", "http"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Whois lookup failed: {str(e)}")

    return {
        "target": req.target,
        "queried_at": datetime.utcnow().isoformat() + "Z",
        "whois_data": result
    }

@app.get("/health")
def health():
    return {"status": "ok", "service": "whois"}
