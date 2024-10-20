from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
# from typing import List
from .vpn_manager import AdvancedVPNNexusManager


app = FastAPI(title="PiVPN Nexus")
vpn_manager = AdvancedVPNNexusManager('/etc/vpn_nexus_manager.conf')

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


class VPNProvider(BaseModel):
    name: str
    config_path: str


@app.get("/")
async def home(request: Request):
    status = vpn_manager.get_status()
    return templates.TemplateResponse("index.html", {"request": request, "status": status})


@app.get("/vpn_providers")
async def list_vpn_providers(request: Request):
    providers = vpn_manager.list_providers()
    return templates.TemplateResponse("vpn_providers.html", {"request": request, "providers": providers})


@app.post("/vpn_providers")
async def add_vpn_provider(request: Request, name: str = Form(...), config_path: str = Form(...)):
    success = vpn_manager.add_provider(name, config_path)
    if success:
        return templates.TemplateResponse("vpn_provider_added.html", {"request": request, "name": name})
    else:
        raise HTTPException(status_code=400, detail="Failed to add VPN provider")


@app.delete("/vpn_providers/{provider_name}")
async def delete_vpn_provider(provider_name: str):
    success = vpn_manager.delete_provider(provider_name)
    if success:
        return True
    else:
        raise HTTPException(status_code=404, detail="VPN provider not found")


@app.get("/optimize_vpn_chain")
async def optimize_vpn_chain(request: Request):
    vpn_manager.optimize_vpn_chain()
    return templates.TemplateResponse("vpn_chain.html", {"request": request, "chain": vpn_manager.vpn_chain})


@app.get("/traffic_stats")
async def get_traffic_stats():
    return vpn_manager.get_traffic_stats()


@app.get("/dns_leak_status")
async def get_dns_leak_status():
    return {"dns_leak_status": vpn_manager.dns_leak_status}


@app.post("/enable_pfs")
async def enable_pfs():
    vpn_manager.enable_pfs()
    return {"message": "Perfect Forward Secrecy enabled"}
