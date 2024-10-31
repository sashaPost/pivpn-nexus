from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .vpn_manager import AdvancedVPNNexusManager
from .logging_utility import logger


app = FastAPI(title="PiVPN Nexus")
vpn_manager = AdvancedVPNNexusManager('config/vpn_nexus_manager.conf')
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


class VPNProvider(BaseModel):
    name: str
    config_path: str

@app.get("/")
async def home(request: Request):
    """Home page with current IP display"""
    try:
        current_ip = vpn_manager.get_current_ip()
        return templates.TemplateResponse("index.html", {
            "request": request,
            "current_ip": current_ip
        })
    except Exception as e:
        logger.error(f"Error in home route: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/setup_chain")
async def setup_chain(num_hops: int = 2):
    """Set up VPN chain with specified number of hops"""
    try:
        success = vpn_manager.setup_vpn_chain(num_hops)
        if success:
            return {"status": "success", "message": f"VPN chain with {num_hops} hops established"}
        else:
            raise HTTPException(status_code=500, detail="Failed to set up VPN chain")
    except Exception as e:
        logger.error(f"Error setting up VPN chain: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to set up VPN chain")


@app.post("/cleanup_chain")
async def cleanup_chain():
    """Clean up all VPN connections and SOCKS proxies"""
    try:
        vpn_manager.cleanup_vpn_chain()
        return {"status": "success", "message": "VPN chain cleaned up"}
    except Exception as e:
        logger.error(f"Error cleaning up VPN chain: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to clean up VPN chain")


@app.get("/current_ip")
async def get_current_ip():
    """Get current public IP address through the VPN chain"""
    try:
        ip = vpn_manager.get_current_ip()
        if ip:
            return {"ip": ip}
        else:
            raise HTTPException(status_code=500, detail="Failed to get current IP")
    except Exception as e:
        logger.error(f"Error getting current IP: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get current IP")
