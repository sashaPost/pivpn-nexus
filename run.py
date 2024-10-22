import uvicorn
from app.main import app
from app.logging_utility import logger


if __name__=='__main__':
    logger.info("Starting PiVPN Nexus application")
    # uvicorn.run(app, host='0.0.0.0', port=8000)
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
