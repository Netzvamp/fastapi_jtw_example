from conf import config
from fastapi import FastAPI
from routes import auth


app = FastAPI()

app.include_router(auth.router, prefix="/auth", tags=["auth"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_config="logging.conf")