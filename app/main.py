from fastapi import FastAPI

from .routers import npm

app = FastAPI()

app.include_router(npm.router)
