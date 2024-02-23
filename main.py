from fastapi import FastAPI
from routes.route import router
from fastapi.middleware.cors import CORSMiddleware
import os

os.makedirs("data", exist_ok=True)

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
