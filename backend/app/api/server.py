"""Production entry point: services from the environment + metrics + all routers."""

from fastapi import FastAPI

from app.api.app import create_app, services_from_env
from app.ops.metrics import Metrics


def build_app() -> FastAPI:
    return create_app(services_from_env(), metrics=Metrics())
