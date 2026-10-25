from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.events import router as events_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.entities import router as entities_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.evaluation import router as evaluation_router
from app.api.v1.graph import router as graph_router
from app.api.v1.summary import router as summary_router

api_v1_router = APIRouter()
api_v1_router.include_router(auth_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(entities_router)
api_v1_router.include_router(dashboard_router)
api_v1_router.include_router(evaluation_router)
api_v1_router.include_router(graph_router)
api_v1_router.include_router(summary_router)

