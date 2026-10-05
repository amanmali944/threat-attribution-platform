from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field

class UserCreate(BaseModel):
    tenant_id: str = Field(..., example="tenant-01")
    username: str = Field(..., example="analyst_jane")
    email: EmailStr = Field(..., example="jane@corp.com")
    password: str = Field(..., min_length=8)
    role: str = Field("analyst", example="analyst")

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
