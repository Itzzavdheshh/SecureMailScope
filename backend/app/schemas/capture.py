"""
Capture Pydantic schemas.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class CaptureBase(BaseModel):
    filename: str
    file_path: str
    file_size_bytes: int
    sha256_hash: str


class CaptureCreate(CaptureBase):
    pass


class CaptureRead(CaptureBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    total_packets: int
    capture_start_time: Optional[datetime] = None
    capture_end_time: Optional[datetime] = None
    status: str
    created_at: datetime
    updated_at: datetime
