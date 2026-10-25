from datetime import datetime
from ipaddress import ip_address

from pydantic import BaseModel, Field, field_validator


class SecurityEvent(BaseModel):
    event_id: int
    timestamp: datetime
    username: str = Field(min_length=1)
    source_ip: str
    hostname: str = Field(min_length=1)
    message: str

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        ip_address(value)
        return value
