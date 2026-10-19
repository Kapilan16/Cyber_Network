"""API schemas for central organization registration."""
from datetime import datetime

import re
import math

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.config import settings
from app.models import OrganizationStatus


class OrganizationRegistration(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    contact_email: EmailStr | None = None

    @field_validator("name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Organization name must not be blank")
        return value


class OrganizationRegistrationResult(BaseModel):
    id: int
    name: str
    api_key: str
    registered_at: datetime


class OrganizationListItem(BaseModel):
    name: str
    status: OrganizationStatus

    model_config = {"from_attributes": True}


class OrganizationIdentity(BaseModel):
    id: int
    name: str
    status: OrganizationStatus

    model_config = {"from_attributes": True}


class DemoOrganizationRegistration(BaseModel):
    id: int
    name: str
    api_key: str


class DemoOrganizationBootstrapResponse(BaseModel):
    organizations: list[DemoOrganizationRegistration]


class SharedIntelPayload(BaseModel):
    """Strict allow-list schema matching the org-local outbound payload."""

    model_config = ConfigDict(extra="forbid")

    sanitized_text: str = Field(max_length=50_000)
    rule_categories: list[str] = Field(default_factory=list, max_length=100)
    mitre_technique_ids: list[str] = Field(default_factory=list, max_length=100)
    severity: list[str] = Field(default_factory=list, max_length=4)
    embedding: list[float] | None = None

    @field_validator("rule_categories")
    @classmethod
    def validate_categories(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            category = value.strip()
            if not category or len(category) > 80:
                raise ValueError("Rule categories must be non-empty and at most 80 characters")
            normalized.append(category)
        return sorted(set(normalized))

    @field_validator("mitre_technique_ids")
    @classmethod
    def validate_techniques(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            technique_id = value.strip().upper()
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
                raise ValueError(f"Invalid MITRE technique ID: {value}")
            normalized.append(technique_id)
        return sorted(set(normalized))

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, values: list[str]) -> list[str]:
        allowed = {"low", "medium", "high", "critical"}
        normalized = [value.strip().lower() for value in values]
        if any(value not in allowed for value in normalized):
            raise ValueError("Severity must contain only low, medium, high, or critical")
        return sorted(set(normalized))

    @field_validator("embedding")
    @classmethod
    def validate_embedding(cls, values: list[float] | None) -> list[float] | None:
        if values is None:
            return None
        if len(values) != settings.CENTRAL_VECTOR_DIM:
            raise ValueError(
                f"Embedding must contain exactly {settings.CENTRAL_VECTOR_DIM} values"
            )
        if any(not math.isfinite(value) for value in values):
            raise ValueError("Embedding values must be finite numbers")
        return values


class SharedIntelSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    embedding: list[float]
    top_k: int = Field(default=10, ge=1, le=50)

    @field_validator("embedding")
    @classmethod
    def validate_search_embedding(cls, values: list[float]) -> list[float]:
        if len(values) != settings.CENTRAL_VECTOR_DIM:
            raise ValueError(
                f"Embedding must contain exactly {settings.CENTRAL_VECTOR_DIM} values"
            )
        if any(not math.isfinite(value) for value in values):
            raise ValueError("Embedding values must be finite numbers")
        return values


class SharedIntelSearchResult(BaseModel):
    sanitized_text: str
    mitre_technique_ids: list[str]
    severity: list[str]
    similarity_score: float


class SharedIntelSearchResponse(BaseModel):
    results: list[SharedIntelSearchResult]
    total_found: int
