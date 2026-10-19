"""Organization model for the org-local deployment."""
import enum
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class OrganizationStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"


class Organization(Base):
    __tablename__ = "organizations"

    id: int = Column(Integer, primary_key=True, index=True)
    name: str = Column(String(255), nullable=False)
    # Org-local installations do not hold central registration credentials.
    api_key_hash: str | None = Column(String(64), nullable=True)
    registered_at: datetime = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    status: OrganizationStatus = Column(
        Enum(
            OrganizationStatus,
            name="organizationstatus",
            native_enum=False,
            create_constraint=True,
        ),
        nullable=False,
        default=OrganizationStatus.active,
        server_default=OrganizationStatus.active.value,
    )
    contact_email: str | None = Column(String(320), nullable=True)
    share_with_network: bool = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    users = relationship("User", back_populates="organization")
