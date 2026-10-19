"""
User ORM model.
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class UserRole(str, enum.Enum):
    analyst = "analyst"
    admin = "admin"


DEFAULT_ORGANIZATION_ID = 1


class User(Base):
    __tablename__ = "users"

    id: int = Column(Integer, primary_key=True, index=True)
    org_id: int = Column(
        Integer,
        ForeignKey("organizations.id"),
        nullable=False,
        default=DEFAULT_ORGANIZATION_ID,
        server_default=str(DEFAULT_ORGANIZATION_ID),
        index=True,
    )
    email: str = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password: str = Column(String(255), nullable=False)
    role: UserRole = Column(
        Enum(UserRole, name="userrole"),
        nullable=False,
        default=UserRole.analyst,
        server_default=UserRole.analyst.value,
    )
    created_at: datetime = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ── Relationships ─────────────────────────────────────────────────────
    submissions = relationship(
        "RawSubmission", back_populates="submitter", lazy="dynamic"
    )
    organization = relationship("Organization", back_populates="users")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id} email={self.email!r} role={self.role}>"
