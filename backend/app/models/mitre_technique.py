"""
MitreTechnique ORM model — local reference table seeded from
backend/app/data/mitre_techniques.json.
"""
from __future__ import annotations

from sqlalchemy import Column, String, Text

from app.core.database import Base


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    # id is the ATT&CK technique identifier, e.g. "T1059.001"
    id: str = Column(String(20), primary_key=True, index=True)
    name: str = Column(String(255), nullable=False)
    tactic: str = Column(String(100), nullable=False, index=True)
    description: str = Column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MitreTechnique id={self.id!r} name={self.name!r} tactic={self.tactic!r}>"
