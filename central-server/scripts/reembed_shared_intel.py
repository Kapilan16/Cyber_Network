#!/usr/bin/env python
"""Re-embed central sanitized intel after a provider/model-space change.

Use the same configured provider/model and 1536-dimensional storage convention
as all contributing org-local instances. Set EMBEDDING_PROVIDER and any provider
credentials to match org-local instances. Quiesce central writes before running.
This command rolls back the rebuild if embedding fails.
"""
from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.embeddings import get_embeddings_client
from app.models import SharedIntel

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("reembed_shared_intel")


def main() -> None:
    client = get_embeddings_client()
    if settings.EMBEDDING_PROVIDER == "local_sentence_transformers":
        if not client.initialize():
            raise RuntimeError(
                "Configured central embedding model could not be loaded; "
                "existing vectors were not changed"
            )

    db: Session = SessionLocal()
    updated = 0
    try:
        for record in db.query(SharedIntel).order_by(SharedIntel.id).yield_per(100):
            if not record.sanitized_text:
                continue
            vector = client.embed(record.sanitized_text)
            if vector is None:
                raise RuntimeError(
                    f"Embedding failed for intel {record.id}; stopping rebuild"
                )
            if len(vector) != settings.CENTRAL_VECTOR_DIM:
                raise ValueError(
                    f"Embedding for intel {record.id} has {len(vector)} dimensions; "
                    f"expected {settings.CENTRAL_VECTOR_DIM}"
                )
            record.embedding = vector
            updated += 1
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    logger.info(
        "Re-embedded %d shared-intel records at %d dimensions.",
        updated,
        settings.CENTRAL_VECTOR_DIM,
    )


if __name__ == "__main__":
    main()
