#!/usr/bin/env python
"""Rebuild org-local submission and rule-description embeddings.

Run after changing EMBEDDING_PROVIDER or LOCAL_EMBEDDING_MODEL, with the
org-local API stopped or otherwise quiesced. The default provider falls back
to feature hashing if the model cannot load, so this command explicitly checks
the configured local model before rewriting existing vectors.
"""
from __future__ import annotations

import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.embeddings.client import EmbeddingsClient
from app.models.raw_submission import EmbeddingStatus, RawSubmission
from app.models.rule import Rule

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("reembed_local_vectors")


def main() -> None:
    client = EmbeddingsClient()
    if settings.EMBEDDING_PROVIDER == "local_sentence_transformers":
        if not client.initialize():
            raise RuntimeError(
                "Configured local model could not be loaded; existing vectors were not changed"
            )

    engine = create_engine(settings.DATABASE_URL)
    session_factory = sessionmaker(bind=engine)
    updated_submissions = 0
    updated_rules = 0
    with session_factory() as db:
        for submission in db.query(RawSubmission).filter(
            RawSubmission.sanitized_text.is_not(None)
        ):
            vector = client.embed(submission.sanitized_text or "")
            if vector is None:
                raise RuntimeError(
                    f"Embedding failed for submission {submission.id}; stopping before completion"
                )
            submission.embedding = (
                json.dumps(vector) if db.bind.dialect.name == "sqlite" else vector
            )
            submission.embedding_status = EmbeddingStatus.complete
            updated_submissions += 1

        for rule in db.query(Rule).filter(Rule.description.is_not(None)):
            vector = client.embed(rule.description or "")
            if vector is None:
                raise RuntimeError(
                    f"Embedding failed for rule {rule.id}; stopping before completion"
                )
            rule.description_embedding = (
                json.dumps(vector) if db.bind.dialect.name == "sqlite" else vector
            )
            updated_rules += 1
        db.commit()

    engine.dispose()
    logger.info(
        "Re-embedded %d submissions and %d rule descriptions at %d dimensions.",
        updated_submissions,
        updated_rules,
        settings.VECTOR_DIM,
    )


if __name__ == "__main__":
    main()
