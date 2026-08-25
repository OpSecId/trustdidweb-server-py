"""Attested resource verify, store, and update helpers."""

import copy
import logging
from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.db.models import DidControllerRecord
from app.utilities import digest_multibase
from config import settings

from .askar import AskarVerifier
from .didwebvh import DidWebVH
from .storage import StorageManager

logger = logging.getLogger(__name__)

webvh = DidWebVH()
storage = StorageManager()
verifier = AskarVerifier()


@dataclass(frozen=True)
class ControllerSnapshot:
    """Detached DID controller fields safe to use from a worker thread."""

    namespace: str
    alias: str
    scid: str
    document: dict


def snapshot_controller(did_controller: DidControllerRecord) -> ControllerSnapshot:
    """Load controller columns on the request thread before offloading work."""
    return ControllerSnapshot(
        namespace=did_controller.namespace,
        alias=did_controller.alias,
        scid=did_controller.scid,
        document=did_controller.document,
    )


def _resource_id_from_payload(secured_resource: dict) -> str:
    """Return the content-addressed resource id from metadata or the resource URI."""
    metadata = secured_resource.get("metadata") or {}
    if resource_id := metadata.get("resourceId"):
        return resource_id
    return secured_resource.get("id", "").split("/")[-1].split(".")[0]


def stored_resource_if_idempotent(resource_id: str, secured_resource: dict) -> dict | None:
    """Return the stored resource when this POST is a safe retry of the same content.

    Raises:
        HTTPException: 409 if the id exists with different content.
    """
    existing = storage.get_resource(resource_id)
    if not existing:
        return None
    stored = existing.attested_resource
    if digest_multibase(stored.get("content")) == digest_multibase(secured_resource.get("content")):
        logger.info("Resource %s already stored; returning existing record", resource_id)
        return stored
    raise HTTPException(
        status_code=409,
        detail=(
            f"Resource already exists with ID '{resource_id}' and different content. "
            "Use PUT to update metadata or links."
        ),
    )


def _create_or_return_existing(scid: str, secured_resource: dict) -> tuple[int, dict]:
    """Insert a resource, or return 200 when the same content-addressed id already exists."""
    resource_id = _resource_id_from_payload(secured_resource)
    if existing := stored_resource_if_idempotent(resource_id, secured_resource):
        return 200, existing
    try:
        storage.create_resource(scid, secured_resource)
    except IntegrityError:
        logger.warning("Resource %s already exists (integrity error)", resource_id)
        if existing := stored_resource_if_idempotent(resource_id, secured_resource):
            return 200, existing
        raise HTTPException(
            status_code=409,
            detail=(
                f"Resource already exists with ID '{resource_id}'. "
                "Use PUT to update metadata or links."
            ),
        ) from None
    return 201, secured_resource


def _verify_endorsement(secured_resource: dict, proofs: list) -> None:
    """Validate witness endorsement when the server policy requires it."""
    if not settings.WEBVH_ENDORSEMENT:
        return
    resource = copy.deepcopy(secured_resource)
    resource.pop("proof", None)
    try:
        assert len(proofs) == 2
        witness_proof = next(
            (proof for proof in proofs if proof["verificationMethod"].startswith("did:key:")),
            None,
        )
        registry = storage.get_registry("knownWitnesses")
        witness_registry = registry.registry_data if registry else {}
        witness_id = witness_proof.get("verificationMethod").split("#")[0]
        assert witness_registry.get(witness_id, None)
        assert verifier.verify_proof(resource, witness_proof, witness_id.split(":")[-1])
    except (AssertionError, TypeError, AttributeError) as e:
        logger.error(f"Endorsement validation failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid endorsement witness proof.") from e


def verify_and_store_resource(
    secured_resource: dict, proofs: list, controller: ControllerSnapshot
) -> tuple[int, dict]:
    """Verify proofs, validate the resource, and store it (idempotent)."""
    _verify_endorsement(secured_resource, proofs)

    author_id = secured_resource["proof"].get("verificationMethod").split("#")[0]
    if (
        len(author_id.split(":")) != 6
        or author_id.split(":")[4] != controller.namespace
        or author_id.split(":")[5] != controller.alias
    ):
        raise HTTPException(status_code=400, detail="Invalid author id value.")

    try:
        verifier.verify_resource_proof(copy.deepcopy(secured_resource), controller.document)
    except HTTPException as e:
        logger.error(f"Resource proof validation failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid resource proof.") from e

    try:
        webvh.validate_resource(copy.deepcopy(secured_resource))
    except HTTPException as e:
        logger.error(f"Resource validation failed: {e.status_code} - {e.detail}")
        raise HTTPException(status_code=400, detail=f"Invalid resource: {e.detail}") from e

    return _create_or_return_existing(controller.scid, secured_resource)


def verify_and_update_resource(
    resource_id: str, secured_resource: dict, controller: ControllerSnapshot
) -> dict:
    """Verify proofs, validate immutability, and update metadata/links."""
    try:
        verifier.verify_resource_proof(copy.deepcopy(secured_resource), controller.document)
    except HTTPException as e:
        logger.error(f"Resource proof validation failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid resource proof.") from e

    try:
        webvh.validate_resource(copy.deepcopy(secured_resource))
    except HTTPException as e:
        logger.error(f"Resource validation failed: {e.status_code} - {e.detail}")
        raise HTTPException(status_code=400, detail=f"Invalid resource: {e.detail}") from e

    if not (existing_resource := storage.get_resource(resource_id)):
        raise HTTPException(status_code=404, detail="Couldn't find resource.")

    webvh.compare_resource(
        copy.deepcopy(existing_resource.attested_resource), copy.deepcopy(secured_resource)
    )
    storage.update_resource(secured_resource)
    return secured_resource
