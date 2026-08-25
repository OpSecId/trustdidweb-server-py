"""Ressource management endpoints."""

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from app.models.web_schemas import ResourceUpload
from app.db.models import DidControllerRecord
from app.utilities import first_proof
from app.dependencies import get_did_controller_dependency
from app.plugins.attested_resources import (
    snapshot_controller,
    storage,
    verify_and_store_resource,
    verify_and_update_resource,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Attested Resources"])


@router.post("/{namespace}/{alias}/resources")
async def upload_attested_resource(
    request_body: ResourceUpload,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
):
    """Upload an attested resource."""
    logger.info(f"=== Uploading resource for {did_controller.namespace}/{did_controller.alias} ===")

    secured_resource = vars(request_body)["attestedResource"].model_dump()
    proofs = secured_resource.get("proof")
    proofs = proofs if isinstance(proofs, list) else [proofs]

    secured_resource["proof"] = next(
        (proof for proof in proofs if proof["verificationMethod"].startswith("did:webvh:")), None
    )

    status_code, body = await asyncio.to_thread(
        verify_and_store_resource,
        secured_resource,
        proofs,
        snapshot_controller(did_controller),
    )
    return JSONResponse(status_code=status_code, content=body)


@router.put("/{namespace}/{alias}/resources/{resource_id}")
async def update_attested_resource(
    resource_id: str,
    request_body: ResourceUpload,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
):
    """Update an attested resource."""
    logger.info(f"=== Updating resource for {did_controller.namespace}/{did_controller.alias} ===")

    secured_resource = vars(request_body)["attestedResource"].model_dump()
    secured_resource["proof"] = first_proof(secured_resource["proof"])

    body = await asyncio.to_thread(
        verify_and_update_resource,
        resource_id,
        secured_resource,
        snapshot_controller(did_controller),
    )
    return JSONResponse(status_code=200, content=body)


@router.get("/{namespace}/{alias}/resources/{resource_id}")
async def get_resource(
    resource_id: str, did_controller: DidControllerRecord = Depends(get_did_controller_dependency)
):
    """Fetch existing resource."""
    logger.info(f"=== Fetching resource for {did_controller.namespace}/{did_controller.alias} ===")

    resource = await asyncio.to_thread(storage.get_resource, resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Couldn't find resource.")

    return JSONResponse(status_code=200, content=resource.attested_resource)
