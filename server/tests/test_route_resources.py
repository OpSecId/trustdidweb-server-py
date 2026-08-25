"""Unit tests for the resources endpoints."""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.plugins.attested_resources import stored_resource_if_idempotent

from app import app
from app.plugins.storage import StorageManager
from tests.fixtures import (
    TEST_DID_NAMESPACE,
    TEST_VERSION_TIME,
    TEST_POLICY,
    TEST_WITNESS_KEY,
    TEST_WITNESS_REGISTRY,
    TEST_UPDATE_KEY,
)
from tests.mock_agents import WitnessAgent, ControllerAgent
from tests.mock_agents import sign
from tests.helpers import (
    create_unique_did,
    setup_controller_with_verification_method,
    create_test_resource,
    create_test_namespace_and_alias,
    assert_error_response,
)
from did_webvh.core.state import DocumentState

# Setup test agents
witness = WitnessAgent()
controller = ControllerAgent()


def test_stored_resource_conflict_when_content_differs(monkeypatch):
    """Same resource id with different content is a 409, not a silent overwrite."""

    class _Existing:
        attested_resource = {"content": {"name": "original"}}

    monkeypatch.setattr(
        "app.plugins.attested_resources.storage.get_resource",
        lambda resource_id: _Existing(),
    )
    with pytest.raises(HTTPException) as exc:
        stored_resource_if_idempotent("zQm123", {"content": {"name": "other"}})
    assert exc.value.status_code == 409
    assert "already exists" in exc.value.detail


@pytest.fixture(autouse=True)
async def setup_database():
    """Set up the database before each test."""
    storage = StorageManager()
    await storage.provision(recreate=True)

    # Store policy and registry in database
    storage.create_or_update_policy("active", TEST_POLICY)
    storage.create_or_update_registry(
        registry_id="knownWitnesses",
        registry_type="witnesses",
        registry_data=TEST_WITNESS_REGISTRY,
        meta={"created": "2024-01-01T00:00:00Z", "updated": "2024-01-01T00:00:00Z"},
    )
    yield


class TestUploadResource:
    """Test cases for uploading attested resources."""

    def create_test_resource(self, issuer_id: str, resource_type: str = "testResource"):
        """Helper to create a test attested resource."""
        content = {
            "name": "Test Resource",
            "description": "A test resource for unit testing",
            "version": "1.0",
            "data": {"key": "value", "number": 42},
        }

        attested_resource, resource_id = controller.attest_resource(content, resource_type)
        # Add witness endorsement
        resource_for_witness = attested_resource.copy()
        controller_proof = resource_for_witness.pop("proof")
        if not isinstance(controller_proof, list):
            controller_proof = [controller_proof]
        witness_signed = witness.sign(resource_for_witness)
        witness_proof = witness_signed.get("proof", [])
        if not isinstance(witness_proof, list):
            witness_proof = [witness_proof]
        attested_resource["proof"] = controller_proof + witness_proof
        return attested_resource, resource_id

    @pytest.mark.asyncio
    async def test_upload_resource_success(self):
        """Test successful resource upload."""
        test_namespace, test_alias = create_test_namespace_and_alias("res-upload-01")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Create test resource with witness endorsement
            attested_resource, resource_id = create_test_resource(
                controller, "testResource", witness=witness
            )

            # Upload resource
            response = test_client.post(
                f"/{test_namespace}/{test_alias}/resources",
                json={"attestedResource": attested_resource},
            )
            assert response.status_code == 201
            upload_response = response.json()

            # Get the actual resource ID from the uploaded resource
            actual_resource_id = upload_response["metadata"]["resourceId"]

            # Verify resource was stored
            response = test_client.get(
                f"/{test_namespace}/{test_alias}/resources/{actual_resource_id}"
            )
            assert response.status_code == 200
            stored_resource = response.json()
            assert stored_resource["metadata"]["resourceId"] == actual_resource_id

    @pytest.mark.asyncio
    async def test_upload_resource_duplicate_same_content_is_idempotent(self):
        """Retrying POST of the same resource returns 200 with the stored record."""
        test_namespace, test_alias = create_test_namespace_and_alias("res-dup-same")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )
            attested_resource, resource_id = create_test_resource(
                controller, "testResource", witness=witness
            )

            first = test_client.post(
                f"/{test_namespace}/{test_alias}/resources",
                json={"attestedResource": attested_resource},
            )
            assert first.status_code == 201

            retry = test_client.post(
                f"/{test_namespace}/{test_alias}/resources",
                json={"attestedResource": attested_resource},
            )
            assert retry.status_code == 200
            assert retry.json()["metadata"]["resourceId"] == first.json()["metadata"]["resourceId"]
            assert retry.json()["content"] == first.json()["content"]

    @pytest.mark.asyncio
    async def test_upload_resource_invalid_proof(self):
        """Test resource upload with invalid proof."""
        test_namespace, test_alias = create_test_namespace_and_alias("res-invalid-proof")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Create resource with valid signature first
            attested_resource, resource_id = create_test_resource(
                controller, "testResource", witness=witness
            )

            # Now tamper with the controller proof (first proof in list)
            if isinstance(attested_resource["proof"], list):
                attested_resource["proof"][0]["proofValue"] = "z" + "1" * 87
            else:
                attested_resource["proof"]["proofValue"] = "z" + "1" * 87

            response = test_client.post(
                f"/{test_namespace}/{test_alias}/resources",
                json={"attestedResource": attested_resource},
            )

            # Should fail with invalid proof
            assert_error_response(response, 400, "Invalid resource proof")

    @pytest.mark.asyncio
    async def test_upload_resource_invalid_author(self):
        """Test resource upload with wrong author ID."""
        test_namespace, test_alias = create_test_namespace_and_alias("resource03")

        with TestClient(app) as test_client:
            # Create DID
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Create resource with wrong issuer ID
            wrong_issuer_id = "did:webvh:wrongscid:example.com:wrong:namespace"
            attested_resource, resource_id = self.create_test_resource(wrong_issuer_id)

            response = test_client.post(
                f"/{test_namespace}/{test_alias}/resources",
                json={"attestedResource": attested_resource},
            )

            # Should fail with invalid author
            assert_error_response(response, 400, "Invalid author id value")

    @pytest.mark.asyncio
    async def test_upload_resource_nonexistent_did(self):
        """Test resource upload for non-existent DID."""
        with TestClient(app) as test_client:
            attested_resource = {
                "@context": [
                    "https://identity.foundation/didwebvh/contexts/v1",
                    "https://w3id.org/security/data-integrity/v2",
                ],
                "type": ["AttestedResource"],
                "id": "did:webvh:test/resources/abc123",
                "content": {"test": "data"},
                "metadata": {"resourceId": "abc123", "resourceType": "testResource"},
                "proof": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": "did:webvh:test#key",
                    "proofValue": "z" + "5" * 87,
                },
            }

            response = test_client.post(
                f"/{TEST_DID_NAMESPACE}/nonexistent999/resources",
                json={
                    "attestedResource": attested_resource,
                    "options": {},
                },
            )

            # Should fail with 404 or 400
            assert response.status_code in [404, 400]

    @pytest.mark.asyncio
    async def test_upload_resource_missing_fields(self):
        """Test resource upload with missing required fields."""
        test_namespace = TEST_DID_NAMESPACE
        test_alias = "resource04"

        with TestClient(app) as test_client:
            # Create a DID
            response = test_client.get(f"?namespace={test_namespace}&alias={test_alias}")
            document = response.json().get("state")
            parameters = response.json().get("parameters")
            parameters["updateKeys"] = [TEST_UPDATE_KEY]
            parameters["witness"] = {
                "threshold": 1,
                "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}],
            }

            initial_state = DocumentState.initial(
                timestamp=TEST_VERSION_TIME,
                params=parameters,
                document=document,
            )
            initial_log_entry = sign(initial_state.history_line())
            witness_signature = witness.create_log_entry_proof(initial_log_entry)

            response = test_client.post(
                f"/{test_namespace}/{test_alias}",
                json={
                    "logEntry": initial_log_entry,
                    "witnessSignature": witness_signature,
                },
            )
            assert response.status_code == 201

            # Try to upload with missing attestedResource
            response = test_client.post(
                f"/{test_namespace}/{test_alias}/resources",
                json={"options": {}},
            )

            # Should return validation error
            assert response.status_code == 422


class TestGetResource:
    """Test cases for fetching attested resources."""

    @pytest.mark.asyncio
    async def test_get_resource_success(self):
        """Test successful resource retrieval."""
        test_namespace, test_alias = create_test_namespace_and_alias("res-get-01")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Upload a resource
            attested_resource, resource_id = create_test_resource(
                controller, "testResource", witness=witness
            )

            response = test_client.post(
                f"/{test_namespace}/{test_alias}/resources",
                json={"attestedResource": attested_resource},
            )
            assert response.status_code == 201
            upload_response = response.json()
            actual_resource_id = upload_response["metadata"]["resourceId"]

            # Fetch the resource
            response = test_client.get(
                f"/{test_namespace}/{test_alias}/resources/{actual_resource_id}"
            )

            assert response.status_code == 200
            fetched_resource = response.json()
            assert fetched_resource.get("metadata", {}).get("resourceId") == actual_resource_id
            assert fetched_resource.get("content") is not None

    @pytest.mark.asyncio
    async def test_get_resource_not_found(self):
        """Test fetching non-existent resource."""
        test_namespace, test_alias = create_test_namespace_and_alias("resource06")

        with TestClient(app) as test_client:
            # Create DID
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Try to fetch non-existent resource
            response = test_client.get(f"/{test_namespace}/{test_alias}/resources/nonexistent123")

            assert_error_response(response, 404, "Couldn't find resource")

    @pytest.mark.asyncio
    async def test_get_resource_from_nonexistent_did(self):
        """Test fetching resource from non-existent DID."""
        with TestClient(app) as test_client:
            response = test_client.get(f"/{TEST_DID_NAMESPACE}/nonexistent999/resources/abc123")

            # Should fail with 404 or 400
            assert response.status_code in [404, 400]


class TestUpdateResource:
    """Test cases for updating attested resources."""

    @pytest.mark.asyncio
    async def test_update_resource_success(self):
        """Test successful resource update."""
        test_namespace, test_alias = create_test_namespace_and_alias("res-update-01")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Upload initial resource
            initial_content = {"name": "Original Resource", "version": "1.0"}
            attested_resource, resource_id = create_test_resource(
                controller, "testResource", initial_content, witness=witness
            )

            response = test_client.post(
                f"/{test_namespace}/{test_alias}/resources",
                json={"attestedResource": attested_resource},
            )
            assert response.status_code == 201
            upload_response = response.json()
            actual_resource_id = upload_response["metadata"]["resourceId"]

            # Fetch the original resource
            response = test_client.get(
                f"/{test_namespace}/{test_alias}/resources/{actual_resource_id}"
            )
            fetched_resource = response.json()

            # Remove proof and add links
            fetched_resource.pop("proof", None)
            fetched_resource["links"] = [
                {
                    "id": f"{controller.issuer_id}/resources/linkedresource123",
                    "type": "relatedResource",
                    "timestamp": 1234567890,
                }
            ]

            # Sign the updated resource with controller and witness
            updated_resource = controller.sign(fetched_resource)
            # Add witness endorsement
            resource_for_witness = updated_resource.copy()
            controller_proof = resource_for_witness.pop("proof")
            if not isinstance(controller_proof, list):
                controller_proof = [controller_proof]
            witness_signed = witness.sign(resource_for_witness)
            witness_proof = witness_signed.get("proof", [])
            if not isinstance(witness_proof, list):
                witness_proof = [witness_proof]
            updated_resource["proof"] = controller_proof + witness_proof

            response = test_client.put(
                f"/{test_namespace}/{test_alias}/resources/{actual_resource_id}",
                json={"attestedResource": updated_resource},
            )

            assert response.status_code == 200
            updated = response.json()
            assert updated.get("links") is not None
            assert len(updated.get("links")) == 1

    @pytest.mark.asyncio
    async def test_update_resource_not_found(self):
        """Test updating non-existent resource."""
        test_namespace, test_alias = create_test_namespace_and_alias("res-update-notfound")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Try to update non-existent resource
            fake_resource, _ = create_test_resource(controller, "testResource", witness=witness)

            response = test_client.put(
                f"/{test_namespace}/{test_alias}/resources/nonexistent123",
                json={"attestedResource": fake_resource},
            )

            assert_error_response(response, 404, "Couldn't find resource")

    @pytest.mark.asyncio
    async def test_update_resource_invalid_proof(self):
        """Test updating resource with invalid proof."""
        test_namespace, test_alias = create_test_namespace_and_alias("res-update-invalid")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Upload initial resource
            attested_resource, resource_id = create_test_resource(
                controller, "testResource", witness=witness
            )

            response = test_client.post(
                f"/{test_namespace}/{test_alias}/resources",
                json={"attestedResource": attested_resource},
            )
            assert response.status_code == 201
            upload_response = response.json()
            actual_resource_id = upload_response["metadata"]["resourceId"]

            # Try to update with tampered proof (tamper with controller proof)
            tampered_resource = attested_resource.copy()
            if isinstance(tampered_resource["proof"], list):
                tampered_resource["proof"][0]["proofValue"] = (
                    "z" + "1" * 87
                )  # Valid multibase format
            else:
                tampered_resource["proof"]["proofValue"] = "z" + "1" * 87  # Valid multibase format

            response = test_client.put(
                f"/{test_namespace}/{test_alias}/resources/{actual_resource_id}",
                json={"attestedResource": tampered_resource},
            )
            assert_error_response(response, 400, "Invalid resource proof.")
