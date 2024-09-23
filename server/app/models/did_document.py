from typing import Union, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
from .di_proof import DataIntegrityProof
from multiformats import multibase
import re
import validators


DID_WEB_REGEX = re.compile(
    "did:web:((?:[a-zA-Z0-9._%-]*:)*[a-zA-Z0-9._%-]+)"
)

DID_WEB_ID_REGEX = re.compile(
    "did:web:((?:[a-zA-Z0-9._%-]*:)*[a-zA-Z0-9._%-]+)#([a-z0-9._%-]+)"
)

class BaseModel(BaseModel):
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class VerificationMethod(BaseModel):
    id: str = Field()
    type: Union[str, List[str]] = Field('Multikey')
    controller: str = Field()
    publicKeyMultibase: str = Field()

    @field_validator("id")
    @classmethod
    def verification_method_id_validator(cls, value):
        # assert DID_WEB_ID_REGEX.match(value), "Expected controller to be a DID."
        return value

    @field_validator("type")
    @classmethod
    def verification_method_type_validator(cls, value):
        assert value == 'Multikey', 'Expected type Multikey'
        return value

    @field_validator("controller")
    @classmethod
    def verification_method_controller_validator(cls, value):
        assert DID_WEB_REGEX.match(value), "Expected controller to be a DID."
        return value

    @field_validator("publicKeyMultibase")
    @classmethod
    def verification_method_public_key_validator(cls, value):
        try:
            multibase.decode(value)
        except:
            assert False, f'Unable to decode public key multibase value {value}'
        return value


class Service(BaseModel):
    id: str = Field()
    type: Union[str, List[str]] = Field()
    serviceEndpoint: str = Field()

    @field_validator("id")
    @classmethod
    def service_id_validator(cls, value):
        assert DID_WEB_ID_REGEX.match(value), "Expected controller to be a DID."
        return value

    @field_validator("serviceEndpoint")
    @classmethod
    def service_endpoint_validator(cls, value):
        assert validators.url(value) , f"Invalid service endpoint {value}."
        return value


class DidDocument(BaseModel):
    context: Union[str, List[str]] = Field(
        ["https://www.w3.org/ns/did/v1"], alias="@context"
    )
    id: str = Field()
    controller: str = Field(None)
    alsoKnownAs: List[str] = Field(None)
    verificationMethod: List[VerificationMethod] = Field()
    authentication: List[Union[str, VerificationMethod]] = Field()
    assertionMethod: List[Union[str, VerificationMethod]] = Field()
    keyAgreement: List[Union[str, VerificationMethod]] = Field(None)
    capabilityInvocation: List[Union[str, VerificationMethod]] = Field(None)
    capabilityDelegation: List[Union[str, VerificationMethod]] = Field(None)
    service: List[Service] = Field(None)

    @field_validator("context")
    @classmethod
    def context_validator(cls, value):
        assert value[0] == "https://www.w3.org/ns/did/v1", "Invalid context."
        return value

    @field_validator("id")
    @classmethod
    def id_validator(cls, value):
        assert DID_WEB_REGEX.match(value), "Expected id to be a DID."
        return value

    @field_validator("authentication")
    @classmethod
    def authentication_validator(cls, value):
        assert len(value) >= 1, "Expected at least one authentication method."
        return value

    @field_validator("assertionMethod")
    @classmethod
    def assertion_method_validator(cls, value):
        assert len(value) >= 1, "Expected at least one assertion method."
        return value

    @field_validator("verificationMethod")
    @classmethod
    def verification_method_validator(cls, value):
        assert len(value) >= 1, "Expected at least one verification method."
        return value


class SecuredDidDocument(DidDocument):
    proof: List[DataIntegrityProof] = Field(None)

    @field_validator("proof")
    @classmethod
    def proof_validator(cls, value):
        assert len(value) == 2, "Expected proof set."
        return value
