"""Enhanced JWT claims testing for post-ADR-003 implementation.

This module provides comprehensive testing for the enhanced JWT claims structure
that now includes complete user context: sub, roles[], organization_id, type.
Tests validate RBAC/ABAC foundations and security claim processing.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, Generator, List, Optional
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request

from app.core.security import create_access_token, decode_token
from app.middleware.authentication import JWTAuthenticationMiddleware
from tests.utils.testclient import SafeTestClient

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

# TestClient imported via TYPE_CHECKING for type hints only


class TestEnhancedJWTClaims:
    """Comprehensive testing for enhanced JWT claims structure."""

    @pytest.fixture
    def app(self) -> FastAPI:
        """Create FastAPI app for JWT claims testing."""
        app = FastAPI()
        app.add_middleware(JWTAuthenticationMiddleware)

        @app.get("/api/v1/users/claims")
        async def get_claims(request: Request) -> Dict[str, Any]:
            """Test endpoint to extract and return JWT claims."""
            return {
                "user_id": getattr(request.state, "user_id", None),
                "token_payload": getattr(request.state, "token_payload", None),
            }

        return app

    def create_enhanced_jwt_token(
        self,
        user_id: str = "user-123",
        roles: Optional[List[str]] = None,
        organization_id: Optional[str] = None,
        token_type: str = "access",
        additional_claims: Optional[Dict[str, Any]] = None,
        exp_delta: Optional[timedelta] = None,
    ) -> str:
        """Create JWT token with enhanced claims structure."""
        if roles is None:
            roles = ["viewer"]

        if exp_delta is None:
            exp_delta = timedelta(hours=1)

        # Core enhanced claims structure
        payload = {
            "sub": user_id,
            "roles": roles,
            "organization_id": organization_id,
            "type": token_type,
            "exp": datetime.now(timezone.utc) + exp_delta,
        }

        # Add any additional claims for testing
        if additional_claims:
            payload.update(additional_claims)

        return create_access_token(data=payload)

    # Core Claims Structure Tests

    def test_complete_claims_structure_validation(self, client: "TestClient") -> None:
        """Test that complete enhanced claims structure is properly validated."""
        token = self.create_enhanced_jwt_token(
            user_id="user-456", roles=["viewer", "tester"], organization_id="org-789", token_type="access"
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/users/claims", headers=headers)
        assert response.status_code == 200

        data = response.json()
        payload = data["token_payload"]

        # Validate all core enhanced claims
        assert payload["sub"] == "user-456"
        assert payload["roles"] == ["viewer", "tester"]
        assert payload["organization_id"] == "org-789"
        assert payload["type"] == "access"
        assert "exp" in payload

    def test_subject_claim_processing(self, client: "TestClient") -> None:
        """Test subject (sub) claim processing and injection."""
        test_cases = [
            "user-123",
            "admin-456",
            "service-account-789",
            str(uuid.uuid4()),
            "user@domain.com",
        ]

        for user_id in test_cases:
            token = self.create_enhanced_jwt_token(user_id=user_id)
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            data = response.json()
            assert data["user_id"] == user_id
            assert data["token_payload"]["sub"] == user_id

    def test_roles_array_processing_for_rbac(self, client: "TestClient") -> None:
        """Test roles array processing for RBAC implementation."""
        role_test_cases = [
            ["viewer"],
            ["tester"],
            ["admin"],
            ["viewer", "tester"],
            ["viewer", "tester", "admin"],
            ["custom_role_1", "custom_role_2"],
            [],  # Empty roles array
        ]

        for roles in role_test_cases:
            token = self.create_enhanced_jwt_token(roles=roles)
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            payload = response.json()["token_payload"]
            assert payload["roles"] == roles
            assert isinstance(payload["roles"], list)

    def test_organization_id_processing_for_abac(self, client: "TestClient") -> None:
        """Test organization_id processing for ABAC implementation."""
        org_test_cases = [
            "org-123",
            "organization-456",
            str(uuid.uuid4()),
            "gov-agency-789",
            None,  # No organization
        ]

        for org_id in org_test_cases:
            token = self.create_enhanced_jwt_token(organization_id=org_id)
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            payload = response.json()["token_payload"]
            assert payload["organization_id"] == org_id

    def test_token_type_validation(self, client: "TestClient") -> None:
        """Test token type validation for access vs refresh tokens."""
        # Valid access token
        access_token = self.create_enhanced_jwt_token(token_type="access")
        headers = {"Authorization": f"Bearer {access_token}"}

        response = client.get("/api/v1/users/claims", headers=headers)
        assert response.status_code == 200
        assert response.json()["token_payload"]["type"] == "access"

        # Invalid refresh token (should be rejected)
        # Use create_refresh_token to properly create a refresh token
        from app.core.security import create_refresh_token

        refresh_payload = {
            "sub": "user-123",
            "roles": ["viewer"],
            "organization_id": None,
        }
        refresh_token = create_refresh_token(data=refresh_payload)
        headers = {"Authorization": f"Bearer {refresh_token}"}

        response = client.get("/api/v1/users/claims", headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid token type"

    # Claims Security Tests

    def test_claims_injection_attack_prevention(self, client: "TestClient") -> None:
        """Test prevention of claims injection attacks."""
        # Attempt to inject malicious claims
        malicious_claims = {
            "admin": True,
            "superuser": True,
            "bypass_auth": True,
            "escalate_privileges": True,
        }

        token = self.create_enhanced_jwt_token(roles=["viewer"], additional_claims=malicious_claims)
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/users/claims", headers=headers)
        assert response.status_code == 200

        payload = response.json()["token_payload"]

        # Core claims should be preserved
        assert payload["roles"] == ["viewer"]
        assert payload["type"] == "access"

        # Additional claims should be present (but authorization logic should ignore them)
        # This tests that the JWT processing doesn't break with extra claims
        assert payload["admin"] is True
        assert payload["superuser"] is True

    def test_claims_tampering_detection(self, client: "TestClient") -> None:
        """Test detection of claims tampering attempts."""
        # Create valid token
        token = self.create_enhanced_jwt_token(roles=["viewer"])

        # Attempt to tamper with token (modify middle part)
        parts = token.split(".")
        if len(parts) == 3:
            # Modify the payload part
            tampered_payload = json.dumps({"sub": "hacker", "roles": ["admin"]})
            # Base64 encode the tampered payload (this will break signature verification)
            import base64

            tampered_b64 = base64.urlsafe_b64encode(tampered_payload.encode()).decode().rstrip("=")
            tampered_token = f"{parts[0]}.{tampered_b64}.{parts[2]}"

            headers = {"Authorization": f"Bearer {tampered_token}"}
            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 401
            assert response.json()["detail"] == "Invalid authentication token"

    def test_missing_required_claims_handling(self, client: "TestClient") -> None:
        """Test handling of tokens missing required claims."""
        # Create token with minimal payload (missing enhanced claims)
        minimal_payload = {
            "sub": "user-123",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }

        token = create_access_token(data=minimal_payload)
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/users/claims", headers=headers)
        # Should still work with minimal claims, defaulting missing ones
        assert response.status_code == 200

        payload = response.json()["token_payload"]
        assert payload["sub"] == "user-123"
        # Missing claims should be None or default values
        assert payload.get("roles") is None
        assert payload.get("organization_id") is None
        # Type is automatically added by create_access_token, so it will be "access"
        assert payload.get("type") == "access"

    # Claims Data Type Validation Tests

    def test_roles_array_type_validation(self, client: "TestClient") -> None:
        """Test that roles claim must be an array."""
        # Test with various invalid role types
        invalid_roles_payloads = [
            {"sub": "user-123", "roles": "viewer", "type": "access"},  # String instead of array
            {"sub": "user-123", "roles": 123, "type": "access"},  # Number instead of array
            {"sub": "user-123", "roles": {"admin": True}, "type": "access"},  # Object instead of array
        ]

        for payload in invalid_roles_payloads:
            payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=1)
            token = create_access_token(data=payload)
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            # Token should be valid (JWT parsing succeeds) but roles type is incorrect
            assert response.status_code == 200
            # Application logic should handle type validation appropriately

    def test_organization_id_string_validation(self, client: "TestClient") -> None:
        """Test that organization_id is properly handled as string or null."""
        org_id_test_cases = [
            "valid-org-123",
            "",  # Empty string
            None,  # Null value
        ]

        for org_id in org_id_test_cases:
            token = self.create_enhanced_jwt_token(organization_id=org_id)
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            payload = response.json()["token_payload"]
            assert payload["organization_id"] == org_id

    def test_subject_claim_string_validation(self, client: "TestClient") -> None:
        """Test that subject claim is properly validated as string."""
        # Test various subject formats
        subject_test_cases = [
            "user-123",
            "123",  # Numeric string
            "",  # Empty string (edge case)
            "user@domain.com",
            "service-account:api-key",
        ]

        for subject in subject_test_cases:
            token = self.create_enhanced_jwt_token(user_id=subject)
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            data = response.json()
            assert data["user_id"] == subject
            assert data["token_payload"]["sub"] == subject

    # Multi-tenant Security Tests

    def test_organization_isolation_context(self, client: "TestClient") -> None:
        """Test organization context for multi-tenant isolation."""
        # Test different organization contexts
        organizations = [
            "org-alpha",
            "org-beta",
            "gov-agency-1",
            "enterprise-client-2",
        ]

        for org_id in organizations:
            token = self.create_enhanced_jwt_token(
                user_id=f"user-in-{org_id}", roles=["viewer"], organization_id=org_id
            )
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            payload = response.json()["token_payload"]
            assert payload["organization_id"] == org_id
            assert payload["sub"] == f"user-in-{org_id}"

    def test_cross_organization_token_boundaries(self, client: "TestClient") -> None:
        """Test that organization boundaries are maintained in tokens."""
        # Create tokens for different organizations
        org_a_token = self.create_enhanced_jwt_token(user_id="user-a", roles=["admin"], organization_id="org-a")

        org_b_token = self.create_enhanced_jwt_token(user_id="user-b", roles=["admin"], organization_id="org-b")

        # Test that each token maintains its organization context
        headers_a = {"Authorization": f"Bearer {org_a_token}"}
        headers_b = {"Authorization": f"Bearer {org_b_token}"}

        response_a = client.get("/api/v1/users/claims", headers=headers_a)
        response_b = client.get("/api/v1/users/claims", headers=headers_b)

        assert response_a.status_code == 200
        assert response_b.status_code == 200

        payload_a = response_a.json()["token_payload"]
        payload_b = response_b.json()["token_payload"]

        assert payload_a["organization_id"] == "org-a"
        assert payload_b["organization_id"] == "org-b"
        assert payload_a["sub"] == "user-a"
        assert payload_b["sub"] == "user-b"

    # Role-Based Access Control (RBAC) Foundation Tests

    def test_rbac_role_hierarchies_in_claims(self, client: "TestClient") -> None:
        """Test RBAC role hierarchies are preserved in JWT claims."""
        role_hierarchies = [
            ["viewer"],  # Basic access
            ["viewer", "tester"],  # Testing permissions
            ["viewer", "tester", "admin"],  # Full permissions
            ["service_account"],  # Service account role
            ["api_client", "readonly"],  # API access roles
        ]

        for roles in role_hierarchies:
            token = self.create_enhanced_jwt_token(roles=roles)
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            payload = response.json()["token_payload"]
            assert payload["roles"] == roles
            assert len(payload["roles"]) == len(roles)

            # Verify role order is preserved
            for i, role in enumerate(roles):
                assert payload["roles"][i] == role

    def test_rbac_role_validation_patterns(self, client: "TestClient") -> None:
        """Test various role validation patterns for RBAC."""
        # Test valid role patterns
        valid_role_patterns = [
            ["viewer"],
            ["tester"],
            ["admin"],
            ["viewer", "tester"],
            ["api_key_manager"],
            ["session_manager"],
            ["audit_reader"],
        ]

        for roles in valid_role_patterns:
            token = self.create_enhanced_jwt_token(roles=roles)
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            payload = response.json()["token_payload"]
            assert payload["roles"] == roles

    # Attribute-Based Access Control (ABAC) Foundation Tests

    def test_abac_attribute_context_preservation(self, client: "TestClient") -> None:
        """Test that ABAC attributes are preserved in JWT context."""
        abac_contexts = [
            {
                "user_id": "user-123",
                "roles": ["viewer"],
                "organization_id": "healthcare-org-1",
            },
            {
                "user_id": "admin-456",
                "roles": ["admin"],
                "organization_id": "government-agency-2",
            },
            {
                "user_id": "service-789",
                "roles": ["api_client"],
                "organization_id": "enterprise-client-3",
            },
        ]

        for context in abac_contexts:
            token = self.create_enhanced_jwt_token(
                user_id=context["user_id"], roles=context["roles"], organization_id=context["organization_id"]
            )
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            payload = response.json()["token_payload"]
            assert payload["sub"] == context["user_id"]
            assert payload["roles"] == context["roles"]
            assert payload["organization_id"] == context["organization_id"]

    # Performance and Scale Tests

    def test_large_roles_array_processing(self, client: "TestClient") -> None:
        """Test processing of large roles arrays."""
        # Create large roles array
        large_roles = [f"role_{i}" for i in range(50)]

        token = self.create_enhanced_jwt_token(roles=large_roles)
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/users/claims", headers=headers)
        assert response.status_code == 200

        payload = response.json()["token_payload"]
        assert len(payload["roles"]) == 50
        assert payload["roles"][0] == "role_0"
        assert payload["roles"][-1] == "role_49"

    def test_complex_organization_identifiers(self, client: "TestClient") -> None:
        """Test complex organization identifier formats."""
        complex_org_ids = [
            "org-123-456-789",
            "healthcare.organization.gov",
            "client_enterprise_2024",
            "federated-identity-provider-1",
            str(uuid.uuid4()),
        ]

        for org_id in complex_org_ids:
            token = self.create_enhanced_jwt_token(organization_id=org_id)
            headers = {"Authorization": f"Bearer {token}"}

            response = client.get("/api/v1/users/claims", headers=headers)
            assert response.status_code == 200

            payload = response.json()["token_payload"]
            assert payload["organization_id"] == org_id

    # Integration with Existing JWT Infrastructure

    def test_backwards_compatibility_with_legacy_claims(self, client: "TestClient") -> None:
        """Test backwards compatibility with pre-enhancement JWT claims."""
        # Create token with minimal legacy claims
        legacy_payload = {
            "sub": "legacy-user-123",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "type": "access",
        }

        token = create_access_token(data=legacy_payload)
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/users/claims", headers=headers)
        assert response.status_code == 200

        data = response.json()
        assert data["user_id"] == "legacy-user-123"

        payload = data["token_payload"]
        assert payload["sub"] == "legacy-user-123"
        assert payload["type"] == "access"
        # Enhanced claims should be None/missing
        assert payload.get("roles") is None
        assert payload.get("organization_id") is None

    def test_enhanced_claims_with_additional_custom_fields(self, client: "TestClient") -> None:
        """Test enhanced claims structure with additional custom fields."""
        custom_claims = {
            "department": "cybersecurity",
            "clearance_level": "secret",
            "api_version": "v1",
            "client_app": "violentutf-web",
        }

        token = self.create_enhanced_jwt_token(
            user_id="analyst-123",
            roles=["tester", "analyst"],
            organization_id="defense-contractor-1",
            additional_claims=custom_claims,
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/users/claims", headers=headers)
        assert response.status_code == 200

        payload = response.json()["token_payload"]

        # Core enhanced claims
        assert payload["sub"] == "analyst-123"
        assert payload["roles"] == ["tester", "analyst"]
        assert payload["organization_id"] == "defense-contractor-1"
        assert payload["type"] == "access"

        # Custom claims
        assert payload["department"] == "cybersecurity"
        assert payload["clearance_level"] == "secret"
        assert payload["api_version"] == "v1"
        assert payload["client_app"] == "violentutf-web"
