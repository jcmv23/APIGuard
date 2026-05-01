"""
Tests for Module 1 - OpenAPI Parser
Run: python -m pytest test_parser.py -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import pytest
from module_1_parser.parser import OpenAPIParser, Endpoint, Parameter

# ── Minimal inline specs ──────────────────────────────────────

OPENAPI3_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Test API", "version": "1.0"},
    "servers": [{"url": "https://api.example.com"}],
    "components": {
        "securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}}
    },
    "paths": {
        "/users": {
            "get": {
                "summary": "List users",
                "tags": ["users"],
                "security": [{"BearerAuth": []}],
                "parameters": [
                    {"name": "page", "in": "query", "schema": {"type": "integer"}}
                ],
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "summary": "Create user",
                "tags": ["users"],
                "security": [{"BearerAuth": []}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "email": {"type": "string"},
                                }
                            }
                        }
                    }
                },
                "responses": {"201": {"description": "Created"}},
            },
        },
        "/users/{userId}": {
            "get": {
                "summary": "Get user by ID",
                "tags": ["users"],
                "security": [{"BearerAuth": []}],
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "format": "int64"},
                    }
                ],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/admin/users/{userId}": {
            "delete": {
                "summary": "Delete user (admin only)",
                "tags": ["admin"],
                "security": [{"BearerAuth": []}],
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {"204": {"description": "Deleted"}},
            }
        },
        "/public/status": {
            "get": {
                "summary": "Health check",
                "tags": ["public"],
                "responses": {"200": {"description": "OK"}},
            }
        },
    },
}

SWAGGER2_SPEC = {
    "swagger": "2.0",
    "info": {"title": "Pet Store", "version": "1.0"},
    "host": "petstore.example.com",
    "basePath": "/v2",
    "schemes": ["https"],
    "paths": {
        "/pets": {
            "get": {
                "summary": "List pets",
                "operationId": "listPets",
                "parameters": [
                    {"name": "limit", "in": "query", "type": "integer", "required": False}
                ],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/pets/{petId}": {
            "get": {
                "summary": "Get pet",
                "operationId": "getPet",
                "parameters": [
                    {"name": "petId", "in": "path", "type": "integer", "required": True}
                ],
                "responses": {"200": {"description": "OK"}},
            }
        },
    },
}


# ── Tests ─────────────────────────────────────────────────────

class TestOpenAPI3Parser:
    def setup_method(self):
        self.parser = OpenAPIParser(spec=OPENAPI3_SPEC)
        self.endpoints = self.parser.parse()

    def test_correct_endpoint_count(self):
        assert len(self.endpoints) == 5

    def test_methods_extracted(self):
        methods = {ep.method for ep in self.endpoints}
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods

    def test_path_param_detected(self):
        ep = next(e for e in self.endpoints if e.path == "/users/{userId}" and e.method == "GET")
        assert len(ep.path_params()) == 1
        assert ep.path_params()[0].name == "userId"
        assert ep.path_params()[0].required is True

    def test_query_param_detected(self):
        ep = next(e for e in self.endpoints if e.path == "/users" and e.method == "GET")
        assert any(p.name == "page" for p in ep.query_params())

    def test_auth_required_flagged(self):
        secured = next(e for e in self.endpoints if e.path == "/users" and e.method == "GET")
        public = next(e for e in self.endpoints if e.path == "/public/status")
        assert secured.requires_auth is True
        assert public.requires_auth is False

    def test_is_resource_endpoint(self):
        ep_resource = next(e for e in self.endpoints if e.path == "/users/{userId}")
        ep_collection = next(e for e in self.endpoints if e.path == "/users" and e.method == "GET")
        assert ep_resource.is_resource_endpoint() is True
        assert ep_collection.is_resource_endpoint() is False

    def test_looks_like_admin(self):
        ep_admin = next(e for e in self.endpoints if e.path == "/admin/users/{userId}")
        ep_user = next(e for e in self.endpoints if e.path == "/users" and e.method == "GET")
        assert ep_admin.looks_like_admin() is True
        assert ep_user.looks_like_admin() is False

    def test_request_body_schema_extracted(self):
        ep = next(e for e in self.endpoints if e.path == "/users" and e.method == "POST")
        assert ep.request_body_schema.get("type") == "object"
        assert "name" in ep.request_body_schema.get("properties", {})

    def test_base_url_from_servers(self):
        assert self.parser.base_url == "https://api.example.com"

    def test_full_url_composed(self):
        ep = next(e for e in self.endpoints if e.path == "/users/{userId}" and e.method == "GET")
        assert ep.full_url == "https://api.example.com/users/{userId}"

    def test_to_dict_serializable(self):
        d = self.parser.to_dict()
        assert "endpoints" in d
        assert d["total_endpoints"] == 5
        # Must be JSON-serializable
        json.dumps(d, default=str)

    def test_summary_string(self):
        s = self.parser.summary()
        assert "https://api.example.com" in s
        assert "GET" in s


class TestSwagger2Parser:
    def setup_method(self):
        self.parser = OpenAPIParser(spec=SWAGGER2_SPEC)
        self.endpoints = self.parser.parse()

    def test_correct_endpoint_count(self):
        assert len(self.endpoints) == 2

    def test_base_url_from_host(self):
        assert self.parser.base_url == "https://petstore.example.com/v2"

    def test_path_param_swagger2(self):
        ep = next(e for e in self.endpoints if e.path == "/pets/{petId}")
        assert ep.path_params()[0].name == "petId"
        assert ep.path_params()[0].required is True

    def test_query_param_swagger2(self):
        ep = next(e for e in self.endpoints if e.path == "/pets" and e.method == "GET")
        assert any(p.name == "limit" for p in ep.query_params())


class TestEdgeCases:
    def test_empty_paths_raises(self):
        parser = OpenAPIParser(spec={"openapi": "3.0.0", "info": {}, "paths": {}})
        endpoints = parser.parse()
        assert endpoints == []

    def test_invalid_spec_raises(self):
        with pytest.raises((ValueError, KeyError)):
            OpenAPIParser(spec={"not_a_spec": True}).parse()

    def test_dict_spec_input(self):
        parser = OpenAPIParser(spec=OPENAPI3_SPEC)
        assert len(parser.parse()) == 5

    def test_json_string_spec_input(self):
        parser = OpenAPIParser(spec=json.dumps(OPENAPI3_SPEC))
        assert len(parser.parse()) == 5