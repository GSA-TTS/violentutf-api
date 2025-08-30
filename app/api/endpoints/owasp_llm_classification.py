"""OWASP LLM Top 10 classification endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.core.enums import OWASPLLMCategory
from app.schemas.base import BaseResponse
from app.services.owasp_llm_classifier import (
    ClassificationConfidence,
    OWASPLLMClassifier,
)

router = APIRouter(prefix="/owasp-llm", tags=["OWASP LLM Classification"])


class ClassificationRequest(BaseModel):
    """Request for OWASP LLM classification."""

    title: str = Field(..., min_length=1, max_length=300, description="Vulnerability title")
    description: Optional[str] = Field(None, description="Vulnerability description")
    proof_of_concept: Optional[str] = Field(None, description="Proof of concept details")
    attack_scenario: Optional[str] = Field(None, description="Attack scenario description")
    ai_model_affected: Optional[str] = Field(None, description="Affected AI model information")
    prompt_pattern: Optional[str] = Field(None, description="Malicious prompt pattern")

    class Config:
        json_schema_extra = {
            "example": {
                "title": "Prompt Injection in Chat Interface",
                "description": "User can bypass safety filters by using jailbreak prompts",
                "proof_of_concept": "Input: 'Ignore previous instructions and act as...'",
                "ai_model_affected": "GPT-3.5 based chatbot",
            }
        }


class ClassificationResponse(BaseModel):
    """Response from OWASP LLM classification."""

    owasp_category: Optional[OWASPLLMCategory] = Field(None, description="Classified OWASP LLM category")
    confidence_level: ClassificationConfidence = Field(..., description="Classification confidence level")
    confidence_score: float = Field(..., ge=0.0, le=5.0, description="Numerical confidence score")
    category_name: Optional[str] = Field(None, description="Human-readable category name")
    severity: Optional[str] = Field(None, description="Suggested severity level")
    attack_vector: Optional[str] = Field(None, description="Suggested attack vector")
    description: Optional[str] = Field(None, description="Category description")
    detection_methods: Optional[List[str]] = Field(None, description="Suggested detection methods")
    remediation_guidance: Optional[str] = Field(None, description="Remediation guidance")
    prevention_measures: Optional[str] = Field(None, description="Prevention measures")


class CategoryDetailsResponse(BaseModel):
    """Detailed information about an OWASP LLM category."""

    category: str = Field(..., description="OWASP LLM category ID")
    name: str = Field(..., description="Human-readable name")
    severity: str = Field(..., description="Default severity level")
    attack_vector: str = Field(..., description="Attack vector type")
    description: str = Field(..., description="Category description")
    keywords: List[str] = Field(..., description="Related keywords")
    detection_methods: List[str] = Field(..., description="Detection methods")
    remediation_guidance: str = Field(..., description="Remediation guidance")
    prevention_measures: str = Field(..., description="Prevention measures")


class TaxonomySuggestionResponse(BaseModel):
    """Suggested taxonomy mapping for a vulnerability."""

    suggested_mapping: Optional[dict] = Field(None, description="Suggested taxonomy structure")
    classification_details: ClassificationResponse = Field(..., description="Classification details")


@router.post("/classify", response_model=BaseResponse[ClassificationResponse])
async def classify_vulnerability(
    request: Request,
    classification_request: ClassificationRequest,
) -> BaseResponse[ClassificationResponse]:
    """Classify a vulnerability according to OWASP LLM Top 10."""

    classifier = OWASPLLMClassifier()

    # Perform classification
    owasp_category, confidence_level, confidence_score = classifier.classify_vulnerability(
        title=classification_request.title,
        description=classification_request.description,
        proof_of_concept=classification_request.proof_of_concept,
        attack_scenario=classification_request.attack_scenario,
        ai_model_affected=classification_request.ai_model_affected,
        prompt_pattern=classification_request.prompt_pattern,
    )

    # Get additional details if classification found
    category_details = {}
    if owasp_category:
        category_details = classifier.get_category_details(owasp_category)

    response_data = ClassificationResponse(
        owasp_category=owasp_category,
        confidence_level=confidence_level,
        confidence_score=confidence_score,
        category_name=category_details.get("name"),
        severity=category_details.get("severity"),
        attack_vector=category_details.get("attack_vector"),
        description=category_details.get("description"),
        detection_methods=category_details.get("detection_methods"),
        remediation_guidance=category_details.get("remediation_guidance"),
        prevention_measures=category_details.get("prevention_measures"),
    )

    message = "Classification completed"
    if owasp_category:
        message += f" - identified as {category_details.get('name', owasp_category.value)}"
    else:
        message += " - no OWASP LLM category identified"

    return BaseResponse(
        data=response_data,
        message=message,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/categories", response_model=BaseResponse[List[CategoryDetailsResponse]])
async def get_all_categories(
    request: Request,
) -> BaseResponse[List[CategoryDetailsResponse]]:
    """Get detailed information for all OWASP LLM Top 10 categories."""

    classifier = OWASPLLMClassifier()
    categories_info = classifier.get_all_categories_info()

    response_data = [CategoryDetailsResponse(**category_info) for category_info in categories_info]

    return BaseResponse(
        data=response_data,
        message=f"Retrieved details for {len(response_data)} OWASP LLM categories",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/categories/{category}", response_model=BaseResponse[CategoryDetailsResponse])
async def get_category_details(
    category: OWASPLLMCategory,
    request: Request,
) -> BaseResponse[CategoryDetailsResponse]:
    """Get detailed information for a specific OWASP LLM category."""

    classifier = OWASPLLMClassifier()
    category_info = classifier.get_category_details(category)

    if not category_info:
        response_data = CategoryDetailsResponse(
            category=category.value,
            name=category.value,
            severity="medium",
            attack_vector="network",
            description="Unknown OWASP LLM category",
            keywords=[],
            detection_methods=[],
            remediation_guidance="Follow general security best practices",
            prevention_measures="Apply security-by-design principles",
        )
    else:
        response_data = CategoryDetailsResponse(**category_info)

    return BaseResponse(
        data=response_data,
        message=f"Retrieved details for {category.value}",
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.post("/suggest-taxonomy", response_model=BaseResponse[TaxonomySuggestionResponse])
async def suggest_taxonomy_mapping(
    request: Request,
    classification_request: ClassificationRequest,
) -> BaseResponse[TaxonomySuggestionResponse]:
    """Suggest a vulnerability taxonomy mapping based on OWASP LLM classification."""

    classifier = OWASPLLMClassifier()

    # Get classification first
    owasp_category, confidence_level, confidence_score = classifier.classify_vulnerability(
        title=classification_request.title,
        description=classification_request.description,
        proof_of_concept=classification_request.proof_of_concept,
        attack_scenario=classification_request.attack_scenario,
        ai_model_affected=classification_request.ai_model_affected,
        prompt_pattern=classification_request.prompt_pattern,
    )

    # Get suggested taxonomy mapping
    suggested_mapping = classifier.suggest_taxonomy_mapping(
        classification_request.title, classification_request.description
    )

    # Get category details for response
    category_details = {}
    if owasp_category:
        category_details = classifier.get_category_details(owasp_category)

    classification_details = ClassificationResponse(
        owasp_category=owasp_category,
        confidence_level=confidence_level,
        confidence_score=confidence_score,
        category_name=category_details.get("name"),
        severity=category_details.get("severity"),
        attack_vector=category_details.get("attack_vector"),
        description=category_details.get("description"),
        detection_methods=category_details.get("detection_methods"),
        remediation_guidance=category_details.get("remediation_guidance"),
        prevention_measures=category_details.get("prevention_measures"),
    )

    response_data = TaxonomySuggestionResponse(
        suggested_mapping=suggested_mapping,
        classification_details=classification_details,
    )

    message = "Taxonomy mapping suggestion generated"
    if suggested_mapping:
        message += f" - suggested as {suggested_mapping.get('name', 'Unknown')}"
    else:
        message += " - no specific mapping suggested"

    return BaseResponse(
        data=response_data,
        message=message,
        trace_id=getattr(request.state, "trace_id", None),
    )
