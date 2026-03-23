from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(
    title="IPv11-S OpenCLAW Demo",
    version="0.1.0",
    description=(
        "Demo control plane implementing social-position-aware hybrid "
        "P2P/centralized legitimacy checks inspired by ipv11_social_position_paper.md"
    ),
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SPD(BaseModel):
    role: str
    affiliation: str
    scope: List[str] = Field(default_factory=list)
    trust_institutional: float = Field(ge=0.0, le=1.0)
    trust_peer: float = Field(ge=0.0, le=1.0)
    task_reliability: float = Field(ge=0.0, le=1.0)
    policy_violations: float = Field(ge=0.0, le=1.0)
    culture_profile_id: str
    valid_until: datetime
    evidence_count: int = Field(ge=0)


class AgentRegistration(BaseModel):
    agent_id: str
    services: List[str] = Field(default_factory=list)
    endpoint: str
    spd: SPD
    domain: str


class EndorsementRequest(BaseModel):
    from_agent_id: str
    to_agent_id: str
    score: float = Field(ge=0.0, le=1.0)


class InteractionRequest(BaseModel):
    src_agent_id: str
    dst_agent_id: str
    action: str
    mode: Literal["p2p", "centralized", "hybrid"] = "hybrid"
    auth_token: Optional[str] = None


class InteractionDecision(BaseModel):
    allow: bool
    stage_a_reachable: bool
    stage_b_legitimate: bool
    reason: str
    trust_score_src: float
    trust_score_dst: float
    policy_assertion_summary: str
    trust_range_extension: str


@dataclass
class AgentState:
    agent_id: str
    services: List[str]
    endpoint: str
    spd: SPD
    domain: str
    endorsements: Dict[str, float] = field(default_factory=dict)
    revoked: bool = False


AGENTS: Dict[str, AgentState] = {}

# T(t) = alpha*Institutional + beta*Peer + gamma*TaskReliability - delta*PolicyViolations
ALPHA = 0.40
BETA = 0.25
GAMMA = 0.25
DELTA = 0.10


def trust_score(agent: AgentState) -> float:
    peer_component = (
        sum(agent.endorsements.values()) / len(agent.endorsements)
        if agent.endorsements
        else agent.spd.trust_peer
    )
    score = (
        ALPHA * agent.spd.trust_institutional
        + BETA * peer_component
        + GAMMA * agent.spd.task_reliability
        - DELTA * agent.spd.policy_violations
    )
    return max(0.0, min(1.0, score))


def trust_band(score: float) -> str:
    if score >= 0.80:
        return "HIGH"
    if score >= 0.60:
        return "MEDIUM"
    if score >= 0.35:
        return "LOW"
    return "VERY_LOW"


def validate_not_revoked(agent: AgentState) -> None:
    if agent.revoked:
        raise HTTPException(status_code=403, detail=f"Agent {agent.agent_id} is revoked")
    if agent.spd.valid_until <= utc_now():
        raise HTTPException(
            status_code=403,
            detail=f"Agent {agent.agent_id} has stale SPD (expired)",
        )


def policy_threshold(action: str) -> float:
    action_lower = action.lower()
    if "critical" in action_lower or "execute" in action_lower:
        return 0.80
    if "write" in action_lower or "approve" in action_lower:
        return 0.65
    return 0.45


@app.get("/")
def root() -> Dict[str, str]:
    return {
        "name": "IPv11-S OpenCLAW Demo",
        "docs": "/docs",
        "description": (
            "OpenCLAW = Open Community Legitimacy and Authorization Workflow"
        ),
    }


@app.post("/api/v1/agents", status_code=201)
def register_agent(payload: AgentRegistration) -> Dict[str, str]:
    AGENTS[payload.agent_id] = AgentState(
        agent_id=payload.agent_id,
        services=payload.services,
        endpoint=payload.endpoint,
        spd=payload.spd,
        domain=payload.domain,
    )
    return {"status": "registered", "agent_id": payload.agent_id}


@app.post("/api/v1/endorsements")
def endorse(payload: EndorsementRequest) -> Dict[str, str]:
    source = AGENTS.get(payload.from_agent_id)
    target = AGENTS.get(payload.to_agent_id)
    if source is None or target is None:
        raise HTTPException(status_code=404, detail="Source or target agent not found")
    validate_not_revoked(source)
    validate_not_revoked(target)
    target.endorsements[payload.from_agent_id] = payload.score
    return {"status": "endorsed", "from": payload.from_agent_id, "to": payload.to_agent_id}


@app.post("/api/v1/interactions/evaluate", response_model=InteractionDecision)
def evaluate_interaction(payload: InteractionRequest) -> InteractionDecision:
    src = AGENTS.get(payload.src_agent_id)
    dst = AGENTS.get(payload.dst_agent_id)
    if src is None or dst is None:
        raise HTTPException(status_code=404, detail="Source or destination agent not found")

    validate_not_revoked(src)
    validate_not_revoked(dst)

    # Stage A: reachability check (transport-routable existence)
    stage_a = bool(src.endpoint and dst.endpoint)
    if not stage_a:
        return InteractionDecision(
            allow=False,
            stage_a_reachable=False,
            stage_b_legitimate=False,
            reason="Stage A failed: endpoint not reachable",
            trust_score_src=0.0,
            trust_score_dst=0.0,
            policy_assertion_summary="REACHABILITY_FAIL",
            trust_range_extension="VERY_LOW",
        )

    # Centralized auth requirement when centralized or hybrid paths are used.
    if payload.mode in {"centralized", "hybrid"}:
        expected_token = f"DA-SIGNED::{src.domain}::{src.agent_id}"
        if payload.auth_token != expected_token:
            return InteractionDecision(
                allow=False,
                stage_a_reachable=True,
                stage_b_legitimate=False,
                reason="Centralized auth failed (invalid domain authority token)",
                trust_score_src=trust_score(src),
                trust_score_dst=trust_score(dst),
                policy_assertion_summary="AUTH_FAIL",
                trust_range_extension=trust_band(min(trust_score(src), trust_score(dst))),
            )

    src_score = trust_score(src)
    dst_score = trust_score(dst)
    threshold = policy_threshold(payload.action)

    # Example social compatibility constraint for high-risk actions.
    high_risk = threshold >= 0.80
    culture_ok = (
        src.spd.culture_profile_id == dst.spd.culture_profile_id or not high_risk
    )
    scope_ok = payload.action in src.spd.scope
    trust_ok = src_score >= threshold and dst_score >= threshold
    stage_b = scope_ok and trust_ok and culture_ok

    reason_parts = []
    if not scope_ok:
        reason_parts.append("source action out of scoped role")
    if not trust_ok:
        reason_parts.append(f"trust below threshold {threshold:.2f}")
    if not culture_ok:
        reason_parts.append("culture profile mismatch for high-risk action")

    reason = "allow" if stage_b else "; ".join(reason_parts)
    return InteractionDecision(
        allow=stage_b,
        stage_a_reachable=True,
        stage_b_legitimate=stage_b,
        reason=reason,
        trust_score_src=src_score,
        trust_score_dst=dst_score,
        policy_assertion_summary=f"MODE={payload.mode}|THRESHOLD={threshold:.2f}",
        trust_range_extension=trust_band(min(src_score, dst_score)),
    )


@app.post("/api/v1/demo/bootstrap")
def bootstrap() -> Dict[str, object]:
    AGENTS.clear()
    valid_until = utc_now() + timedelta(days=30)

    register_agent(
        AgentRegistration(
            agent_id="agent-alpha",
            services=["triage", "routing-assist"],
            endpoint="ipv11://society/a/alpha",
            domain="hospital-net",
            spd=SPD(
                role="triage-coordinator",
                affiliation="hospital-a",
                scope=["read-case", "approve-transfer", "critical-transfer-execute"],
                trust_institutional=0.98,
                trust_peer=0.90,
                task_reliability=0.96,
                policy_violations=0.01,
                culture_profile_id="clinical-v1",
                valid_until=valid_until,
                evidence_count=120,
            ),
        )
    )

    register_agent(
        AgentRegistration(
            agent_id="agent-beta",
            services=["bed-allocation", "intake"],
            endpoint="ipv11://society/b/beta",
            domain="hospital-net",
            spd=SPD(
                role="allocation-manager",
                affiliation="hospital-b",
                scope=["read-case", "approve-transfer", "critical-transfer-execute"],
                trust_institutional=0.95,
                trust_peer=0.88,
                task_reliability=0.94,
                policy_violations=0.01,
                culture_profile_id="clinical-v1",
                valid_until=valid_until,
                evidence_count=88,
            ),
        )
    )

    endorse(EndorsementRequest(from_agent_id="agent-alpha", to_agent_id="agent-beta", score=0.92))
    endorse(EndorsementRequest(from_agent_id="agent-beta", to_agent_id="agent-alpha", score=0.90))

    return {"status": "bootstrapped", "agents": list(AGENTS.keys()), "count": len(AGENTS)}
