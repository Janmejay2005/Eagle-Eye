"""
Quantum measurement schema covering projective Pauli bases X, Y, Z.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class PauliBasis(str, Enum):
    X = "X"
    Y = "Y"
    Z = "Z"


class MeasurementRecord(BaseModel):
    """Result of a single qubit projective measurement."""
    qubit_index: int = Field(..., ge=0, description="Index of the signature qubit")
    basis: PauliBasis = Field(..., description="Measurement basis choice (X, Y, or Z)")
    outcome: int = Field(..., ge=0, le=1, description="Binary projective measurement result (0 or 1)")
    ideal_outcome: Optional[int] = Field(None, ge=0, le=1, description="Expected noiseless outcome for calibration/audit")
    shots: int = Field(default=1024, gt=0, description="Shot count used in circuit simulation")
    counts: Dict[str, int] = Field(default_factory=dict, description="Raw outcome frequency counts")

    @field_validator("counts")
    @classmethod
    def validate_counts(cls, v: Dict[str, int]) -> Dict[str, int]:
        for k in v.keys():
            if k not in ("0", "1"):
                raise ValueError(f"Measurement count key must be '0' or '1', got {k}")
        return v


class MeasurementBatch(BaseModel):
    """Collection of projective measurements corresponding to a QDS verification block."""
    batch_id: str = Field(..., description="Unique measurement batch identifier")
    session_id: str = Field(..., description="Associated verification session ID")
    records: List[MeasurementRecord] = Field(..., min_length=1, description="Measurement records")

    @property
    def sample_size(self) -> int:
        return len(self.records)

    @property
    def error_count(self) -> int:
        return sum(
            1 for r in self.records
            if r.ideal_outcome is not None and r.outcome != r.ideal_outcome
        )
