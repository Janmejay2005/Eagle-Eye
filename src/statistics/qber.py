"""
Quantum Bit Error Rate (QBER) and basis-specific error analytics.
No AI/ML — purely deterministic quantum information metrics.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.schemas.measurement import MeasurementBatch, PauliBasis


class QBERReport(BaseModel):
    """Structured report containing overall and basis-decomposed QBER."""
    total_qubits: int = Field(..., ge=0)
    evaluated_qubits: int = Field(..., ge=0)
    error_count: int = Field(..., ge=0)
    overall_qber: float = Field(..., ge=0.0, le=1.0)
    basis_qber: Dict[str, float] = Field(default_factory=dict)
    basis_counts: Dict[str, int] = Field(default_factory=dict)
    basis_error_counts: Dict[str, int] = Field(default_factory=dict)
    basis_asymmetry: float = Field(default=0.0, ge=0.0, description="Max absolute divergence between basis QBERs")


def calculate_qber(batch: MeasurementBatch) -> QBERReport:
    """
    Computes overall QBER and per-basis error rates (X, Y, Z).
    Only measurements with known ideal outcomes can be assessed for error.
    """
    total = len(batch.records)
    evaluated = 0
    errors = 0

    basis_eval: Dict[str, int] = {PauliBasis.X.value: 0, PauliBasis.Y.value: 0, PauliBasis.Z.value: 0}
    basis_err: Dict[str, int] = {PauliBasis.X.value: 0, PauliBasis.Y.value: 0, PauliBasis.Z.value: 0}

    for rec in batch.records:
        if rec.ideal_outcome is not None:
            evaluated += 1
            b_name = rec.basis.value
            basis_eval[b_name] = basis_eval.get(b_name, 0) + 1

            if rec.outcome != rec.ideal_outcome:
                errors += 1
                basis_err[b_name] = basis_err.get(b_name, 0) + 1

    overall = float(errors / evaluated) if evaluated > 0 else 0.0

    basis_rates: Dict[str, float] = {}
    for b in (PauliBasis.X.value, PauliBasis.Y.value, PauliBasis.Z.value):
        cnt = basis_eval.get(b, 0)
        basis_rates[b] = float(basis_err.get(b, 0) / cnt) if cnt > 0 else 0.0

    active_rates = [rate for b, rate in basis_rates.items() if basis_eval.get(b, 0) > 0]
    asymmetry = float(max(active_rates) - min(active_rates)) if len(active_rates) > 1 else 0.0

    return QBERReport(
        total_qubits=total,
        evaluated_qubits=evaluated,
        error_count=errors,
        overall_qber=overall,
        basis_qber=basis_rates,
        basis_counts=basis_eval,
        basis_error_counts=basis_err,
        basis_asymmetry=asymmetry,
    )
