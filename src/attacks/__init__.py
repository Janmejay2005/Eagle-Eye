"""
Attacks package providing parameterized attack simulations against QDS.
"""
from src.attacks.forgery import ForgerySimulator
from src.attacks.impersonation import ImpersonationSimulator
from src.attacks.replay import ReplaySimulator
from src.attacks.channel import ChannelAttackSimulator
from src.attacks.unauthorized import UnauthorizedVerificationSimulator

__all__ = [
    "ForgerySimulator",
    "ImpersonationSimulator",
    "ReplaySimulator",
    "ChannelAttackSimulator",
    "UnauthorizedVerificationSimulator",
]
