"""
Cryptographic Baseline Management & Poisoning Safeguards.
Tracks baseline profiles across captures with observation count thresholds
(NO_BASELINE -> PROVISIONAL -> ESTABLISHED / TRUSTED) to prevent baseline poisoning.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from app.analyzers.identity import CryptographicProfile


class BaselineStatus(str, Enum):
    NO_BASELINE = "NO_BASELINE"
    PROVISIONAL = "PROVISIONAL"
    ESTABLISHED = "ESTABLISHED"
    TRUSTED = "TRUSTED"


@dataclass
class InfrastructureBaseline:
    identity_key: str
    status: BaselineStatus = BaselineStatus.NO_BASELINE
    observation_count: int = 0
    profile: Optional[CryptographicProfile] = None
    observation_history: List[Dict[str, Any]] = field(default_factory=list)

    def add_observation(
        self,
        new_profile: CryptographicProfile,
        min_established_count: int = 3,
        force_trusted: bool = False
    ) -> bool:
        """
        Record a new cryptographic profile observation for this infrastructure identity.
        Implements baseline poisoning safeguards:
        - Baseline requires min_established_count observations to become ESTABLISHED.
        - If force_trusted is True, sets status to TRUSTED (pinned by analyst).
        - Returns True if baseline was updated/created, False if rejected.
        """
        if self.status == BaselineStatus.TRUSTED and not force_trusted:
            # Trusted analyst baseline pinned — do not auto-overwrite profile
            self.observation_count += 1
            self.observation_history.append(new_profile.to_dict())
            return False

        self.observation_count += 1
        self.observation_history.append(new_profile.to_dict())

        if force_trusted:
            self.status = BaselineStatus.TRUSTED
            self.profile = new_profile
            return True

        if self.observation_count < min_established_count:
            self.status = BaselineStatus.PROVISIONAL
            if self.profile is None:
                self.profile = new_profile
            return True
        else:
            self.status = BaselineStatus.ESTABLISHED
            self.profile = new_profile
            return True


class BaselineStore:
    """In-memory or persistent store for infrastructure baselines."""
    def __init__(self):
        self._baselines: Dict[str, InfrastructureBaseline] = {}

    def clear(self) -> None:
        self._baselines.clear()

    def get_baseline(self, identity_key: str) -> Optional[InfrastructureBaseline]:

        return self._baselines.get(identity_key)

    def get_or_create_baseline(self, identity_key: str) -> InfrastructureBaseline:
        if identity_key not in self._baselines:
            self._baselines[identity_key] = InfrastructureBaseline(identity_key=identity_key)
        return self._baselines[identity_key]

    def record_profile(
        self,
        identity_key: str,
        profile: CryptographicProfile,
        min_established_count: int = 3,
        force_trusted: bool = False
    ) -> InfrastructureBaseline:
        bl = self.get_or_create_baseline(identity_key)
        bl.add_observation(profile, min_established_count=min_established_count, force_trusted=force_trusted)
        return bl


global_baseline_store = BaselineStore()

