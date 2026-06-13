# Copyright 2012 Antonin Beaujeant
#
# This file is part of epassportviewer.
#
# epassportviewer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# epassportviewer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with epassportviewer.
# If not, see <http://www.gnu.org/licenses/>.

"""Security research modules for ePassport / eMRTD vulnerability analysis."""

from pypassport.attacks.brute_force import BruteForce, BruteForceException
from pypassport.attacks.mac_traceability import (
    MacTraceability,
    MacTraceabilityException,
)
from pypassport.attacks.error_fingerprinting import (
    ErrorFingerprinting,
    ErrorFingerprintingException,
)
from pypassport.attacks.sign_everything import (
    SignEverything,
    SignEverythingException,
)
from pypassport.attacks.active_authentication_traceability import (
    AATraceability,
    AATraceabilityException,
)

__all__ = [
    "BruteForce",
    "BruteForceException",
    "MacTraceability",
    "MacTraceabilityException",
    "ErrorFingerprinting",
    "ErrorFingerprintingException",
    "SignEverything",
    "SignEverythingException",
    "AATraceability",
    "AATraceabilityException",
]

