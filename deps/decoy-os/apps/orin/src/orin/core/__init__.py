# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
orin.core – Foundational Engine Components
===========================================
Provides the three infrastructure pillars that the rest of Orin relies on:

Modules
-------
config    – JSON configuration loader with built-in safe defaults.
database  – SQLite schema definition and ``OrinStorage`` context-manager ORM.
crypto    – HMAC-SHA256 signing and verification for portable export bundles.
logging   – Structured JSON logging for SIEM integration.
"""