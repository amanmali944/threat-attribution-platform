"""Attribution layer (Developer A).

Implements contract sections 6-8 in ``docs/DETECTION_CONTRACT.md``:

* ``correlation`` - Fused Alerts -> Incident Objects (one causal story per attack)

Pure Python like the detection layer: no database, no network, plain dicts in and out.
"""
