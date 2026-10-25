"""Detection layer (Developer A).

Implements the contract in ``docs/DETECTION_CONTRACT.md``:

* ``contract``  - frozen constants shared by every detection module
* ``resolve``   - canonical event -> enriched event (resolved entities)
* ``features``  - enriched events -> deterministic Feature Vectors

Modules here are pure Python: no database, no network. They read and return
plain dicts / dataclasses so they can be tested against fixtures alone.
"""
