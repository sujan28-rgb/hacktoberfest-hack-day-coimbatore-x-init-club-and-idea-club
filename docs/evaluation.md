# Replaying the engine

Run `python -m sentinel_evidence.evaluation --fixtures fixtures` after installing
the package. The command returns machine-readable JSON and exits nonzero on a
scenario-label mismatch or failed evidence-removal check.

Each hand-authored episode is one sample. Removal variants are checks on their parent
episode, not independent observations. B0 counts detector/timeline output; B1 runs the
deterministic engine. Scenario-label precision, recall, false-positive rate, citation
existence, unresolved identity rate, latency and Python allocation peak are measured.
Zero-denominator metrics are null. Python allocation peak is not total RAM or VRAM.

These tiny fixture results are regression checks, not an accuracy benchmark. Citation
existence is not semantic citation support. Unconstrained/citation-only model baselines,
controlled VM capture collection and representative labeled datasets have not been run.
