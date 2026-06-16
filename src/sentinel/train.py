"""Train and persist the supervised injection classifier.

Run with:  python -m sentinel.train   (or the ``sentinel-train`` command)

Trains on the deepset/prompt-injections train split and saves the model so the
service can load it at startup. The model is tied to the embedding backend it
was trained with, so retrain after switching embedders.
"""

from __future__ import annotations

from sentinel.benchmark import load_prompt_injections
from sentinel.detectors.classifier import DEFAULT_MODEL_PATH, TrainedInjectionClassifier


def train(path: str = DEFAULT_MODEL_PATH) -> TrainedInjectionClassifier:
    texts, labels = load_prompt_injections(split="train")
    detector = TrainedInjectionClassifier().fit(texts, labels)
    detector.save(path)
    return detector


def main() -> None:
    detector = train()
    print(
        f"Trained injection classifier (backend={detector.backend_}, dim={detector.dim_}) "
        f"saved to {DEFAULT_MODEL_PATH}"
    )


if __name__ == "__main__":
    main()
