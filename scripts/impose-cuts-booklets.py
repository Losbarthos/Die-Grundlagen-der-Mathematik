"""Create the two B19 booklets using the established unscaled vector imposition."""
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]

def main():
    impose = runpy.run_path(str(ROOT / "scripts/impose-binomial-booklet.py"))["impose"]
    for kind, suffix, title in (
        ("reading", "booklet", "Druckbroschüre"),
        ("exercises", "exercises-booklet", "Übungsheft - Druckbroschüre"),
    ):
        impose(ROOT / f"registry/cuts/_B19-cuts-{kind}.pdf",
               ROOT / f"registry/cuts/_B19-cuts-{suffix}.pdf",
               ROOT / f"tmp/cuts-editions/{suffix}-page-plan.json",
               f"Band 19 - Dedekindsche Schnitte und Vollständigkeit - {title}")

if __name__ == "__main__":
    main()
