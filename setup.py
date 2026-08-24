"""Build the supported package with private checker/schema/fixture resources."""

from pathlib import Path
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent


class BuildPy(build_py):
    def run(self) -> None:
        super().run()
        package = Path(self.build_lib) / "flyology_type_ir"
        shutil.copy2(ROOT / "scripts/check_fixtures.py", package / "_checker.py")
        data = package / "_root"
        (data / "schema").mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            ROOT / "schema/type-ir-v1.schema.json",
            data / "schema/type-ir-v1.schema.json",
        )
        fixtures = data / "fixtures"
        (fixtures / "ada").mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "fixtures/fixtures.gpr", fixtures / "fixtures.gpr")
        for source in (ROOT / "fixtures/ada").glob("*.ads"):
            shutil.copy2(source, fixtures / "ada" / source.name)
        extraction = fixtures / "extraction"
        (extraction / "src").mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            ROOT / "fixtures/extraction/production_shapes.gpr",
            extraction / "production_shapes.gpr",
        )
        shutil.copy2(
            ROOT / "fixtures/extraction/src/production_shapes.ads",
            extraction / "src/production_shapes.ads",
        )


setup(cmdclass={"build_py": BuildPy})
