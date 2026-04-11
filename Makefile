.PHONY: install clean build-binary run run-json run-sarif

install:
	pip3 install .

run:
	python3 -m escapewatch.cli

run-json:
	python3 -m escapewatch.cli --format json

run-sarif:
	python3 -m escapewatch.cli --format sarif

run-compact:
	python3 -m escapewatch.cli --format compact

run-ci:
	python3 -m escapewatch.cli --ci --fail-on high --format json

sample-outputs:
	python3 -m escapewatch.cli --format json --output examples/sample_report.json
	python3 -m escapewatch.cli --format sarif --output examples/sample_report.sarif

build-binary:
	pip3 install pyinstaller
	python3 -m PyInstaller --onefile \
		--name escapewatch \
		--distpath dist/ \
		src/escapewatch/cli.py
	@echo "Binary available at dist/escapewatch"

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info escapewatch.spec
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
