.PHONY: install test run-mock run-live lint
install:
	pip install -e ".[dev]"
test:
	pytest -q
run-mock:
	EXECUTOR=mock FIXTURES_DIR=$(PWD)/fixtures/sample_case \
	EVIDENCE_ALLOWLIST=$(PWD)/fixtures/sample_case DB_PATH=$(PWD)/mock_run.db \
	python -m find_evil.interfaces.cli "ransomware on win10 endpoint" \
	  --evidence $(PWD)/fixtures/sample_case/disk.img \
	  --evidence $(PWD)/fixtures/sample_case/memory.mem -o mock_report.md
run-live:
	python -m find_evil.interfaces.cli "$(INCIDENT)" --evidence "$(EVIDENCE)" -o report.md
lint:
	ruff check src tests && black --check src tests
