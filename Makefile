.PHONY: help test drill policy policy-negative fmt validate lambda.zip release clean

help:
	@echo "emr-bunker make targets"
	@echo "  test            - python unit tests"
	@echo "  drill           - run the ransomware drill (the provable gate)"
	@echo "  policy          - conftest policies against k8s/"
	@echo "  policy-negative - verify the policies reject the bad fixtures"
	@echo "  fmt             - terraform fmt"
	@echo "  validate        - terraform validate"
	@echo "  lambda.zip      - package the response lambda"
	@echo "  release         - build the v1.0.0 release archives + checksums"
	@echo "  clean           - remove caches"

test:
	python3 -m pytest tests/ -q

drill:
	python3 drill/ransomware_drill.py

policy:
	conftest test k8s/ --policy policy/

policy-negative:
	@if conftest test examples/policy-negative/ --policy policy/ >/dev/null 2>&1; then \
		echo "FAIL: the bad manifests passed the policies"; exit 1; \
	else \
		echo "OK: the bad manifests are rejected"; \
	fi

fmt:
	cd terraform && terraform fmt -recursive

validate:
	cd terraform && terraform init -backend=false && terraform validate

lambda.zip:
	python3 scripts/build_lambda_zip.py

release:
	bash scripts/release.sh

clean:
	rm -rf .pytest_cache playbook/__pycache__ playbook/drivers/__pycache__ \
		canary/__pycache__ tests/__pycache__ terraform/.terraform lambda.zip
