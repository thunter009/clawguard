.PHONY: setup-hooks

setup-hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks path set to .githooks"
