.PHONY: callbackd-apply callbackd-plan

callbackd-plan:
	terraform -chdir=infra plan

callbackd-apply:
	terraform -chdir=infra apply
