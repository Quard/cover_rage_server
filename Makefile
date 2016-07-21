.PHONY: run

run:
	gunicorn "cover_rage_server:get_application()" --bind 0.0.0.0:8080 --worker-class aiohttp.worker.GunicornWebWorker --log-level INFO --reload --timeout 0

clean_pyc:
	find . -name \*.pyc -delete
	find . -name \*.pyo -delete

test:
	RAGE_SRV_HOST=example.com python -m unittest

test_with_coverage:
	RAGE_SRV_HOST=example.com nosetests --with-coverage --cover-html --cover-html-dir=html_coverage

test_ci:
	RAGE_SRV_HOST=example.com nosetests --with-coverage --cover-xml --with-xunit

docker:
	docker-compose --file docker-compose.yml --project-name rage_srv up

dev_docker:
	docker-compose --file dev-docker-compose.yml --project-name rage_srv_dev up

build:
	python setup.py sdist

release:
	python setup.py sdist upload

sinclude makefile-local
