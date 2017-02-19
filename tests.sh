#!/usr/bin/env bash

STATUS=0

echo "Starting bandit and flake8 tests..."

bandit -r .

if [ $? -eq 0 ]; then
	echo "Bandit PASSED!"
else
	echo "Bandit FAILED!"
	STATUS=1
fi

flake8 .

if [ $? -eq 0 ]; then
	echo "flake8 PASSED!"
else
	echo "flake8 FAILED!"
	STATUS=1
fi

exit $STATUS
