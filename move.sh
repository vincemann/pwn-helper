#!/bin/bash
# move to host system to then git push
rsync -av --progress pwnhelper/ share/ --exclude venv/ --exclude move.sh