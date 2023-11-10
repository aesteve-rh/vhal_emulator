# SPDX-FileCopyrightText: Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

VENV_DIR = $(HOME)/.venv/vhal_emulator
VENV = $(VENV_DIR)/bin

venv:
	python3 -m venv $(VENV_DIR) && \
	$(VENV)/python3 -m pip install --upgrade pip && \
	$(VENV)/python3 -m pip install -r src/codegen/requirements.txt

render:
	./src/codegen/gen_vhal_const.py