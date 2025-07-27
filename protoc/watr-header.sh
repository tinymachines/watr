#!/bin/bash

source "${WATR_ROOT}/.env"

export WATR_ROOT="${WATR_ROOT}"
set WATR_ROOT="${WATR_ROOT}"

export WATR_LLM="${WATR_LLM}"
set WATR_LLM="${WATR_LLM}"

export WATR_NAME="${WATR_NAME}"
set WATR_NAME="${WATR_NAME}"

source ${HOME}/.pyenv/versions/tinmac/bin/activate
