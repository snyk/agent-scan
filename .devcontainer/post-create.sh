#!/usr/bin/env sh

# update
sudo apt update -y

## Install gh cli
sudo apt install gh -y

# Install Snyk
npm install -g snyk

# Install Gemini CLI
npm install -g @google/gemini-cli

# Install uv
pipx install uv