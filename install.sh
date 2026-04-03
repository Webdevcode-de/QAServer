#!/bin/bash

echo "Creating virtual environment..."
python3 -m venv venv

echo "Installing dependencies..."
venv/bin/pip install --upgrade pip

if [ -f requirements.txt ]; then
    venv/bin/pip install -r requirements.txt
else
    echo "No requirements.txt found."
fi

echo ""
echo "Setup complete!"
echo "To activate the environment, run:"
echo "source venv/bin/activate"