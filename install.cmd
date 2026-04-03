@echo off

echo Creating virtual environment...
python -m venv venv

echo Installing dependencies...
venv\Scripts\pip install --upgrade pip

if exist requirements.txt (
    venv\Scripts\pip install -r requirements.txt
) else (
    echo No requirements.txt found.
)

echo.
echo Setup complete!
echo To activate the environment, run:
echo venv\Scripts\activate

pause