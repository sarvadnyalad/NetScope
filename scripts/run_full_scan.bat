@echo off
call .venv\Scripts\activate
python src\netscope.py --profile full %*
