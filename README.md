virtualenv commands:

virtualenv venv # create venv
. venv/bin/activate

deactivate # deactivates venv

to start:

export FLASK_APP=name.py
flask run --host=0.0.0.0
