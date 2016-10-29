from flask import Flask, url_for
from flask import render_template
from flask import request

app = Flask(__name__, instance_relative_config=True)
app.config.from_object('config')
app.config.from_pyfile('config.py')

debug_level = app.config['DEBUG']


@app.route('/', methods=['GET'])
def index(name=None):
    return render_template('index.html', backdrop=url_for('static', filename='backdrop.png'))

