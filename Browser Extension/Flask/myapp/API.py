import subprocess
import logging
from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)

phishing_detector_enabled = False

detected_urls = []

@app.route('/detect_phishing', methods=['GET', 'POST'])
def detect_phishing():
    app.logger.debug('detect_phishing called')

    if request.method == 'POST':
        enabled = request.json.get('enabled')
        if enabled is None:
            return jsonify({'error': 'Please provide an "enabled" parameter'})

        app.logger.debug(f'Phishing detector enabled: {enabled}')

        phishing_detector_enabled = enabled

        if phishing_detector_enabled:
            app.logger.debug('Starting phishpit script...')
            subprocess.Popen(["python", "C:/Users/kyleb/iCloudDrive/UNI WORK/Honours Year/PROJECT 2023/Browser Extension/Flask/myapp/autoclassify.py"])

            app.logger.debug('Phishing detector script started')

        message = f'Phishing detector is now {"enabled" if phishing_detector_enabled else "disabled"}'
        app.logger.debug(message)

        return jsonify({'result': message})

    else:
        return jsonify({'enabled': phishing_detector_enabled})



@app.route('/urls')
def urls():
    try:
        response = requests.get('http://127.0.0.1:5000/detected_urls')
        detected_urls = response.json()['detected_urls']
    except requests.exceptions.RequestException as e:
        print(e)
        detected_urls = []

    if not detected_urls:
        message = 'No URLs detected'
        return render_template('urls.html', message=message)
    else:
        return render_template('urls.html', detected_urls=detected_urls)



@app.route('/detected_urls')
def get_detected_urls():
    global detected_urls
    return jsonify({'detected_urls': detected_urls})



if __name__ == '__main__':
    app.run(debug=True)