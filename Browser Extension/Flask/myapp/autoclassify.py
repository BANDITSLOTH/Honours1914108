# Import necessary libraries
from shutil import ExecError
from tkinter import CURRENT
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from collections import defaultdict
import re
from sklearn.impute import SimpleImputer
import numpy as np

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import NoSuchWindowException
import requests
from urllib.parse import urlparse, urlunparse
import time
from lxml import html
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import whois
from datetime import datetime

 #function for RandomForest Classification
def RFClassify ():

    # Load and preprocess the dataset
    datasetraw = pd.read_csv("C:\\Users\\kyleb\\iCloudDrive\\UNI WORK\\Honours Year\\PROJECT 2023\\Detection Script\\dataset_phishing.csv")
    (datasetraw.shape)
    print("Loading 25%")
    pd.reset_option('display.max_rows')
    datasetraw.isna().sum()

    # Map the class labels to integers
    class_map = {'legitimate':0, 'phishing':1}
    datasetraw['status'] = datasetraw['status'].map(class_map)

    # Calculate the correlation between features
    corr = datasetraw.corr(numeric_only=True)

    # Select the most relevant features
    features_selected = corr[['length_url','ip','nb_at','nb_percent','nb_hyphens','nb_dslash','prefix_suffix','nb_underscore','https_token','nb_dots','nb_dollar','nb_subdomains','nb_com','domain_age','domain_registration_length','whois_registered_domain']]
    X = datasetraw[features_selected.columns]
    y = datasetraw['status']

    # Split the dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, random_state=42)
    print("Loading 50%")

    # Scale the features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Handle missing values
    X_train = pd.DataFrame(X_train)
    X_train.dropna(inplace=True)  
    imputer = SimpleImputer(strategy="mean")
    imputer.fit(X_train.values)

    # Train the RandomForestClassifier
    model = RandomForestClassifier()
    model.fit(X_train.values, y_train)

    print("Loading 75%")

    # Make predictions on the training data
    y_train_pred = model.predict(X_train)

    # Calculate the accuracy of the model on the training data
    accuracy = accuracy_score(y_train, y_train_pred)
    print("Training accuracy: {:.2f}%".format(accuracy*100))

    def classify_url(url):
        # Feature extraction for the input URL
        input_data = {}
        input_data['length_url'] = len(url)
        input_data['ip'] = int(re.match(r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\:[0-9]{1,5})?([\/\?\#].*)?$', url) is not None)
        input_data['nb_at'] = int("@" in url)
        input_data['nb_percent'] = int("%" in url)
        input_data['nb_hyphens'] = int("-" in url)
        input_data['nb_dslash'] = int("//" in url)
        input_data['prefix_suffix'] = int(re.match(r'^(?:http|ftp)s?://|www\.|[a-zA-Z0-9_-]+\.(?:com|org|net|mil|edu|COM|ORG|NET|MIL|EDU)$', url) is not None)
        input_data['nb_underscore'] = int("_" in url)
        input_data['https_token'] = int("https" in url)
        input_data['nb_dots'] = int("." in url)
        input_data['nb_dollar'] = int("$" in url)
        input_data['nb_subdomains'] = url.count(".") - 1
        input_data['nb_com'] = int(".com" in url)
        parsed_url = urlparse(url)
        domain_info = get_domain_info(parsed_url.netloc)
        input_data['domain_age'] = domain_info['domain_age'] if domain_info['domain_age'] is not None else -1
        input_data['domain_registration_length'] = domain_info['domain_registration_length'] if domain_info['domain_registration_length'] is not None else -1
        input_data['whois_registered_domain'] = domain_info['whois_registered_domain'] if domain_info['whois_registered_domain'] is not None else -1


        # Convert the extracted features into a data frame
        input_data = pd.DataFrame.from_dict(input_data, orient='index', columns=["value"]).T

        # Select only the features in the "features_selected" list
        input_data = input_data[features_selected.columns]

        # Handling NaN values in the input
        input_data = input_data.replace([np.inf, -np.inf], np.nan)
        input_data = pd.DataFrame(imputer.transform(input_data))
        input_data.columns = features_selected.columns
        # Scale the features
        input_data = scaler.transform(input_data)

        # Predict the class of the URL
        prediction = model.predict(input_data)
        prediction_proba = model.predict_proba(input_data)

        # Return the prediction results
        return prediction[0], prediction_proba

    return classify_url
   
    
 # function for automatic URL detection and classification
def AutoURLDetect(custom_classify_url):
    # Set up the chrome webdriver
    service = ChromeService(executable_path=ChromeDriverManager().install())
    chrome_user_data_dir = "C:/Users/kyleb/AppData/Local/Google/Chrome/User Data"
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument(f"user-data-dir={chrome_user_data_dir}")
    chrome_options.add_argument("--remote-debugging-port=9222")

    driver = webdriver.Chrome(service=service, options=chrome_options)
  

    detected_urls_list=[]
    print('Chrome driver initialized')
    
    # Navigate to a URL
    driver.get("https://www.facebook.com")
    detected_urls = defaultdict(int)
    classified_urls = defaultdict(int)  # create a set for classified URLs

    print('Page loaded')

    previous_url = None

    #function to modify the URL colour based on classifcation 
    def modify_link_color(url, classification):
        if classification == "phishing":
            color = "red"
        elif classification == "legitimate":
            color = "green"
 

        # Create a JavaScript code snippet to change the color of the specified URL text
        js_code = f'''
        var links = document.getElementsByTagName('a');
        for (var i = 0; i < links.length; i++) {{
            if (links[i].href === '{url}') {{
                links[i].style.color = '{color}';
            }}
        }}
        '''

        # Execute the JavaScript code in the web browser using Selenium
        driver.execute_script(js_code)

    # Loop over the detected URLs and classify them
    while True:
        try:

            current_url = driver.current_url
            if current_url != previous_url:
                classified_urls = set()
                detected_urls.clear()
                previous_url = current_url
            # Get the page source
            html_source = driver.page_source

            # Parse the HTML source using lxml
            tree = html.fromstring(html_source)

            # Find all URLs that are displayed as plain text to the user
            urls = tree.xpath('//a[text() and not(@style) and not(ancestor::button or ancestor::a)]/@href')

            base_url = get_base_url(driver.current_url)
            urls.insert(0, base_url)
            # Add the detected URLs to the list
            for url in urls:
                    detected_urls[url] += 1
            window_handles = driver.window_handles

            for handle in window_handles:
                try:
                    driver.switch_to.window(handle)
                except NoSuchWindowException:
                    print("Window has been closed. Stopping...")
                    continue
                except Exception as e:
                    print(f"Error Switching to Window Handle: {e}")
                    continue

            detected_urls_list = list(detected_urls)

            for url in detected_urls_list:
                if url not in classified_urls:
                    formatted_url = format_url(url)
                    prediction, prediction_proba = classify_url(formatted_url)
                    classification = "phishing" if prediction == 1 else "legitimate"
                    print(f"URL: {formatted_url}\nClassification: {classification}\n")
                    modify_link_color(formatted_url, classification)

                    # Add the URL to the classified_urls set
                    classified_urls.add(url)
              
            time.sleep(1)
        except NoSuchWindowException:
            continue
        except Exception as e:
            print(f"Error encountered: {e}")
            time.sleep(1)
    

def custom_classify_url(url, threshold=0.7):
    prediction, prediction_proba = classify_url(url)
    if prediction == 1 and prediction_proba[0][1] >= threshold:
        return "phishing", prediction_proba
    elif prediction == 0 and prediction_proba[0][0] >= threshold:
        return "legitimate", prediction_proba
    else:
        return "uncertain", prediction_proba

def format_url(url):
    if url.startswith('http:///'):
        return None
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    return url

def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        result = {}
        if domain_info.creation_date and type(domain_info.creation_date) != str:
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            domain_age = (datetime.now() - creation_date).days
            result['domain_age'] = domain_age
        else:
            result['domain_age'] = None

        if domain_info.expiration_date and type(domain_info.expiration_date) != str:
            if isinstance(domain_info.expiration_date, list):
                expiration_date = domain_info.expiration_date[0]
            else:
                expiration_date = domain_info.expiration_date
            domain_registration_length = (expiration_date - creation_date).days
            result['domain_registration_length'] = domain_registration_length
        else:
            result['domain_registration_length'] = None

        result['whois_registered_domain'] = 1 if domain_info.registered_domain else 0

        return result
    except Exception as e:
        return {'domain_age': None, 'domain_registration_length': None, 'whois_registered_domain': None}


def get_base_url(url):
    parsed_url = urlparse(url)
    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, "", "", "", ""))
    return base_url



classify_url = RFClassify()
AutoURLDetect(custom_classify_url)
