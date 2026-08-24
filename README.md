\# AI-Based Cyberattack Detection and Proactive Neutralization Using Transformer Networks



\## Overview



This project implements an AI-based Network Intrusion Detection System (NIDS) for detecting suspicious and malicious network traffic and applying automated response actions.



The system combines live packet capture, sequential traffic analysis, a Transformer-based deep learning model, future-risk prediction, threat neutralization, and a web-based IDS dashboard.



\## System Architecture



```text

Network Traffic

&#x20;     ↓

Packet Capture (Npcap + Scapy)

&#x20;     ↓

Feature Extraction

&#x20;     ↓

Sequential Traffic Analysis

&#x20;     ↓

Transformer Neural Network

&#x20;     ↓

Current Attack Detection

&#x20;     +

Future Risk Prediction

&#x20;     ↓

Neutralization Engine

&#x20;     ↓

IDS Dashboard

