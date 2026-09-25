# Project Spectre

## Behavioral Host Intrusion Detection System

### Design Document and Incremental SDLC Roadmap

---

# 1. Vision

Spectre is a behavioral Host Intrusion Detection System (HIDS) that focuses on relationships and execution chains rather than signatures.

Traditional antivirus asks:

> "Is this file known?"

Spectre asks:

> "Does this sequence of actions make sense?"

The goal is to model the grammar of a computer system and detect execution patterns that violate expected behavior.

---

# 2. Design Principles

### Simplicity First

Every version must remain usable.

No feature should require future features.

---

### Incremental Evolution

Each release should be functional.

No "build everything then release".

---

### Explainability

Every alert must explain:

* What happened.
* Why it is suspicious.
* Which process caused it.
* Which chain produced the alert.

---

### Local First

No cloud dependency.

No external APIs required.

---

### Low Resource Consumption

Target:

* CPU <5%
* RAM <200 MB

---

# 3. Core Concepts

## Entities

### Process

Examples:

* python
* bash
* nginx

---

### File

Examples:

* /etc/shadow
* ~/.ssh/id_rsa

---

### Socket

Examples:

* 192.168.1.15:4444

---

## Relationships

### SPAWN

Process → Process

Example:

nginx → bash

---

### READ

Process → File

Example:

bash → /etc/shadow

---

### WRITE

Process → File

Example:

python → config.json

---

### CONNECT

Process → Socket

Example:

nc → 192.168.1.20:4444

---

# 4. High Level Architecture

Sensor Layer
↓

Event Normalization

↓

Graph Builder

↓

Detection Engine

↓

Alert Generator

↓

User Interface

---

# 5. Incremental SDLC

---

# V0

## Goal

Proof of concept.

## Components

Process monitor.

## Technology

Python

psutil

## Output

Console only.

Example:

python
└── bash
└── curl

---

# V1

## Goal

Rule-based behavioral detector.

## Features

Process tree construction.

Suspicious chain scoring.

Alert generation.

Explanation engine.

## Example

nginx
↓
bash
↓
netcat

Alert:

Web server spawned shell.

Score = 20

---

## Technology

Python

psutil

dataclasses

logging

---

## Deliverable

Working HIDS.

---

# V2

## Goal

Resource tracking.

## New Entity Types

Files

Sockets

## New Events

READ

WRITE

CONNECT

## Example

bash

↓

/etc/shadow

↓

4444 connection

---

## Deliverable

Process-resource graph.

---

# V3

## Goal

Sliding window graph.

## Features

Event expiration.

Rolling memory.

Graph cleanup.

---

## Technology

deque

dictionary

networkx

---

# V4

## Goal

Detection Engine.

## Features

Weighted scoring.

Rule configuration.

Thresholds.

JSON rules.

Example:

{
"parent":"nginx",
"child":"bash",
"score":10
}

---

# V5

## Goal

Attack Mapping.

## Framework

MITRE ATT&CK.

Example:

PowerShell execution

↓

T1059

Credential access

↓

T1003

---

# V6

## Goal

Persistence.

## Storage

SQLite.

Store:

Events.

Alerts.

Scores.

Process chains.

---

# V7

## Goal

REST API.

## Framework

FastAPI.

Endpoints:

/events

/alerts

/processes

/chains

---

# V8

## Goal

Dashboard.

## Technology

Next.js

TailwindCSS

WebSockets

## Features

Live graph.

Alert feed.

Timeline.

Statistics.

---

# V9

## Goal

YARA Integration.

## Features

Hash lookup.

String signatures.

File scanning.

---

# V10

## Goal

Containment.

## Actions

SIGSTOP.

SIGTERM.

Kill tree.

Quarantine.

---

# V11

## Goal

Attack Replay Framework.

## Purpose

Generate known malicious chains.

## Sources

Atomic Red Team.

Custom scripts.

---

# V12

## Goal

Telemetry Improvements.

## Linux

eBPF

auditd

procfs

---

# V13

## Goal

Machine Learning.

## Models

Isolation Forest

LOF

One-Class SVM

---

## Input

Behavior vectors.

---

## Output

Anomaly score.

---

# V14

## Goal

Graph Embeddings.

## Algorithms

Node2Vec

DeepWalk

---

# V15

## Goal

Multi-host Support.

## Architecture

Agent

↓

Collector

↓

Detection Engine

---

## Transport

Kafka

Redis Streams

RabbitMQ

---

# V16

## Goal

LLM Explanations.

Example:

nginx spawned bash.

bash accessed /etc/shadow.

Network communication to port 4444 followed.

The sequence resembles ATT&CK T1059 and T1003.

---

# V17

## Goal

Research Branch.

## Possible Directions

Graph Neural Networks.

Temporal Graph Networks.

Dynamic Graph Learning.

GCN + GRU.

Continuous-Time Graphs.

---

# Directory Structure

spectre/

core/

sensor/

graph/

rules/

detectors/

alerts/

storage/

api/

dashboard/

tests/

examples/

docs/

---

# Recommended Stack

Language:

Python

Storage:

SQLite

API:

FastAPI

Frontend:

Next.js

Graph:

NetworkX

Monitoring:

psutil

Visualization:

react-force-graph

Testing:

pytest

---

# Success Criteria

V1

Detect suspicious chains.

Explain alerts.

Run continuously.

Low resource usage.

---

V5

Provide ATT&CK mapping.

---

V10

Contain malicious process trees.

---

V13

Perform anomaly detection.

---

V17

Experiment with graph learning.

---

# Final Goal

A lightweight behavioral EDR capable of understanding execution relationships rather than relying exclusively on signatures.

Its purpose is not to answer:

"Is this file malicious?"

but rather:

"Does this sequence of actions belong on this machine?"
