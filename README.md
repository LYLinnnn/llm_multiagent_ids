# llm_multiagent_ids
# Honours Research Project - Yilin Li

# Overview

This project proposes an autonomous LLM-based IDS, powered by LangGraph, RAG (Retrieval-Augmented Generation), and Heuristic In-Context Learning. 

Instead of traditional ML/DL classifiers, there are 5 agents in total:
1. EventProcessingAgent: clean and choose the most security-relevant features, normalise the data
2. ThreatCognitiveAgent: make predictions (either benign or malicious) by retriving the knowledge base and doing the heuristic in-context learning by feeding in some examples as prompts. Also provide reasoning. 
3. ResponseDecisionAgent: decide response, block, alert, monitor, or ignore. Provide reasoning for the response. 
4. EnforcementAgent: provide action to the target
5. AuditLearningAgent: generate report automatically

# DATASET:
Please download the dataset from this link: https://www.kaggle.com/datasets/primus11/cic-ids-2018-dataset. 
Place the CSV file in project root and name it as "cis-ids2018.csv". 

# Requirement:
Python 3.10+

# Installation:
Key libraries:

- openai
- langgraph
- sentence-transformers
- faiss-cpu
- pandas
- python-dotenv

# Environment Setup
Create .env file and put you OPENAI API key inside this file

# Run
1. create virtual environment:
   python -m venv venv,
   source venv/bin/activate
2. install dependencies:
   pip install -r requirements.txt
3. run:
   python3 cisids_runner.py
4. output:
   results saved to results/llm_ids_results.csv



