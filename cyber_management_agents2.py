"""
Prototype: LLM-Only Cybersecurity Management Multi-Agents (LangGraph)
File: cyber_management_agents2.py
input: CIS-IDS2018.csv

Agents:
1. EventProcessingAgent (Ingest + Clean)
2. ThreatCognibstiveAgent (Detect + Analyse)
3. ResponseDecisionAgent
4. EnforcementAgent
5. AuditLearningAgent

Requirements:
    pip install langgraph openai python-dotenv

Run:
    cd /Users/yilinli/honours
        source venv/bin/activate -- activate the virtual env
    python3 cyber_management_agents2.py
"""

from typing import TypedDict, Dict, Any, List
import time
import json

from langgraph.graph import StateGraph, START, END
from openai import OpenAI
from dotenv import load_dotenv
from rag_retriever import ThreatRAG
import os
rag = ThreatRAG()

# -----------------------------
# LLM Client
# -----------------------------
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("Missing OPENAI_API_KEY in .env")
client = OpenAI(api_key=OPENAI_API_KEY)

def llm_call(system_prompt: str, user_prompt: str) -> dict:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0,
    )

    content = response.choices[0].message.content.strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        print("⚠️ LLM returned invalid JSON:")
        print(content)
        raise


# -----------------------------
# State Definition
# -----------------------------
class CyberState(TypedDict, total=False):
    # Input
    raw_row: Dict[str, Any]

    # true label
    true_label: Dict[str, Any]

    # agent outputs
    processed_event: Dict[str, Any]
    threat_report: Dict[str, Any]
    response_decision: Dict[str, Any]
    enforcement_result: Dict[str, Any]
    log: List[Dict[str, Any]]


# -----------------------------
# 1) Event Processing Agent
# -----------------------------
def event_processing_agent(state: CyberState) -> CyberState:
    system = ("You are a cybersecurity data processing agent."
            "You clean raw network flow data and select only the most security-relevant features for intrusion detection. "
            "You must output structured, valid JSON only.")
    user = f"""
            Raw CIC-IDS2018 network flow row:
            {json.dumps(state["raw_row"], indent=2)}

        Tasks:
        - Select 10-15 features relevant to intrusion detection. HOWEVER, if available in raw data, ALWAYS include:
            - destination_port
            - protocol
            - flow_duration
            - total_number_of_forwarding_packets
            _ total_number_of_backward_packets
            - flow_byte_per_second
            - flow_packets_per_second
            - SYN_flag
            - ACK_flag
            - max_idle_value
        - Normalize values (convert durations to ms if needed)
        - Remove irrelevant/noisy features
        - Choose feature name yourself

        Rules:
        - Return ONLY valid JSON
        - NEVER include any ground-truth labels
        - Do NOT include markdown, code fences, or explanations
        - Keys must be descriptive and security relevant
        
        """ 
    
    state["processed_event"] = llm_call(system, user)

    return state


# -----------------------------
# 2) Threat Intelligence Agent
# -----------------------------
def threat_intelligence_agent(state: CyberState) -> CyberState:
    event_text = json.dumps(state["processed_event"], indent=2)
    # 🔵 Retrieve threat knowledge
    context_docs = rag.retrieve(event_text)
    context = "\n\n".join(context_docs)

    # -------------------------
    # Few-shot examples (heuristic anchors)
    # -------------------------
    few_shot_examples = """
    Example 1 (Benign):
    flow_duration=476608μs 
    destination_port=80
    protocol=6
    total_forwarding_packets=5
    total_backward_packets=3
    flow_bytes_per_second=1405.7674231234
    flow_packets_per_second=16.78528266
    SYN_flag=0
    ACK_flag=0
    max_idle_value=0
    label=benign

    Example 2 (Benign):
    flow_duration=2094μs
    destination_port=49906
    protocol=6
    total_forwarding_packets=2
    total_backward_packets=1
    flow_bytes_per_second=18147.08691
    flow_packets_per_second=1432.664756
    SYN_flag=1
    ACK_flag=1
    max_idle_value=0
    label=benign

    Example 3 (FTP Brute Force):
    flow_duration=2μs 
    destination_port=21
    protocol=6
    total_forwarding_packets=1
    total_backward_packets=1
    flow_bytes_per_second=0
    flow_packets_per_second=1000000
    SYN_flag=0
    ACK_flag=0
    max_idle_value=0
    label=FTP Brute Force

    Example 4 (SSH Brute Force):
    flow_duration=353159μs 
    destination_port=22
    protocol=6
    total_forwarding_packets=1
    total_backward_packets=1
    flow_bytes_per_second=0
    flow_packets_per_second=333333.33
    SYN_flag=0
    ACK_flag=1
    max_idle_value=0
    label=SSH Brute Force
    """

    # Example 5 (Port Scan):
    # very short flows, small packets, MANY different destination ports contacted
    # label=PortScan

    # Example 6 (Data Exfiltration):
    # long duration, steady outbound bytes, upload >> download
    # label=Infiltration

    system = """
    You are an expert SOC analyst.

    CRITICAL:
    You MUST reason like a human analyst.

    DO NOT immediately classify.
    First derive detection heuristics from examples.
    Then compare the observed event against those heuristics.

    Most traffic is benign.

    Return JSON only.
    """

# Threat Intelligence Knowledge:
#   {context}

    user = f"""
    REFERENCE EXAMPLES
    {few_shot_examples}

    Tasks:
    - Classify as benign or malicious
    - Identify attack type if malicious, the malicious types include SSH Brute Force and FTP Brute Force . Pick the most relevant attack type.
    - Provide confidence score (0–100)

    Step 1 — Heuristic Thinking

    Answer these silently, no need to return:

    1. What are common traits of benign traffic?
    2. What traffic characteristics strongly indicate DoS?
    3. What distinguishes Brute Force from DoS?
    4. What distinguishes Port Scan from Brute Force?
    5. What duration and packet-rate ranges are considered normal?
    6. Summarize detection heuristics for each attack type.

    -----------------------------------------
    Step 2 — Apply reasoning

    Observed event:
    {event_text}

    Answer this silently, no need to return:
    - explain which heuristics match or do NOT match

    Then output ONLY valid JSON:
    Do NOT include markdown, code fences, or explanations.
    {{
    "label": "malicious | benign",
    "attack_type": "...",
    "confidence": number,
    "reasoning": "clear security reasoning using heuristics and evidence"
    }}

    """

    state["threat_report"] = llm_call(system, user)
    return state


# -----------------------------
# 3) Response Decision Agent
# -----------------------------
def response_decision_agent(state: CyberState) -> CyberState:
    system = "You are a SOC response decision agent."
    user = f"""
Threat intelligence report:
{json.dumps(state["threat_report"], indent=2)}

Tasks:
- Decide response: block, alert, monitor, or ignore
- Justify the decision based on risk

Rules:
- You MUST NOT assume access to any grounf-truth labels when predicting the results
- Base decisions only on provided features

Return ONLY valid JSON:
Do NOT include markdown, code fences, or explanations.
{{
  "response": "block | alert | monitor | ignore",
  "justification": "..."
}}
"""
    state["response_decision"] = llm_call(system, user)
    return state


# -----------------------------
# 4) Enforcement Agent
# -----------------------------
def enforcement_agent(state: CyberState) -> CyberState:
    system = "You are a security enforcement automation agent. Provide the action to the target and give a specific ip address or host for the target getting from the user input. " \
    "Provide specific and detailed mechanism as well, the steps to take for this intrusion/threat. " 

    source_ip = state["processed_event"].get("source_ip", "unknown")
    decision = state["response_decision"]["response"]

    user = f"""
Incident details:
{json.dumps(state["response_decision"], indent=2)}
- Source IP: {source_ip}
- Response decision: {decision}

Tasks:
- Simulate enforcement actions
- Output firewall / IAM / SOAR-style commands or actions

Return ONLY valid JSON
Do NOT include markdown, code fences, or explanations.
{{
  "action": "block_ip | alert | isolate_host | none",
  "target": "{source_ip}",
  "mechanism": "firewall | IAM | SOAR",
  "detailed action": "...",
  "status": "executed | simulated | failed"
}}
No explanations. No markdown.
"""
    state["enforcement_result"] = llm_call(system, user)
    return state


# -----------------------------
# 5) Audit & Learning Agent / Evaluation agent
# -----------------------------
def audit_learning_agent(state: CyberState) -> CyberState:
    entry = {
        "timestamp": time.time(),
        "raw_row": state.get("raw_row"),
        "processed_event": state.get("processed_event"),
        "threat_report": state.get("threat_report"),
        "response_decision": state.get("response_decision"),
        "enforcement_result": state.get("enforcement_result"),
    }

    logs = state.get("log", [])
    logs.append(entry)
    state["log"] = logs

    return state

# -----------------------------
# Convert tabular dataset to text
# -----------------------------
def flow_row_to_text(row):
    """
    Convert one CIC-IDS2018 row into an LLM-readable security event.
    """
    return (
        f"Network flow observed: "
        f"Protocol {row['Protocol']}, "
        f"Destination port {row['Dst Port']}, "
        f"Flow duration {row['Flow Duration']} microseconds, "
        f"Forward packets {row['Tot Fwd Pkts']}, "
        f"Backward packets {row['Tot Bwd Pkts']}, "
        f"Total forward bytes {row['TotLen Fwd Pkts']}, "
        f"Total backward bytes {row['TotLen Bwd Pkts']}."
    )


# -----------------------------
# Build LangGraph Pipeline
# -----------------------------
def build_graph():
    graph = StateGraph(CyberState)

    graph.add_node("event_processing", event_processing_agent)
    graph.add_node("threat_intel", threat_intelligence_agent)
    graph.add_node("decision", response_decision_agent)
    graph.add_node("enforce", enforcement_agent)
    graph.add_node("audit", audit_learning_agent)

    graph.add_edge(START, "event_processing")
    graph.add_edge("event_processing", "threat_intel")
    graph.add_edge("threat_intel", "decision")
    graph.add_edge("decision", "enforce")
    graph.add_edge("enforce", "audit")
    graph.add_edge("audit", END)

    return graph.compile()



# -----------------------------
# Test Run
# -----------------------------
# if __name__ == "__main__":

#     # Load dataset (use a SMALL subset first)
#     df = pd.read_csv("cis-ids2018.csv")
#     df = df.sample(n=50, random_state=42)

#     agent_graph = build_graph()

#     results = []

#     for _, row in df.iterrows():
#         raw_event = flow_row_to_text(row)

#         output = agent_graph.invoke({
#             "raw_event": raw_event,
#             "processed_event": {},
#             "threat_report": {},
#             "response_decision": {},
#             "enforcement_result": {},
#             "log": []
#         })

#     results.append({
#         "generated_event": raw_event,
#         "true_label": row["Label"],
#         "predicted_label": output["threat_report"]["label"],
#         "confidence": output["threat_report"]["confidence"],
#         "response": output["response_decision"]["response"]
#     })

#     pd.DataFrame(results).to_csv("cicids_llm_results.csv", index=False)
#     print("✅ CIC-IDS2018 evaluation complete")
