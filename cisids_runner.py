import pandas as pd
from cyber_management_agents2 import build_graph
import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# -----------------------------
# 1) Load & sample dataset
# -----------------------------
df = pd.read_csv("cis-ids2018.csv")

# Optional: small sample for testing
df = df.sample(30, random_state=42).reset_index(drop=True)

# -----------------------------
# 2) Build agent graph
# -----------------------------
agent_graph = build_graph()

results = []

# -----------------------------
# 3) Run inference (NO LABEL LEAKAGE)
# -----------------------------
for _, row in df.iterrows():
    # Convert row to dictionary
    row_dict = row.to_dict()

    # Extract and REMOVE true label
    true_label = row_dict.pop("Label", None)

    # Safety check (prevents accidental leakage)
    assert "Label" not in row_dict, "🚨 Label leaked into agent input!"

    # Invoke agent graph with label-free data
    output = agent_graph.invoke({
        "raw_row": row_dict,   # ✅ agents see features only
        "log": []
    })

    # Store results (label only used for evaluation)
    results.append({
        "true_label": true_label,
        "predicted_label": output["threat_report"]["label"],
        "attack_type": output["threat_report"]["attack_type"],
        "processed_event": output["processed_event"],
        "reasoning": output["threat_report"]["reasoning"],
        "confidence": output["threat_report"]["confidence"],
        "response": output["response_decision"]["response"]
    })

# -----------------------------
# 4) Save results
# -----------------------------
results_df = pd.DataFrame(results)
results_df.to_csv("results/llm_ids_results4.csv", index=False)

print("✅ CIC-IDS2018 LLM evaluation complete")

# -----------------------------
# 5) Display summary
# -----------------------------
print("\n📊 FINAL SUMMARY")
print(results_df)