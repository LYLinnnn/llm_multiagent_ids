import numpy as np
from sentence_transformers import SentenceTransformer


THREAT_DOCS = [
    "DoS attack: single source floods target with packets causing resource exhaustion. Indicators: very high packets per second, long flows, repeated same IP.",

    "DDoS attack: many distributed sources overwhelm a service simultaneously. Indicators: multiple IPs, extremely high traffic, short bursts, SYN floods.",

    "SSH brute force: repeated login attempts to port 22. Indicators: many short connections, failed authentication, same IP retrying passwords.",

    "FTP brute force: repeated login attempts to port 21. Indicators: numerous connections, authentication failures, small payloads.",

    "Web attacks like SQL injection, XSS, command injection. Indicators: HTTP traffic, abnormal payloads, suspicious query strings, POST requests.",

    "Infiltration from inside network: lateral movement or internal privilege abuse. Indicators: internal IP scanning, unusual internal ports, privilege escalation.",

    "Botnet activity: infected host contacting command and control servers. Indicators: periodic beaconing, small regular traffic, suspicious domains.",

    "Port scanning and reconnaissance: scanning many ports quickly. Indicators: many short connections to sequential ports, low bytes per flow."
]


class ThreatRAG:
    def __init__(self):
        self.docs = THREAT_DOCS
        self.model = SentenceTransformer("all-MiniLM-L6-v2")

        self.embeddings = self.model.encode(
            self.docs,
            normalize_embeddings=True
        )

    def retrieve(self, query, k=3):
        q = self.model.encode([query], normalize_embeddings=True)[0]
        scores = np.dot(self.embeddings, q)
        idx = np.argsort(scores)[-k:][::-1]
        return [self.docs[i] for i in idx]
