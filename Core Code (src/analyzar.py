import hashlib
import json
import re

class BlockchainSecurityAnalyzer:
    def __init__(self, blockchain_data):
        self.blockchain = blockchain_data
        self.issues = []

    # 🔍 Check block hash integrity
    def check_hash_integrity(self):
        for i, block in enumerate(self.blockchain):
            block_data = json.dumps(block["data"], sort_keys=True).encode()
            calculated_hash = hashlib.sha256(block_data).hexdigest()

            if block["hash"] != calculated_hash:
                self.issues.append(f"[!] Block {i} hash mismatch!")

    # 🔗 Check previous hash linkage
    def check_chain_link(self):
        for i in range(1, len(self.blockchain)):
            if self.blockchain[i]["previous_hash"] != self.blockchain[i-1]["hash"]:
                self.issues.append(f"[!] Block {i} previous hash mismatch!")

    # 💰 Detect suspicious transactions
    def detect_suspicious_transactions(self):
        for i, block in enumerate(self.blockchain):
            for tx in block["data"]:
                if tx["amount"] > 100000:  # large transaction
                    self.issues.append(f"[!] Suspicious large transaction in Block {i}")

                if not re.match(r"^[A-Za-z0-9]{26,35}$", tx["sender"]):
                    self.issues.append(f"[!] Invalid sender address in Block {i}")

    # ⛓️ Check double spending (same sender quick repeat)
    def detect_double_spending(self):
        seen = {}
        for i, block in enumerate(self.blockchain):
            for tx in block["data"]:
                sender = tx["sender"]
                if sender in seen:
                    self.issues.append(f"[!] Possible double spending by {sender} in Block {i}")
                seen[sender] = True

    # 🚀 Run all checks
    def run_analysis(self):
        self.check_hash_integrity()
        self.check_chain_link()
        self.detect_suspicious_transactions()
        self.detect_double_spending()

        return self.issues


# 🧪 Sample Blockchain Data (Demo)
sample_blockchain = [
    {
        "data": [{"sender": "Alice12345678901234567890123", "amount": 500}],
        "hash": hashlib.sha256(json.dumps([{"sender": "Alice12345678901234567890123", "amount": 500}], sort_keys=True).encode()).hexdigest(),
        "previous_hash": "0"
    },
    {
        "data": [{"sender": "Bob1234567890123456789012345", "amount": 200000}],
        "hash": "fakehash123",  # ❌ Wrong hash for testing
        "previous_hash": "invalid_previous_hash"
    }
]


# ▶️ Run Analyzer
if __name__ == "__main__":
    analyzer = BlockchainSecurityAnalyzer(sample_blockchain)
    issues = analyzer.run_analysis()

    print("🔐 Blockchain Security Report:")
    if issues:
        for issue in issues:
            print(issue)
    else:
        print("✅ No issues found. Blockchain is secure!")
